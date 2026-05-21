package com.puntokek.fidobridge.protocol

import android.util.Log
import com.puntokek.fidobridge.bridge.PendingCredentialOperation
import com.puntokek.fidobridge.bridge.WebAuthnBridge
import com.puntokek.fidobridge.protocol.cbor.*
import com.puntokek.fidobridge.transport.apdu.ApduResponse
import kotlinx.coroutines.CompletableDeferred
import java.io.InputStream

private const val TAG = "Ctap2CommandRouter"

/**
 * Routes incoming CTAP2 commands to the appropriate handler.
 * Synchronous commands (GetInfo) return [CtapResult.Immediate].
 * Credential operations return [CtapResult.Async] for CredentialManager delegation.
 */
@OptIn(ExperimentalUnsignedTypes::class)
class Ctap2CommandRouter {

    /**
     * Process a CTAP2 command.
     * @param rawCommand the CTAP2 command byte
     * @param data the CBOR payload stream (without the command byte)
     */
    fun processCommand(rawCommand: UByte, data: InputStream): CtapResult {
        val command = Ctap2Command.fromByte(rawCommand.toByte())
        val cmdName = command?.name ?: "0x${rawCommand.toString(16)}"
        Log.i(TAG, "processCommand: $cmdName (0x${rawCommand.toString(16)})")

        return try {
            if (command == null) {
                Log.w(TAG, "Unknown command 0x${rawCommand.toString(16)}")
                return ctap2ErrorResponse(Ctap2StatusCode.INVALID_COMMAND)
            }
            when (command) {
                Ctap2Command.GET_INFO -> handleGetInfo()
                Ctap2Command.MAKE_CREDENTIAL -> handleMakeCredential(data)
                Ctap2Command.GET_ASSERTION -> handleGetAssertion(data)
                else -> {
                    Log.w(TAG, "$cmdName not implemented")
                    ctap2ErrorResponse(Ctap2StatusCode.INVALID_COMMAND)
                }
            }
        } catch (e: Ctap2Error) {
            Log.w(TAG, "CTAP2 error: ${e.status.name} (0x${e.status.code.toString(16)})")
            ctap2ErrorResponse(e.status)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error", e)
            ctap2ErrorResponse(Ctap2StatusCode.OTHER)
        }
    }

    // ── Command handlers ─────────────────────────────────────────────────

    private fun handleGetInfo(): CtapResult {
        val responseBytes = Ctap2Authenticator.handleGetInfo().toCtap2SuccessResponse()
        Log.i(TAG, "GetInfo: ${responseBytes.size} bytes")
        return CtapResult.Immediate(ApduResponse(ApduResponse.SW_NO_ERROR, responseBytes))
    }

    private fun handleMakeCredential(data: InputStream): CtapResult {
        val rawBytes = data.readAllBytes()
        val params = fromCborToEnd(rawBytes)
            ?: ctap2Error(Ctap2StatusCode.INVALID_CBOR, "Invalid CBOR in MakeCredential")

        val clientDataHash = params.getRequired(MakeCredentialParam.CLIENT_DATA_HASH).unbox<ByteArray>()
        val rpId = WebAuthnBridge.extractRpId(params, MakeCredentialParam.RP)
        val requestJson = WebAuthnBridge.buildCreateRequestJson(params)
        val origin = "https://$rpId"

        Log.i(TAG, "MakeCredential: rpId=$rpId → delegating to CredentialManager")

        return CtapResult.Async(PendingCredentialOperation(
            type = PendingCredentialOperation.Type.CREATE,
            requestJson = requestJson,
            clientDataHash = clientDataHash,
            origin = origin,
            rpId = rpId,
            deferred = CompletableDeferred()
        ))
    }

    private fun handleGetAssertion(data: InputStream): CtapResult {
        val rawBytes = data.readAllBytes()
        val params = fromCborToEnd(rawBytes)
            ?: ctap2Error(Ctap2StatusCode.INVALID_CBOR, "Invalid CBOR in GetAssertion")

        val clientDataHash = params.getRequired(GetAssertionParam.CLIENT_DATA_HASH).unbox<ByteArray>()
        val rpId = params.getRequired(GetAssertionParam.RP_ID).unbox<String>()
        val requestJson = WebAuthnBridge.buildGetRequestJson(params)
        val origin = "https://$rpId"

        Log.i(TAG, "GetAssertion: rpId=$rpId → delegating to CredentialManager")

        return CtapResult.Async(PendingCredentialOperation(
            type = PendingCredentialOperation.Type.GET,
            requestJson = requestJson,
            clientDataHash = clientDataHash,
            origin = origin,
            rpId = rpId,
            deferred = CompletableDeferred()
        ))
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private fun ctap2ErrorResponse(status: Ctap2StatusCode): CtapResult.Immediate {
        return CtapResult.Immediate(
            ApduResponse(ApduResponse.SW_NO_ERROR, byteArrayOf(status.code))
        )
    }
}
