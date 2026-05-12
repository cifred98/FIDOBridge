package com.puntokek.fidobridge.transport

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.NoCredentialException
import com.puntokek.fidobridge.FidoBridgeApplication
import com.puntokek.fidobridge.bridge.CredentialBridgeActivity
import com.puntokek.fidobridge.bridge.PendingCredentialOperation
import com.puntokek.fidobridge.debug.DebugLog
import com.puntokek.fidobridge.protocol.Ctap2StatusCode
import com.puntokek.fidobridge.protocol.CtapResult
import com.puntokek.fidobridge.protocol.NfcCtap
import com.puntokek.fidobridge.transport.apdu.ApduRequest
import com.puntokek.fidobridge.transport.apdu.ApduResponse
import com.puntokek.fidobridge.util.toHex
import kotlinx.coroutines.*
import java.io.ByteArrayInputStream

/**
 * NFC Host Card Emulation service that acts as a FIDO2 authenticator.
 *
 * Receives ISO 7816-4 APDUs from an NFC reader, routes them through
 * [Ctap2CommandRouter], and delegates credential operations to the
 * Android CredentialManager via [CredentialBridgeActivity].
 */
@OptIn(ExperimentalUnsignedTypes::class)
class FidoNfcService : HostApduService() {

    companion object {
        private const val TAG = "FidoNfcService"
    }

    private val serviceScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var pendingJob: Job? = null

    /** True while waiting for a CredentialManager result to call sendResponseApdu(). */
    @Volatile private var asyncInFlight = false

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate — NFC HCE ready")
    }

    // ── APDU routing ─────────────────────────────────────────────────────

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        Log.d(TAG, "raw APDU (${commandApdu.size}B): ${commandApdu.toHex()}")

        try {
            val request = ApduRequest.parse(commandApdu.toUByteArray())
            DebugLog.logRequest(commandApdu, request)

            // While an async credential operation is running, absorb duplicate
            // commands from the reader (it retries while the user interacts).
            if (asyncInFlight) {
                Log.i(TAG, "Async in-flight — absorbing command, returning null")
                return null
            }

            val result = routeApdu(request)

            return when (result) {
                is CtapResult.Immediate -> {
                    val encoded = result.response.encode()
                    DebugLog.logResponse(encoded, result.response)
                    Log.d(TAG, "raw response (${encoded.size}B): ${encoded.toHex()}")
                    encoded
                }
                is CtapResult.Async -> {
                    startAsyncOperation(result.pending)
                    null
                }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "processCommandApdu failed", t)
            return ApduResponse(ApduResponse.SW_UNKNOWN).encode()
        }
    }

    /**
     * Route an APDU to the appropriate handler.
     */
    private fun routeApdu(request: ApduRequest): CtapResult {
        Log.i(TAG, "routeApdu cla=0x${request.cla.toString(16).padStart(2, '0')} " +
                "ins=0x${request.ins.toString(16).padStart(2, '0')} " +
                "p1=0x${request.p1.toString(16).padStart(2, '0')} " +
                "p2=0x${request.p2.toString(16).padStart(2, '0')} " +
                "dataLen=${request.data.size}")

        // SELECT AID (ISO 7816-4)
        if (request.cla.toInt() == 0x00 &&
            request.ins.toInt() == NfcCtap.INS_SELECT &&
            request.p1.toInt() == 0x04 &&
            request.p2.toInt() == 0x00
        ) {
            Log.i(TAG, "SELECT AID → returning FIDO version string")
            return CtapResult.Immediate(
                ApduResponse(ApduResponse.SW_NO_ERROR, NfcCtap.SELECT_RESPONSE)
            )
        }

        // NFCCTAP_MSG (CLA=0x80, INS=0x10): wraps a CTAP2 command
        if (request.cla.toInt() == 0x80 &&
            request.ins.toInt() == NfcCtap.INS_MSG &&
            request.p1.toInt() == 0x00 &&
            request.p2.toInt() == 0x00 &&
            request.data.isNotEmpty()
        ) {
            val ctap2Command = request.data[0].toUByte()
            val payload = ByteArrayInputStream(
                request.data.toByteArray(), 1, request.data.size - 1
            )
            return FidoBridgeApplication.commandRouter.processCommand(ctap2Command, payload)
        }

        Log.w(TAG, "Unrecognised command → SW_INS_NOT_SUPPORTED")
        return CtapResult.Immediate(ApduResponse(ApduResponse.SW_INS_NOT_SUPPORTED))
    }

    // ── Async credential flow ────────────────────────────────────────────

    /**
     * Launch a CredentialManager flow in the background.
     * Returns null from processCommandApdu; calls sendResponseApdu() when done.
     */
    private fun startAsyncOperation(pending: PendingCredentialOperation) {
        asyncInFlight = true
        pendingJob?.cancel()

        pendingJob = serviceScope.launch {
            try {
                // Pre-check: for GetAssertion, verify credentials exist before
                // launching the (potentially slow) activity UI.
                if (pending.type == PendingCredentialOperation.Type.GET) {
                    if (!preCheckCredentials(pending)) {
                        Log.i(TAG, "Pre-check: no credentials for ${pending.origin}")
                        sendCtap2Response(byteArrayOf(Ctap2StatusCode.NO_CREDENTIALS.code))
                        return@launch
                    }
                }

                // Brief pause to let any previous CredentialBridgeActivity finish
                delay(300)

                // Hand off to CredentialBridgeActivity
                FidoBridgeApplication.setPendingOperation(pending)
                val intent = Intent(
                    this@FidoNfcService,
                    CredentialBridgeActivity::class.java
                ).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                }
                startActivity(intent)

                // Wait for the activity to complete the deferred
                val responseData = pending.deferred.await()
                Log.d(TAG, "Async completed (${responseData.size}B)")
                sendCtap2Response(responseData)
            } catch (e: CancellationException) {
                Log.w(TAG, "Async operation cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "Async operation failed", e)
                sendCtap2Response(byteArrayOf(Ctap2StatusCode.OTHER.code))
            } finally {
                asyncInFlight = false
            }
        }
    }

    /**
     * Pre-check whether the system credential provider has any passkeys for the
     * given rpId. Uses [CredentialManager.prepareGetCredential] which does NOT
     * show any UI — it only queries providers in the background.
     */
    private suspend fun preCheckCredentials(pending: PendingCredentialOperation): Boolean {
        return try {
            val credentialManager = CredentialManager.create(this@FidoNfcService)
            val option = GetPublicKeyCredentialOption(
                requestJson = pending.requestJson,
                clientDataHash = pending.clientDataHash
            )
            val request = GetCredentialRequest.Builder()
                .addCredentialOption(option)
                .setOrigin(pending.origin)
                .build()

            val prepared = credentialManager.prepareGetCredential(request)
            val hasResults = prepared.hasCredentialResults(
                "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
            ) || prepared.hasAuthenticationResults()

            Log.i(TAG, "preCheck: origin=${pending.origin} hasResults=$hasResults")
            hasResults
        } catch (e: NoCredentialException) {
            Log.i(TAG, "preCheck: NoCredentialException for ${pending.origin}")
            false
        } catch (e: Exception) {
            Log.w(TAG, "preCheck failed — proceeding to full flow", e)
            true
        }
    }

    // ── Response helpers ─────────────────────────────────────────────────

    private fun sendCtap2Response(data: ByteArray) {
        val response = ApduResponse(ApduResponse.SW_NO_ERROR, data)
        val encoded = response.encode()
        DebugLog.logResponse(encoded, response)
        Log.d(TAG, "sendResponseApdu (${encoded.size}B): ${encoded.toHex()}")
        sendResponseApdu(encoded)
    }

    // ── Lifecycle ────────────────────────────────────────────────────────

    private fun cancelAsyncOperation() {
        pendingJob?.cancel()
        pendingJob = null
        asyncInFlight = false
        FidoBridgeApplication.cancelPendingOperation()
    }

    override fun onDeactivated(reason: Int) {
        Log.i(TAG, "onDeactivated reason=$reason")
        cancelAsyncOperation()
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}
