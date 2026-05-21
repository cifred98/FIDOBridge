package com.puntokek.fidobridge.debug

import android.util.Log
import com.puntokek.fidobridge.BuildConfig
import com.puntokek.fidobridge.protocol.*
import com.puntokek.fidobridge.protocol.cbor.*
import com.puntokek.fidobridge.transport.apdu.ApduRequest
import com.puntokek.fidobridge.transport.apdu.ApduResponse
import com.puntokek.fidobridge.util.toHex
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.Instant

private const val TAG = "APDU-DEBUG"
private const val MAX_LOG_ENTRIES = 200

@OptIn(ExperimentalUnsignedTypes::class)
object DebugLog {

    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries.asStateFlow()

    fun logRequest(rawApdu: ByteArray, parsed: ApduRequest) {
        if (!BuildConfig.DEBUG) return

        val rawHex = rawApdu.toHex()
        val fields = "CLA=%02x INS=%02x P1=%02x P2=%02x Lc=%d Le=%d".format(
            parsed.cla.toInt(), parsed.ins.toInt(),
            parsed.p1.toInt(), parsed.p2.toInt(),
            parsed.data.size, parsed.le.toInt()
        )

        val decoded = decodeRequestPayload(parsed)

        val entry = LogEntry(
            timestamp = Instant.now(),
            direction = ApduDirection.REQUEST,
            rawHex = rawHex,
            parsedFields = fields,
            decodedCtap = decoded
        )

        Log.d(TAG, "→ REQ raw=$rawHex")
        Log.d(TAG, "→ REQ $fields")
        if (decoded != null) Log.d(TAG, "→ REQ decoded: $decoded")

        appendEntry(entry)
    }

    fun logResponse(rawResponse: ByteArray, parsed: ApduResponse) {
        if (!BuildConfig.DEBUG) return

        val rawHex = rawResponse.toHex()
        val sw = "SW=%04x".format(parsed.status.toInt())
        val dataHex = parsed.data?.toHex() ?: ""
        val fields = "$sw dataLen=${parsed.data?.size ?: 0}"

        val decoded = decodeResponsePayload(parsed)

        val entry = LogEntry(
            timestamp = Instant.now(),
            direction = ApduDirection.RESPONSE,
            rawHex = rawHex,
            parsedFields = fields,
            decodedCtap = decoded
        )

        Log.d(TAG, "← RES raw=$rawHex")
        Log.d(TAG, "← RES $fields")
        if (decoded != null) Log.d(TAG, "← RES decoded: $decoded")

        appendEntry(entry)
    }

    fun clear() {
        _entries.value = emptyList()
    }

    @Synchronized
    private fun appendEntry(entry: LogEntry) {
        val current = _entries.value
        _entries.value = if (current.size >= MAX_LOG_ENTRIES) {
            current.drop(1) + entry
        } else {
            current + entry
        }
    }

    private fun decodeRequestPayload(request: ApduRequest): String? {
        // SELECT AID
        if (request.cla.toInt() == 0x00 && request.ins.toInt() == NfcCtap.INS_SELECT &&
            request.p1.toInt() == 0x04 && request.p2.toInt() == 0x00
        ) {
            val aidHex = request.data.toByteArray().toHex()
            return "SELECT AID $aidHex (FIDO2 NFC)"
        }

        // CTAP2 command (NFCCTAP_MSG)
        if (request.cla.toInt() == 0x80 && request.ins.toInt() == NfcCtap.INS_MSG &&
            request.data.isNotEmpty()
        ) {
            val cmdByte = request.data[0].toByte()
            val cmd = Ctap2Command.fromByte(cmdByte)
            val cmdName = cmd?.name ?: "Unknown(0x${"%02x".format(cmdByte)})"

            if (request.data.size <= 1) return "CTAP2 $cmdName"

            val cborBytes = request.data.toByteArray().copyOfRange(1, request.data.size)
            val cbor = try { fromCborToEnd(cborBytes) } catch (_: Exception) { null }
                ?: return "CTAP2 $cmdName (${cborBytes.size}B payload)"

            // Produce a user-friendly summary based on command type
            return when (cmd) {
                Ctap2Command.MAKE_CREDENTIAL -> {
                    val rpId = try { cbor.getOptional(MakeCredentialParam.RP)?.getOptional("id")?.unbox<String>() } catch (_: Throwable) { null }
                    val userName = try { cbor.getOptional(MakeCredentialParam.USER)?.getOptional("name")?.unbox<String>() } catch (_: Throwable) { null }
                    buildString {
                        append("CTAP2 MakeCredential")
                        if (rpId != null) append("\n  rpId: $rpId")
                        if (userName != null) append("\n  user: $userName")
                    }
                }
                Ctap2Command.GET_ASSERTION -> {
                    val rpId = try { cbor.getOptional(GetAssertionParam.RP_ID)?.unbox<String>() } catch (_: Throwable) { null }
                    buildString {
                        append("CTAP2 GetAssertion")
                        if (rpId != null) append("\n  rpId: $rpId")
                    }
                }
                Ctap2Command.GET_INFO -> "CTAP2 GetInfo"
                else -> "CTAP2 $cmdName"
            }
        }

        return null
    }

    private fun decodeResponsePayload(response: ApduResponse): String? {
        val data = response.data ?: return null
        if (data.isEmpty()) return null

        // CTAP2 response: first byte is status code
        if (response.status == ApduResponse.SW_NO_ERROR && data.isNotEmpty()) {
            val ctapStatus = data[0].toInt() and 0xFF
            val statusName = if (ctapStatus == 0) "OK" else {
                Ctap2StatusCode.entries.find { (it.code.toInt() and 0xFF) == ctapStatus }?.name
                    ?: "0x${"%02x".format(ctapStatus)}"
            }

            if (data.size <= 1) return "CTAP2 status: $statusName"

            val cborBytes = data.copyOfRange(1, data.size)
            val cbor = try { fromCborToEnd(cborBytes) } catch (_: Exception) { null }

            if (cbor == null) return "CTAP2 status: $statusName (${cborBytes.size}B payload)"

            // Try to decode authData for user-friendly output
            val authDataDecoded = decodeAuthDataFromResponse(cbor)

            return buildString {
                append("CTAP2 status: $statusName")
                if (authDataDecoded != null) {
                    append("\n  $authDataDecoded")
                }
                // Show response structure summary
                val summary = decodeResponseSummary(cbor)
                if (summary != null) append("\n  $summary")
            }
        }

        // Version string in SELECT response
        val asString = try { data.decodeToString() } catch (_: Exception) { "" }
        if (asString.startsWith("FIDO_") || asString.startsWith("U2F_")) {
            return "FIDO version: $asString"
        }

        return null
    }

    /**
     * Produce a concise summary of a CTAP2 response CBOR (e.g. GetInfo fields).
     */
    private fun decodeResponseSummary(cbor: CborValue): String? = try {
        decodeResponseSummaryInternal(cbor)
    } catch (_: Throwable) { null }

    private fun decodeResponseSummaryInternal(cbor: CborValue): String? {
        // GetInfo response: has versions (key 1) and aaguid (key 3)
        val versions = try { cbor.getOptional(0x01L) } catch (_: Throwable) { null }
        val aaguid = try { cbor.getOptional(0x03L)?.unbox<ByteArray>() } catch (_: Throwable) { null }
        if (versions != null && aaguid != null) {
            return "GetInfo: aaguid=${aaguid.toHex()}"
        }

        // MakeCredential response: has fmt (key 1) — it's a text string
        val fmt = try { cbor.getOptional(0x01L)?.unbox<String>() } catch (_: Throwable) { null }
        if (fmt != null) {
            return "attestation fmt=$fmt"
        }

        // GetAssertion response: has credential (key 1) with type
        val cred = try { cbor.getOptional(0x01L)?.getOptional("type")?.unbox<String>() } catch (_: Throwable) { null }
        if (cred != null) {
            return "assertion credential type=$cred"
        }

        return null
    }

    /**
     * Attempt to extract and decode authenticatorData from a CTAP2 response CBOR map.
     * Works for both MakeCredential (key 0x02) and GetAssertion (key 0x02) responses.
     */
    private fun decodeAuthDataFromResponse(cbor: CborValue): String? {
        // Both MakeCredential and GetAssertion responses have authData at key 0x02
        val authDataBytes = try {
            cbor.getOptional(0x02L)?.unbox<ByteArray>()
        } catch (_: Throwable) { null } ?: return null

        val parsed = AuthDataParser.parse(authDataBytes) ?: return null
        return parsed.toString()
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
fun cborValueToString(value: CborValue, depth: Int = 0): String {
    if (depth > 5) return "..."
    return when (value) {
        is CborLong -> value.value.toString()
        is CborUnsignedInteger -> value.value.toString()
        is CborNegativeInteger -> "neg(${value.value})"
        is CborTextString -> "\"${value.value}\""
        is CborByteString -> "h'${value.value.toHex()}' (${value.value.size}B)"
        is CborBoolean -> value.value.toString()
        is CborNull -> "null"
        is CborUndefined -> "undefined"
        is CborArray -> "[${value.value.joinToString(", ") { cborValueToString(it, depth + 1) }}]"
        is CborLongMap -> "{${value.value.entries.joinToString(", ") { (k, v) ->
            "$k: ${cborValueToString(v, depth + 1)}"
        }}}"
        is CborTextStringMap -> "{${value.value.entries.joinToString(", ") { (k, v) ->
            "\"$k\": ${cborValueToString(v, depth + 1)}"
        }}}"
        is CborMap -> "{map(${value.value.size})}"
        is CborSimpleValue -> "simple(${value.value})"
        is CborFloatingPointNumber -> value.value.toString()
        else -> value.toString()
    }
}
