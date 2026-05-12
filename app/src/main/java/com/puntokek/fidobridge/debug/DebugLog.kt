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
            return "SELECT AID=${request.data.toByteArray().toHex()}"
        }

        // CTAP2 command (NFCCTAP_MSG)
        if (request.cla.toInt() == 0x80 && request.ins.toInt() == NfcCtap.INS_MSG &&
            request.data.isNotEmpty()
        ) {
            val cmdByte = request.data[0].toByte()
            val cmd = Ctap2Command.fromByte(cmdByte)
            val cmdName = cmd?.name ?: "Unknown(0x${"%02x".format(cmdByte)})"
            val payload = if (request.data.size > 1) {
                val cborBytes = request.data.toByteArray().copyOfRange(1, request.data.size)
                val cbor = try { fromCborToEnd(cborBytes) } catch (_: Exception) { null }
                if (cbor != null) " cbor=${cborValueToString(cbor)}" else " data=${cborBytes.toHex()}"
            } else ""
            return "CTAP2 cmd=$cmdName$payload"
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

            if (data.size > 1) {
                val cborBytes = data.copyOfRange(1, data.size)
                val cbor = try { fromCborToEnd(cborBytes) } catch (_: Exception) { null }
                val payload = if (cbor != null) cborValueToString(cbor) else cborBytes.toHex()
                return "CTAP2 status=$statusName cbor=$payload"
            }
            return "CTAP2 status=$statusName"
        }

        // Version string in SELECT response
        val asString = try { data.decodeToString() } catch (_: Exception) { "" }
        if (asString.startsWith("FIDO_") || asString.startsWith("U2F_")) {
            return "version=$asString"
        }

        return null
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
