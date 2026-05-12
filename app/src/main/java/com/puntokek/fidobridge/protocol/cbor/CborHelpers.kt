package com.puntokek.fidobridge.protocol.cbor

import com.puntokek.fidobridge.protocol.Ctap2StatusCode
import com.puntokek.fidobridge.protocol.CoseKeyParam
import com.puntokek.fidobridge.protocol.CoseAlgorithm
import com.puntokek.fidobridge.protocol.ctap2Error
import java.io.ByteArrayOutputStream

/**
 * CBOR helper functions for navigating and extracting values from parsed
 * CTAP2 CBOR structures.
 */

// ── Value extraction ─────────────────────────────────────────────────────

@ExperimentalUnsignedTypes
inline fun <reified T : Any> CborValue?.unbox(): T {
    if (this == null)
        ctap2Error(Ctap2StatusCode.MISSING_PARAMETER, "Failed to unbox ${T::class.java.simpleName} from null")
    if (this is CborBoxedValue<*> && this.value is T) {
        @Suppress("UNCHECKED_CAST")
        return this.value as T
    } else if (this is CborBoxedValue<*>) {
        val temp = this.value
        if (temp is Any) {
            ctap2Error(Ctap2StatusCode.CBOR_UNEXPECTED_TYPE,
                "Failed to unbox ${T::class.java.simpleName}; found ${temp::class.java.simpleName}")
        } else {
            ctap2Error(Ctap2StatusCode.CBOR_UNEXPECTED_TYPE,
                "Failed to unbox ${T::class.java.simpleName}; found null")
        }
    } else {
        ctap2Error(Ctap2StatusCode.CBOR_UNEXPECTED_TYPE,
            "Failed to unbox ${T::class.java.simpleName} from ${this::class.java.simpleName}")
    }
}

// ── Map key lookup (integer-keyed and string-keyed) ──────────────────────

@ExperimentalUnsignedTypes
fun CborValue?.getOptional(index: Long): CborValue? {
    if (this == null)
        ctap2Error(Ctap2StatusCode.INVALID_CBOR, "Failed to look up '$index'; object could not be parsed")
    if (this !is CborLongMap)
        ctap2Error(Ctap2StatusCode.CBOR_UNEXPECTED_TYPE, "Failed to look up '$index'; object is not a CborLongMap")
    return this.value[index]
}

@ExperimentalUnsignedTypes
fun CborValue?.getRequired(index: Long): CborValue {
    return getOptional(index) ?: ctap2Error(Ctap2StatusCode.MISSING_PARAMETER, "Required key missing: $index")
}

@ExperimentalUnsignedTypes
fun CborValue?.getOptional(index: String): CborValue? {
    if (this == null)
        ctap2Error(Ctap2StatusCode.INVALID_CBOR, "Failed to look up '$index'; object could not be parsed")
    if (this !is CborTextStringMap)
        ctap2Error(Ctap2StatusCode.CBOR_UNEXPECTED_TYPE, "Failed to look up '$index'; object is not a CborTextStringMap")
    return this.value[index]
}

@ExperimentalUnsignedTypes
fun CborValue?.getRequired(index: String): CborValue {
    return getOptional(index) ?: ctap2Error(Ctap2StatusCode.MISSING_PARAMETER, "Required key missing: $index")
}

// ── CTAP2 response framing ───────────────────────────────────────────────

/**
 * Wrap a CBOR value as a CTAP2 success response: status byte 0x00 followed
 * by the CBOR-encoded payload.
 */
fun CborValue?.toCtap2SuccessResponse(): ByteArray {
    val out = ByteArrayOutputStream()
    out.write(Ctap2StatusCode.OK.code.toInt())
    this?.writeAsCbor(out)
    return out.toByteArray()
}

// ── COSE key template ────────────────────────────────────────────────────

@ExperimentalUnsignedTypes
fun coseKeyEs256Template(): Map<Long, CborValue> = mapOf(
    CoseKeyParam.KTY to CborLong(CoseKeyParam.KTY_EC2),
    CoseKeyParam.ALG to CborLong(CoseAlgorithm.ES256),
    CoseKeyParam.CRV to CborLong(CoseKeyParam.CRV_P256)
)
