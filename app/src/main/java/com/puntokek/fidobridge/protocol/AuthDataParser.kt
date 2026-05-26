package com.puntokek.fidobridge.protocol

import com.puntokek.fidobridge.protocol.cbor.CborValue
import com.puntokek.fidobridge.protocol.cbor.fromCborToEnd
import com.puntokek.fidobridge.util.toHex
import java.nio.ByteBuffer

/**
 * Parsed representation of CTAP2 authenticatorData.
 * See CTAP2 §6.1 (authenticatorData structure).
 */
data class ParsedAuthData(
    val rpIdHash: ByteArray,
    val flags: Byte,
    val up: Boolean,
    val uv: Boolean,
    val at: Boolean,
    val ed: Boolean,
    val signCount: UInt,
    val attestedCredData: AttestedCredData?,
    val rawBytes: ByteArray
) {
    fun flagsString(): String = buildString {
        if (up) append("UP ") else append("-- ")
        if (uv) append("UV ") else append("-- ")
        if (at) append("AT ") else append("-- ")
        if (ed) append("ED") else append("--")
    }

    override fun toString(): String = buildString {
        append("rpIdHash=${rpIdHash.toHex().take(16)}... ")
        append("flags=[${flagsString()}] ")
        append("signCount=$signCount")
        if (attestedCredData != null) {
            append(" aaguid=${attestedCredData.aaguid.toHex()}")
            append(" credId(${attestedCredData.credentialId.size}B)")
        }
    }
}

data class AttestedCredData(
    val aaguid: ByteArray,
    val credentialId: ByteArray,
    val cosePublicKey: CborValue?
)

/**
 * Parser for authenticatorData byte arrays.
 * Returns null if the data is malformed rather than throwing.
 */
object AuthDataParser {

    private const val MIN_AUTH_DATA_LENGTH = 37 // 32 (rpIdHash) + 1 (flags) + 4 (signCount)
    private const val AAGUID_LENGTH = 16
    private const val CRED_ID_LENGTH_SIZE = 2

    /**
     * Parse authenticatorData bytes into structured format.
     * Returns null if data is too short or structurally invalid.
     */
    fun parse(authData: ByteArray): ParsedAuthData? {
        if (authData.size < MIN_AUTH_DATA_LENGTH) return null

        val rpIdHash = authData.copyOfRange(0, 32)
        val flags = authData[32]
        val up = (flags.toInt() and AuthDataFlags.UP.toInt()) != 0
        val uv = (flags.toInt() and AuthDataFlags.UV.toInt()) != 0
        val at = (flags.toInt() and AuthDataFlags.AT.toInt()) != 0
        val ed = (flags.toInt() and AuthDataFlags.ED.toInt()) != 0

        val signCount = ByteBuffer.wrap(authData, 33, 4).int.toUInt()

        var attestedCredData: AttestedCredData? = null
        if (at) {
            attestedCredData = parseAttestedCredData(authData, 37)
        }

        return ParsedAuthData(
            rpIdHash = rpIdHash,
            flags = flags,
            up = up,
            uv = uv,
            at = at,
            ed = ed,
            signCount = signCount,
            attestedCredData = attestedCredData,
            rawBytes = authData
        )
    }

    /**
     * Patch the flags byte in authenticatorData at offset 32.
     * Returns a copy with modified flags.
     */
    fun patchFlags(authData: ByteArray, up: Boolean? = null, uv: Boolean? = null,
                   be: Boolean? = null, bs: Boolean? = null): ByteArray {
        if (authData.size < MIN_AUTH_DATA_LENGTH) return authData
        val patched = authData.copyOf()
        var flags = patched[32].toInt()
        if (up != null) {
            flags = if (up) flags or AuthDataFlags.UP.toInt()
            else flags and AuthDataFlags.UP.toInt().inv()
        }
        if (uv != null) {
            flags = if (uv) flags or AuthDataFlags.UV.toInt()
            else flags and AuthDataFlags.UV.toInt().inv()
        }
        if (be != null) {
            flags = if (be) flags or AuthDataFlags.BE.toInt()
            else flags and AuthDataFlags.BE.toInt().inv()
        }
        if (bs != null) {
            flags = if (bs) flags or AuthDataFlags.BS.toInt()
            else flags and AuthDataFlags.BS.toInt().inv()
        }
        patched[32] = flags.toByte()
        return patched
    }

    /**
     * Patch the AAGUID in attestedCredentialData (bytes 37..52 of authData).
     * Only valid when AT flag is set. Returns a copy with modified AAGUID.
     */
    fun patchAaguid(authData: ByteArray, newAaguid: ByteArray): ByteArray {
        if (authData.size < MIN_AUTH_DATA_LENGTH + AAGUID_LENGTH) return authData
        if (newAaguid.size != AAGUID_LENGTH) return authData
        val flags = authData[32].toInt()
        if ((flags and AuthDataFlags.AT.toInt()) == 0) return authData

        val patched = authData.copyOf()
        System.arraycopy(newAaguid, 0, patched, 37, AAGUID_LENGTH)
        return patched
    }

    private fun parseAttestedCredData(authData: ByteArray, offset: Int): AttestedCredData? {
        if (authData.size < offset + AAGUID_LENGTH + CRED_ID_LENGTH_SIZE) return null

        val aaguid = authData.copyOfRange(offset, offset + AAGUID_LENGTH)

        val credIdLen = ByteBuffer.wrap(authData, offset + AAGUID_LENGTH, CRED_ID_LENGTH_SIZE)
            .short.toInt() and 0xFFFF

        val credIdStart = offset + AAGUID_LENGTH + CRED_ID_LENGTH_SIZE
        if (authData.size < credIdStart + credIdLen) return null

        val credentialId = authData.copyOfRange(credIdStart, credIdStart + credIdLen)

        // Try to parse COSE public key CBOR after credential ID
        val coseKeyStart = credIdStart + credIdLen
        val coseKey = if (coseKeyStart < authData.size) {
            try {
                fromCborToEnd(authData.copyOfRange(coseKeyStart, authData.size))
            } catch (_: Exception) {
                null
            }
        } else null

        return AttestedCredData(
            aaguid = aaguid,
            credentialId = credentialId,
            cosePublicKey = coseKey
        )
    }
}
