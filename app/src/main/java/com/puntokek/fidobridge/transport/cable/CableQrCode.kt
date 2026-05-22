package com.puntokek.fidobridge.transport.cable

import android.util.Log
import com.puntokek.fidobridge.protocol.cbor.*

private const val TAG = "CableQrCode"

/**
 * Parsed representation of a FIDO2 caBLE QR code.
 *
 * The QR code URI format is: `FIDO:/` followed by digit-encoded CBOR bytes.
 * The digit encoding converts each byte to a 3-digit decimal (zero-padded),
 * yielding a numeric-only string optimized for QR code alphanumeric mode.
 *
 * The CBOR map contains:
 * - Key 0: Client's ephemeral P-256 public key (compressed, 33 bytes)
 * - Key 1: QR secret (16 bytes)
 * - Key 2: Number of known tunnel server domains (optional, integer)
 * - Key 3: Current time as epoch seconds (optional, integer)
 *
 * @see CableConstants for CBOR map key definitions
 */
data class CableQrCode(
    /** Client's ephemeral EC public key (compressed P-256, 33 bytes) */
    val peerPublicKey: ByteArray,
    /** QR secret used for key derivation (16 bytes) */
    val qrSecret: ByteArray,
    /** Number of known tunnel server domains (determines which server to use) */
    val numKnownDomains: Int?,
    /** Client's current time as epoch seconds (for clock skew detection) */
    val currentTime: Long?
) {
    companion object {
        /**
         * Parse a FIDO2 caBLE QR code from its raw URI string.
         *
         * @param uri The full QR code content (starting with "FIDO:/")
         * @return Parsed QR code data, or null if parsing fails
         */
        @OptIn(ExperimentalUnsignedTypes::class)
        fun parse(uri: String): CableQrCode? {
            if (!uri.startsWith(CableConstants.QR_URI_PREFIX, ignoreCase = true)) {
                Log.w(TAG, "QR code does not start with FIDO:/ prefix: ${uri.take(10)}")
                return null
            }

            val digitString = uri.substring(CableConstants.QR_URI_PREFIX.length)
            val cborBytes = decodeDigits(digitString) ?: run {
                Log.w(TAG, "Failed to decode digit string (${digitString.length} digits)")
                return null
            }
            Log.d(TAG, "Decoded ${digitString.length} digits → ${cborBytes.size} bytes")

            return parseCbor(cborBytes)
        }

        /**
         * Decode the caBLE digit encoding.
         *
         * The encoding splits CBOR bytes into 7-byte chunks. Each chunk is
         * interpreted as a **little-endian** unsigned 56-bit integer and rendered
         * as a 17-digit zero-padded decimal string. The last chunk may be shorter
         * (fewer bytes → fewer digits).
         *
         * Digit-to-byte mapping:
         *   7 bytes → 17 digits, 6 bytes → 15 digits, 5 bytes → 13 digits,
         *   4 bytes → 10 digits, 3 bytes → 8 digits, 2 bytes → 5 digits,
         *   1 byte → 3 digits.
         */
        private fun decodeDigits(digits: String): ByteArray? {
            if (digits.isEmpty() || !digits.all { it.isDigit() }) return null

            return try {
                val result = mutableListOf<Byte>()
                var offset = 0
                while (offset < digits.length) {
                    val remaining = digits.length - offset
                    val chunkDigits: Int
                    val chunkBytes: Int

                    if (remaining >= 17) {
                        chunkDigits = 17
                        chunkBytes = 7
                    } else {
                        chunkDigits = remaining
                        chunkBytes = when {
                            remaining <= 3 -> 1
                            remaining <= 5 -> 2
                            remaining <= 8 -> 3
                            remaining <= 10 -> 4
                            remaining <= 13 -> 5
                            remaining <= 15 -> 6
                            else -> 7
                        }
                    }

                    val chunkStr = digits.substring(offset, offset + chunkDigits)
                    val value = chunkStr.toLong()

                    // Little-endian: least significant byte first
                    for (i in 0 until chunkBytes) {
                        result.add(((value shr (i * 8)) and 0xFF).toByte())
                    }

                    offset += chunkDigits
                }
                result.toByteArray()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to decode digit-encoded QR data", e)
                null
            }
        }

        /**
         * Parse the CBOR map from decoded bytes.
         */
        @OptIn(ExperimentalUnsignedTypes::class)
        private fun parseCbor(bytes: ByteArray): CableQrCode? {
            val cbor = fromCborToEnd(bytes) ?: run {
                Log.w(TAG, "Failed to parse CBOR from QR payload (${bytes.size} bytes)")
                return null
            }

            if (cbor !is CborLongMap) {
                Log.w(TAG, "QR CBOR is not a long-keyed map")
                return null
            }

            val map = cbor.value

            // Key 0: public key (33 bytes compressed P-256)
            val publicKeyValue = map[CableConstants.QR_KEY_PUBLIC_KEY]
            if (publicKeyValue !is CborByteString || publicKeyValue.value.size != 33) {
                Log.w(TAG, "Missing or invalid public key in QR CBOR")
                return null
            }

            // Key 1: QR secret (16 bytes)
            val secretValue = map[CableConstants.QR_KEY_QR_SECRET]
            if (secretValue !is CborByteString || secretValue.value.size != 16) {
                Log.w(TAG, "Missing or invalid QR secret in QR CBOR")
                return null
            }

            // Key 2: number of known domains (optional)
            val numDomains = (map[CableConstants.QR_KEY_NUM_KNOWN_DOMAINS] as? CborLong)?.value?.toInt()

            // Key 3: current time (optional)
            val currentTime = (map[CableConstants.QR_KEY_CURRENT_TIME] as? CborLong)?.value

            Log.i(TAG, "Parsed QR code: pubKey=${publicKeyValue.value.size}B secret=${secretValue.value.size}B domains=$numDomains")

            return CableQrCode(
                peerPublicKey = publicKeyValue.value,
                qrSecret = secretValue.value,
                numKnownDomains = numDomains,
                currentTime = currentTime
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CableQrCode) return false
        return peerPublicKey.contentEquals(other.peerPublicKey) &&
                qrSecret.contentEquals(other.qrSecret) &&
                numKnownDomains == other.numKnownDomains &&
                currentTime == other.currentTime
    }

    override fun hashCode(): Int {
        var result = peerPublicKey.contentHashCode()
        result = 31 * result + qrSecret.contentHashCode()
        result = 31 * result + (numKnownDomains ?: 0)
        result = 31 * result + (currentTime?.hashCode() ?: 0)
        return result
    }
}
