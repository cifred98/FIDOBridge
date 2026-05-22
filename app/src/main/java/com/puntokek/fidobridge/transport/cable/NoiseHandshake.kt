package com.puntokek.fidobridge.transport.cable

import android.util.Log
import java.security.KeyPair
import java.security.PublicKey

/**
 * Noise protocol handshake implementation for caBLE.
 *
 * Implements Noise KNpsk0 over P-256 with AES-GCM and SHA-256.
 * In caBLE QR flows, the phone (authenticator) is the **responder**.
 *
 * Pattern KNpsk0:
 *   pre-message: -> s (initiator's static key is known to responder, from QR)
 *   message 1:   -> psk, e (initiator sends ephemeral + PSK mixed + AEAD tag)
 *   message 2:   <- e, ee, se (responder sends ephemeral, DH operations, AEAD tag)
 *
 * After handshake, two traffic keys are derived for bidirectional encryption.
 *
 * Key sizes: P-256 X9.62 uncompressed = 65 bytes.
 * Message sizes: 65 (ephemeral) + 16 (AEAD tag) = 81 bytes each.
 */
class NoiseHandshake(
    private val psk: ByteArray,
    private val localKeyPair: KeyPair,
    private val peerStaticPublicKey: PublicKey,
    private val peerStaticCompressed: ByteArray? = null
) {
    companion object {
        private const val TAG = "NoiseHandshake"

        /** Noise protocol name (31 bytes, zero-padded to 32) */
        private val PROTOCOL_NAME = "Noise_KNpsk0_P256_AESGCM_SHA256".toByteArray()
    }

    // Noise state variables
    private var chainingKey: ByteArray
    private var handshakeHash: ByteArray
    private var symmetricKey: ByteArray? = null
    private var symmetricNonce: Int = 0
    private var peerEphemeralPublicKey: PublicKey? = null

    // Output: derived after handshake completes
    var writeKey: ByteArray = ByteArray(0)
        private set
    var readKey: ByteArray = ByteArray(0)
        private set
    var writeNonce: Long = 0
        private set
    var readNonce: Long = 0
        private set

    var isComplete: Boolean = false
        private set

    init {
        // Initialize h = ck = protocol_name zero-padded to 32 bytes
        val initHash = if (PROTOCOL_NAME.size <= 32) {
            PROTOCOL_NAME + ByteArray(32 - PROTOCOL_NAME.size)
        } else {
            CableCrypto.sha256(PROTOCOL_NAME)
        }
        chainingKey = initHash.copyOf()
        handshakeHash = initHash.copyOf()

        // MixHash(prologue) — caBLE QR KNpsk0 uses a 1-byte prologue {0x01}
        mixHash(byteArrayOf(0x01))

        // Pre-message: MixHash(initiator's static public key uncompressed - 65 bytes)
        // Use BouncyCastle's native encoding to avoid Java BigInteger roundtrip issues
        val initiatorStaticUncompressed = if (peerStaticCompressed != null) {
            val spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1")
            spec.curve.decodePoint(peerStaticCompressed).getEncoded(false)
        } else {
            CableCrypto.getUncompressedPublicKey(peerStaticPublicKey)
        }
        mixHash(initiatorStaticUncompressed)
    }

    /**
     * Process the initiator's first message (-> psk, e, AEAD_tag).
     * Message is 81 bytes: 65 (ephemeral uncompressed) + 16 (AEAD tag).
     *
     * @param message The initiator's handshake message
     * @return The responder's handshake message (<- e, ee, se, AEAD_tag) or null on failure
     */
    fun processInitiatorHello(message: ByteArray): ByteArray? {
        try {
            if (message.size != 81) {
                Log.e(TAG, "Initiator hello wrong size: ${message.size}, expected 81")
                return null
            }

            // MixKeyAndHash(PSK) — psk0 token
            mixKeyAndHash(psk)

            // Read initiator's ephemeral public key (65 bytes uncompressed X9.62)
            val peerEphemeralBytes = message.sliceArray(0 until 65)
            peerEphemeralPublicKey = decompressUncompressedKey(peerEphemeralBytes)

            // MixHash(e_i) then MixKey(e_i) — in PSK patterns, 'e' token does both
            mixHash(peerEphemeralBytes)
            mixKey(peerEphemeralBytes)

            // DecryptAndHash the AEAD tag (16 bytes, decrypting empty plaintext)
            val ciphertextTag = message.sliceArray(65 until 81)
            val decrypted = decryptAndHash(ciphertextTag)
            if (decrypted == null) {
                Log.e(TAG, "Failed to decrypt initiator's AEAD tag")
                return null
            }

            // Build responder message
            val localEphemeralUncompressed = CableCrypto.getUncompressedPublicKey(localKeyPair.public)

            // MixHash(e_r) + MixKey(e_r) — PSK pattern requires both for 'e' token
            mixHash(localEphemeralUncompressed)
            mixKey(localEphemeralUncompressed)

            // MixKey(ECDH(e_r.private, e_i.public)) — ee
            val ee = CableCrypto.ecdh(localKeyPair.private, peerEphemeralPublicKey!!)
            mixKey(ee)

            // MixKey(ECDH(e_r.private, s_i.public)) — se (from responder's e to initiator's s)
            val se = CableCrypto.ecdh(localKeyPair.private, peerStaticPublicKey)
            mixKey(se)

            // EncryptAndHash(empty payload) → 16-byte AEAD tag
            val responseTag = encryptAndHash(ByteArray(0))

            // Split: derive traffic keys
            split()

            isComplete = true
            Log.i(TAG, "Noise KNpsk0 handshake complete")

            return localEphemeralUncompressed + responseTag
        } catch (e: Exception) {
            Log.e(TAG, "Failed to process initiator hello", e)
            return null
        }
    }

    /**
     * Encrypt a message using the write key (post-handshake).
     * Pads to 32-byte blocks and uses AES-256-GCM with no AAD.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        check(isComplete) { "Handshake not yet complete" }
        val nonce = buildTrafficNonce(writeNonce++)
        val padded = padToBlockSize(plaintext)
        return CableCrypto.aesGcmEncrypt(writeKey, nonce, padded)
    }

    /**
     * Decrypt a message using the read key (post-handshake).
     * Uses new construction: nonce = 4-byte big-endian counter at nonce[8..12], no AAD.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        check(isComplete) { "Handshake not yet complete" }
        val nonce = buildTrafficNonce(readNonce++)
        val padded = CableCrypto.aesGcmDecrypt(readKey, nonce, ciphertext)
        return unpad(padded)
    }

    /**
     * Pad plaintext to a multiple of 32 bytes per Chromium's caBLE Crypter.
     * Format: plaintext || zeros || one_byte_padding_length
     * where padding_length = number of zero bytes added (not counting the length byte itself).
     * Total padded size is a multiple of 32.
     */
    private fun padToBlockSize(plaintext: ByteArray): ByteArray {
        val blockSize = 32
        // We need space for at least 1 byte (the padding length byte)
        val paddedLen = ((plaintext.size + blockSize) / blockSize) * blockSize
        val padCount = paddedLen - plaintext.size - 1
        val result = ByteArray(paddedLen)
        plaintext.copyInto(result)
        // Zero bytes are already 0 by default
        result[paddedLen - 1] = padCount.toByte()
        return result
    }

    /**
     * Remove padding added by padToBlockSize.
     * Last byte indicates number of zero padding bytes before it.
     */
    private fun unpad(padded: ByteArray): ByteArray {
        require(padded.isNotEmpty()) { "Cannot unpad empty array" }
        val padCount = padded.last().toInt() and 0xFF
        val plaintextLen = padded.size - 1 - padCount
        require(plaintextLen >= 0) { "Invalid padding" }
        return padded.sliceArray(0 until plaintextLen)
    }

    // ── Noise primitives ─────────────────────────────────────────────────

    private fun mixHash(data: ByteArray) {
        handshakeHash = CableCrypto.sha256(handshakeHash + data)
    }

    private fun mixKey(inputKeyMaterial: ByteArray) {
        // HKDF2: salt=ck, ikm=inputKeyMaterial → 64 bytes → split into ck(32) + tempK(32)
        val output = CableCrypto.hkdf(
            ikm = inputKeyMaterial,
            salt = chainingKey,
            info = ByteArray(0),
            length = 64
        )
        chainingKey = output.sliceArray(0 until 32)
        symmetricKey = output.sliceArray(32 until 64)
        symmetricNonce = 0
    }

    private fun mixKeyAndHash(inputKeyMaterial: ByteArray) {
        // HKDF3: salt=ck, ikm=inputKeyMaterial → 96 bytes → split into ck(32) + tempH(32) + tempK(32)
        val output = CableCrypto.hkdf(
            ikm = inputKeyMaterial,
            salt = chainingKey,
            info = ByteArray(0),
            length = 96
        )
        chainingKey = output.sliceArray(0 until 32)
        val tempH = output.sliceArray(32 until 64)
        symmetricKey = output.sliceArray(64 until 96)
        symmetricNonce = 0
        mixHash(tempH)
    }

    private fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val key = symmetricKey ?: error("No symmetric key available")
        val nonce = buildHandshakeNonce(symmetricNonce++)
        val ciphertext = CableCrypto.aesGcmEncrypt(key, nonce, plaintext, handshakeHash)
        mixHash(ciphertext)
        return ciphertext
    }

    private fun decryptAndHash(ciphertext: ByteArray): ByteArray? {
        val key = symmetricKey ?: return null
        val nonce = buildHandshakeNonce(symmetricNonce++)
        return try {
            val plaintext = CableCrypto.aesGcmDecrypt(key, nonce, ciphertext, handshakeHash)
            mixHash(ciphertext)
            plaintext
        } catch (e: Exception) {
            Log.e(TAG, "DecryptAndHash failed", e)
            null
        }
    }

    private fun split() {
        // HKDF2: salt=ck, ikm=∅ → 64 bytes → (k1, k2)
        val output = CableCrypto.hkdf(
            ikm = ByteArray(0),
            salt = chainingKey,
            info = ByteArray(0),
            length = 64
        )
        // k1 = initiator write key (we read); k2 = responder write key (we write)
        readKey = output.sliceArray(0 until 32)
        writeKey = output.sliceArray(32 until 64)
    }

    /** Handshake nonce: 4-byte big-endian counter at nonce[0..4] */
    private fun buildHandshakeNonce(counter: Int): ByteArray {
        val nonce = ByteArray(12)
        nonce[0] = (counter shr 24).toByte()
        nonce[1] = (counter shr 16).toByte()
        nonce[2] = (counter shr 8).toByte()
        nonce[3] = counter.toByte()
        return nonce
    }

    /** Traffic nonce (new construction): 4-byte big-endian counter at nonce[8..12] */
    private fun buildTrafficNonce(counter: Long): ByteArray {
        val nonce = ByteArray(12)
        val c = counter.toInt()
        nonce[8] = (c shr 24).toByte()
        nonce[9] = (c shr 16).toByte()
        nonce[10] = (c shr 8).toByte()
        nonce[11] = c.toByte()
        return nonce
    }

    /**
     * Parse an uncompressed X9.62 P-256 public key (65 bytes starting with 0x04).
     */
    private fun decompressUncompressedKey(bytes: ByteArray): PublicKey {
        require(bytes.size == 65 && bytes[0] == 0x04.toByte()) {
            "Expected 65-byte uncompressed P-256 key"
        }
        val spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1")
        val point = spec.curve.decodePoint(bytes)
        val ecSpec = java.security.spec.ECParameterSpec(
            java.security.spec.EllipticCurve(
                java.security.spec.ECFieldFp(spec.curve.field.characteristic),
                spec.curve.a.toBigInteger(),
                spec.curve.b.toBigInteger()
            ),
            java.security.spec.ECPoint(
                spec.g.affineXCoord.toBigInteger(),
                spec.g.affineYCoord.toBigInteger()
            ),
            spec.n,
            spec.h.intValueExact()
        )
        val pubPoint = java.security.spec.ECPoint(
            point.affineXCoord.toBigInteger(),
            point.affineYCoord.toBigInteger()
        )
        val pubSpec = java.security.spec.ECPublicKeySpec(pubPoint, ecSpec)
        val kf = java.security.KeyFactory.getInstance("EC")
        return kf.generatePublic(pubSpec)
    }
}
