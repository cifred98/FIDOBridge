package com.puntokek.fidobridge.transport.cable

import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Cryptographic utilities for the caBLE protocol.
 *
 * Implements:
 * - P-256 ECDH key agreement
 * - HKDF-SHA256 key derivation
 * - AES-256-GCM encryption/decryption
 * - EID derivation from QR secret
 * - Noise KNpsk0 handshake state machine
 */
object CableCrypto {

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    // ── HKDF-SHA256 ──────────────────────────────────────────────────────

    /**
     * HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
     */
    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        mac.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    /**
     * HKDF-Expand: OKM = T(1) || T(2) || ... truncated to [length] bytes
     */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val n = (length + 31) / 32
        val okm = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        for (i in 1..n) {
            mac.reset()
            mac.update(t)
            mac.update(info)
            mac.update(i.toByte())
            t = mac.doFinal()
            val copyLen = minOf(32, length - offset)
            System.arraycopy(t, 0, okm, offset, copyLen)
            offset += copyLen
        }
        return okm
    }

    /**
     * Full HKDF: extract + expand.
     */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hkdfExtract(salt, ikm)
        return hkdfExpand(prk, info, length)
    }

    // ── P-256 ECDH ──────────────────────────────────────────────────────

    /**
     * Generate a new P-256 ephemeral key pair.
     */
    fun generateP256KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        return kpg.generateKeyPair()
    }

    /**
     * Perform ECDH key agreement and return the shared secret (32 bytes).
     */
    fun ecdh(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)
        return agreement.generateSecret()
    }

    /**
     * Compress a P-256 public key to 33 bytes (0x02/0x03 prefix + X coordinate).
     */
    fun compressPublicKey(publicKey: PublicKey): ByteArray {
        val ecPub = publicKey as java.security.interfaces.ECPublicKey
        val x = ecPub.w.affineX.toByteArray().let { padOrTrim(it, 32) }
        val y = ecPub.w.affineY
        val prefix: Byte = if (y.testBit(0)) 0x03 else 0x02
        return byteArrayOf(prefix) + x
    }

    /**
     * Decompress a 33-byte compressed P-256 public key.
     */
    fun decompressPublicKey(compressed: ByteArray): PublicKey {
        require(compressed.size == 33) { "Compressed key must be 33 bytes" }
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val point = spec.curve.decodePoint(compressed)
        // Get uncompressed point bytes (0x04 + X + Y) and use Android's default EC KeyFactory
        val uncompressed = point.getEncoded(false)
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
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePublic(pubSpec)
    }

    // ── AES-256-GCM ─────────────────────────────────────────────────────

    /**
     * Encrypt with AES-256-GCM.
     * @return nonce (12 bytes) + ciphertext + tag (16 bytes)
     */
    fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    /**
     * Decrypt with AES-256-GCM.
     * @param ciphertext The ciphertext + tag (no nonce prefix)
     */
    fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    // ── EID Derivation ──────────────────────────────────────────────────

    /**
     * Derive a value using the caBLE HKDF pattern.
     * info = 4-byte **little-endian** type integer (per Chromium/webauthn-rs).
     *
     * @param secret The QR secret (16 bytes IKM)
     * @param salt Salt for HKDF (e.g., decrypted EID for PSK derivation)
     * @param type The DerivedValueType constant
     * @param length Output length in bytes
     */
    fun derive(secret: ByteArray, salt: ByteArray, type: Int, length: Int): ByteArray {
        val info = ByteArray(4)
        info[0] = type.toByte()
        info[1] = (type shr 8).toByte()
        info[2] = (type shr 16).toByte()
        info[3] = (type shr 24).toByte()
        return hkdf(ikm = secret, salt = salt, info = info, length = length)
    }

    /**
     * Derive the EID key (64 bytes: 32 AES key + 32 HMAC key) from the QR secret.
     */
    fun deriveEidKey(qrSecret: ByteArray): ByteArray {
        return derive(qrSecret, ByteArray(0), CableConstants.DerivedValueType.EID_KEY, 64)
    }

    /**
     * Derive the tunnel ID (16 bytes) from the QR secret.
     */
    fun deriveTunnelId(qrSecret: ByteArray): ByteArray {
        return derive(qrSecret, ByteArray(0), CableConstants.DerivedValueType.TUNNEL_ID, 16)
    }

    /**
     * Derive the PSK (32 bytes) from the QR secret and the decrypted EID.
     */
    fun derivePsk(qrSecret: ByteArray, eid: ByteArray): ByteArray {
        return derive(qrSecret, eid, CableConstants.DerivedValueType.PSK, 32)
    }

    /**
     * Construct the EID plaintext (16 bytes).
     * Layout (per webauthn-rs/Chromium):
     * [0]: reserved (0x00)
     * [1..11]: nonce (10 bytes)
     * [11..14]: routing_id (3 bytes)
     * [14..16]: tunnel_server_domain_id (2 bytes, little-endian)
     */
    fun buildEidPlaintext(tunnelServerDomainId: Int, routingId: ByteArray, nonce: ByteArray): ByteArray {
        require(routingId.size == 3) { "Routing ID must be 3 bytes" }
        require(nonce.size == 10) { "Nonce must be 10 bytes" }
        val eid = ByteArray(16)
        eid[0] = 0x00  // reserved
        System.arraycopy(nonce, 0, eid, 1, 10)        // bytes 1-10
        System.arraycopy(routingId, 0, eid, 11, 3)    // bytes 11-13
        eid[14] = tunnelServerDomainId.toByte()       // LE low byte
        eid[15] = (tunnelServerDomainId shr 8).toByte() // LE high byte
        return eid
    }

    /**
     * Encrypt an EID plaintext to produce the 20-byte BLE advert payload.
     * Uses AES-256-ECB for the 16-byte block, then appends 4-byte HMAC-SHA256 tag
     * computed over the **encrypted** bytes (not the plaintext).
     */
    fun encryptEid(eidPlaintext: ByteArray, eidKey: ByteArray): ByteArray {
        require(eidPlaintext.size == 16) { "EID plaintext must be 16 bytes" }
        require(eidKey.size == 64) { "EID key must be 64 bytes" }

        val aesKey = eidKey.sliceArray(0 until 32)
        val hmacKey = eidKey.sliceArray(32 until 64)

        // AES-256-ECB encrypt (single 16-byte block)
        val cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"))
        val encrypted = cipher.doFinal(eidPlaintext)

        // HMAC-SHA256 over the **encrypted** bytes, truncated to 4 bytes
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
        val hmac = mac.doFinal(encrypted)
        val tag = hmac.sliceArray(0 until 4)

        return encrypted + tag
    }

    /**
     * Decrypt a 20-byte BLE advert to recover the EID plaintext.
     * Returns null if the HMAC tag doesn't match.
     */
    fun decryptEid(advert: ByteArray, eidKey: ByteArray): ByteArray? {
        require(advert.size == 20) { "Advert must be 20 bytes" }
        require(eidKey.size == 64) { "EID key must be 64 bytes" }

        val aesKey = eidKey.sliceArray(0 until 32)
        val hmacKey = eidKey.sliceArray(32 until 64)

        val encrypted = advert.sliceArray(0 until 16)
        val tag = advert.sliceArray(16 until 20)

        // AES-256-ECB decrypt
        val cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"))
        val plaintext = cipher.doFinal(encrypted)

        // Verify HMAC tag
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
        val expectedTag = mac.doFinal(plaintext).sliceArray(0 until 4)

        return if (tag.contentEquals(expectedTag)) plaintext else null
    }

    /**
     * Get the uncompressed (X9.62) encoding of a P-256 public key (65 bytes).
     */
    fun getUncompressedPublicKey(publicKey: PublicKey): ByteArray {
        val ecPub = publicKey as java.security.interfaces.ECPublicKey
        val x = ecPub.w.affineX.toByteArray().let { padOrTrim(it, 32) }
        val y = ecPub.w.affineY.toByteArray().let { padOrTrim(it, 32) }
        return byteArrayOf(0x04) + x + y
    }

    /** Pad or trim a BigInteger byte array to exactly [size] bytes. */
    private fun padOrTrim(bytes: ByteArray, size: Int): ByteArray {
        return when {
            bytes.size == size -> bytes
            bytes.size > size -> bytes.sliceArray(bytes.size - size until bytes.size)
            else -> ByteArray(size - bytes.size) + bytes
        }
    }

    // ── SHA-256 helper ──────────────────────────────────────────────────

    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }
}
