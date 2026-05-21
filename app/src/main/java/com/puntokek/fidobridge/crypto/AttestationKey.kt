package com.puntokek.fidobridge.crypto

import android.content.Context
import android.util.Log
import com.puntokek.fidobridge.settings.AppSettings
import com.puntokek.fidobridge.util.toHex
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.*

private const val TAG = "AttestationKey"

// FIDO AAGUID extension OID: 1.3.6.1.4.1.45724.1.1.4
private const val FIDO_AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4"

private const val CA_KEY_FILE = "attestation_ca_key.der"
private const val CA_CERT_FILE = "attestation_ca_cert.der"
private const val LEAF_KEY_FILE = "attestation_leaf_key.der"
private const val LEAF_CERT_FILE = "attestation_leaf_cert.der"

/**
 * Immutable snapshot of attestation material for thread-safe usage during signing.
 */
data class AttestationMaterial(
    val aaguid: ByteArray,
    val certDer: ByteArray,
    val caCertDer: ByteArray,
    val privateKey: PrivateKey
) {
    fun sign(authenticatorData: ByteArray, clientDataHash: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKey)
        sig.update(authenticatorData)
        sig.update(clientDataHash)
        return sig.sign()
    }
}

/**
 * Human-readable info about the current attestation key for the settings UI.
 */
data class AttestationKeyInfo(
    val aaguid: String,
    val aaguidUuid: String,
    val certSubject: String,
    val certIssuer: String,
    val certExpiry: String,
    val certSerial: String,
    val certFingerprint: String
)

/**
 * Parameters for certificate generation.
 */
data class CertParams(
    val subject: String,
    val issuer: String,
    val expiryYears: Int,
    val serialHex: String  // empty = random
)

/**
 * Manages the batch attestation key and certificate chain for packed attestation.
 * Keys and certs are generated once on first launch and persisted to internal storage.
 * Supports regeneration with custom AAGUID.
 */
object AttestationKey {

    @Volatile
    private var material: AttestationMaterial? = null
    private lateinit var filesDir: File

    /**
     * Initialize attestation keys. Must be called once from Application.onCreate().
     * Loads existing keys from storage or generates new ones on first launch.
     */
    fun init(context: Context) {
        filesDir = context.filesDir
        val aaguid = AppSettings.getAaguid()

        if (File(filesDir, LEAF_KEY_FILE).exists()) {
            loadKeys(aaguid)
            Log.i(TAG, "Loaded existing attestation keys")
        } else {
            generateAndSaveKeys(aaguid, getCertParamsFromSettings())
            Log.i(TAG, "Generated new attestation keys (aaguid=${aaguid.toHex()})")
        }
    }

    /** Get current attestation material snapshot (thread-safe). */
    fun getMaterial(): AttestationMaterial =
        material ?: error("AttestationKey not initialized")

    // Legacy accessors for backward compatibility
    val certDer: ByteArray get() = getMaterial().certDer
    val caCertDer: ByteArray get() = getMaterial().caCertDer

    fun sign(authenticatorData: ByteArray, clientDataHash: ByteArray): ByteArray =
        getMaterial().sign(authenticatorData, clientDataHash)

    /**
     * Regenerate all keys and certificates with the given AAGUID and cert params.
     * Deletes old key files and generates fresh ones.
     */
    @Synchronized
    fun regenerate(aaguid: ByteArray, certParams: CertParams = getCertParamsFromSettings()) {
        require(aaguid.size == 16) { "AAGUID must be 16 bytes" }
        Log.i(TAG, "Regenerating attestation keys with aaguid=${aaguid.toHex()}")

        // Delete old files
        listOf(CA_KEY_FILE, CA_CERT_FILE, LEAF_KEY_FILE, LEAF_CERT_FILE).forEach {
            File(filesDir, it).delete()
        }

        generateAndSaveKeys(aaguid, certParams)
        Log.i(TAG, "Attestation keys regenerated successfully")
    }

    /** Build CertParams from current AppSettings values. */
    fun getCertParamsFromSettings(): CertParams = CertParams(
        subject = AppSettings.getCertSubject(),
        issuer = AppSettings.getCertIssuer(),
        expiryYears = AppSettings.getCertExpiryYears(),
        serialHex = AppSettings.getCertSerial()
    )

    /**
     * Get human-readable info about the current attestation key.
     */
    fun getKeyInfo(): AttestationKeyInfo {
        val mat = getMaterial()
        val aaguidHex = mat.aaguid.toHex()
        val aaguidUuid = formatAsUuid(mat.aaguid)

        val cert = parseCertificate(mat.certDer)
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(mat.certDer)
            .toHex()
            .chunked(2).joinToString(":")

        val dateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.US)

        return AttestationKeyInfo(
            aaguid = aaguidHex,
            aaguidUuid = aaguidUuid,
            certSubject = cert?.subjectX500Principal?.name ?: "Unknown",
            certIssuer = cert?.issuerX500Principal?.name ?: "Unknown",
            certExpiry = cert?.notAfter?.let { dateFormat.format(it) } ?: "Unknown",
            certSerial = cert?.serialNumber?.toString(16) ?: "Unknown",
            certFingerprint = fingerprint
        )
    }

    private fun formatAsUuid(bytes: ByteArray): String {
        require(bytes.size == 16)
        val hex = bytes.toHex()
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}"
    }

    private fun parseCertificate(der: ByteArray): X509Certificate? = try {
        val cf = CertificateFactory.getInstance("X.509")
        cf.generateCertificate(der.inputStream()) as X509Certificate
    } catch (_: Exception) { null }

    private fun loadKeys(aaguid: ByteArray) {
        val caCertBytes = File(filesDir, CA_CERT_FILE).readBytes()
        val leafCertBytes = File(filesDir, LEAF_CERT_FILE).readBytes()
        val leafKeyBytes = File(filesDir, LEAF_KEY_FILE).readBytes()
        val kf = KeyFactory.getInstance("EC")
        val privKey = kf.generatePrivate(PKCS8EncodedKeySpec(leafKeyBytes))

        material = AttestationMaterial(
            aaguid = aaguid,
            certDer = leafCertBytes,
            caCertDer = caCertBytes,
            privateKey = privKey
        )
    }

    private fun generateAndSaveKeys(aaguid: ByteArray, certParams: CertParams) {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))

        // Generate CA key pair
        val caKeyPair = kpg.generateKeyPair()
        val caName = X500Name(certParams.issuer)
        val now = Date()
        val expiry = Date(now.time + certParams.expiryYears.toLong() * 365 * 24 * 3600 * 1000)

        // Serial: use custom if provided, otherwise random
        val serial = if (certParams.serialHex.isNotBlank()) {
            try { BigInteger(certParams.serialHex, 16) } catch (_: Exception) { BigInteger(128, SecureRandom()) }
        } else {
            BigInteger(128, SecureRandom())
        }

        // Self-signed CA certificate
        val caCertBuilder = X509v3CertificateBuilder(
            caName,
            serial,
            now,
            expiry,
            caName,
            SubjectPublicKeyInfo.getInstance(caKeyPair.public.encoded)
        )
        caCertBuilder.addExtension(
            Extension.basicConstraints, true,
            BasicConstraints(1)
        )
        caCertBuilder.addExtension(
            Extension.subjectKeyIdentifier, false,
            SubjectKeyIdentifier(
                MessageDigest.getInstance("SHA-1")
                    .digest(caKeyPair.public.encoded)
            )
        )

        val caSigner = JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.private)
        val caCert = JcaX509CertificateConverter().getCertificate(caCertBuilder.build(caSigner))
        val caCertDerBytes = caCert.encoded

        // Generate leaf (attestation) key pair
        val leafKeyPair = kpg.generateKeyPair()
        val leafName = X500Name(certParams.subject)
        val leafSerial = BigInteger(128, SecureRandom())

        val leafCertBuilder = X509v3CertificateBuilder(
            caName,
            leafSerial,
            now,
            expiry,
            leafName,
            SubjectPublicKeyInfo.getInstance(leafKeyPair.public.encoded)
        )
        leafCertBuilder.addExtension(
            Extension.basicConstraints, true,
            BasicConstraints(false)
        )
        // FIDO AAGUID extension
        val aaguidValue = DEROctetString(aaguid)
        leafCertBuilder.addExtension(
            ASN1ObjectIdentifier(FIDO_AAGUID_OID), false,
            aaguidValue
        )

        val leafSigner = JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.private)
        val leafCert = JcaX509CertificateConverter().getCertificate(leafCertBuilder.build(leafSigner))
        val leafCertDerBytes = leafCert.encoded
        val leafPrivateKey = leafKeyPair.private

        // Set material atomically
        material = AttestationMaterial(
            aaguid = aaguid,
            certDer = leafCertDerBytes,
            caCertDer = caCertDerBytes,
            privateKey = leafPrivateKey
        )

        // Persist to internal storage
        File(filesDir, CA_KEY_FILE).writeBytes(caKeyPair.private.encoded)
        File(filesDir, CA_CERT_FILE).writeBytes(caCertDerBytes)
        File(filesDir, LEAF_KEY_FILE).writeBytes(leafPrivateKey.encoded)
        File(filesDir, LEAF_CERT_FILE).writeBytes(leafCertDerBytes)
    }
}
