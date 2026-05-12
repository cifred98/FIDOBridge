package com.puntokek.fidobridge.crypto

import android.content.Context
import android.util.Log
import com.puntokek.fidobridge.protocol.FIDOBRIDGE_AAGUID
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

private const val TAG = "AttestationKey"

// FIDO AAGUID extension OID: 1.3.6.1.4.1.45724.1.1.4
private const val FIDO_AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4"

private const val CA_KEY_FILE = "attestation_ca_key.der"
private const val CA_CERT_FILE = "attestation_ca_cert.der"
private const val LEAF_KEY_FILE = "attestation_leaf_key.der"
private const val LEAF_CERT_FILE = "attestation_leaf_cert.der"

/**
 * Manages the batch attestation key and certificate chain for packed attestation.
 * Keys and certs are generated once on first launch and persisted to internal storage.
 */
object AttestationKey {

    lateinit var certDer: ByteArray
        private set
    lateinit var caCertDer: ByteArray
        private set
    private lateinit var privateKey: PrivateKey

    /**
     * Initialize attestation keys. Must be called once from Application.onCreate().
     * Loads existing keys from storage or generates new ones on first launch.
     */
    fun init(context: Context) {
        val filesDir = context.filesDir

        if (File(filesDir, LEAF_KEY_FILE).exists()) {
            loadKeys(filesDir)
            Log.i(TAG, "Loaded existing attestation keys")
        } else {
            generateAndSaveKeys(filesDir)
            Log.i(TAG, "Generated new attestation keys")
        }
    }

    /**
     * Sign (authenticatorData || clientDataHash) with the batch attestation key
     * using SHA256withECDSA (ES256).
     */
    fun sign(authenticatorData: ByteArray, clientDataHash: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKey)
        sig.update(authenticatorData)
        sig.update(clientDataHash)
        return sig.sign()
    }

    private fun loadKeys(dir: File) {
        caCertDer = File(dir, CA_CERT_FILE).readBytes()
        certDer = File(dir, LEAF_CERT_FILE).readBytes()
        val leafKeyBytes = File(dir, LEAF_KEY_FILE).readBytes()
        val kf = KeyFactory.getInstance("EC")
        privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(leafKeyBytes))
    }

    private fun generateAndSaveKeys(dir: File) {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))

        // Generate CA key pair
        val caKeyPair = kpg.generateKeyPair()
        val caName = X500Name("CN=FIDOBridge Root CA, O=FIDOBridge")
        val now = Date()
        val tenYears = Date(now.time + 10L * 365 * 24 * 3600 * 1000)

        // Self-signed CA certificate
        val caSerial = BigInteger(128, SecureRandom())
        val caCertBuilder = X509v3CertificateBuilder(
            caName,
            caSerial,
            now,
            tenYears,
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
        caCertDer = caCert.encoded

        // Generate leaf (attestation) key pair
        val leafKeyPair = kpg.generateKeyPair()
        val leafName = X500Name("CN=FIDOBridge Attestation, O=FIDOBridge")
        val leafSerial = BigInteger(128, SecureRandom())

        val leafCertBuilder = X509v3CertificateBuilder(
            caName,
            leafSerial,
            now,
            tenYears,
            leafName,
            SubjectPublicKeyInfo.getInstance(leafKeyPair.public.encoded)
        )
        leafCertBuilder.addExtension(
            Extension.basicConstraints, true,
            BasicConstraints(false)
        )
        // FIDO AAGUID extension
        val aaguidValue = DEROctetString(FIDOBRIDGE_AAGUID)
        leafCertBuilder.addExtension(
            ASN1ObjectIdentifier(FIDO_AAGUID_OID), false,
            aaguidValue
        )

        val leafSigner = JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.private)
        val leafCert = JcaX509CertificateConverter().getCertificate(leafCertBuilder.build(leafSigner))
        certDer = leafCert.encoded
        privateKey = leafKeyPair.private

        // Persist to internal storage
        File(dir, CA_KEY_FILE).writeBytes(caKeyPair.private.encoded)
        File(dir, CA_CERT_FILE).writeBytes(caCertDer)
        File(dir, LEAF_KEY_FILE).writeBytes(leafKeyPair.private.encoded)
        File(dir, LEAF_CERT_FILE).writeBytes(certDer)
    }
}
