package com.puntokek.fidobridge.crypto.mds

import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

private const val TAG = "MdsParser"

/**
 * Parses the FIDO Alliance Metadata Service (MDS) blob.
 * The blob is a JWT (~10MB) whose payload contains authenticator metadata entries.
 */
object MdsParser {

    /**
     * Parse an MDS blob JWT from an InputStream.
     * Returns a list of MDS entries with AAGUID and attestation certificates.
     *
     * The JWT format is: header.payload.signature (dot-separated Base64url).
     * We only need the payload (middle part).
     */
    fun parse(inputStream: InputStream): List<MdsEntry> {
        Log.i(TAG, "Starting MDS blob parse")

        // Read the JWT and extract the payload (second dot-separated part)
        val jwt = inputStream.bufferedReader().use { it.readText() }
        val parts = jwt.split(".")
        if (parts.size != 3) {
            Log.e(TAG, "Invalid JWT format: expected 3 parts, got ${parts.size}")
            return emptyList()
        }

        val payloadJson = String(Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP))
        val root = JSONObject(payloadJson)
        val entries = root.optJSONArray("entries") ?: run {
            Log.e(TAG, "No 'entries' array in MDS blob")
            return emptyList()
        }

        val results = mutableListOf<MdsEntry>()
        for (i in 0 until entries.length()) {
            val entry = entries.optJSONObject(i) ?: continue
            val aaguid = entry.optString("aaguid", "").takeIf { it.isNotBlank() } ?: continue
            val statement = entry.optJSONObject("metadataStatement") ?: continue

            val description = statement.optString("description", "Unknown Device")
            val icon = statement.optString("icon", "").takeIf { it.isNotBlank() }
            val protocolFamily = statement.optString("protocolFamily", "").takeIf { it.isNotBlank() }

            // Attestation root certificates (Base64 DER)
            val certsArray = statement.optJSONArray("attestationRootCertificates")
            val certs = mutableListOf<String>()
            if (certsArray != null) {
                for (j in 0 until certsArray.length()) {
                    val certB64 = certsArray.optString(j, "").takeIf { it.isNotBlank() }
                    if (certB64 != null) certs.add(certB64)
                }
            }

            // Attestation types
            val typesArray = statement.optJSONArray("attestationTypes")
            val types = mutableListOf<String>()
            if (typesArray != null) {
                for (j in 0 until typesArray.length()) {
                    types.add(typesArray.optString(j, ""))
                }
            }

            // Extract subject/issuer from the first certificate if available
            var certSubject: String? = null
            var certIssuer: String? = null
            if (certs.isNotEmpty()) {
                try {
                    val certDer = Base64.decode(certs[0], Base64.DEFAULT)
                    val cf = CertificateFactory.getInstance("X.509")
                    val x509 = cf.generateCertificate(certDer.inputStream()) as X509Certificate
                    certSubject = x509.subjectX500Principal.name
                    certIssuer = x509.issuerX500Principal.name
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse cert for $aaguid: ${e.message}")
                }
            }

            results.add(
                MdsEntry(
                    aaguid = aaguid,
                    description = description,
                    icon = icon,
                    attestationRootCertificates = certs,
                    attestationTypes = types,
                    certSubject = certSubject,
                    certIssuer = certIssuer,
                    protocolFamily = protocolFamily
                )
            )
        }

        Log.i(TAG, "Parsed ${results.size} MDS entries (from ${entries.length()} total)")
        return results
    }

    /**
     * Decode a Base64 DER certificate and return it as an X509Certificate.
     */
    fun decodeCertificate(base64Der: String): X509Certificate? {
        return try {
            val der = Base64.decode(base64Der, Base64.DEFAULT)
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(der.inputStream()) as X509Certificate
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decode certificate: ${e.message}")
            null
        }
    }
}
