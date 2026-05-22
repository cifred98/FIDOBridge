package com.puntokek.fidobridge.crypto.mds

/**
 * A single authenticator entry from the FIDO Alliance Metadata Service blob.
 */
data class MdsEntry(
    val aaguid: String,
    val description: String,
    val icon: String?,
    val attestationRootCertificates: List<String>,
    val attestationTypes: List<String>,
    val certSubject: String?,
    val certIssuer: String?,
    val protocolFamily: String?
) {
    /** Number of root certificates available */
    val certCount: Int get() = attestationRootCertificates.size
}
