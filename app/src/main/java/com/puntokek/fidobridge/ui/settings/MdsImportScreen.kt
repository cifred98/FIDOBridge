package com.puntokek.fidobridge.ui.settings

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.puntokek.fidobridge.crypto.AttestationKey
import com.puntokek.fidobridge.crypto.CertParams
import com.puntokek.fidobridge.crypto.mds.MdsEntry
import com.puntokek.fidobridge.crypto.mds.MdsParser
import com.puntokek.fidobridge.crypto.mds.MdsRepository
import com.puntokek.fidobridge.settings.AppSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun MdsImportScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val entries by MdsRepository.entries.collectAsState()
    val isLoaded by MdsRepository.isLoaded.collectAsState()

    var searchQuery by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var selectedEntry by remember { mutableStateOf<MdsEntry?>(null) }
    var showCertDialog by remember { mutableStateOf(false) }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        isLoading = true
        statusMessage = null
        scope.launch {
            val success = withContext(Dispatchers.IO) {
                context.contentResolver.openInputStream(uri)?.use { stream ->
                    MdsRepository.importBlob(stream)
                } ?: false
            }
            isLoading = false
            statusMessage = if (success) {
                "Loaded ${MdsRepository.entries.value.size} authenticators"
            } else {
                "Failed to parse MDS blob"
            }
        }
    }

    Column(modifier = modifier.fillMaxSize()) {
        // Header
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "FIDO Metadata Service",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "Import the MDS blob from mds.fidoalliance.org to clone a certified authenticator's attestation identity.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )
        }

        // Import controls
        Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = { filePicker.launch("*/*") },
                        enabled = !isLoading
                    ) {
                        Text(if (isLoaded) "Re-import" else "Import MDS Blob")
                    }

                    if (isLoaded) {
                        OutlinedButton(onClick = {
                            MdsRepository.clear()
                            statusMessage = "MDS data cleared"
                        }) {
                            Text("Clear")
                        }
                    }

                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                    }
                }

                if (statusMessage != null) {
                    Text(statusMessage!!, style = MaterialTheme.typography.bodySmall)
                }

                if (isLoaded) {
                    Text(
                        "${entries.size} authenticators available",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }

        // Search + list (only when loaded)
        if (isLoaded) {
            Spacer(modifier = Modifier.height(8.dp))

            // Search field
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                label = { Text("Search authenticators") },
                leadingIcon = { Text("🔍") },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Filtered list
            val filteredEntries = remember(entries, searchQuery) {
                if (searchQuery.isBlank()) {
                    entries
                } else {
                    val query = searchQuery.lowercase()
                    entries.filter { entry ->
                        entry.description.lowercase().contains(query) ||
                                entry.aaguid.lowercase().contains(query) ||
                                (entry.certSubject?.lowercase()?.contains(query) == true)
                    }
                }
            }

            Text(
                "${filteredEntries.size} results",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp)
            )

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                items(filteredEntries, key = { it.aaguid }) { entry ->
                    AuthenticatorListItem(
                        entry = entry,
                        onClick = {
                            selectedEntry = entry
                            showCertDialog = true
                        }
                    )
                }
            }
        }
    }

    // Certificate selection dialog
    if (showCertDialog && selectedEntry != null) {
        CertSelectionDialog(
            entry = selectedEntry!!,
            onDismiss = {
                showCertDialog = false
                selectedEntry = null
            },
            onApply = { entry, certIndex ->
                showCertDialog = false
                selectedEntry = null
                applyMdsEntry(entry, certIndex)
                statusMessage = "Applied: ${entry.description}"
            }
        )
    }
}

@Composable
private fun AuthenticatorListItem(entry: MdsEntry, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = entry.description,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = entry.aaguid,
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (entry.certCount > 0) {
                    Text(
                        text = "${entry.certCount} cert${if (entry.certCount > 1) "s" else ""}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }
    }
}

@Composable
private fun CertSelectionDialog(
    entry: MdsEntry,
    onDismiss: () -> Unit,
    onApply: (MdsEntry, Int) -> Unit
) {
    var selectedCertIndex by remember { mutableStateOf(0) }

    // Parse certificate details
    val certDetails = remember(entry) {
        entry.attestationRootCertificates.mapIndexed { index, b64 ->
            val cert = MdsParser.decodeCertificate(b64)
            if (cert != null) {
                CertDetail(
                    index = index,
                    subject = cert.subjectX500Principal.name,
                    issuer = cert.issuerX500Principal.name,
                    algorithm = cert.sigAlgName,
                    keyType = cert.publicKey.algorithm,
                    keySize = getKeySize(cert)
                )
            } else {
                CertDetail(index, "Failed to parse", "", "", "", 0)
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(entry.description, style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "AAGUID: ${entry.aaguid}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )

                if (certDetails.isEmpty()) {
                    Text(
                        "No attestation certificates available for this device.",
                        color = MaterialTheme.colorScheme.error
                    )
                } else {
                    Text(
                        "Select a certificate to use as attestation root:",
                        style = MaterialTheme.typography.bodySmall
                    )

                    certDetails.forEach { detail ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { selectedCertIndex = detail.index },
                            colors = CardDefaults.cardColors(
                                containerColor = if (selectedCertIndex == detail.index)
                                    MaterialTheme.colorScheme.primaryContainer
                                else
                                    MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Column(modifier = Modifier.padding(8.dp)) {
                                Text(
                                    "Certificate ${detail.index + 1}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    "Subject: ${detail.subject}",
                                    style = MaterialTheme.typography.bodySmall,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    "Issuer: ${detail.issuer}",
                                    style = MaterialTheme.typography.bodySmall,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    "Algorithm: ${detail.algorithm} (${detail.keyType}, ${detail.keySize} bits)",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onApply(entry, selectedCertIndex) },
                enabled = certDetails.isNotEmpty()
            ) {
                Text("Apply")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

private data class CertDetail(
    val index: Int,
    val subject: String,
    val issuer: String,
    val algorithm: String,
    val keyType: String,
    val keySize: Int
)

private fun getKeySize(cert: java.security.cert.X509Certificate): Int {
    return try {
        when (val key = cert.publicKey) {
            is java.security.interfaces.ECPublicKey -> {
                key.params.order.bitLength()
            }
            is java.security.interfaces.RSAPublicKey -> {
                key.modulus.bitLength()
            }
            else -> 0
        }
    } catch (_: Exception) { 0 }
}

/**
 * Apply an MDS entry's attestation parameters to regenerate our attestation key.
 * Uses the selected certificate's subject/issuer and the device's AAGUID.
 */
private fun applyMdsEntry(entry: MdsEntry, certIndex: Int) {
    // Parse AAGUID from UUID string to 16 bytes
    val aaguidBytes = entry.aaguid.replace("-", "").lowercase()
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // Get cert parameters from the selected certificate
    val certB64 = entry.attestationRootCertificates.getOrNull(certIndex)
    val cert = certB64?.let { MdsParser.decodeCertificate(it) }

    val subject = cert?.subjectX500Principal?.name ?: "CN=${entry.description}"
    val issuer = cert?.issuerX500Principal?.name ?: subject

    // Save settings
    AppSettings.setAaguid(aaguidBytes)
    AppSettings.setCertSubject(subject)
    AppSettings.setCertIssuer(issuer)

    // Regenerate attestation key with these parameters
    val certParams = CertParams(
        subject = subject,
        issuer = issuer,
        expiryYears = AppSettings.getCertExpiryYears(),
        serialHex = AppSettings.getCertSerial()
    )
    AttestationKey.regenerate(aaguidBytes, certParams)
}
