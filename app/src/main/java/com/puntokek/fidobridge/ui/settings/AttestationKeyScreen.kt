package com.puntokek.fidobridge.ui.settings

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.puntokek.fidobridge.crypto.AttestationKey
import com.puntokek.fidobridge.crypto.AttestationKeyInfo
import com.puntokek.fidobridge.crypto.CertParams
import com.puntokek.fidobridge.crypto.mds.MdsEntry
import com.puntokek.fidobridge.crypto.mds.MdsParser
import com.puntokek.fidobridge.crypto.mds.MdsRepository
import com.puntokek.fidobridge.settings.AppSettings
import com.puntokek.fidobridge.util.toHex
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

@Composable
fun AttestationKeyScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val currentAaguid by AppSettings.aaguid.collectAsState()
    var keyInfo by remember { mutableStateOf<AttestationKeyInfo?>(null) }
    var aaguidInput by remember { mutableStateOf("") }
    var subjectInput by remember { mutableStateOf("") }
    var issuerInput by remember { mutableStateOf("") }
    var expiryYearsInput by remember { mutableStateOf("") }
    var serialInput by remember { mutableStateOf("") }
    var showRegenerateDialog by remember { mutableStateOf(false) }
    var showMdsBrowser by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // MDS state
    val mdsEntries by MdsRepository.entries.collectAsState()
    val mdsLoaded by MdsRepository.isLoaded.collectAsState()
    var mdsLoading by remember { mutableStateOf(false) }
    var mdsStatus by remember { mutableStateOf<String?>(null) }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        mdsLoading = true
        mdsStatus = null
        scope.launch {
            val success = withContext(Dispatchers.IO) {
                context.contentResolver.openInputStream(uri)?.use { stream ->
                    MdsRepository.importBlob(stream)
                } ?: false
            }
            mdsLoading = false
            mdsStatus = if (success) "Loaded ${MdsRepository.entries.value.size} authenticators"
            else "Failed to parse MDS blob"
        }
    }

    LaunchedEffect(currentAaguid) {
        keyInfo = try { AttestationKey.getKeyInfo() } catch (_: Exception) { null }
        aaguidInput = formatAsUuid(currentAaguid)
        subjectInput = AppSettings.getCertSubject()
        issuerInput = AppSettings.getCertIssuer()
        expiryYearsInput = AppSettings.getCertExpiryYears().toString()
        serialInput = AppSettings.getCertSerial()
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Attestation Key",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )

        // Current Key Info
        keyInfo?.let { info ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Current Key", style = MaterialTheme.typography.titleMedium)
                    InfoRow("AAGUID", info.aaguidUuid)
                    InfoRow("Subject", info.certSubject)
                    InfoRow("Issuer", info.certIssuer)
                    InfoRow("Expires", info.certExpiry)
                    InfoRow("Serial", info.certSerial)
                    InfoRow("SHA-256", info.certFingerprint)
                }
            }
        }

        // ── MDS Import & Browse ──────────────────────────────────────────
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("FIDO Metadata Service", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Import the MDS blob from mds.fidoalliance.org to clone a certified authenticator's attestation identity.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedButton(
                        onClick = { filePicker.launch("*/*") },
                        enabled = !mdsLoading
                    ) {
                        Text(if (mdsLoaded) "Re-import" else "Import Blob")
                    }

                    if (mdsLoaded) {
                        Button(onClick = { showMdsBrowser = true }) {
                            Text("Browse (${mdsEntries.size})")
                        }
                    }

                    if (mdsLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    }
                }

                if (mdsLoaded) {
                    OutlinedButton(onClick = {
                        MdsRepository.clear()
                        mdsStatus = "MDS data cleared"
                    }) {
                        Text("Clear")
                    }
                }

                mdsStatus?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                }
            }
        }

        // AAGUID
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("AAGUID", style = MaterialTheme.typography.titleMedium)

                OutlinedTextField(
                    value = aaguidInput,
                    onValueChange = { aaguidInput = it },
                    label = { Text("UUID format") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 14.sp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(onClick = { aaguidInput = UUID.randomUUID().toString() }) {
                        Text("Random")
                    }
                    OutlinedButton(onClick = {
                        AppSettings.resetAaguid()
                        aaguidInput = formatAsUuid(AppSettings.getAaguid())
                        errorMessage = null
                    }) {
                        Text("Reset")
                    }
                }
            }
        }

        // Certificate Parameters
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Certificate Parameters", style = MaterialTheme.typography.titleMedium)

                OutlinedTextField(
                    value = subjectInput,
                    onValueChange = { subjectInput = it },
                    label = { Text("Subject (X.500 DN)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    textStyle = LocalTextStyle.current.copy(fontSize = 13.sp)
                )

                OutlinedTextField(
                    value = issuerInput,
                    onValueChange = { issuerInput = it },
                    label = { Text("Issuer / CA (X.500 DN)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    textStyle = LocalTextStyle.current.copy(fontSize = 13.sp)
                )

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = expiryYearsInput,
                        onValueChange = { expiryYearsInput = it },
                        label = { Text("Validity (years)") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = serialInput,
                        onValueChange = { serialInput = it },
                        label = { Text("Serial (hex, empty=random)") },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                    )
                }

                OutlinedButton(onClick = {
                    AppSettings.resetCertParams()
                    subjectInput = AppSettings.getCertSubject()
                    issuerInput = AppSettings.getCertIssuer()
                    expiryYearsInput = AppSettings.getCertExpiryYears().toString()
                    serialInput = AppSettings.getCertSerial()
                }) {
                    Text("Reset to defaults")
                }
            }
        }

        // Error message
        if (errorMessage != null) {
            Text(errorMessage!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        // Action Buttons
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Actions", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Regenerating creates a new key pair and certificate. " +
                            "Previous registrations will no longer validate attestation.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            val parsed = parseUuidToBytes(aaguidInput.trim())
                            if (parsed == null) {
                                errorMessage = "Invalid UUID format"
                                return@Button
                            }
                            errorMessage = null
                            val years = expiryYearsInput.toIntOrNull() ?: 10
                            AppSettings.setAaguid(parsed)
                            AppSettings.setCertSubject(subjectInput.trim())
                            AppSettings.setCertIssuer(issuerInput.trim())
                            AppSettings.setCertExpiryYears(years)
                            AppSettings.setCertSerial(serialInput.trim())
                            AttestationKey.regenerate(parsed)
                            keyInfo = try { AttestationKey.getKeyInfo() } catch (_: Exception) { null }
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Save & Regenerate")
                    }

                    OutlinedButton(
                        onClick = { showRegenerateDialog = true },
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        ),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Regenerate Only")
                    }
                }
            }
        }
    }

    // ── Dialogs ──────────────────────────────────────────────────────────

    if (showRegenerateDialog) {
        AlertDialog(
            onDismissRequest = { showRegenerateDialog = false },
            title = { Text("Regenerate Key?") },
            text = { Text("Generate a new key pair using current settings. Previous attestations will no longer verify.") },
            confirmButton = {
                TextButton(onClick = {
                    showRegenerateDialog = false
                    AttestationKey.regenerate(AppSettings.getAaguid())
                    keyInfo = try { AttestationKey.getKeyInfo() } catch (_: Exception) { null }
                }) { Text("Regenerate") }
            },
            dismissButton = {
                TextButton(onClick = { showRegenerateDialog = false }) { Text("Cancel") }
            }
        )
    }

    if (showMdsBrowser) {
        MdsBrowserDialog(
            entries = mdsEntries,
            onDismiss = { showMdsBrowser = false },
            onApply = { entry, certIndex ->
                showMdsBrowser = false
                applyMdsEntry(entry, certIndex)
                // Refresh UI
                aaguidInput = formatAsUuid(AppSettings.getAaguid())
                subjectInput = AppSettings.getCertSubject()
                issuerInput = AppSettings.getCertIssuer()
                keyInfo = try { AttestationKey.getKeyInfo() } catch (_: Exception) { null }
                mdsStatus = "Applied: ${entry.description}"
            }
        )
    }
}

// ── MDS Browser Dialog (full screen) ─────────────────────────────────────

@Composable
private fun MdsBrowserDialog(
    entries: List<MdsEntry>,
    onDismiss: () -> Unit,
    onApply: (MdsEntry, Int) -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    var selectedEntry by remember { mutableStateOf<MdsEntry?>(null) }

    val filteredEntries = remember(entries, searchQuery) {
        if (searchQuery.isBlank()) entries
        else {
            val query = searchQuery.lowercase()
            entries.filter {
                it.description.lowercase().contains(query) ||
                        it.aaguid.lowercase().contains(query) ||
                        (it.certSubject?.lowercase()?.contains(query) == true)
            }
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background
        ) {
            Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                // Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Browse MDS", style = MaterialTheme.typography.titleLarge)
                    TextButton(onClick = onDismiss) { Text("Close") }
                }

                Spacer(modifier = Modifier.height(8.dp))

                // Search
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    label = { Text("Search by name, AAGUID, or issuer") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                Text(
                    "${filteredEntries.size} results",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 4.dp)
                )

                // List
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(filteredEntries, key = { it.aaguid }) { entry ->
                        Card(
                            modifier = Modifier.fillMaxWidth().clickable { selectedEntry = entry },
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    entry.description,
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
                                        entry.aaguid,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    if (entry.certCount > 0) {
                                        Text(
                                            "${entry.certCount} cert${if (entry.certCount > 1) "s" else ""}",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Cert selection when an entry is tapped
    if (selectedEntry != null) {
        CertSelectionDialog(
            entry = selectedEntry!!,
            onDismiss = { selectedEntry = null },
            onApply = { entry, certIndex ->
                selectedEntry = null
                onApply(entry, certIndex)
            }
        )
    }
}

@Composable
private fun CertSelectionDialog(
    entry: MdsEntry,
    onDismiss: () -> Unit,
    onApply: (MdsEntry, Int) -> Unit
) {
    var selectedCertIndex by remember { mutableStateOf(0) }

    val certDetails = remember(entry) {
        entry.attestationRootCertificates.mapIndexed { index, b64 ->
            val cert = MdsParser.decodeCertificate(b64)
            if (cert != null) {
                CertDetail(index, cert.subjectX500Principal.name, cert.issuerX500Principal.name,
                    cert.sigAlgName, cert.publicKey.algorithm, getKeySize(cert))
            } else {
                CertDetail(index, "Failed to parse", "", "", "", 0)
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(entry.description, style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("AAGUID: ${entry.aaguid}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)

                if (certDetails.isEmpty()) {
                    Text("No attestation certificates available.", color = MaterialTheme.colorScheme.error)
                } else {
                    Text("Select certificate:", style = MaterialTheme.typography.bodySmall)
                    certDetails.forEach { detail ->
                        Card(
                            modifier = Modifier.fillMaxWidth().clickable { selectedCertIndex = detail.index },
                            colors = CardDefaults.cardColors(
                                containerColor = if (selectedCertIndex == detail.index)
                                    MaterialTheme.colorScheme.primaryContainer
                                else MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Column(modifier = Modifier.padding(8.dp)) {
                                Text("Cert ${detail.index + 1}", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                                Text("S: ${detail.subject}", style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text("I: ${detail.issuer}", style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text("${detail.algorithm} (${detail.keyType} ${detail.keySize}b)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onApply(entry, selectedCertIndex) }, enabled = certDetails.isNotEmpty()) { Text("Apply") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

// ── Helpers ──────────────────────────────────────────────────────────────

private data class CertDetail(val index: Int, val subject: String, val issuer: String, val algorithm: String, val keyType: String, val keySize: Int)

private fun getKeySize(cert: java.security.cert.X509Certificate): Int = try {
    when (val key = cert.publicKey) {
        is java.security.interfaces.ECPublicKey -> key.params.order.bitLength()
        is java.security.interfaces.RSAPublicKey -> key.modulus.bitLength()
        else -> 0
    }
} catch (_: Exception) { 0 }

private fun applyMdsEntry(entry: MdsEntry, certIndex: Int) {
    val aaguidBytes = entry.aaguid.replace("-", "").lowercase()
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    val certB64 = entry.attestationRootCertificates.getOrNull(certIndex)
    val cert = certB64?.let { MdsParser.decodeCertificate(it) }

    val subject = cert?.subjectX500Principal?.name ?: "CN=${entry.description}"
    val issuer = cert?.issuerX500Principal?.name ?: subject

    AppSettings.setAaguid(aaguidBytes)
    AppSettings.setCertSubject(subject)
    AppSettings.setCertIssuer(issuer)

    AttestationKey.regenerate(aaguidBytes, CertParams(
        subject = subject,
        issuer = issuer,
        expiryYears = AppSettings.getCertExpiryYears(),
        serialHex = AppSettings.getCertSerial()
    ))
}

@Composable
private fun InfoRow(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
    }
}

private fun formatAsUuid(bytes: ByteArray): String {
    if (bytes.size != 16) return bytes.toHex()
    val hex = bytes.toHex()
    return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}"
}

private fun parseUuidToBytes(input: String): ByteArray? {
    val hex = input.replace("-", "").lowercase()
    if (hex.length != 32) return null
    return try {
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    } catch (_: Exception) { null }
}
