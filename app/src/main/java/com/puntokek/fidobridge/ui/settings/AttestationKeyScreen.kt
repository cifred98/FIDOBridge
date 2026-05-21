package com.puntokek.fidobridge.ui.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.puntokek.fidobridge.crypto.AttestationKey
import com.puntokek.fidobridge.crypto.AttestationKeyInfo
import com.puntokek.fidobridge.settings.AppSettings
import com.puntokek.fidobridge.util.toHex
import java.util.UUID

@Composable
fun AttestationKeyScreen(modifier: Modifier = Modifier) {
    val currentAaguid by AppSettings.aaguid.collectAsState()
    var keyInfo by remember { mutableStateOf<AttestationKeyInfo?>(null) }
    var aaguidInput by remember { mutableStateOf("") }
    var subjectInput by remember { mutableStateOf("") }
    var issuerInput by remember { mutableStateOf("") }
    var expiryYearsInput by remember { mutableStateOf("") }
    var serialInput by remember { mutableStateOf("") }
    var showRegenerateDialog by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

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
    } catch (_: Exception) {
        null
    }
}
