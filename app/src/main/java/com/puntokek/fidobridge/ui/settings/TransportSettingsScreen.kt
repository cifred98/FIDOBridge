package com.puntokek.fidobridge.ui.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.puntokek.fidobridge.settings.ALL_TRANSPORTS
import com.puntokek.fidobridge.settings.AppSettings
import com.puntokek.fidobridge.settings.AuthenticatorOptions

/**
 * Combined screen for transports and all FIDO2 authenticator options.
 * Transports at the top, then protocol versions, extensions, options,
 * algorithms, PIN protocols, and numeric limits.
 */
@Composable
fun TransportSettingsScreen(modifier: Modifier = Modifier) {
    val currentTransports by AppSettings.transports.collectAsState()
    val versions by AuthenticatorOptions.versions.collectAsState()
    val extensions by AuthenticatorOptions.extensions.collectAsState()
    val options by AuthenticatorOptions.options.collectAsState()
    val algorithms by AuthenticatorOptions.algorithms.collectAsState()
    val pinProtocols by AuthenticatorOptions.pinProtocols.collectAsState()
    val maxMsgSize by AuthenticatorOptions.maxMsgSize.collectAsState()
    val maxCredCount by AuthenticatorOptions.maxCredCount.collectAsState()
    val maxCredIdLen by AuthenticatorOptions.maxCredIdLen.collectAsState()
    val firmwareVersion by AuthenticatorOptions.firmwareVersion.collectAsState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // ── Transports ───────────────────────────────────────────────────
        Text("Advertised Transports", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Override transport types in authenticatorGetInfo, regardless of actual capabilities.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                ALL_TRANSPORTS.forEach { transport ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Checkbox(
                            checked = transport in currentTransports,
                            onCheckedChange = { isChecked ->
                                val newSet = if (isChecked) currentTransports + transport
                                else currentTransports - transport
                                if (newSet.isNotEmpty()) AppSettings.setTransports(newSet)
                            }
                        )
                        Column(modifier = Modifier.padding(start = 4.dp)) {
                            Text(transport, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                transportDescription(transport),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(onClick = { AppSettings.resetTransports() }) {
                    Text("Reset transports")
                }
            }
        }

        HorizontalDivider()

        // ── FIDO2 Options Header ─────────────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("FIDO2 Options", style = MaterialTheme.typography.headlineSmall)
            OutlinedButton(onClick = { AuthenticatorOptions.resetAll() }) {
                Text("Reset All")
            }
        }
        Text(
            "Configure what this authenticator reports in authenticatorGetInfo.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // ── Versions ─────────────────────────────────────────────────────
        SectionCard("Protocol Versions") {
            AuthenticatorOptions.ALL_VERSIONS.forEach { version ->
                CheckboxRow(
                    label = version,
                    checked = version in versions,
                    onCheckedChange = { checked ->
                        AuthenticatorOptions.setVersions(
                            if (checked) versions + version else versions - version
                        )
                    }
                )
            }
        }

        // ── Extensions ───────────────────────────────────────────────────
        SectionCard("Extensions") {
            AuthenticatorOptions.ALL_EXTENSIONS.forEach { ext ->
                CheckboxRow(
                    label = ext,
                    checked = ext in extensions,
                    onCheckedChange = { checked ->
                        AuthenticatorOptions.setExtensions(
                            if (checked) extensions + ext else extensions - ext
                        )
                    }
                )
            }
        }

        // ── Options ──────────────────────────────────────────────────────
        SectionCard("Options (true / false / absent)") {
            AuthenticatorOptions.ALL_OPTIONS.forEach { optDef ->
                TriStateOptionRow(
                    label = optDef.key,
                    description = optDef.description,
                    value = options[optDef.key],
                    onValueChange = { AuthenticatorOptions.setOption(optDef.key, it) }
                )
            }
        }

        // ── Algorithms ───────────────────────────────────────────────────
        SectionCard("Supported Algorithms") {
            AuthenticatorOptions.ALL_ALGORITHMS.forEach { alg ->
                CheckboxRow(
                    label = "${alg.name} (${alg.coseId})",
                    checked = alg.name in algorithms,
                    onCheckedChange = { checked ->
                        AuthenticatorOptions.setAlgorithms(
                            if (checked) algorithms + alg.name else algorithms - alg.name
                        )
                    }
                )
            }
        }

        // ── PIN/UV Auth Protocols ────────────────────────────────────────
        SectionCard("PIN/UV Auth Protocols") {
            AuthenticatorOptions.ALL_PIN_PROTOCOLS.forEach { proto ->
                CheckboxRow(
                    label = "Protocol $proto",
                    checked = proto in pinProtocols,
                    onCheckedChange = { checked ->
                        AuthenticatorOptions.setPinProtocols(
                            if (checked) pinProtocols + proto else pinProtocols - proto
                        )
                    }
                )
            }
        }

        // ── Numeric Limits ───────────────────────────────────────────────
        SectionCard("Numeric Limits") {
            NumericField("maxMsgSize", maxMsgSize) { AuthenticatorOptions.setMaxMsgSize(it) }
            NumericField("maxCredentialCountInList", maxCredCount) { AuthenticatorOptions.setMaxCredCount(it) }
            NumericField("maxCredentialIdLength", maxCredIdLen) { AuthenticatorOptions.setMaxCredIdLen(it) }
            NumericField("firmwareVersion (0 = not reported)", firmwareVersion) { AuthenticatorOptions.setFirmwareVersion(it) }
        }
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
            Spacer(modifier = Modifier.height(4.dp))
            content()
        }
    }
}

@Composable
private fun CheckboxRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 4.dp))
    }
}

@Composable
private fun TriStateOptionRow(
    label: String,
    description: String,
    value: Boolean?,
    onValueChange: (Boolean?) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        TriStateCheckbox(
            state = when (value) {
                true -> ToggleableState.On
                false -> ToggleableState.Indeterminate
                null -> ToggleableState.Off
            },
            onClick = {
                onValueChange(when (value) { null -> true; true -> false; false -> null })
            }
        )
        Column(modifier = Modifier.padding(start = 4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(label, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    when (value) { true -> "✓"; false -> "✗"; null -> "—" },
                    style = MaterialTheme.typography.labelSmall,
                    color = when (value) {
                        true -> MaterialTheme.colorScheme.primary
                        false -> MaterialTheme.colorScheme.error
                        null -> MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
            }
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun NumericField(label: String, value: Int, onValueChange: (Int) -> Unit) {
    var text by remember(value) { mutableStateOf(value.toString()) }
    OutlinedTextField(
        value = text,
        onValueChange = { newText ->
            text = newText
            newText.toIntOrNull()?.let { onValueChange(it) }
        },
        label = { Text(label) },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true
    )
}

private fun transportDescription(transport: String): String = when (transport) {
    "nfc" -> "Near Field Communication"
    "ble" -> "Bluetooth Low Energy"
    "hybrid" -> "caBLE / Hybrid (QR + BLE tunnel)"
    "internal" -> "Platform authenticator"
    "usb" -> "USB HID"
    else -> ""
}
