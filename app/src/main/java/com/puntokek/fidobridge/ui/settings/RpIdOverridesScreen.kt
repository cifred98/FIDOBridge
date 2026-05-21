package com.puntokek.fidobridge.ui.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.puntokek.fidobridge.settings.RpIdOverride
import com.puntokek.fidobridge.settings.RpIdOverrideRepository

@Composable
fun RpIdOverridesScreen(modifier: Modifier = Modifier) {
    val overrides by RpIdOverrideRepository.overrides.collectAsState()
    var showAddDialog by remember { mutableStateOf(false) }
    var editingOverride by remember { mutableStateOf<RpIdOverride?>(null) }

    Column(modifier = modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "RP ID Overrides",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            FloatingActionButton(
                onClick = { showAddDialog = true },
                modifier = Modifier.size(40.dp)
            ) {
                Text("+", style = MaterialTheme.typography.titleLarge)
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            "Configure per-domain flag overrides. UP/UV flags can be patched in " +
                    "MakeCredential responses (re-signed). For GetAssertion, only the " +
                    "userVerification request parameter can be changed (flags in the response " +
                    "are already signed by the credential key).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(16.dp))

        if (overrides.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "No overrides configured.\nTap + to add one.",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(overrides) { override ->
                    OverrideCard(
                        override = override,
                        onEdit = { editingOverride = it },
                        onDelete = { RpIdOverrideRepository.remove(it.rpId) }
                    )
                }
            }
        }
    }

    if (showAddDialog) {
        OverrideEditDialog(
            initial = null,
            onDismiss = { showAddDialog = false },
            onSave = { override ->
                RpIdOverrideRepository.addOrUpdate(override)
                showAddDialog = false
            }
        )
    }

    if (editingOverride != null) {
        OverrideEditDialog(
            initial = editingOverride,
            onDismiss = { editingOverride = null },
            onSave = { override ->
                RpIdOverrideRepository.addOrUpdate(override)
                editingOverride = null
            }
        )
    }
}

@Composable
private fun OverrideCard(
    override: RpIdOverride,
    onEdit: (RpIdOverride) -> Unit,
    onDelete: (RpIdOverride) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = { onEdit(override) }
    ) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    override.rpId,
                    style = MaterialTheme.typography.titleSmall,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    override.summaryString(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = { onDelete(override) }) {
                Text("🗑️")
            }
        }
    }
}

@Composable
private fun OverrideEditDialog(
    initial: RpIdOverride?,
    onDismiss: () -> Unit,
    onSave: (RpIdOverride) -> Unit
) {
    var rpId by remember { mutableStateOf(initial?.rpId ?: "") }
    var overrideUp by remember { mutableStateOf(initial?.overrideUp) }
    var overrideUv by remember { mutableStateOf(initial?.overrideUv) }
    var userVerification by remember { mutableStateOf(initial?.userVerification ?: "") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial == null) "Add Override" else "Edit Override") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = rpId,
                    onValueChange = { rpId = it },
                    label = { Text("RP ID (e.g. github.com)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    enabled = initial == null
                )

                Text("Flag Overrides (MakeCredential only)", style = MaterialTheme.typography.labelMedium)

                TriStateToggle("UP (User Present)", overrideUp) { overrideUp = it }
                TriStateToggle("UV (User Verified)", overrideUv) { overrideUv = it }

                OutlinedTextField(
                    value = userVerification,
                    onValueChange = { userVerification = it },
                    label = { Text("userVerification (request)") },
                    placeholder = { Text("required / preferred / discouraged") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                Text(
                    "Leave userVerification empty to use default (required). " +
                            "UP/UV flag patches only apply to MakeCredential (we re-sign). " +
                            "GetAssertion responses cannot be modified.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (rpId.isNotBlank()) {
                        val uv = userVerification.trim().ifEmpty { null }
                        onSave(RpIdOverride(rpId.trim(), overrideUp, overrideUv, uv))
                    }
                },
                enabled = rpId.isNotBlank()
            ) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun TriStateToggle(label: String, value: Boolean?, onValueChange: (Boolean?) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        SegmentedButtonRow(value, onValueChange)
    }
}

@Composable
private fun SegmentedButtonRow(value: Boolean?, onValueChange: (Boolean?) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        FilterChip(
            selected = value == null,
            onClick = { onValueChange(null) },
            label = { Text("Off", style = MaterialTheme.typography.labelSmall) }
        )
        FilterChip(
            selected = value == true,
            onClick = { onValueChange(true) },
            label = { Text("True", style = MaterialTheme.typography.labelSmall) }
        )
        FilterChip(
            selected = value == false,
            onClick = { onValueChange(false) },
            label = { Text("False", style = MaterialTheme.typography.labelSmall) }
        )
    }
}
