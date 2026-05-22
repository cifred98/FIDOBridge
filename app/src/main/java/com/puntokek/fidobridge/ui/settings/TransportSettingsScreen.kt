package com.puntokek.fidobridge.ui.settings

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.puntokek.fidobridge.settings.ALL_TRANSPORTS
import com.puntokek.fidobridge.settings.AppSettings

/**
 * Settings screen for choosing which transport types are advertised
 * in the authenticatorGetInfo response. This is independent of the
 * actual transport capabilities of the device.
 */
@Composable
fun TransportSettingsScreen(modifier: Modifier = Modifier) {
    val currentTransports by AppSettings.transports.collectAsState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Advertised Transports",
            style = MaterialTheme.typography.headlineSmall
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Select which transport types to advertise in the authenticatorGetInfo response. " +
                    "This overrides what the NFC reader sees, regardless of actual capabilities.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(16.dp))

        ALL_TRANSPORTS.forEach { transport ->
            val checked = transport in currentTransports
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp)
            ) {
                Checkbox(
                    checked = checked,
                    onCheckedChange = { isChecked ->
                        val newSet = if (isChecked) {
                            currentTransports + transport
                        } else {
                            currentTransports - transport
                        }
                        if (newSet.isNotEmpty()) {
                            AppSettings.setTransports(newSet)
                        }
                    }
                )
                Spacer(modifier = Modifier.width(8.dp))
                Column {
                    Text(
                        text = transport,
                        style = MaterialTheme.typography.bodyLarge
                    )
                    Text(
                        text = transportDescription(transport),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        OutlinedButton(onClick = { AppSettings.resetTransports() }) {
            Text("Reset to default (NFC only)")
        }
    }
}

private fun transportDescription(transport: String): String = when (transport) {
    "nfc" -> "Near Field Communication"
    "ble" -> "Bluetooth Low Energy"
    "hybrid" -> "caBLE / Hybrid (QR + BLE tunnel)"
    "internal" -> "Platform authenticator"
    "usb" -> "USB HID"
    else -> ""
}
