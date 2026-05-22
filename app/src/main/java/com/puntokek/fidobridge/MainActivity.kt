package com.puntokek.fidobridge

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import com.puntokek.fidobridge.ui.cable.CableQrScanScreen
import com.puntokek.fidobridge.ui.debug.DebugLogPanel
import com.puntokek.fidobridge.ui.settings.AttestationKeyScreen
import com.puntokek.fidobridge.ui.settings.MdsImportScreen
import com.puntokek.fidobridge.ui.settings.RpIdOverridesScreen
import com.puntokek.fidobridge.ui.settings.TransportSettingsScreen
import com.puntokek.fidobridge.ui.theme.FIDOBridgeTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            FIDOBridgeTheme {
                MainScreen()
            }
        }
    }
}

@Composable
private fun MainScreen() {
    var selectedTab by remember { mutableIntStateOf(0) }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    icon = { Text("📋") },
                    label = { Text("Debug") },
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 }
                )
                NavigationBarItem(
                    icon = { Text("📷") },
                    label = { Text("caBLE") },
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 }
                )
                NavigationBarItem(
                    icon = { Text("🔑") },
                    label = { Text("Attestation") },
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 }
                )
                NavigationBarItem(
                    icon = { Text("📦") },
                    label = { Text("MDS") },
                    selected = selectedTab == 3,
                    onClick = { selectedTab = 3 }
                )
                NavigationBarItem(
                    icon = { Text("📡") },
                    label = { Text("Transports") },
                    selected = selectedTab == 4,
                    onClick = { selectedTab = 4 }
                )
                NavigationBarItem(
                    icon = { Text("⚙️") },
                    label = { Text("Overrides") },
                    selected = selectedTab == 5,
                    onClick = { selectedTab = 5 }
                )
            }
        }
    ) { innerPadding ->
        when (selectedTab) {
            0 -> DebugLogPanel(modifier = Modifier.padding(innerPadding))
            1 -> CableQrScanScreen(modifier = Modifier.padding(innerPadding))
            2 -> AttestationKeyScreen(modifier = Modifier.padding(innerPadding))
            3 -> MdsImportScreen(modifier = Modifier.padding(innerPadding))
            4 -> TransportSettingsScreen(modifier = Modifier.padding(innerPadding))
            5 -> RpIdOverridesScreen(modifier = Modifier.padding(innerPadding))
        }
    }
}