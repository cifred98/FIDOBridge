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
import com.puntokek.fidobridge.ui.debug.DebugLogPanel
import com.puntokek.fidobridge.ui.settings.AttestationKeyScreen
import com.puntokek.fidobridge.ui.settings.RpIdOverridesScreen
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
                    label = { Text("Debug Log") },
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 }
                )
                NavigationBarItem(
                    icon = { Text("🔑") },
                    label = { Text("Attestation") },
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 }
                )
                NavigationBarItem(
                    icon = { Text("⚙️") },
                    label = { Text("Overrides") },
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 }
                )
            }
        }
    ) { innerPadding ->
        when (selectedTab) {
            0 -> DebugLogPanel(modifier = Modifier.padding(innerPadding))
            1 -> AttestationKeyScreen(modifier = Modifier.padding(innerPadding))
            2 -> RpIdOverridesScreen(modifier = Modifier.padding(innerPadding))
        }
    }
}