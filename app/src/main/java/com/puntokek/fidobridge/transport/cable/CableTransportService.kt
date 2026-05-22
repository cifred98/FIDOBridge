package com.puntokek.fidobridge.transport.cable

import android.content.Context
import android.util.Log
import com.puntokek.fidobridge.FidoBridgeApplication
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Manages the caBLE transport lifecycle.
 *
 * Responsible for:
 * - Initiating sessions from scanned QR codes
 * - Managing BLE advertising
 * - Coordinating the tunnel and Noise handshake
 * - Routing CTAP2 commands to [Ctap2CommandRouter]
 * - Delegating credential operations to [CredentialBridgeActivity]
 *
 * This is a singleton accessed via [FidoBridgeApplication].
 */
object CableTransportService {

    private const val TAG = "CableTransport"

    private lateinit var appContext: Context

    private val _currentSession = MutableStateFlow<CableSession?>(null)
    val currentSession: StateFlow<CableSession?> = _currentSession.asStateFlow()

    private val _status = MutableStateFlow("Idle")
    val status: StateFlow<String> = _status.asStateFlow()

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /**
     * Start a caBLE session from a scanned QR code.
     *
     * @param qrContent The raw QR code string (expected format: "FIDO:/...")
     * @return true if the QR code was valid and a session was started
     */
    fun startSessionFromQr(qrContent: String): Boolean {
        val qrCode = CableQrCode.parse(qrContent)
        if (qrCode == null) {
            Log.w(TAG, "Failed to parse caBLE QR code")
            _status.value = "Invalid QR code"
            return false
        }

        // Cancel any existing session
        _currentSession.value?.close()

        val session = CableSession(qrCode, appContext)
        _currentSession.value = session
        _status.value = "Starting..."

        scope.launch {
            try {
                _status.value = "Advertising & connecting..."
                val job = session.start()

                // Monitor session state changes
                launch {
                    while (session.state != CableSession.State.CLOSED) {
                        _status.value = when (session.state) {
                            CableSession.State.IDLE -> "Idle"
                            CableSession.State.ADVERTISING -> "BLE Advertising..."
                            CableSession.State.TUNNEL_CONNECTING -> "Connecting to tunnel..."
                            CableSession.State.NOISE_HANDSHAKE -> "Noise handshake..."
                            CableSession.State.ACTIVE -> "Active — processing commands"
                            CableSession.State.CLOSED -> "Closed"
                        }
                        delay(200)
                    }
                }

                job.join()
                _status.value = "Session ended"
                _currentSession.value = null
            } catch (e: Exception) {
                Log.e(TAG, "caBLE session failed", e)
                _status.value = "Error: ${e.message}"
                _currentSession.value = null
            }
        }

        return true
    }

    /** Cancel the current session (if any). */
    fun cancelSession() {
        _currentSession.value?.close()
        _currentSession.value = null
        _status.value = "Idle"
    }
}
