package com.puntokek.fidobridge.transport.cable

import android.content.Context
import android.content.Intent
import android.util.Log
import com.puntokek.fidobridge.FidoBridgeApplication
import com.puntokek.fidobridge.bridge.CredentialBridgeActivity
import com.puntokek.fidobridge.bridge.PendingCredentialOperation
import com.puntokek.fidobridge.protocol.Ctap2StatusCode
import com.puntokek.fidobridge.protocol.CtapResult
import kotlinx.coroutines.*
import java.io.ByteArrayInputStream
import java.security.KeyPair

/**
 * Full lifecycle manager for a single caBLE session.
 *
 * Flow:
 * 1. Parse QR → derive EID and tunnel ID
 * 2. Start BLE advertising with derived EID
 * 3. Connect to tunnel server via WebSocket
 * 4. Perform Noise KNpsk0 handshake (we are responder)
 * 5. Enter ACTIVE state — decrypt incoming CTAP2 commands, encrypt responses
 * 6. Teardown when done or on error
 */
class CableSession(
    private val qrCode: CableQrCode,
    private val context: Context
) {
    companion object {
        private const val TAG = "CableSession"
    }

    enum class State {
        IDLE,
        ADVERTISING,
        TUNNEL_CONNECTING,
        NOISE_HANDSHAKE,
        ACTIVE,
        CLOSED
    }

    var state: State = State.IDLE
        private set

    private var bleAdvertiser: CableBleAdvertiser? = null
    private var tunnel: CableTunnel? = null
    private var noiseHandshake: NoiseHandshake? = null
    private var localKeyPair: KeyPair? = null
    private var sessionJob: Job? = null

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Derived values
    private lateinit var eidPlaintext: ByteArray
    private lateinit var tunnelId: ByteArray
    private lateinit var psk: ByteArray
    private lateinit var eidKey: ByteArray
    private var tunnelDomainId: Int = 0

    /**
     * Start the caBLE session.
     * This initiates BLE advertising and tunnel connection.
     */
    fun start(): Job {
        Log.i(TAG, "Starting caBLE session")

        // Generate our ephemeral key pair for the Noise handshake
        localKeyPair = CableCrypto.generateP256KeyPair()

        // Derive EID key and tunnel ID from QR secret
        eidKey = CableCrypto.deriveEidKey(qrCode.qrSecret)
        tunnelId = CableCrypto.deriveTunnelId(qrCode.qrSecret)

        // Pick tunnel domain index 0 (Google's cable.ua5v.com)
        tunnelDomainId = 0

        state = State.TUNNEL_CONNECTING

        sessionJob = scope.launch {
            try {
                // Step 1: Connect to tunnel server first to get routing ID
                tunnel = CableTunnel()
                val domain = CableConstants.KNOWN_TUNNEL_DOMAINS[tunnelDomainId]
                tunnel!!.connect(domain, tunnelId)

                val connectedOk = tunnel!!.connected.await()
                if (!connectedOk) {
                    Log.e(TAG, "Failed to connect to tunnel server")
                    close()
                    return@launch
                }
                Log.i(TAG, "Tunnel connected")

                // Step 2: Get routing ID from tunnel server response
                val routingId = tunnel!!.routingId ?: run {
                    Log.w(TAG, "No routing ID from server, using random")
                    ByteArray(3).also { java.security.SecureRandom().nextBytes(it) }
                }
                Log.i(TAG, "Routing ID received")

                // Step 3: Build EID with server-provided routing ID
                val nonce = ByteArray(10).also { java.security.SecureRandom().nextBytes(it) }
                eidPlaintext = CableCrypto.buildEidPlaintext(tunnelDomainId, routingId, nonce)
                val advertPayload = CableCrypto.encryptEid(eidPlaintext, eidKey)

                // Step 4: Start BLE advertising with the correct EID
                state = State.ADVERTISING
                bleAdvertiser = CableBleAdvertiser(context)
                val advertisingStarted = bleAdvertiser!!.startAdvertising(advertPayload)
                if (!advertisingStarted) {
                    Log.w(TAG, "BLE advertising failed to start, continuing with tunnel only")
                }

                // Perform Noise handshake (initiator connects after detecting BLE advert)
                state = State.NOISE_HANDSHAKE
                val handshakeSuccess = performNoiseHandshake()

                // Stop BLE advertising after handshake completes
                bleAdvertiser?.stopAdvertising()

                if (!handshakeSuccess) {
                    Log.e(TAG, "Noise handshake failed")
                    close()
                    return@launch
                }

                // Send post-handshake message (GetInfo response)
                sendPostHandshakeMessage()

                // Enter active state — process CTAP2 commands
                state = State.ACTIVE
                Log.i(TAG, "caBLE session ACTIVE — ready for CTAP2 commands")

                processCtap2Loop()
            } catch (e: CancellationException) {
                Log.i(TAG, "Session cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "Session error", e)
            } finally {
                cleanup()
            }
        }

        return sessionJob!!
    }

    /**
     * Perform the Noise KNpsk0 handshake as responder.
     * We wait for the initiator's hello (81 bytes), then send our response (81 bytes).
     */
    private suspend fun performNoiseHandshake(): Boolean {
        val peerStaticKey = CableCrypto.decompressPublicKey(qrCode.peerPublicKey)

        // Derive PSK from QR secret + EID plaintext
        psk = CableCrypto.derivePsk(qrCode.qrSecret, eidPlaintext)

        noiseHandshake = NoiseHandshake(
            psk = psk,
            localKeyPair = localKeyPair!!,
            peerStaticPublicKey = peerStaticKey,
            peerStaticCompressed = qrCode.peerPublicKey
        )

        // Wait for initiator hello (81 bytes: 65 ephemeral + 16 AEAD tag)
        val initiatorHello = tunnel!!.receive() ?: run {
            Log.e(TAG, "Tunnel closed before receiving handshake")
            return false
        }

        // Process and generate response
        val response = noiseHandshake!!.processInitiatorHello(initiatorHello) ?: run {
            Log.e(TAG, "Failed to process initiator hello")
            return false
        }

        // Send our handshake response (81 bytes: 65 ephemeral + 16 AEAD tag)
        tunnel!!.send(response)
        Log.i(TAG, "Sent handshake response (${response.size} bytes)")

        return noiseHandshake!!.isComplete
    }

    /**
     * Send the post-handshake message containing our GetInfo response.
     * Per caBLE v2.1 protocol, the phone sends this first after handshake completes.
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    private suspend fun sendPostHandshakeMessage() {
        val getInfoCbor = com.puntokek.fidobridge.protocol.Ctap2Authenticator.handleGetInfo()
        val getInfoBytes = getInfoCbor.toCbor()

        // Build post-handshake CBOR: { 0x01: getInfoBytes }
        val postHandshake = com.puntokek.fidobridge.protocol.cbor.CborLongMap(mapOf(
            CableConstants.PostHandshakeKey.GET_INFO_RESPONSE to
                    com.puntokek.fidobridge.protocol.cbor.CborByteString(getInfoBytes)
        )).toCbor()

        val encrypted = noiseHandshake!!.encrypt(postHandshake)
        tunnel!!.send(encrypted)
        Log.i(TAG, "Sent post-handshake message (${postHandshake.size} bytes plaintext)")
    }

    /**
     * Main loop: receive encrypted CTAP2 commands, decrypt, process, encrypt response, send.
     * Uses caBLE v2.1 framing: [frame_type: 1 byte] [payload...]
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    private suspend fun processCtap2Loop() {
        while (state == State.ACTIVE) {
            val encryptedMsg = tunnel!!.receive() ?: break

            try {
                // Decrypt the incoming message
                val plaintext = noiseHandshake!!.decrypt(encryptedMsg)
                if (plaintext.isEmpty()) {
                    Log.w(TAG, "Received empty message after decryption")
                    continue
                }

                // Parse frame type (caBLE v2.1)
                val frameType = plaintext[0]
                when (frameType) {
                    CableConstants.FrameType.SHUTDOWN -> {
                        Log.i(TAG, "Received shutdown frame")
                        break
                    }
                    CableConstants.FrameType.CTAP -> {
                        // CTAP frame: [0x01] [ctap2_command_byte] [cbor_payload...]
                        if (plaintext.size < 2) {
                            Log.w(TAG, "CTAP frame too short")
                            continue
                        }
                        val ctap2Data = plaintext.sliceArray(1 until plaintext.size)
                        val responseData = handleCtap2Command(ctap2Data)

                        // Frame response: [0x01] [response_bytes...]
                        val framedResponse = byteArrayOf(CableConstants.FrameType.CTAP) + responseData
                        val encryptedResponse = noiseHandshake!!.encrypt(framedResponse)
                        tunnel!!.send(encryptedResponse)
                        Log.d(TAG, "Sent CTAP2 response (${responseData.size} bytes)")
                    }
                    CableConstants.FrameType.UPDATE -> {
                        Log.i(TAG, "Received update frame (linking info) — ignored")
                    }
                    else -> {
                        Log.w(TAG, "Unknown frame type: 0x${"%02x".format(frameType)}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error processing message", e)
                // Send error response
                val errorFrame = byteArrayOf(CableConstants.FrameType.CTAP, Ctap2StatusCode.OTHER.code)
                val encrypted = noiseHandshake!!.encrypt(errorFrame)
                tunnel!!.send(encrypted)
            }
        }
    }

    /**
     * Handle a single CTAP2 command (same logic as NFC service).
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    private suspend fun handleCtap2Command(ctap2Data: ByteArray): ByteArray {
        val ctap2Command = ctap2Data[0].toUByte()
        val payload = ByteArrayInputStream(ctap2Data, 1, ctap2Data.size - 1)
        val result = FidoBridgeApplication.commandRouter.processCommand(ctap2Command, payload)

        return when (result) {
            is CtapResult.Immediate -> result.response.data ?: byteArrayOf(Ctap2StatusCode.OK.code)
            is CtapResult.Async -> handleAsyncOperation(result.pending)
        }
    }

    /**
     * Handle an async credential operation (MakeCredential/GetAssertion).
     * Launches CredentialBridgeActivity and waits for the result.
     */
    private suspend fun handleAsyncOperation(pending: PendingCredentialOperation): ByteArray {
        FidoBridgeApplication.setPendingOperation(pending)
        val intent = Intent(context, CredentialBridgeActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        context.startActivity(intent)

        return try {
            pending.deferred.await()
        } catch (e: Exception) {
            Log.e(TAG, "Async credential operation failed", e)
            byteArrayOf(Ctap2StatusCode.OTHER.code)
        }
    }

    /** Close the session and release all resources. */
    fun close() {
        if (state == State.CLOSED) return
        Log.i(TAG, "Closing caBLE session (was $state)")
        state = State.CLOSED
        sessionJob?.cancel()
        cleanup()
    }

    private fun cleanup() {
        bleAdvertiser?.stopAdvertising()
        bleAdvertiser = null
        tunnel?.close()
        tunnel = null
        noiseHandshake = null
        state = State.CLOSED
    }
}
