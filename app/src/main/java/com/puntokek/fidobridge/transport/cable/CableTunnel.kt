package com.puntokek.fidobridge.transport.cable

import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * WebSocket tunnel client for caBLE.
 *
 * Connects to the tunnel relay server and provides a bidirectional
 * byte-oriented channel for the Noise handshake and subsequent CTAP2 messaging.
 *
 * The tunnel URL format: wss://{domain}/cable/connect/{tunnelId}
 */
class CableTunnel {

    companion object {
        private const val TAG = "CableTunnel"
        private const val CONNECT_TIMEOUT_MS = 10_000L
    }

    private var webSocket: WebSocket? = null
    private val client = OkHttpClient.Builder()
        .readTimeout(0, java.util.concurrent.TimeUnit.MILLISECONDS)
        .build()

    /** Incoming messages from the tunnel */
    val incoming: Channel<ByteArray> = Channel(Channel.UNLIMITED)

    /** Signals when the WebSocket connection is established */
    val connected = CompletableDeferred<Boolean>()

    /** Signals when the connection is closed */
    val closed = CompletableDeferred<Unit>()

    private val listener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            Log.i(TAG, "Tunnel WebSocket connected")
            // Extract routing ID from response header
            val routingIdHex = response.header("X-caBLE-Routing-ID")
            if (routingIdHex != null) {
                routingId = routingIdHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                Log.i(TAG, "Received routing ID: $routingIdHex (${routingId!!.size} bytes)")
            }
            connected.complete(true)
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            Log.d(TAG, "Received ${bytes.size} bytes from tunnel")
            incoming.trySend(bytes.toByteArray())
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            Log.d(TAG, "Received text message from tunnel (${text.length} chars)")
            incoming.trySend(text.toByteArray())
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            Log.i(TAG, "Tunnel closing: code=$code reason=$reason")
            webSocket.close(1000, null)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            Log.i(TAG, "Tunnel closed: code=$code reason=$reason")
            incoming.close()
            if (!closed.isCompleted) closed.complete(Unit)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            Log.e(TAG, "Tunnel failure: ${t.message}", t)
            if (!connected.isCompleted) connected.complete(false)
            incoming.close(t)
            if (!closed.isCompleted) closed.complete(Unit)
        }
    }

    /**
     * Connect to the tunnel relay server as the authenticator (new tunnel).
     *
     * URL format: wss://{domain}/cable/new/{tunnelId_hex}
     * Subprotocol: fido.cable
     *
     * @param domain The tunnel server domain (e.g., "cable.ua5v.com")
     * @param tunnelId The 16-byte tunnel ID (hex-encoded in the URL)
     * @return true if connection was initiated successfully
     */
    fun connect(domain: String, tunnelId: ByteArray): Boolean {
        val tunnelIdHex = tunnelId.joinToString("") { "%02X".format(it) }
        val url = "wss://$domain${CableConstants.TUNNEL_PATH_NEW}$tunnelIdHex"
        Log.i(TAG, "Connecting to tunnel: $url")

        val request = Request.Builder()
            .url(url)
            .header("Sec-WebSocket-Protocol", CableConstants.WS_SUBPROTOCOL)
            .header("Origin", "wss://$domain")
            .build()

        webSocket = client.newWebSocket(request, listener)
        return true
    }

    /**
     * Get the routing ID returned by the tunnel server in the connection response.
     * Available after [connected] completes with true.
     */
    var routingId: ByteArray? = null
        private set

    /**
     * Send binary data over the tunnel.
     */
    fun send(data: ByteArray): Boolean {
        val ws = webSocket ?: return false
        return ws.send(data.toByteString())
    }

    /**
     * Receive the next message from the tunnel (suspending).
     * Returns null if the channel is closed.
     */
    suspend fun receive(): ByteArray? {
        return try {
            incoming.receive()
        } catch (e: ClosedReceiveChannelException) {
            null
        }
    }

    /**
     * Close the tunnel connection.
     */
    fun close() {
        webSocket?.close(1000, "Session ended")
        webSocket = null
        incoming.close()
        if (!closed.isCompleted) closed.complete(Unit)
    }
}
