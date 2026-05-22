package com.puntokek.fidobridge.transport.cable

/**
 * Constants for the FIDO2 caBLE (Cloud-Assisted BLE) / Hybrid transport protocol.
 *
 * References:
 * - CTAP2.2 §11.5 (Hybrid transport)
 * - Chromium: device/fido/cable/v2_constants.h
 * - kanidm/webauthn-rs: webauthn-authenticator-rs/src/cable/
 */
object CableConstants {

    /** BLE service UUID for FIDO2 caBLE advertisements (16-bit UUID 0xFFF9) */
    const val CABLE_BLE_SERVICE_UUID = "0000fff9-0000-1000-8000-00805f9b34fb"

    /** Legacy BLE service UUID (Google Cable, used by iOS 16 and older Chrome) */
    const val CABLE_BLE_SERVICE_UUID_LEGACY = "0000fde2-0000-1000-8000-00805f9b34fb"

    /** Known tunnel server domains by index */
    val KNOWN_TUNNEL_DOMAINS = arrayOf(
        "cable.ua5v.com",   // 0 = Google
        "cable.auth.com"    // 1 = Apple
    )

    /**
     * QR code CBOR map keys (per CTAP2.2 §11.5.2):
     * 0 = peer_identity: compressed P-256 public key (33 bytes)
     * 1 = qr_secret (16 bytes)
     * 2 = num_known_domains (uint)
     * 3 = timestamp (uint, epoch seconds)
     * 4 = supports_linking (bool, presence indicates caBLE v2.1)
     * 5 = request_type (text: "ga" | "mc" | "dcp")
     */
    const val QR_KEY_PUBLIC_KEY = 0x00L
    const val QR_KEY_QR_SECRET = 0x01L
    const val QR_KEY_NUM_KNOWN_DOMAINS = 0x02L
    const val QR_KEY_CURRENT_TIME = 0x03L
    const val QR_KEY_SUPPORTS_LINKING = 0x04L
    const val QR_KEY_REQUEST_TYPE = 0x05L

    /** Prefix for FIDO2 caBLE QR code URIs */
    const val QR_URI_PREFIX = "FIDO:/"

    /** Noise protocol pattern used for QR-initiated sessions */
    const val NOISE_PROTOCOL_QR = "Noise_KNpsk0_P256_AESGCM_SHA256"

    /** Noise protocol pattern used for paired/linked device sessions */
    const val NOISE_PROTOCOL_PAIRED = "Noise_NKpsk0_P256_AESGCM_SHA256"

    /** BLE advert size: 16 (encrypted EID) + 4 (HMAC tag) = 20 bytes */
    const val ADVERT_SIZE = 20

    /** EID plaintext size (tunnel_server_domain[2] + routing_id[3] + nonce[10] + flags[1]) */
    const val EID_PLAINTEXT_SIZE = 16

    /** P-256 uncompressed public key size (0x04 + X[32] + Y[32]) */
    const val P256_X962_LENGTH = 65

    /** Derived value type constants for HKDF info field (4-byte big-endian) */
    object DerivedValueType {
        const val EID_KEY = 1
        const val TUNNEL_ID = 2
        const val PSK = 3
    }

    /** caBLE v2.1 frame types */
    object FrameType {
        const val SHUTDOWN: Byte = 0x00
        const val CTAP: Byte = 0x01
        const val UPDATE: Byte = 0x02
    }

    /** Post-handshake message CBOR keys */
    object PostHandshakeKey {
        const val GET_INFO_RESPONSE = 0x01L
        const val LINKING_INFO = 0x02L
    }

    /** WebSocket subprotocol */
    const val WS_SUBPROTOCOL = "fido.cable"

    /** Tunnel URL paths */
    const val TUNNEL_PATH_NEW = "/cable/new/"
    const val TUNNEL_PATH_CONNECT = "/cable/connect/"
}

