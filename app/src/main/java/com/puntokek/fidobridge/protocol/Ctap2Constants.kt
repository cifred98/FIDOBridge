package com.puntokek.fidobridge.protocol

/**
 * CTAP2 (Client to Authenticator Protocol 2) constants as defined in the
 * FIDO2 specification: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
 */

// ── CTAP2 Commands (§6) ──────────────────────────────────────────────────

enum class Ctap2Command(val code: Byte) {
    MAKE_CREDENTIAL(0x01),
    GET_ASSERTION(0x02),
    GET_INFO(0x04),
    CLIENT_PIN(0x06),
    RESET(0x07),
    GET_NEXT_ASSERTION(0x08),
    SELECTION(0x0B);

    companion object {
        private val BY_CODE = entries.associateBy(Ctap2Command::code)
        fun fromByte(code: Byte): Ctap2Command? = BY_CODE[code]
    }
}

// ── CTAP2 Status Codes (§6.3) ────────────────────────────────────────────

enum class Ctap2StatusCode(val code: Byte) {
    OK(0x00),
    INVALID_COMMAND(0x01),
    INVALID_PARAMETER(0x02),
    INVALID_LENGTH(0x03),
    CBOR_UNEXPECTED_TYPE(0x11),
    INVALID_CBOR(0x12),
    MISSING_PARAMETER(0x14),
    UNSUPPORTED_EXTENSION(0x16),
    CREDENTIAL_EXCLUDED(0x19),
    UNSUPPORTED_ALGORITHM(0x26),
    OPERATION_DENIED(0x27),
    KEY_STORE_FULL(0x28),
    UNSUPPORTED_OPTION(0x2B),
    INVALID_OPTION(0x2C),
    KEEPALIVE_CANCEL(0x2D),
    NO_CREDENTIALS(0x2E),
    USER_ACTION_TIMEOUT(0x2F),
    NOT_ALLOWED(0x30),
    PIN_AUTH_INVALID(0x33),
    PIN_REQUIRED(0x36),
    REQUEST_TOO_LARGE(0x39),
    OTHER(0x7F);
}

data class Ctap2Error(val status: Ctap2StatusCode) : Throwable(status.name)

fun ctap2Error(status: Ctap2StatusCode, message: String? = null): Nothing {
    android.util.Log.w("CTAP2", "${status.name}: $message")
    throw Ctap2Error(status)
}

// ── authenticatorMakeCredential request parameters (§6.1) ────────────────

object MakeCredentialParam {
    const val CLIENT_DATA_HASH = 0x01L
    const val RP = 0x02L
    const val USER = 0x03L
    const val PUB_KEY_CRED_PARAMS = 0x04L
    const val EXCLUDE_LIST = 0x05L
    const val EXTENSIONS = 0x06L
    const val OPTIONS = 0x07L
    const val PIN_UV_AUTH_PARAM = 0x08L
    const val PIN_UV_AUTH_PROTOCOL = 0x09L
}

// ── authenticatorMakeCredential response keys (§6.1) ─────────────────────

object MakeCredentialResponse {
    const val FMT = 0x01L
    const val AUTH_DATA = 0x02L
    const val ATT_STMT = 0x03L
}

// ── authenticatorGetAssertion request parameters (§6.2) ──────────────────

object GetAssertionParam {
    const val RP_ID = 0x01L
    const val CLIENT_DATA_HASH = 0x02L
    const val ALLOW_LIST = 0x03L
    const val EXTENSIONS = 0x04L
    const val OPTIONS = 0x05L
    const val PIN_UV_AUTH_PARAM = 0x06L
    const val PIN_UV_AUTH_PROTOCOL = 0x07L
}

// ── authenticatorGetAssertion response keys (§6.2) ───────────────────────

object GetAssertionResponse {
    const val CREDENTIAL = 0x01L
    const val AUTH_DATA = 0x02L
    const val SIGNATURE = 0x03L
    const val USER = 0x04L
    const val NUMBER_OF_CREDENTIALS = 0x05L
}

// ── authenticatorGetInfo response keys (§6.4) ────────────────────────────

object GetInfoResponse {
    const val VERSIONS = 0x01L
    const val EXTENSIONS = 0x02L
    const val AAGUID = 0x03L
    const val OPTIONS = 0x04L
    const val MAX_MSG_SIZE = 0x05L
    const val PIN_UV_AUTH_PROTOCOLS = 0x06L
    const val MAX_CREDENTIAL_COUNT_IN_LIST = 0x07L
    const val MAX_CREDENTIAL_ID_LENGTH = 0x08L
    const val TRANSPORTS = 0x09L
    const val ALGORITHMS = 0x0AL
    const val FIRMWARE_VERSION = 0x0EL
}

// ── COSE Algorithm Identifiers (RFC 8152) ────────────────────────────────

object CoseAlgorithm {
    const val ES256 = -7L       // ECDSA w/ SHA-256
}

object CoseKeyParam {
    const val KTY = 1L          // Key Type
    const val ALG = 3L          // Algorithm
    const val CRV = -1L         // Curve (EC2)
    const val KTY_EC2 = 2L      // Key Type: EC2
    const val CRV_P256 = 1L     // Curve: P-256
}

// ── Authenticator Data Flags (§6.1, Table 1) ─────────────────────────────

object AuthDataFlags {
    const val UP: Byte = 0x01           // User Present
    const val UV: Byte = 0x04           // User Verified
    const val AT: Byte = 0x40           // Attested credential data included
    const val ED: Byte = 0x80.toByte()  // Extension data included
}

// ── Authenticator Identity ────────────────────────────────────────────────

/** Maximum CBOR message size we advertise in GetInfo */
const val MAX_CBOR_MSG_SIZE = 4096L

/** AAGUID identifying this authenticator model (random, unique to FIDOBridge) */
val FIDOBRIDGE_AAGUID = byteArrayOf(
    0xbf.toByte(), 0x21, 0xd0.toByte(), 0xfb.toByte(),
    0x1d, 0xbf.toByte(), 0x4e, 0x72,
    0x8e.toByte(), 0x3f, 0x46, 0x51,
    0x6f, 0x49, 0x34, 0x46
)

// ── NFC Transport Constants ──────────────────────────────────────────────

object NfcCtap {
    /** NFCCTAP_MSG: wraps CTAP2 commands over NFC (ISO 7816-4 INS byte) */
    const val INS_MSG: Int = 0x10

    /** INS byte for SELECT command (ISO 7816-4) */
    const val INS_SELECT: Int = 0xA4

    /**
     * Response to SELECT AID: "U2F_V2" (ASCII).
     * Despite the name, this is required by the FIDO NFC transport spec
     * even for CTAP2-only authenticators (§8.2.6.1).
     */
    val SELECT_RESPONSE = "U2F_V2".toByteArray(Charsets.UTF_8)
}
