package com.puntokek.fidobridge.protocol

import android.util.Log
import com.puntokek.fidobridge.protocol.cbor.*

private const val TAG = "Ctap2Authenticator"

/**
 * Implements CTAP2 authenticator commands that can be handled synchronously
 * (without CredentialManager interaction).
 */
@OptIn(ExperimentalUnsignedTypes::class)
object Ctap2Authenticator {

    /**
     * authenticatorGetInfo (0x04) — returns authenticator capabilities.
     * See CTAP2 §6.4.
     */
    fun handleGetInfo(): CborValue {
        Log.i(TAG, "authenticatorGetInfo → building response")

        val options = CborTextStringMap(mapOf(
            "plat" to CborBoolean(false),   // not a platform authenticator
            "rk"   to CborBoolean(true),    // discoverable credentials supported
            "up"   to CborBoolean(true),    // user presence always asserted
            "uv"   to CborBoolean(true)     // user verification supported
        ))

        val algorithms = CborArray(arrayOf(
            CborTextStringMap(mapOf(
                "alg"  to CborLong(CoseAlgorithm.ES256),
                "type" to CborTextString("public-key")
            ))
        ))

        val info = CborLongMap(mapOf(
            GetInfoResponse.VERSIONS to CborArray(arrayOf(
                CborTextString("FIDO_2_0")
            )),
            GetInfoResponse.AAGUID to CborByteString(FIDOBRIDGE_AAGUID),
            GetInfoResponse.OPTIONS to options,
            GetInfoResponse.MAX_MSG_SIZE to CborLong(MAX_CBOR_MSG_SIZE),
            GetInfoResponse.MAX_CREDENTIAL_COUNT_IN_LIST to CborLong(8),
            GetInfoResponse.MAX_CREDENTIAL_ID_LENGTH to CborLong(64),
            GetInfoResponse.TRANSPORTS to CborArray(arrayOf(
                CborTextString("nfc")
            )),
            GetInfoResponse.ALGORITHMS to algorithms
        ))

        Log.i(TAG, "authenticatorGetInfo: versions=[FIDO_2_0] transport=nfc alg=ES256/-7")
        return info
    }
}
