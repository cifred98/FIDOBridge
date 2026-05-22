package com.puntokek.fidobridge.protocol

import android.util.Log
import com.puntokek.fidobridge.protocol.cbor.*
import com.puntokek.fidobridge.settings.AppSettings
import com.puntokek.fidobridge.settings.AuthenticatorOptions

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

        val currentAaguid = AppSettings.getAaguid()

        // Versions
        val versionSet = AuthenticatorOptions.versions.value
        val versionsArray: Array<CborValue> = versionSet.map { CborTextString(it) }.toTypedArray()

        // Extensions (omit if empty)
        val extensionSet = AuthenticatorOptions.extensions.value

        // Options map (only include options that have a value)
        val optionsMap = AuthenticatorOptions.options.value
        val optionsCbor = CborTextStringMap(optionsMap.mapValues { CborBoolean(it.value) })

        // Algorithms
        val algorithmSet = AuthenticatorOptions.algorithms.value
        val algList = algorithmSet.mapNotNull { name ->
            AuthenticatorOptions.ALL_ALGORITHMS.find { it.name == name }
        }.map { alg ->
            CborTextStringMap(mapOf(
                "alg"  to CborLong(alg.coseId),
                "type" to CborTextString("public-key")
            )) as CborValue
        }.toTypedArray()
        val algorithms = CborArray(algList)

        // Transports
        val transportStrings = AppSettings.getTransports()
        val transportsArray: Array<CborValue> = transportStrings.map { CborTextString(it) }.toTypedArray()

        // PIN/UV auth protocols
        val pinProtos = AuthenticatorOptions.pinProtocols.value

        // Numeric limits
        val maxMsg = AuthenticatorOptions.maxMsgSize.value.toLong()
        val maxCredCount = AuthenticatorOptions.maxCredCount.value.toLong()
        val maxCredIdLen = AuthenticatorOptions.maxCredIdLen.value.toLong()
        val firmwareVer = AuthenticatorOptions.firmwareVersion.value

        // Build the response map
        val infoMap = mutableMapOf<Long, CborValue>(
            GetInfoResponse.VERSIONS to CborArray(versionsArray),
            GetInfoResponse.AAGUID to CborByteString(currentAaguid),
            GetInfoResponse.OPTIONS to optionsCbor,
            GetInfoResponse.MAX_MSG_SIZE to CborLong(maxMsg),
            GetInfoResponse.MAX_CREDENTIAL_COUNT_IN_LIST to CborLong(maxCredCount),
            GetInfoResponse.MAX_CREDENTIAL_ID_LENGTH to CborLong(maxCredIdLen),
            GetInfoResponse.TRANSPORTS to CborArray(transportsArray),
            GetInfoResponse.ALGORITHMS to algorithms
        )

        // Conditionally include extensions
        if (extensionSet.isNotEmpty()) {
            infoMap[GetInfoResponse.EXTENSIONS] = CborArray(
                extensionSet.map { CborTextString(it) as CborValue }.toTypedArray()
            )
        }

        // Conditionally include PIN protocols
        if (pinProtos.isNotEmpty()) {
            infoMap[GetInfoResponse.PIN_UV_AUTH_PROTOCOLS] = CborArray(
                pinProtos.sorted().map { CborLong(it.toLong()) as CborValue }.toTypedArray()
            )
        }

        // Conditionally include firmware version
        if (firmwareVer > 0) {
            infoMap[GetInfoResponse.FIRMWARE_VERSION] = CborLong(firmwareVer.toLong())
        }

        val info = CborLongMap(infoMap)

        Log.i(TAG, "authenticatorGetInfo: versions=$versionSet transports=$transportStrings alg=$algorithmSet")
        return info
    }
}
