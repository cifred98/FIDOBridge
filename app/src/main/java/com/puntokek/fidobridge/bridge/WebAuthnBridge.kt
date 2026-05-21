package com.puntokek.fidobridge.bridge

import android.util.Log
import com.puntokek.fidobridge.crypto.AttestationKey
import com.puntokek.fidobridge.protocol.*
import com.puntokek.fidobridge.protocol.cbor.*
import com.puntokek.fidobridge.settings.RpIdOverrideRepository
import com.puntokek.fidobridge.util.base64url
import com.puntokek.fidobridge.util.decodeBase64url
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "WebAuthnBridge"

@OptIn(ExperimentalUnsignedTypes::class)
object WebAuthnBridge {

    private val DUMMY_CHALLENGE = ByteArray(32) { 0x00 }.base64url()

    /**
     * Build PublicKeyCredentialCreationOptions JSON from CTAP2 MakeCredential CBOR.
     */
    fun buildCreateRequestJson(params: CborValue): String {
        val rp = params.getRequired(MakeCredentialParam.RP)
        val rpId = rp.getRequired("id").unbox<String>()
        val rpName = rp.getOptional("name")?.unbox<String>() ?: rpId

        val user = params.getRequired(MakeCredentialParam.USER)
        val userId = user.getRequired("id").unbox<ByteArray>()
        val userName = user.getRequired("name").unbox<String>()
        val userDisplayName = user.getOptional("displayName")?.unbox<String>() ?: userName

        val pubKeyCredParams = params.getRequired(MakeCredentialParam.PUB_KEY_CRED_PARAMS)
            .unbox<Array<CborValue>>()

        val options = params.getOptional(MakeCredentialParam.OPTIONS)
        val requestedRk = options?.getOptional("rk")?.unbox<Boolean>() == true

        // Apply per-rpId userVerification override
        val override = RpIdOverrideRepository.getOverride(rpId)
        val userVerification = override?.userVerification ?: "required"

        val json = JSONObject().apply {
            put("rp", JSONObject().apply {
                put("id", rpId)
                put("name", rpName)
            })
            put("user", JSONObject().apply {
                put("id", userId.base64url())
                put("name", userName)
                put("displayName", userDisplayName)
            })
            put("challenge", DUMMY_CHALLENGE)
            put("pubKeyCredParams", buildPubKeyCredParams(pubKeyCredParams))
            put("timeout", 60000)
            put("attestation", "none")
            put("authenticatorSelection", JSONObject().apply {
                put("residentKey", if (requestedRk) "required" else "preferred")
                put("userVerification", userVerification)
            })

            val excludeList = params.getOptional(MakeCredentialParam.EXCLUDE_LIST)
            if (excludeList != null) {
                put("excludeCredentials", buildCredentialDescriptorList(excludeList))
            }
        }

        Log.i(TAG, "buildCreateRequestJson: rpId=$rpId user=$userName rk=$requestedRk uv=$userVerification")
        return json.toString()
    }

    /**
     * Build PublicKeyCredentialRequestOptions JSON from CTAP2 GetAssertion CBOR.
     */
    fun buildGetRequestJson(params: CborValue): String {
        val rpId = params.getRequired(GetAssertionParam.RP_ID).unbox<String>()

        // Apply per-rpId userVerification override
        val override = RpIdOverrideRepository.getOverride(rpId)
        val userVerification = override?.userVerification ?: "required"

        val json = JSONObject().apply {
            put("challenge", DUMMY_CHALLENGE)
            put("rpId", rpId)
            put("timeout", 60000)
            put("userVerification", userVerification)

            val allowList = params.getOptional(GetAssertionParam.ALLOW_LIST)
            if (allowList != null) {
                put("allowCredentials", buildCredentialDescriptorList(allowList))
            }
        }

        Log.i(TAG, "buildGetRequestJson: rpId=$rpId uv=$userVerification")
        return json.toString()
    }

    /**
     * Extract rpId from the RP map in a MakeCredential or GetAssertion CBOR map.
     * @param params the top-level CBOR map
     * @param rpKey the key for the RP field (MakeCredentialParam.RP or GetAssertionParam.RP_ID)
     */
    fun extractRpId(params: CborValue, rpKey: Long): String {
        val rpValue = params.getRequired(rpKey)
        // MakeCredential uses a map {id, name}, GetAssertion uses a plain string
        return if (rpValue is CborTextString) {
            rpValue.value
        } else {
            rpValue.getRequired("id").unbox()
        }
    }

    /**
     * Parse a WebAuthn registration response and build CTAP2 MakeCredential
     * response bytes (status byte + CBOR) with packed attestation.
     * Patches AAGUID in authData and applies flag overrides before re-signing.
     */
    fun parseCreateResponse(responseJson: String, clientDataHash: ByteArray, rpId: String): ByteArray {
        val json = JSONObject(responseJson)
        val response = json.getJSONObject("response")
        val attestationObjectBytes = response.getString("attestationObject").decodeBase64url()
            ?: error("Failed to decode attestationObject base64url")

        val attObj = fromCborToEnd(attestationObjectBytes)
            ?: error("Failed to decode attestationObject CBOR")

        var authData = attObj.getRequired("authData").unbox<ByteArray>()

        // Patch AAGUID in attested credential data to match our configured AAGUID
        val mat = AttestationKey.getMaterial()
        authData = AuthDataParser.patchAaguid(authData, mat.aaguid)

        // Apply per-rpId flag overrides (UP/UV only — safe because we re-sign)
        val override = RpIdOverrideRepository.getOverride(rpId)
        if (override != null) {
            authData = AuthDataParser.patchFlags(authData, up = override.overrideUp, uv = override.overrideUv)
            Log.i(TAG, "Applied flag overrides for rpId=$rpId: up=${override.overrideUp} uv=${override.overrideUv}")
        }

        // Re-attest with our batch attestation key (packed + x5c)
        val sig = mat.sign(authData, clientDataHash)
        val attStmt = CborTextStringMap(mapOf(
            "alg" to CborLong(CoseAlgorithm.ES256),
            "sig" to CborByteString(sig),
            "x5c" to CborArray(arrayOf(
                CborByteString(mat.certDer),
                CborByteString(mat.caCertDer)
            ))
        ))

        val ctapResponse = CborLongMap(mapOf(
            MakeCredentialResponse.FMT to CborTextString("packed"),
            MakeCredentialResponse.AUTH_DATA to CborByteString(authData),
            MakeCredentialResponse.ATT_STMT to attStmt
        ))

        Log.i(TAG, "parseCreateResponse: fmt=packed authDataLen=${authData.size} sigLen=${sig.size}")
        return ctapResponse.toCtap2SuccessResponse()
    }

    /**
     * Parse a WebAuthn authentication response and build CTAP2 GetAssertion
     * response bytes (status byte + CBOR).
     */
    fun parseGetResponse(responseJson: String): ByteArray {
        val json = JSONObject(responseJson)
        val credentialId = json.getString("rawId").decodeBase64url()
            ?: error("Failed to decode rawId")
        val response = json.getJSONObject("response")

        val authenticatorData = response.getString("authenticatorData").decodeBase64url()
            ?: error("Failed to decode authenticatorData")
        val signature = response.getString("signature").decodeBase64url()
            ?: error("Failed to decode signature")

        val responseMap = mutableMapOf<Long, CborValue>(
            GetAssertionResponse.CREDENTIAL to CborTextStringMap(mapOf(
                "type" to CborTextString("public-key"),
                "id" to CborByteString(credentialId)
            )),
            GetAssertionResponse.AUTH_DATA to CborByteString(authenticatorData),
            GetAssertionResponse.SIGNATURE to CborByteString(signature)
        )

        if (response.has("userHandle") && !response.isNull("userHandle")) {
            val userHandle = response.getString("userHandle").decodeBase64url()
            if (userHandle != null && userHandle.isNotEmpty()) {
                responseMap[GetAssertionResponse.USER] = CborTextStringMap(mapOf(
                    "id" to CborByteString(userHandle)
                ))
            }
        }

        Log.i(TAG, "parseGetResponse: credId=${credentialId.base64url()} " +
                "authDataLen=${authenticatorData.size} sigLen=${signature.size}")
        return CborLongMap(responseMap).toCtap2SuccessResponse()
    }

    private fun buildPubKeyCredParams(params: Array<CborValue>): JSONArray {
        val arr = JSONArray()
        for (param in params) {
            val alg = try { param.getOptional("alg")?.unbox<Long>() } catch (_: Exception) { null }
            if (alg != null) {
                arr.put(JSONObject().apply {
                    put("type", "public-key")
                    put("alg", alg)
                })
            }
        }
        return arr
    }

    private fun buildCredentialDescriptorList(cborList: CborValue): JSONArray {
        val items = cborList.unbox<Array<CborValue>>()
        val arr = JSONArray()
        for (item in items) {
            val id = try { item.getOptional("id")?.unbox<ByteArray>() } catch (_: Exception) { null }
            if (id != null) {
                arr.put(JSONObject().apply {
                    put("type", "public-key")
                    put("id", id.base64url())
                })
            }
        }
        return arr
    }
}
