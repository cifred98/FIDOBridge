package com.puntokek.fidobridge.bridge

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import androidx.lifecycle.lifecycleScope
import com.puntokek.fidobridge.FidoBridgeApplication
import com.puntokek.fidobridge.protocol.Ctap2StatusCode
import kotlinx.coroutines.launch

private const val TAG = "CredentialBridgeActivity"

/**
 * Transparent activity that hosts CredentialManager UI for passkey creation/assertion.
 * Launched by FidoNfcService when a CTAP2 MakeCredential or GetAssertion requires
 * user interaction with the system credential provider.
 */
class CredentialBridgeActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pending = FidoBridgeApplication.consumePendingOperation()
        if (pending == null) {
            Log.w(TAG, "No pending operation — finishing")
            finish()
            return
        }

        lifecycleScope.launch {
            try {
                val result = when (pending.type) {
                    PendingCredentialOperation.Type.CREATE -> handleCreate(pending)
                    PendingCredentialOperation.Type.GET -> handleGet(pending)
                }
                pending.deferred.complete(result)
            } catch (e: CreateCredentialCancellationException) {
                Log.w(TAG, "User cancelled create", e)
                pending.deferred.complete(byteArrayOf(Ctap2StatusCode.OPERATION_DENIED.code))
            } catch (e: GetCredentialCancellationException) {
                Log.w(TAG, "User cancelled get", e)
                pending.deferred.complete(byteArrayOf(Ctap2StatusCode.OPERATION_DENIED.code))
            } catch (e: NoCredentialException) {
                Log.w(TAG, "No credentials available", e)
                pending.deferred.complete(byteArrayOf(Ctap2StatusCode.NO_CREDENTIALS.code))
            } catch (e: Exception) {
                Log.e(TAG, "CredentialManager call failed", e)
                pending.deferred.complete(byteArrayOf(Ctap2StatusCode.OTHER.code))
            } finally {
                finish()
            }
        }
    }

    private suspend fun handleCreate(pending: PendingCredentialOperation): ByteArray {
        Log.i(TAG, "handleCreate: origin=${pending.origin}")
        val credentialManager = CredentialManager.create(this)
        val request = CreatePublicKeyCredentialRequest(
            requestJson = pending.requestJson,
            clientDataHash = pending.clientDataHash,
            preferImmediatelyAvailableCredentials = false,
            origin = pending.origin,
            isAutoSelectAllowed = false
        )
        val response = credentialManager.createCredential(this, request)
        val responseJson = extractRegistrationJson(response)
        Log.i(TAG, "handleCreate: got registration response")
        return WebAuthnBridge.parseCreateResponse(responseJson, pending.clientDataHash, pending.rpId)
    }

    private suspend fun handleGet(pending: PendingCredentialOperation): ByteArray {
        Log.i(TAG, "handleGet: origin=${pending.origin}")
        val credentialManager = CredentialManager.create(this)
        val option = GetPublicKeyCredentialOption(
            requestJson = pending.requestJson,
            clientDataHash = pending.clientDataHash
        )
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(option)
            .setOrigin(pending.origin)
            .build()
        val response = credentialManager.getCredential(this, request)
        val credential = response.credential
        val responseJson = credential.data.getString(
            "androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON"
        ) ?: error("No authentication response JSON in credential data")
        Log.i(TAG, "handleGet: got assertion response")
        return WebAuthnBridge.parseGetResponse(responseJson)
    }

    private fun extractRegistrationJson(response: CreateCredentialResponse): String {
        return response.data.getString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON")
            ?: error("No registration response JSON in credential data")
    }
}
