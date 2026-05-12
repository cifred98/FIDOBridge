package com.puntokek.fidobridge.bridge

import kotlinx.coroutines.CompletableDeferred

/**
 * Holds state for a pending CredentialManager operation while the NFC service
 * waits for the user to interact with the CredentialBridgeActivity.
 */
data class PendingCredentialOperation(
    val type: Type,
    val requestJson: String,
    val clientDataHash: ByteArray,
    val origin: String,
    val deferred: CompletableDeferred<ByteArray>,
    val operationId: Long = System.nanoTime()
) {
    enum class Type { CREATE, GET }
}
