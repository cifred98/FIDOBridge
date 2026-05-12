package com.puntokek.fidobridge.protocol

import com.puntokek.fidobridge.bridge.PendingCredentialOperation
import com.puntokek.fidobridge.transport.apdu.ApduResponse

/**
 * Result of processing a CTAP2 command. Either an immediate APDU response
 * or an async operation that requires CredentialManager interaction.
 */
sealed class CtapResult {
    data class Immediate(val response: ApduResponse) : CtapResult()
    data class Async(val pending: PendingCredentialOperation) : CtapResult()
}
