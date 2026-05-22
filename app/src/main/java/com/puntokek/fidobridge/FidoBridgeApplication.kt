package com.puntokek.fidobridge

import android.app.Application
import android.util.Log
import com.puntokek.fidobridge.bridge.PendingCredentialOperation
import com.puntokek.fidobridge.crypto.AttestationKey
import com.puntokek.fidobridge.crypto.mds.MdsRepository
import com.puntokek.fidobridge.protocol.Ctap2CommandRouter
import com.puntokek.fidobridge.settings.AppSettings
import com.puntokek.fidobridge.settings.RpIdOverrideRepository
import com.puntokek.fidobridge.transport.cable.CableTransportService

class FidoBridgeApplication : Application() {

    companion object {
        private const val TAG = "FidoBridgeApp"

        lateinit var commandRouter: Ctap2CommandRouter
            private set

        @Volatile
        private var pendingOperation: PendingCredentialOperation? = null

        @Synchronized
        fun setPendingOperation(op: PendingCredentialOperation) {
            pendingOperation?.deferred?.cancel()
            pendingOperation = op
            Log.i(TAG, "setPendingOperation: type=${op.type} origin=${op.origin} id=${op.operationId}")
        }

        @Synchronized
        fun consumePendingOperation(): PendingCredentialOperation? {
            val op = pendingOperation
            pendingOperation = null
            Log.i(TAG, "consumePendingOperation: ${op?.type ?: "null"}")
            return op
        }

        @Synchronized
        fun cancelPendingOperation() {
            pendingOperation?.deferred?.cancel()
            pendingOperation = null
            Log.i(TAG, "cancelPendingOperation")
        }
    }

    override fun onCreate() {
        super.onCreate()
        AppSettings.init(this)
        RpIdOverrideRepository.init(this)
        MdsRepository.init(this)
        AttestationKey.init(this)
        CableTransportService.init(this)
        commandRouter = Ctap2CommandRouter()
        Log.i(TAG, "FidoBridgeApplication initialized")
    }
}
