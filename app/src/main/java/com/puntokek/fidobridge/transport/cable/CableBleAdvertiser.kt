package com.puntokek.fidobridge.transport.cable

import android.bluetooth.BluetoothManager
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID

/**
 * Manages BLE advertising for caBLE discovery.
 *
 * When a QR code is scanned, we derive an EID from the QR secret and
 * advertise it as service data under the FIDO caBLE BLE service UUID.
 * The client (browser) scans for this advertisement and connects.
 */
class CableBleAdvertiser(private val context: Context) {

    companion object {
        private const val TAG = "CableBleAdvertiser"
        private val CABLE_SERVICE_UUID = ParcelUuid(
            UUID.fromString(CableConstants.CABLE_BLE_SERVICE_UUID)
        )
    }

    private var advertiser: BluetoothLeAdvertiser? = null
    private var isAdvertising = false

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.i(TAG, "BLE advertising started successfully")
            isAdvertising = true
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "BLE advertising failed to start: errorCode=$errorCode")
            isAdvertising = false
        }
    }

    /**
     * Start BLE advertising with the given advert payload (20 bytes: encrypted EID + HMAC tag).
     *
     * @param advertPayload The 20-byte BLE service data (from CableCrypto.encryptEid)
     * @return true if advertising was initiated (actual start is async via callback)
     */
    fun startAdvertising(advertPayload: ByteArray): Boolean {
        require(advertPayload.size == CableConstants.ADVERT_SIZE) {
            "Advert payload must be ${CableConstants.ADVERT_SIZE} bytes"
        }

        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = bluetoothManager?.adapter
        if (adapter == null || !adapter.isEnabled) {
            Log.e(TAG, "Bluetooth adapter not available or not enabled")
            return false
        }

        advertiser = adapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.e(TAG, "BLE advertising not supported on this device")
            return false
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(false)
            .setTimeout(0) // no timeout
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(CABLE_SERVICE_UUID)
            .addServiceData(CABLE_SERVICE_UUID, advertPayload)
            .build()

        try {
            advertiser?.startAdvertising(settings, data, advertiseCallback)
            Log.i(TAG, "BLE advertising initiated with ${advertPayload.size}-byte payload")
            return true
        } catch (e: SecurityException) {
            Log.e(TAG, "Missing BLUETOOTH_ADVERTISE permission", e)
            return false
        }
    }

    /**
     * Stop BLE advertising.
     */
    fun stopAdvertising() {
        if (isAdvertising) {
            try {
                advertiser?.stopAdvertising(advertiseCallback)
            } catch (e: SecurityException) {
                Log.w(TAG, "SecurityException stopping advertising", e)
            }
            isAdvertising = false
            Log.i(TAG, "BLE advertising stopped")
        }
    }

    fun isCurrentlyAdvertising(): Boolean = isAdvertising
}
