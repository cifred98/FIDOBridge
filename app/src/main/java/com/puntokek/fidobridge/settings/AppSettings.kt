package com.puntokek.fidobridge.settings

import android.content.Context
import android.content.SharedPreferences
import com.puntokek.fidobridge.protocol.FIDOBRIDGE_AAGUID
import com.puntokek.fidobridge.util.toHex
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val PREFS_NAME = "fidobridge_settings"
private const val KEY_AAGUID = "custom_aaguid_hex"
private const val KEY_CERT_SUBJECT = "cert_subject"
private const val KEY_CERT_ISSUER = "cert_issuer"
private const val KEY_CERT_EXPIRY_YEARS = "cert_expiry_years"
private const val KEY_CERT_SERIAL = "cert_serial"
private const val KEY_TRANSPORTS = "advertised_transports"

private const val DEFAULT_SUBJECT = "CN=FIDOBridge Attestation, O=FIDOBridge"
private const val DEFAULT_ISSUER = "CN=FIDOBridge Root CA, O=FIDOBridge"
private const val DEFAULT_EXPIRY_YEARS = 10
private const val DEFAULT_SERIAL = ""  // empty = random

/** All transport types that can be advertised in GetInfo */
val ALL_TRANSPORTS = listOf("nfc", "ble", "hybrid", "internal", "usb")
private val DEFAULT_TRANSPORTS = setOf("nfc")

/**
 * Manages app-level settings stored in SharedPreferences.
 * Provides reactive state for Compose UI.
 */
object AppSettings {

    private lateinit var prefs: SharedPreferences

    private val _aaguid = MutableStateFlow(FIDOBRIDGE_AAGUID)
    val aaguid: StateFlow<ByteArray> = _aaguid.asStateFlow()

    private val _transports = MutableStateFlow(DEFAULT_TRANSPORTS)
    val transports: StateFlow<Set<String>> = _transports.asStateFlow()

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        _aaguid.value = loadAaguid()
        _transports.value = loadTransports()
    }

    fun getAaguid(): ByteArray = _aaguid.value

    fun setAaguid(newAaguid: ByteArray) {
        require(newAaguid.size == 16) { "AAGUID must be exactly 16 bytes" }
        prefs.edit().putString(KEY_AAGUID, newAaguid.toHex()).apply()
        _aaguid.value = newAaguid
    }

    fun resetAaguid() {
        prefs.edit().remove(KEY_AAGUID).apply()
        _aaguid.value = FIDOBRIDGE_AAGUID
    }

    // ── Certificate parameters ───────────────────────────────────────────

    fun getCertSubject(): String = prefs.getString(KEY_CERT_SUBJECT, null) ?: DEFAULT_SUBJECT
    fun setCertSubject(value: String) = prefs.edit().putString(KEY_CERT_SUBJECT, value).apply()

    fun getCertIssuer(): String = prefs.getString(KEY_CERT_ISSUER, null) ?: DEFAULT_ISSUER
    fun setCertIssuer(value: String) = prefs.edit().putString(KEY_CERT_ISSUER, value).apply()

    fun getCertExpiryYears(): Int = prefs.getInt(KEY_CERT_EXPIRY_YEARS, DEFAULT_EXPIRY_YEARS)
    fun setCertExpiryYears(value: Int) = prefs.edit().putInt(KEY_CERT_EXPIRY_YEARS, value).apply()

    /** Custom serial (hex string) or empty for random. */
    fun getCertSerial(): String = prefs.getString(KEY_CERT_SERIAL, null) ?: DEFAULT_SERIAL
    fun setCertSerial(value: String) = prefs.edit().putString(KEY_CERT_SERIAL, value).apply()

    fun resetCertParams() {
        prefs.edit()
            .remove(KEY_CERT_SUBJECT)
            .remove(KEY_CERT_ISSUER)
            .remove(KEY_CERT_EXPIRY_YEARS)
            .remove(KEY_CERT_SERIAL)
            .apply()
    }

    // ── Advertised transports ────────────────────────────────────────────

    fun getTransports(): Set<String> = _transports.value

    fun setTransports(value: Set<String>) {
        val filtered = value.filter { it in ALL_TRANSPORTS }.toSet()
        val toStore = filtered.ifEmpty { DEFAULT_TRANSPORTS }
        prefs.edit().putStringSet(KEY_TRANSPORTS, toStore).apply()
        _transports.value = toStore
    }

    fun resetTransports() {
        prefs.edit().remove(KEY_TRANSPORTS).apply()
        _transports.value = DEFAULT_TRANSPORTS
    }

    private fun loadTransports(): Set<String> {
        val stored = prefs.getStringSet(KEY_TRANSPORTS, null) ?: return DEFAULT_TRANSPORTS
        val valid = stored.filter { it in ALL_TRANSPORTS }.toSet()
        return valid.ifEmpty { DEFAULT_TRANSPORTS }
    }

    private fun loadAaguid(): ByteArray {
        val hex = prefs.getString(KEY_AAGUID, null) ?: return FIDOBRIDGE_AAGUID
        return try {
            val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            if (bytes.size == 16) bytes else FIDOBRIDGE_AAGUID
        } catch (_: Exception) {
            FIDOBRIDGE_AAGUID
        }
    }
}
