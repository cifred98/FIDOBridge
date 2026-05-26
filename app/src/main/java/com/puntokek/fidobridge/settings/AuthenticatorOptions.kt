package com.puntokek.fidobridge.settings

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val PREFS_NAME = "fidobridge_authenticator_options"

/**
 * All configurable CTAP2 authenticator features reported in GetInfo.
 */
object AuthenticatorOptions {

    private lateinit var prefs: SharedPreferences

    // ── Versions ─────────────────────────────────────────────────────────
    val ALL_VERSIONS = listOf("U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1")
    private val DEFAULT_VERSIONS = setOf("FIDO_2_0")

    private val _versions = MutableStateFlow(DEFAULT_VERSIONS)
    val versions: StateFlow<Set<String>> = _versions.asStateFlow()

    // ── Extensions ───────────────────────────────────────────────────────
    val ALL_EXTENSIONS = listOf(
        "credProtect", "hmac-secret", "largeBlobKey", "credBlob",
        "minPinLength", "prf"
    )
    private val DEFAULT_EXTENSIONS = emptySet<String>()

    private val _extensions = MutableStateFlow(DEFAULT_EXTENSIONS)
    val extensions: StateFlow<Set<String>> = _extensions.asStateFlow()

    // ── Options (boolean map) ────────────────────────────────────────────
    data class OptionDef(
        val key: String,
        val description: String,
        val defaultValue: Boolean?
    )

    val ALL_OPTIONS = listOf(
        OptionDef("plat", "Platform authenticator", false),
        OptionDef("rk", "Discoverable credentials (resident keys)", true),
        OptionDef("up", "User presence", true),
        OptionDef("uv", "User verification", true),
        OptionDef("clientPin", "Client PIN configured", null),
        OptionDef("pinUvAuthToken", "PIN/UV auth token support", null),
        OptionDef("noMcGaPermissionsWithClientPin", "No MC/GA perms with clientPin", null),
        OptionDef("largeBlobs", "Large blobs support", null),
        OptionDef("credMgmt", "Credential management", null),
        OptionDef("authnrCfg", "Authenticator config", null),
        OptionDef("alwaysUv", "Always require UV", null),
        OptionDef("makeCredUvNotRqd", "MakeCredential UV not required", null),
        OptionDef("ep", "Enterprise attestation", null),
        OptionDef("bioEnroll", "Biometric enrollment", null),
        OptionDef("uvBioEnroll", "UV biometric enrollment", null),
        OptionDef("setMinPINLength", "Set minimum PIN length", null)
    )

    private val _options = MutableStateFlow<Map<String, Boolean>>(emptyMap())
    val options: StateFlow<Map<String, Boolean>> = _options.asStateFlow()

    // ── Algorithms ───────────────────────────────────────────────────────
    data class AlgorithmDef(val name: String, val coseId: Long)

    val ALL_ALGORITHMS = listOf(
        AlgorithmDef("ES256", -7L),
        AlgorithmDef("ES384", -35L),
        AlgorithmDef("ES512", -36L),
        AlgorithmDef("EdDSA", -8L),
        AlgorithmDef("RS256", -257L),
        AlgorithmDef("RS384", -258L),
        AlgorithmDef("RS512", -259L),
        AlgorithmDef("PS256", -37L)
    )
    private val DEFAULT_ALGORITHMS = setOf("ES256")

    private val _algorithms = MutableStateFlow(DEFAULT_ALGORITHMS)
    val algorithms: StateFlow<Set<String>> = _algorithms.asStateFlow()

    // ── PIN/UV Auth Protocols ────────────────────────────────────────────
    val ALL_PIN_PROTOCOLS = listOf(1, 2)
    private val DEFAULT_PIN_PROTOCOLS = emptySet<Int>()

    private val _pinProtocols = MutableStateFlow(DEFAULT_PIN_PROTOCOLS)
    val pinProtocols: StateFlow<Set<Int>> = _pinProtocols.asStateFlow()

    // ── Numeric limits ───────────────────────────────────────────────────
    private const val DEFAULT_MAX_MSG_SIZE = 4096
    private const val DEFAULT_MAX_CRED_COUNT = 8
    private const val DEFAULT_MAX_CRED_ID_LEN = 64
    private const val DEFAULT_FIRMWARE_VERSION = 0

    private val _maxMsgSize = MutableStateFlow(DEFAULT_MAX_MSG_SIZE)
    val maxMsgSize: StateFlow<Int> = _maxMsgSize.asStateFlow()

    private val _maxCredCount = MutableStateFlow(DEFAULT_MAX_CRED_COUNT)
    val maxCredCount: StateFlow<Int> = _maxCredCount.asStateFlow()

    private val _maxCredIdLen = MutableStateFlow(DEFAULT_MAX_CRED_ID_LEN)
    val maxCredIdLen: StateFlow<Int> = _maxCredIdLen.asStateFlow()

    private val _firmwareVersion = MutableStateFlow(DEFAULT_FIRMWARE_VERSION)
    val firmwareVersion: StateFlow<Int> = _firmwareVersion.asStateFlow()

    // ── Attestation format ───────────────────────────────────────────────
    val ALL_ATTESTATION_FORMATS = listOf("packed", "none")
    private const val DEFAULT_ATTESTATION_FORMAT = "packed"

    private val _attestationFormat = MutableStateFlow(DEFAULT_ATTESTATION_FORMAT)
    val attestationFormat: StateFlow<String> = _attestationFormat.asStateFlow()

    // ── Credential flags (BE/BS) ─────────────────────────────────────────
    // BE (Backup Eligible) = bit 3 of flags; BS (Backup State) = bit 4
    // null = passthrough from credential manager, true/false = force override
    private val _overrideBackupEligible = MutableStateFlow<Boolean?>(null)
    val overrideBackupEligible: StateFlow<Boolean?> = _overrideBackupEligible.asStateFlow()

    private val _overrideBackupState = MutableStateFlow<Boolean?>(null)
    val overrideBackupState: StateFlow<Boolean?> = _overrideBackupState.asStateFlow()

    // ── Init ─────────────────────────────────────────────────────────────

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        _versions.value = loadStringSet("versions", DEFAULT_VERSIONS)
        _extensions.value = loadStringSet("extensions", DEFAULT_EXTENSIONS)
        _options.value = loadOptions()
        _algorithms.value = loadStringSet("algorithms", DEFAULT_ALGORITHMS)
        _pinProtocols.value = loadIntSet("pin_protocols", DEFAULT_PIN_PROTOCOLS)
        _maxMsgSize.value = prefs.getInt("max_msg_size", DEFAULT_MAX_MSG_SIZE)
        _maxCredCount.value = prefs.getInt("max_cred_count", DEFAULT_MAX_CRED_COUNT)
        _maxCredIdLen.value = prefs.getInt("max_cred_id_len", DEFAULT_MAX_CRED_ID_LEN)
        _firmwareVersion.value = prefs.getInt("firmware_version", DEFAULT_FIRMWARE_VERSION)
        _attestationFormat.value = prefs.getString("attestation_format", DEFAULT_ATTESTATION_FORMAT) ?: DEFAULT_ATTESTATION_FORMAT
        _overrideBackupEligible.value = loadNullableBoolean("override_be")
        _overrideBackupState.value = loadNullableBoolean("override_bs")
    }

    // ── Setters ──────────────────────────────────────────────────────────

    fun setVersions(value: Set<String>) {
        val filtered = value.filter { it in ALL_VERSIONS }.toSet().ifEmpty { DEFAULT_VERSIONS }
        prefs.edit().putStringSet("versions", filtered).apply()
        _versions.value = filtered
    }

    fun setExtensions(value: Set<String>) {
        prefs.edit().putStringSet("extensions", value).apply()
        _extensions.value = value
    }

    fun setOption(key: String, value: Boolean?) {
        val current = _options.value.toMutableMap()
        if (value == null) current.remove(key) else current[key] = value
        saveOptions(current)
        _options.value = current
    }

    fun setAlgorithms(value: Set<String>) {
        val filtered = value.filter { name -> ALL_ALGORITHMS.any { it.name == name } }.toSet()
            .ifEmpty { DEFAULT_ALGORITHMS }
        prefs.edit().putStringSet("algorithms", filtered).apply()
        _algorithms.value = filtered
    }

    fun setPinProtocols(value: Set<Int>) {
        prefs.edit().putStringSet("pin_protocols", value.map { it.toString() }.toSet()).apply()
        _pinProtocols.value = value
    }

    fun setMaxMsgSize(value: Int) {
        prefs.edit().putInt("max_msg_size", value).apply()
        _maxMsgSize.value = value
    }

    fun setMaxCredCount(value: Int) {
        prefs.edit().putInt("max_cred_count", value).apply()
        _maxCredCount.value = value
    }

    fun setMaxCredIdLen(value: Int) {
        prefs.edit().putInt("max_cred_id_len", value).apply()
        _maxCredIdLen.value = value
    }

    fun setFirmwareVersion(value: Int) {
        prefs.edit().putInt("firmware_version", value).apply()
        _firmwareVersion.value = value
    }

    fun setAttestationFormat(value: String) {
        prefs.edit().putString("attestation_format", value).apply()
        _attestationFormat.value = value
    }

    fun setOverrideBackupEligible(value: Boolean?) {
        saveNullableBoolean("override_be", value)
        _overrideBackupEligible.value = value
    }

    fun setOverrideBackupState(value: Boolean?) {
        saveNullableBoolean("override_bs", value)
        _overrideBackupState.value = value
    }

    fun resetAll() {
        prefs.edit().clear().apply()
        _versions.value = DEFAULT_VERSIONS
        _extensions.value = DEFAULT_EXTENSIONS
        _options.value = ALL_OPTIONS.filter { it.defaultValue != null }
            .associate { it.key to it.defaultValue!! }
        _algorithms.value = DEFAULT_ALGORITHMS
        _pinProtocols.value = DEFAULT_PIN_PROTOCOLS
        _maxMsgSize.value = DEFAULT_MAX_MSG_SIZE
        _maxCredCount.value = DEFAULT_MAX_CRED_COUNT
        _maxCredIdLen.value = DEFAULT_MAX_CRED_ID_LEN
        _firmwareVersion.value = DEFAULT_FIRMWARE_VERSION
        _attestationFormat.value = DEFAULT_ATTESTATION_FORMAT
        _overrideBackupEligible.value = null
        _overrideBackupState.value = null
    }

    // ── Persistence helpers ──────────────────────────────────────────────

    private fun loadStringSet(key: String, default: Set<String>): Set<String> =
        prefs.getStringSet(key, null) ?: default

    private fun loadIntSet(key: String, default: Set<Int>): Set<Int> =
        prefs.getStringSet(key, null)?.mapNotNull { it.toIntOrNull() }?.toSet() ?: default

    private fun loadOptions(): Map<String, Boolean> {
        val stored = prefs.getStringSet("options_set", null) ?: run {
            return ALL_OPTIONS.filter { it.defaultValue != null }
                .associate { it.key to it.defaultValue!! }
        }
        return stored.associate { entry ->
            val parts = entry.split("=")
            parts[0] to (parts.getOrNull(1) == "true")
        }
    }

    private fun saveOptions(options: Map<String, Boolean>) {
        val set = options.map { "${it.key}=${it.value}" }.toSet()
        prefs.edit().putStringSet("options_set", set).apply()
    }

    private fun loadNullableBoolean(key: String): Boolean? {
        if (!prefs.contains(key)) return null
        return prefs.getBoolean(key, false)
    }

    private fun saveNullableBoolean(key: String, value: Boolean?) {
        if (value == null) prefs.edit().remove(key).apply()
        else prefs.edit().putBoolean(key, value).apply()
    }
}
