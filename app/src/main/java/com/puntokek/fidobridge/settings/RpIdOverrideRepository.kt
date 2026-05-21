package com.puntokek.fidobridge.settings

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "RpIdOverrides"
private const val PREFS_NAME = "fidobridge_rpid_overrides"
private const val KEY_OVERRIDES = "overrides_json"

/**
 * Per-rpId override configuration.
 *
 * @param rpId Exact RP ID to match (e.g. "github.com")
 * @param overrideUp Override UP flag in authData for MakeCredential (null = don't override)
 * @param overrideUv Override UV flag in authData for MakeCredential (null = don't override)
 * @param userVerification WebAuthn userVerification value for request JSON ("required", "preferred", "discouraged"). Null = use default ("required").
 */
data class RpIdOverride(
    val rpId: String,
    val overrideUp: Boolean? = null,
    val overrideUv: Boolean? = null,
    val userVerification: String? = null
) {
    fun hasAnyOverride(): Boolean =
        overrideUp != null || overrideUv != null || userVerification != null

    fun summaryString(): String = buildString {
        if (overrideUp != null) append("UP=$overrideUp ")
        if (overrideUv != null) append("UV=$overrideUv ")
        if (userVerification != null) append("uv=$userVerification")
    }.trim().ifEmpty { "none" }
}

/**
 * Repository for per-rpId override settings.
 * Stored as JSON in SharedPreferences.
 */
object RpIdOverrideRepository {

    private lateinit var prefs: SharedPreferences

    private val _overrides = MutableStateFlow<List<RpIdOverride>>(emptyList())
    val overrides: StateFlow<List<RpIdOverride>> = _overrides.asStateFlow()

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        _overrides.value = loadOverrides()
        Log.i(TAG, "Loaded ${_overrides.value.size} rpId overrides")
    }

    /** Get override for exact rpId match, or null if none configured. */
    fun getOverride(rpId: String): RpIdOverride? =
        _overrides.value.find { it.rpId == rpId }

    fun addOrUpdate(override: RpIdOverride) {
        val current = _overrides.value.toMutableList()
        val idx = current.indexOfFirst { it.rpId == override.rpId }
        if (idx >= 0) {
            current[idx] = override
        } else {
            current.add(override)
        }
        _overrides.value = current
        persist(current)
    }

    fun remove(rpId: String) {
        val current = _overrides.value.filter { it.rpId != rpId }
        _overrides.value = current
        persist(current)
    }

    private fun persist(list: List<RpIdOverride>) {
        val arr = JSONArray()
        for (o in list) {
            arr.put(JSONObject().apply {
                put("rpId", o.rpId)
                if (o.overrideUp != null) put("overrideUp", o.overrideUp)
                if (o.overrideUv != null) put("overrideUv", o.overrideUv)
                if (o.userVerification != null) put("userVerification", o.userVerification)
            })
        }
        prefs.edit().putString(KEY_OVERRIDES, arr.toString()).apply()
    }

    private fun loadOverrides(): List<RpIdOverride> {
        val json = prefs.getString(KEY_OVERRIDES, null) ?: return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val obj = arr.getJSONObject(i)
                RpIdOverride(
                    rpId = obj.getString("rpId"),
                    overrideUp = if (obj.has("overrideUp")) obj.getBoolean("overrideUp") else null,
                    overrideUv = if (obj.has("overrideUv")) obj.getBoolean("overrideUv") else null,
                    userVerification = if (obj.has("userVerification")) obj.getString("userVerification") else null
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load overrides", e)
            emptyList()
        }
    }
}
