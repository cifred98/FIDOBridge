package com.puntokek.fidobridge.crypto.mds

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.io.InputStream

private const val TAG = "MdsRepository"
private const val MDS_CACHE_FILE = "mds_blob_cache.jwt"

/**
 * Manages the loaded MDS blob data.
 * Caches the file to internal storage so it persists across app restarts.
 */
object MdsRepository {

    private val _entries = MutableStateFlow<List<MdsEntry>>(emptyList())
    val entries: StateFlow<List<MdsEntry>> = _entries.asStateFlow()

    private val _isLoaded = MutableStateFlow(false)
    val isLoaded: StateFlow<Boolean> = _isLoaded.asStateFlow()

    private lateinit var cacheFile: File

    fun init(context: Context) {
        cacheFile = File(context.filesDir, MDS_CACHE_FILE)
        if (cacheFile.exists()) {
            loadFromCache()
        }
    }

    /**
     * Import an MDS blob from an InputStream (e.g. from a file picker).
     * Caches the raw JWT and parses entries.
     */
    fun importBlob(inputStream: InputStream): Boolean {
        return try {
            // Read and cache the raw JWT
            val bytes = inputStream.readBytes()
            cacheFile.writeBytes(bytes)
            Log.i(TAG, "Cached MDS blob (${bytes.size} bytes)")

            // Parse entries
            val parsed = MdsParser.parse(bytes.inputStream())
            _entries.value = parsed
            _isLoaded.value = parsed.isNotEmpty()
            Log.i(TAG, "Loaded ${parsed.size} authenticator entries")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to import MDS blob", e)
            false
        }
    }

    /**
     * Clear the cached MDS blob.
     */
    fun clear() {
        cacheFile.delete()
        _entries.value = emptyList()
        _isLoaded.value = false
    }

    private fun loadFromCache() {
        try {
            val parsed = MdsParser.parse(cacheFile.inputStream())
            _entries.value = parsed
            _isLoaded.value = parsed.isNotEmpty()
            Log.i(TAG, "Loaded ${parsed.size} entries from cache")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load MDS cache, clearing", e)
            cacheFile.delete()
        }
    }
}
