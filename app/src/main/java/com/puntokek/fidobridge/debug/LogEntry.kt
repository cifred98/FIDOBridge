package com.puntokek.fidobridge.debug

import java.time.Instant

enum class ApduDirection { REQUEST, RESPONSE }

data class LogEntry(
    val timestamp: Instant,
    val direction: ApduDirection,
    val rawHex: String,
    val parsedFields: String,
    val decodedCtap: String? = null
)
