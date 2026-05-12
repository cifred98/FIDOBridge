package com.puntokek.fidobridge.util

import android.util.Base64
import java.nio.ByteBuffer
import java.security.MessageDigest

fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)
fun String.sha256(): ByteArray = this.toByteArray().sha256()

fun ByteArray.base64url(): String =
    Base64.encodeToString(this, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)

fun String.decodeBase64url(): ByteArray? = try {
    Base64.decode(this, Base64.NO_WRAP or Base64.URL_SAFE)
} catch (e: IllegalArgumentException) {
    null
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.truncate(targetLength: Int): String =
    if (length > targetLength) this.take(targetLength - 1) + "…" else this

fun Boolean.bytes() = byteArrayOf(if (this) 0x01 else 0x00)
fun Byte.bytes() = byteArrayOf(this)

@OptIn(ExperimentalUnsignedTypes::class)
fun UShort.bytes(): ByteArray =
    ByteBuffer.allocate(java.lang.Long.BYTES)
        .putLong(this.toLong())
        .array()
        .sliceArray((java.lang.Long.BYTES - java.lang.Short.BYTES) until java.lang.Long.BYTES)

@OptIn(ExperimentalUnsignedTypes::class)
fun UInt.bytes(): ByteArray =
    ByteBuffer.allocate(java.lang.Long.BYTES)
        .putLong(this.toLong())
        .array()
        .sliceArray((java.lang.Long.BYTES - Integer.BYTES) until java.lang.Long.BYTES)
