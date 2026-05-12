package com.puntokek.fidobridge.transport.apdu

import com.puntokek.fidobridge.util.toHex

data class ApduResponse(
    val status: UShort,
    val data: ByteArray?
) {
    constructor(status: UShort) : this(status, null)

    constructor(status: UShort, data: String) : this(status, data.toByteArray(Charsets.US_ASCII))

    override fun toString(): String {
        return "ApduResponse(status=%04x, data=%s)".format(
            status.toInt(), (data ?: ByteArray(0)).toHex()
        )
    }

    fun encode(): ByteArray {
        val ret: ByteArray
        if (data != null) {
            ret = ByteArray(data.size + 2)
            System.arraycopy(data, 0, ret, 0, data.size)
        } else {
            ret = ByteArray(2)
        }
        ret[ret.size - 2] = status.toInt().shr(8).toByte()
        ret[ret.size - 1] = status.toByte()
        return ret
    }

    companion object {
        val SW_APPLET_SELECT_FAILED = 0x6999.toUShort()
        val SW_CLA_NOT_SUPPORTED = 0x6E00.toUShort()
        val SW_CONDITIONS_NOT_SATISFIED = 0x6985.toUShort()
        val SW_INS_NOT_SUPPORTED = 0x6D00.toUShort()
        val SW_NO_ERROR = 0x9000.toUShort()
        val SW_PROCESSING = 0x9100.toUShort()
        val SW_UNKNOWN = 0x6F00.toUShort()
        val SW_WRONG_DATA = 0x6A80.toUShort()
        val SW_WRONG_LENGTH = 0x6700.toUShort()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ApduResponse
        return status == other.status && data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = status.hashCode()
        result = 31 * result + (data?.contentHashCode() ?: 0)
        return result
    }
}
