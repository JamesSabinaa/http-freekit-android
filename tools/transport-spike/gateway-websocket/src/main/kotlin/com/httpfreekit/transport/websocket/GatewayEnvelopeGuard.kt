package com.httpfreekit.transport.websocket

import org.java_websocket.enums.Opcode
import org.java_websocket.exceptions.InvalidDataException

/** Validates only bounded wire envelopes; the maintained engine still decodes all payloads. */
internal class GatewayEnvelopeGuard {
    private val header = ByteArray(14)
    private val bounds = GatewayMessageBounds()
    private var used = 0
    private var needed = 2
    private var payloadRemaining = 0L

    fun feed(bytes: ByteArray, offset: Int, count: Int, accept: (ByteArray, Int, Int) -> Unit) {
        require(offset >= 0 && count in 0..8192 && offset <= bytes.size - count)
        var at = offset
        val end = offset + count
        while (at < end) {
            if (payloadRemaining > 0) {
                val size = minOf(payloadRemaining, (end - at).toLong()).toInt()
                accept(bytes, at, size)
                at += size; payloadRemaining -= size
                continue
            }
            while (at < end && used < needed) header[used++] = bytes[at++]
            if (used < needed) break
            if (needed == 2) {
                val first = header[0].toInt() and 255
                val second = header[1].toInt() and 255
                if (first and 0x70 != 0 || second and 0x80 != 0) invalid()
                needed = when (second and 127) { 126 -> 4; 127 -> 10; else -> 2 }
                if (used < needed) continue
            }
            var length = (header[1].toInt() and 127).toLong()
            if (needed > 2) {
                if (needed == 10 && header[2].toInt() and 128 != 0) invalid()
                length = 0
                for (index in 2 until needed) length = (length shl 8) or (header[index].toLong() and 255)
                if (needed == 4 && length < 126 || needed == 10 && length < 65536) invalid()
            }
            val first = header[0].toInt() and 255
            val opcode = when (first and 15) {
                0 -> Opcode.CONTINUOUS; 1 -> Opcode.TEXT; 2 -> Opcode.BINARY
                8 -> Opcode.CLOSING; 9 -> Opcode.PING; 10 -> Opcode.PONG
                else -> invalid()
            }
            bounds.accept(opcode, first and 128 != 0, length)
            accept(header, 0, used)
            payloadRemaining = length
            used = 0; needed = 2
        }
    }

    override fun toString() = "GatewayEnvelopeGuard([REDACTED])"
}

internal class GatewayMessageBounds {
    private var kind: Opcode? = null
    private var bytes = 0L
    private var fragments = 0

    fun accept(opcode: Opcode, fin: Boolean, length: Long) {
        if (length < 0 || length > 65536) invalid()
        if (opcode in setOf(Opcode.PING, Opcode.PONG, Opcode.CLOSING)) {
            if (!fin || length > 125) invalid()
            return
        }
        if (opcode == Opcode.CONTINUOUS) {
            if (kind == null) invalid()
        } else {
            if (kind != null || opcode !in setOf(Opcode.TEXT, Opcode.BINARY)) invalid()
            kind = opcode; bytes = 0; fragments = 0
        }
        bytes += length; fragments++
        if (bytes > (if (kind == Opcode.TEXT) 16384 else 65536) || fragments > 128) invalid()
        if (fin) { kind = null; bytes = 0; fragments = 0 }
    }
}

internal fun invalid(): Nothing = throw InvalidDataException(1002, "Invalid gateway envelope")
