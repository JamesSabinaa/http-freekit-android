package com.httpfreekit.research.websocket

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/** Research framing only: no upgrade, sockets, authentication, timers or application lifecycle. */
enum class EndpointRole { CLIENT, SERVER }
enum class FramingFailure { PROTOCOL, TOO_LARGE, TRUNCATED, IO, CLOSED, CONCURRENT_READ, MESSAGE_PENDING }

class ResearchWebSocketException(val failure: FramingFailure) : IOException("WebSocket ${failure.name}")

/** One leased event. Copies are caller-owned; release is idempotent and invalidates further copies. */
sealed class ResearchWebSocketEvent(private var bytes: ByteArray?) {
    private var released: (() -> Unit)? = null
    @Synchronized fun copyBytes(): ByteArray = bytes?.copyOf() ?: fail(FramingFailure.CLOSED)
    @Synchronized fun release() {
        bytes = null
        released?.invoke()
        released = null
    }
    internal fun onRelease(callback: () -> Unit) { released = callback }
    class Text(bytes: ByteArray) : ResearchWebSocketEvent(bytes) {
        override fun toString() = "WebSocket text"
    }
    class Binary(bytes: ByteArray) : ResearchWebSocketEvent(bytes) {
        override fun toString() = "WebSocket binary"
    }
    class Ping(bytes: ByteArray) : ResearchWebSocketEvent(bytes) {
        override fun toString() = "WebSocket ping"
    }
    class Pong(bytes: ByteArray) : ResearchWebSocketEvent(bytes) {
        override fun toString() = "WebSocket pong"
    }
    class Close(val code: Int?, val reason: String) : ResearchWebSocketEvent(null) {
        override fun toString() = "WebSocket close"
    }
}

/**
 * Pulls exactly one event; never reads ahead into the following frame. Interleaved control events
 * can be returned while one bounded fragmented message is in progress. The owner must process an
 * event and release it before calling read again, enforce deadlines, and close/join real I/O on
 * any failure. Research guards limit a fragmented message to 64 data frames/64 control events.
 * InputStream/TLS/kernel buffering and caller retention are outside this reader's memory bound.
 */
class ResearchWebSocketReader(
    private val input: InputStream,
    private val role: EndpointRole,
    private val maxBinaryBytes: Int = 65536,
    private val maxTextBytes: Int = 16384,
) {
    private val reading = AtomicBoolean(false)
    private val leased = AtomicBoolean(false)
    private var failure: FramingFailure? = null
    private var closed = false
    private var fragment: ByteArray? = null
    private var fragmentSize = 0
    private var fragmentOpcode = 0
    private var fragments = 0
    private var controls = 0

    init { validateLimits(maxBinaryBytes, maxTextBytes) }

    fun read(): ResearchWebSocketEvent {
        if (!reading.compareAndSet(false, true)) fail(FramingFailure.CONCURRENT_READ)
        try {
            // Caller misuse is not a peer protocol failure and must not discard a partial message.
            if (leased.get()) fail(FramingFailure.MESSAGE_PENDING)
            failure?.let { fail(it) }
            if (closed) fail(FramingFailure.CLOSED)
            while (true) {
                val first = byte()
                val second = byte()
                val final = first and 128 != 0
                val opcode = first and 15
                if (first and 112 != 0 || opcode !in setOf(0, 1, 2, 8, 9, 10)) fail(FramingFailure.PROTOCOL)
                val control = opcode >= 8
                val masked = second and 128 != 0
                if (masked != (role == EndpointRole.SERVER)) fail(FramingFailure.PROTOCOL)
                if (control && (!final || second and 127 > 125)) fail(FramingFailure.PROTOCOL)
                if (!control && ((opcode == 0) != (fragment != null))) fail(FramingFailure.PROTOCOL)
                if (control && fragment != null && ++controls > 64) fail(FramingFailure.PROTOCOL)
                if (opcode == 0 && ++fragments > 64) fail(FramingFailure.PROTOCOL)

                val size = length(second and 127)
                val limit = if (control) 125 else if ((if (opcode == 0) fragmentOpcode else opcode) == 1) {
                    maxTextBytes
                } else maxBinaryBytes
                val existing = if (opcode == 0) fragmentSize else 0
                if (size > limit - existing) fail(FramingFailure.TOO_LARGE)
                // All attacker-controlled lengths have now been checked, before payload allocation.
                val count = size.toInt()
                val mask = if (masked) ByteArray(4).also { exact(it, 0, 4) } else null
                if (control) {
                    val bytes = ByteArray(count)
                    payload(bytes, 0, count, mask)
                    return retain(when (opcode) {
                        9 -> ResearchWebSocketEvent.Ping(bytes)
                        10 -> ResearchWebSocketEvent.Pong(bytes)
                        else -> {
                            val close = closePayload(bytes)
                            fragment = null
                            fragmentSize = 0
                            closed = true
                            close
                        }
                    })
                }
                if (opcode != 0 && final) {
                    val bytes = ByteArray(count)
                    payload(bytes, 0, count, mask)
                    return retain(message(opcode, bytes))
                }
                if (opcode != 0) {
                    fragment = ByteArray(limit)
                    fragmentOpcode = opcode
                    fragmentSize = 0
                    fragments = 1
                    controls = 0
                }
                val buffer = fragment ?: fail(FramingFailure.PROTOCOL)
                payload(buffer, fragmentSize, count, mask)
                fragmentSize += count
                if (final) {
                    val bytes = buffer.copyOf(fragmentSize)
                    val kind = fragmentOpcode
                    fragment = null
                    fragmentSize = 0
                    return retain(message(kind, bytes))
                }
            }
        } catch (error: ResearchWebSocketException) {
            if (error.failure == FramingFailure.MESSAGE_PENDING) throw error
            failure = failure ?: error.failure
            fragment = null
            fragmentSize = 0
            throw error
        } catch (_: IOException) {
            failure = FramingFailure.IO
            fragment = null
            fragmentSize = 0
            fail(FramingFailure.IO)
        } finally {
            reading.set(false)
        }
    }

    private fun retain(event: ResearchWebSocketEvent): ResearchWebSocketEvent {
        leased.set(true)
        event.onRelease { leased.set(false) }
        return event
    }

    private fun byte(): Int = input.read().also { if (it < 0) fail(FramingFailure.TRUNCATED) }

    private fun length(marker: Int): Long = when (marker) {
        126 -> ((byte() shl 8) or byte()).toLong().also { if (it < 126) fail(FramingFailure.PROTOCOL) }
        127 -> {
            val first = byte()
            if (first and 128 != 0) fail(FramingFailure.PROTOCOL)
            var value = first.toLong()
            repeat(7) { value = (value shl 8) or byte().toLong() }
            if (value < 65536) fail(FramingFailure.PROTOCOL)
            value
        }
        else -> marker.toLong()
    }

    private fun exact(target: ByteArray, offset: Int, count: Int) {
        var position = offset
        while (position < offset + count) {
            val read = input.read(target, position, offset + count - position)
            if (read < 0) fail(FramingFailure.TRUNCATED)
            if (read == 0) fail(FramingFailure.IO)
            position += read
        }
    }

    private fun payload(target: ByteArray, offset: Int, count: Int, mask: ByteArray?) {
        exact(target, offset, count)
        if (mask != null) repeat(count) { index ->
            target[offset + index] = (target[offset + index].toInt() xor mask[index % 4].toInt()).toByte()
        }
    }

    private fun message(opcode: Int, bytes: ByteArray): ResearchWebSocketEvent = if (opcode == 1) {
        strictUtf8(bytes)
        ResearchWebSocketEvent.Text(bytes)
    } else ResearchWebSocketEvent.Binary(bytes)
}

/**
 * Writes one complete frame under a single lock, with no owned asynchronous queue. A successful
 * flush is only actual local OutputStream completion; it says nothing about remote consumption.
 * The owner must close its socket to interrupt blocked I/O and join the writer before releasing
 * lifecycle leases. This class never calls resources_closed or owns a timeout/worker thread.
 */
class ResearchWebSocketWriter(
    private val output: OutputStream,
    private val role: EndpointRole,
    private val maxBinaryBytes: Int = 65536,
    private val maxTextBytes: Int = 16384,
) {
    private val lock = Any()
    private val random = SecureRandom()
    private var closed = false
    private var failed = false

    init { validateLimits(maxBinaryBytes, maxTextBytes) }

    fun text(bytes: ByteArray) = write(1, bytes)
    fun binary(bytes: ByteArray) = write(2, bytes)
    fun ping(bytes: ByteArray) = write(9, bytes)
    fun pong(bytes: ByteArray) = write(10, bytes)
    fun close(bytes: ByteArray = byteArrayOf()) = write(8, bytes)

    private fun write(opcode: Int, supplied: ByteArray): Unit = synchronized(lock) {
        if (closed || failed) fail(FramingFailure.CLOSED)
        val limit = when (opcode) { 1 -> maxTextBytes; 2 -> maxBinaryBytes; else -> 125 }
        if (supplied.size > limit) fail(FramingFailure.TOO_LARGE)
        val bytes = supplied.copyOf()
        if (opcode == 1) strictUtf8(bytes)
        if (opcode == 8) closePayload(bytes)
        val masked = role == EndpointRole.CLIENT
        val maskBit = if (masked) 128 else 0
        val mask = if (masked) ByteArray(4).also { random.nextBytes(it) } else null
        try {
            output.write(128 or opcode)
            when {
                bytes.size < 126 -> output.write(maskBit or bytes.size)
                bytes.size <= 65535 -> {
                    output.write(maskBit or 126)
                    output.write(bytes.size ushr 8)
                    output.write(bytes.size and 255)
                }
                else -> {
                    output.write(maskBit or 127)
                    repeat(4) { output.write(0) }
                    for (shift in listOf(24, 16, 8, 0)) output.write((bytes.size ushr shift) and 255)
                }
            }
            if (mask != null) {
                output.write(mask)
                repeat(bytes.size) { index -> bytes[index] = (bytes[index].toInt() xor mask[index % 4].toInt()).toByte() }
            }
            output.write(bytes)
            output.flush()
            if (opcode == 8) closed = true
        } catch (_: IOException) {
            failed = true
            fail(FramingFailure.IO)
        }
    }
}

private fun validateLimits(binary: Int, text: Int) {
    require(binary in 1..65536 && text in 1..16384) { "Invalid WebSocket limits" }
}

private fun strictUtf8(bytes: ByteArray): String = try {
    Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
} catch (_: CharacterCodingException) { fail(FramingFailure.PROTOCOL) }

private fun closePayload(bytes: ByteArray): ResearchWebSocketEvent.Close {
    if (bytes.isEmpty()) return ResearchWebSocketEvent.Close(null, "")
    if (bytes.size == 1) fail(FramingFailure.PROTOCOL)
    val code = ((bytes[0].toInt() and 255) shl 8) or (bytes[1].toInt() and 255)
    if (!(code in 1000..1014 && code !in setOf(1004, 1005, 1006) || code in 3000..4999)) {
        fail(FramingFailure.PROTOCOL)
    }
    return ResearchWebSocketEvent.Close(code, strictUtf8(bytes.copyOfRange(2, bytes.size)))
}

private fun fail(failure: FramingFailure): Nothing = throw ResearchWebSocketException(failure)
