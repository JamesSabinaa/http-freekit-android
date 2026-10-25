package com.httpfreekit.transport.websocket

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.util.ArrayDeque
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocket
import kotlin.concurrent.withLock
import org.java_websocket.WebSocket
import org.java_websocket.WebSocketAdapter
import org.java_websocket.WebSocketImpl
import org.java_websocket.handshake.ClientHandshake
import org.java_websocket.handshake.HandshakeImpl1Client
import org.java_websocket.handshake.Handshakedata
import org.java_websocket.handshake.ServerHandshake
import org.java_websocket.framing.Framedata
import org.java_websocket.framing.PingFrame
import org.java_websocket.enums.Opcode
import org.slf4j.LoggerFactory
import org.slf4j.helpers.NOPLoggerFactory

class GatewayWebSocketException internal constructor(val code: String) : IllegalStateException("Gateway WebSocket unavailable: $code") {
    override fun toString() = "GatewayWebSocketException($code)"
}

/** Owns I/O around a maintained engine. The caller has already authenticated the scoped TLS socket. */
class OwnedGatewayWebSocket(
    private val socket: SSLSocket,
    private val interruptRaw: () -> Unit,
    private val authority: String,
    private val path: String,
    private val sessionHeader: String? = null,
) : AutoCloseable {
    sealed interface Incoming {
        class Text internal constructor(private val value: String) : Incoming {
            fun text(): String = value
            override fun toString() = "Incoming.Text([REDACTED])"
        }
        class Binary internal constructor(private val value: ByteArray) : Incoming {
            fun copyBytes(): ByteArray = value.copyOf()
            override fun toString() = "Incoming.Binary([REDACTED])"
        }
        class Closed internal constructor(val normal: Boolean) : Incoming {
            override fun toString() = "Incoming.Closed(normal=$normal)"
        }
        class Ping internal constructor() : Incoming { override fun toString() = "Incoming.Ping" }
        class Pong internal constructor() : Incoming { override fun toString() = "Incoming.Pong" }
    }
    class Snapshot internal constructor(
        val started: Boolean, val open: Boolean, val admissionClosed: Boolean,
        val readerAlive: Boolean, val writerAlive: Boolean,
        val pendingOutputSlots: Int, val pendingOutputBytes: Long,
        val incomingMessages: Int, val incomingBytes: Long,
        val joined: Boolean, val failureCode: String?,
    ) {
        override fun toString() = "GatewayWebSocketSnapshot(open=$open, joined=$joined, failureCode=$failureCode)"
    }
    private class Receipt(val deadline: Long) { var remaining = 0; var sealed = false; var done = false; var completedAt = 0L }
    private class Output(val bytes: ByteArray, val receipt: Receipt?)
    private class Input(val value: Incoming, val size: Int)
    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private val engineLock = ReentrantLock()
    private val outgoing = ArrayDeque<Output>()
    private val incoming = ArrayDeque<Input>()
    private var slots = 0
    private var outputBytes = 0L
    private var inputBytes = 0L
    private var started = false
    private var opened = false
    private var usable = false
    private var openedAt = 0L
    private var admissionClosed = false
    private var stopping = false
    private var closeRequested = false
    private var closeEncoded = false
    private var engineClosed = false
    private var peerCloseSeen = false // Engine-lock confined, set only after maintained frame validation.
    private var closedNormal = false
    private var closedDelivered = false
    private var failureCode: String? = null
    private var joined = false
    private var rawClosed = false
    private var tlsClosed = false
    private var closureGeneration = 0L
    private var reader: Thread? = null
    private var writer: Thread? = null
    private var currentReceipt: Receipt? = null // Engine-lock confined; never an I/O acknowledgement.
    private val envelope = GatewayEnvelopeGuard()

    init {
        if (authority.length !in 1..512 || authority.any { it.code !in 33..126 } ||
            path !in setOf("/companion/v1/control", "/companion/v1/streams") ||
            (path.endsWith("/control") && sessionHeader != null) ||
            (path.endsWith("/streams") && !canonicalSession(sessionHeader))) throw GatewayWebSocketException("invalid_request")
    }

    private val listener = object : WebSocketAdapter() {
        override fun onWebsocketOpen(conn: WebSocket, handshake: Handshakedata) = lock.withLock {
            if (!stopping) { opened = true; openedAt = System.nanoTime() }
            changed.signalAll()
        }
        override fun onWebsocketHandshakeReceivedAsClient(conn: WebSocket, request: ClientHandshake, response: ServerHandshake) {
            if (response.hasFieldValue("Sec-WebSocket-Protocol") || response.hasFieldValue("Sec-WebSocket-Extensions")) invalid()
        }
        override fun onWebsocketMessage(conn: WebSocket, message: String) = push(Incoming.Text(message), message.toByteArray(Charsets.UTF_8).size)
        override fun onWebsocketMessage(conn: WebSocket, bytes: ByteBuffer) {
            val copied = ByteArray(bytes.remaining()); bytes.duplicate().get(copied)
            push(Incoming.Binary(copied), copied.size)
        }
        override fun onWebsocketPing(conn: WebSocket, frame: Framedata) {
            super.onWebsocketPing(conn, frame)
            push(Incoming.Ping(), 0)
        }
        override fun onWebsocketPong(conn: WebSocket, frame: Framedata) = push(Incoming.Pong(), 0)
        override fun onWriteDemand(conn: WebSocket) {
            val impl = conn as WebSocketImpl
            while (true) {
                val encoded = impl.outQueue.poll() ?: return
                val copied = ByteArray(encoded.remaining()); encoded.duplicate().get(copied)
                lock.withLock {
                    if (stopping || slots >= 8 || outputBytes + copied.size > 131072) throw GatewayWebSocketException("capacity")
                    currentReceipt?.let { it.remaining++ }
                    outgoing.addLast(Output(copied, currentReceipt)); slots++; outputBytes += copied.size
                    changed.signalAll()
                }
            }
        }
        override fun onWebsocketClose(conn: WebSocket, code: Int, reason: String?, remote: Boolean) = lock.withLock {
            engineClosed = true; admissionClosed = true
            closedNormal = code == 1000 && peerCloseSeen && failureCode == null
            if (!closedNormal) signalFailure(if (code == 1006) "io" else "protocol")
            changed.signalAll()
        }
        override fun onWebsocketError(conn: WebSocket, error: Exception) = signalFailure("protocol")
        override fun onWebsocketClosing(conn: WebSocket, code: Int, reason: String?, remote: Boolean) = lock.withLock {
            admissionClosed = true; changed.signalAll()
        }
        override fun onWebsocketCloseInitiated(conn: WebSocket, code: Int, reason: String?) = Unit
        override fun getLocalSocketAddress(conn: WebSocket) = null
        override fun getRemoteSocketAddress(conn: WebSocket) = null
    }
    private var engineValue: WebSocketImpl? = null // Engine-lock confined and discarded only after real worker joins.
    private val engine: WebSocketImpl
        get() = engineValue ?: WebSocketImpl(listener, GuardedGatewayDraft()).also { engineValue = it }

    fun start(deadlineNanos: Long) {
        if (LoggerFactory.getILoggerFactory().javaClass != NOPLoggerFactory::class.java) {
            interrupt(); throw GatewayWebSocketException("logging")
        }
        try {
            lock.withLock {
                if (started || stopping) throw GatewayWebSocketException("closed")
                started = true
                writer = worker("gateway-websocket-write", ::writeLoop).also { it.start() }
                reader = worker("gateway-websocket-read", ::readLoop).also { it.start() }
            }
            val handshakeReceipt = encode(deadlineNanos, 4096) {
                engine.startHandshake(HandshakeImpl1Client().apply {
                    setResourceDescriptor(path); put("Host", authority)
                    sessionHeader?.let { put("X-FreeKit-Session", it) }
                })
            }
            lock.withLock {
                while ((!opened || !handshakeReceipt.done) && !stopping) waitUntil(deadlineNanos)
                if (!opened || !handshakeReceipt.done || stopping) throw GatewayWebSocketException(failureCode ?: "closed")
                if (openedAt - deadlineNanos > 0 || handshakeReceipt.completedAt - deadlineNanos > 0) throw GatewayWebSocketException("deadline")
                usable = true
            }
        } catch (failure: GatewayWebSocketException) { abortAndThrow(failure.code) }
        catch (_: Exception) { abortAndThrow("handshake") }
    }

    fun writeText(text: String, deadlineNanos: Long) {
        val size = utf8Size(text)
        write(deadlineNanos, size + 14) { engine.send(text) }
    }

    fun writeBinary(bytes: ByteArray, deadlineNanos: Long) {
        if (bytes.isEmpty() || bytes.size > 65536) throw GatewayWebSocketException("invalid_request")
        write(deadlineNanos, bytes.size + 14) { engine.send(bytes.copyOf()) }
    }

    fun writePing(deadlineNanos: Long) = write(deadlineNanos, 14) { engine.sendFrame(PingFrame()) }

    private fun write(deadline: Long, reserve: Int, action: () -> Unit) {
        if (!lock.withLock { usable && !admissionClosed && !stopping }) throw GatewayWebSocketException("closed")
        try {
            val receipt = encode(deadline, reserve, action)
            lock.withLock {
                while (!receipt.done && !stopping) waitUntil(deadline)
                if (!receipt.done || stopping) throw GatewayWebSocketException(failureCode ?: "closed")
                if (receipt.completedAt - deadline > 0) throw GatewayWebSocketException("deadline")
            }
        } catch (failure: GatewayWebSocketException) {
            if (failure.code == "closed" && lock.withLock { closeRequested && !stopping }) throw failure
            abortAndThrow(failure.code)
        }
        catch (_: Exception) { abortAndThrow("write") }
    }

    private fun encode(deadline: Long, reserve: Int, action: () -> Unit): Receipt {
        val remaining = deadline - System.nanoTime()
        if (remaining <= 0 || !engineLock.tryLock(remaining, TimeUnit.NANOSECONDS)) throw GatewayWebSocketException("deadline")
        try {
            lock.withLock {
                while (!stopping && !admissionClosed && (slots >= 8 || outputBytes + reserve > 131072)) waitUntil(deadline)
                if (stopping || admissionClosed) throw GatewayWebSocketException(failureCode ?: "closed")
                if (System.nanoTime() - deadline >= 0) throw GatewayWebSocketException("deadline")
            }
            val receipt = Receipt(deadline)
            currentReceipt = receipt
            try { action() } finally { currentReceipt = null }
            lock.withLock { receipt.sealed = true; receipt.done = receipt.remaining == 0; changed.signalAll() }
            return receipt
        } finally { engineLock.unlock() }
    }

    fun pollIncoming(waitMillis: Int): Incoming? {
        if (waitMillis !in 0..1000) throw GatewayWebSocketException("invalid_request")
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(waitMillis.toLong())
        return lock.withLock {
            while (incoming.isEmpty() && !engineClosed && !stopping) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) return@withLock null
                changed.awaitNanos(remaining)
            }
            if (incoming.isNotEmpty()) {
                val input = incoming.removeFirst(); inputBytes -= input.size; changed.signalAll(); input.value
            } else if (!closedDelivered && (engineClosed || stopping)) {
                closedDelivered = true; Incoming.Closed(closedNormal && failureCode == null)
            } else null
        }
    }

    fun requestClose() = lock.withLock {
        if (!stopping && !closeRequested) { admissionClosed = true; closeRequested = true; changed.signalAll() }
    }

    fun interrupt() {
        lock.withLock {
            stopping = true; admissionClosed = true
            if (!engineClosed || failureCode != null) closedNormal = false
            closureGeneration++
            incoming.clear(); inputBytes = 0; changed.signalAll()
            if (writer == null) writer = worker("gateway-websocket-write", ::writeLoop)
            if (writer?.state == Thread.State.NEW) {
                try { writer!!.start() } catch (_: Exception) { if (failureCode == null) failureCode = "cleanup" }
            }
        }
        closeRaw()
    }

    fun awaitJoined(deadlineNanos: Long): Boolean {
        val workers = lock.withLock { listOfNotNull(reader, writer) }
        if (workers.any { it === Thread.currentThread() }) return false
        try {
            for (thread in workers) {
                val remaining = deadlineNanos - System.nanoTime()
                if (thread.isAlive && remaining > 0) TimeUnit.NANOSECONDS.timedJoin(thread, remaining)
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return false
        }
        if (!lock.withLock { workers.isNotEmpty() && workers.none { it.isAlive } && rawClosed && tlsClosed && slots == 0 && incoming.isEmpty() }) return false
        if (!engineLock.tryLock()) return false
        try {
            engineValue?.let { it.draft.reset(); it.outQueue.clear(); it.inQueue.clear() }
            engineValue = null
            return lock.withLock { joined = true; true }
        } finally { engineLock.unlock() }
    }

    override fun close() {
        interrupt()
        if (!awaitJoined(System.nanoTime() + TimeUnit.SECONDS.toNanos(5))) throw GatewayWebSocketException("cleanup")
    }

    fun snapshot(): Snapshot = lock.withLock { Snapshot(started, usable && !admissionClosed, admissionClosed,
        reader?.isAlive == true, writer?.isAlive == true, slots, outputBytes, incoming.size, inputBytes, joined, failureCode) }
    override fun toString() = "OwnedGatewayWebSocket([REDACTED])"

    private fun readLoop() {
        try {
            val buffer = ByteArray(8192)
            val headers = ByteArrayOutputStream(4096)
            var handshake = false
            var tail = 0
            while (!lock.withLock { stopping || engineClosed }) {
                val size = socket.inputStream.read(buffer)
                if (size < 0) { engineLock.withLock { engine.eot() }; closeRaw(); break }
                if (size == 0) throw GatewayWebSocketException("io")
                var offset = 0
                if (!handshake) {
                    while (offset < size && !handshake) {
                        if (headers.size() == 4096) invalid()
                        val byte = buffer[offset++]; headers.write(byte.toInt())
                        tail = (tail shl 8) or (byte.toInt() and 255)
                        if (tail == 0x0d0a0d0a) {
                            engineLock.withLock { engine.decode(ByteBuffer.wrap(headers.toByteArray())) }
                            if (!lock.withLock { opened && !stopping }) invalid()
                            handshake = true; headers.reset()
                        }
                    }
                }
                if (handshake && offset < size) envelope.feed(buffer, offset, size - offset) { bytes, at, count ->
                    engineLock.withLock {
                        // v1.6.0 WebSocketImpl.decode:227-230 drops all CLOSING frames; eot:611
                        // can report the local1000 without a peer Close. Use its public draft
                        // for maintained payload/UTF8/close processing, and require peerCloseSeen.
                        val draft = engine.draft
                        for (frame in draft.translateFrame(ByteBuffer.wrap(bytes, at, count))) {
                            if (peerCloseSeen) invalid()
                            if (frame.opcode == Opcode.CLOSING) peerCloseSeen = true
                            draft.processFrame(engine, frame)
                        }
                    }
                }
                if (lock.withLock { stopping }) closeRaw()
            }
        } catch (failure: GatewayWebSocketException) { signalFailure(failure.code); closeRaw() }
        catch (_: IOException) { signalFailure("io"); closeRaw() }
        catch (_: Exception) { signalFailure("protocol"); closeRaw() }
        finally {
            lock.withLock {
                if (!engineClosed && !stopping) signalFailure("io")
                changed.signalAll()
            }
        }
    }

    private fun writeLoop() {
        try {
            while (true) {
                var encodeClose = false
                val output = lock.withLock {
                    while (!stopping && outgoing.isEmpty() && !engineClosed && !(closeRequested && !closeEncoded)) changed.await()
                    if (stopping) null
                    else if (outgoing.isNotEmpty()) outgoing.removeFirst()
                    else {
                        if (engineClosed) { stopping = true; admissionClosed = true }
                        else encodeClose = true
                        null
                    }
                }
                if (output != null) {
                    if (output.receipt?.let { System.nanoTime() - it.deadline >= 0 } == true) throw GatewayWebSocketException("deadline")
                    socket.outputStream.write(output.bytes)
                    socket.outputStream.flush()
                    val completedAt = System.nanoTime()
                    lock.withLock {
                        slots--; outputBytes -= output.bytes.size
                        output.receipt?.let { it.remaining--; it.completedAt = completedAt; it.done = it.sealed && it.remaining == 0 }
                        changed.signalAll()
                    }
                } else if (encodeClose) {
                    if (engineLock.tryLock(50, TimeUnit.MILLISECONDS)) {
                        try {
                            if (!lock.withLock { stopping }) { engine.close(1000, ""); lock.withLock { closeEncoded = true } }
                        } finally { engineLock.unlock() }
                    }
                } else break
            }
        } catch (failure: GatewayWebSocketException) { signalFailure(failure.code) }
        catch (_: Exception) { signalFailure("io") }
        finally {
            closeRaw()
            finishTlsClosure()
            lock.withLock {
                outgoing.clear(); slots = 0; outputBytes = 0; changed.signalAll()
            }
        }
    }

    private fun finishTlsClosure() {
        while (true) {
            val generation = lock.withLock { closureGeneration }
            try { socket.close(); lock.withLock { tlsClosed = true; changed.signalAll() }; return }
            catch (_: Exception) {
                signalFailure("cleanup")
                lock.withLock { while (closureGeneration == generation) changed.await() }
            }
        }
    }

    private fun closeRaw() {
        try { interruptRaw(); lock.withLock { rawClosed = true; changed.signalAll() } }
        catch (_: Exception) { signalFailure("cleanup") }
    }

    private fun push(value: Incoming, size: Int) = lock.withLock {
        if (size > 65536) throw GatewayWebSocketException("protocol")
        while (!stopping && (incoming.size == 2 || inputBytes + size > 131072)) changed.await()
        if (stopping) throw GatewayWebSocketException("closed")
        incoming.addLast(Input(value, size)); inputBytes += size; changed.signalAll()
    }

    private fun waitUntil(deadline: Long) {
        val remaining = deadline - System.nanoTime()
        if (remaining <= 0) throw GatewayWebSocketException("deadline")
        changed.awaitNanos(remaining)
    }

    private fun signalFailure(code: String) = lock.withLock {
        if (failureCode == null) failureCode = code
        stopping = true; admissionClosed = true; closedNormal = false
        incoming.clear(); inputBytes = 0; changed.signalAll()
    }

    private fun abortAndThrow(fallback: String): Nothing {
        signalFailure(fallback); interrupt(); throw GatewayWebSocketException(lock.withLock { failureCode ?: fallback })
    }

    private fun worker(name: String, action: () -> Unit) = Thread(action, name).apply { isDaemon = true }

    companion object {
        private fun utf8Size(text: String): Int {
            if (text.length > 16384) throw GatewayWebSocketException("invalid_request")
            var size = 0; var index = 0
            while (index < text.length) {
                val value = text[index++]
                size += when {
                    value.code < 128 -> 1
                    value.code < 2048 -> 2
                    value.isHighSurrogate() -> {
                        if (index == text.length || !text[index++].isLowSurrogate()) throw GatewayWebSocketException("invalid_request")
                        4
                    }
                    value.isLowSurrogate() -> throw GatewayWebSocketException("invalid_request")
                    else -> 3
                }
                if (size > 16384) throw GatewayWebSocketException("invalid_request")
            }
            return size
        }
        private fun canonicalSession(value: String?): Boolean = try {
            value != null && Regex("[A-Za-z0-9_-]{43}").matches(value) &&
                Base64.getUrlDecoder().decode(value).size == 32 &&
                Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(value)) == value
        } catch (_: Exception) { false }
    }
}
