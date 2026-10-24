package com.httpfreekit.interop

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.protocol.*
import com.httpfreekit.research.websocket.EndpointRole
import com.httpfreekit.research.websocket.ResearchWebSocketEvent
import com.httpfreekit.research.websocket.ResearchWebSocketReader
import com.httpfreekit.research.websocket.ResearchWebSocketWriter
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Real research I/O adapter. Its lock protects model events, never a blocking socket operation. */
internal class DraftStreamingOwner(
    private val fixture: DraftStreamingFixture,
    val credential: DraftStreamingFixture.Credential,
    scenario: String,
) : AutoCloseable {
    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private val clock = DraftStreamingClock()
    private val pool = DraftBudgetPool(4, 8, 65536)
    private val model = DraftSession(credential.deviceId, "research-desktop", CAPABILITIES, pool, clock.now())
    private val streams = ArrayList<Stream>()
    private val tls: DraftStreamingTls
    private val reader: ResearchWebSocketReader
    private val writer: ResearchWebSocketWriter
    private val workers = DraftStreamingWorkers { abort() }
    private val closed = AtomicBoolean(false)
    private val abortFailed = AtomicBoolean(false)
    val expiresAtMillis: Long
    var readyAtUtcMillis: Long = 0
        private set
    var readyAtNanos: Long = 0
        private set
    val deadlineTicks = AtomicLong()
    val expiredDeadlineTicks = AtomicLong()

    init {
        check(scenario in setOf("gated", "backpressure", "cancel", "expiry", "binding", "malformed", "premature"))
        val upgraded = fixture.upgrade(credential, "/companion/v1/control", scenario = scenario)
        tls = upgraded.first
        try {
            check(upgraded.second == 101) { "Control upgrade refused" }
            reader = ResearchWebSocketReader(tls.socket.inputStream, EndpointRole.CLIENT, FRAME)
            writer = ResearchWebSocketWriter(tls.socket.outputStream, EndpointRole.CLIENT, FRAME)
            val hello = DraftWireCodec.encode(DraftMessage.Hello(CAPABILITIES, CAPABILITIES))
            accepted(lock.withLock { model.text(DraftDirection.CLIENT, hello, clock.now()) })
            writer.text(hello)
            tls.socket.soTimeout = 5000
            val event = reader.read()
            try {
                check(event is ResearchWebSocketEvent.Text) { "Control readiness was not text" }
                val bytes = event.copyBytes()
                val decoded = DraftWireCodec.decode(DraftChannel.CONTROL, bytes)
                check(decoded is DraftDecodeResult.Accepted && decoded.message is DraftMessage.SessionReady) { "Invalid control readiness" }
                val ready = decoded.message as DraftMessage.SessionReady
                check(ready.limits == LIMITS && ready.capabilities.toSet() == CAPABILITIES.toSet()) { "Unexpected research limits" }
                expiresAtMillis = ready.expiresAt.toEpochMilli()
                accepted(lock.withLock { model.text(DraftDirection.GATEWAY, bytes, clock.now()) })
                readyAtUtcMillis = System.currentTimeMillis()
                readyAtNanos = System.nanoTime()
            } finally { event.release() }
            tls.socket.soTimeout = 0
            workers.launch("control-reader") { controlRead() }
            workers.launch("control-heartbeat") {
                var next = System.nanoTime()
                while (!workers.stopping.get()) {
                    if (System.nanoTime() >= next) {
                        writer.ping(byteArrayOf(1))
                        lock.withLock {
                            if (model.snapshot().phase == DraftControlPhase.ACTIVE) accepted(model.pingPong(DraftDirection.CLIENT, clock.now()))
                        }
                        next = System.nanoTime() + 5_000_000_000
                    }
                    Thread.sleep(25)
                }
            }
            workers.launch("deadline") {
                while (!workers.stopping.get()) {
                    val terminal = lock.withLock {
                        val result = model.tick(clock.now())
                        deadlineTicks.incrementAndGet()
                        if (result.code == "session_expired") expiredDeadlineTicks.incrementAndGet()
                        changed.signalAll()
                        model.snapshot().phase in setOf(DraftControlPhase.CLOSED, DraftControlPhase.FAILED)
                    }
                    val failedStreams = lock.withLock { streams.filter { it.terminalLocked() } }
                    failedStreams.forEach { it.interrupt() }
                    if (terminal) { abort(); break }
                    Thread.sleep(25)
                }
            }
        } catch (failure: Exception) {
            abort()
            try { tls.close() } finally { workers.joinAll() }
            check(!abortFailed.get()) { "Control construction cleanup failed" }
            lock.withLock { model.confirmClosed(clock.now()) }
            throw failure
        }
    }

    fun token(): String = lock.withLock { checkNotNull(model.sessionHeader()) }
    fun snapshot() = lock.withLock { model.snapshot() }
    fun budget() = pool.snapshot()

    fun open(): Stream {
        lock.withLock { check(streams.size < 8 && !closed.get()) { "Research stream admission exceeded" } }
        val allocation = lock.withLock { model.allocateStream(credential.deviceId, token(), clock.now()) }
        accepted(allocation.result)
        val allocated = checkNotNull(allocation.stream)
        val stream = try { Stream(allocated, "stream_${lock.withLock { streams.size + 1 }}") }
        catch (failure: Exception) {
            // createPair closes partial real sockets before this orphan lease is released.
            lock.withLock { allocated.confirmClosed(clock.now()) }
            throw failure
        }
        lock.withLock { streams.add(stream) }
        try { stream.start() } catch (failure: Exception) { stream.close(); throw failure }
        return stream
    }

    private fun controlRead() {
        while (!workers.stopping.get()) {
            val event = reader.read()
            try {
                when (event) {
                    is ResearchWebSocketEvent.Ping -> {
                        accepted(lock.withLock { model.pingPong(DraftDirection.GATEWAY, clock.now()) })
                        writer.pong(event.copyBytes())
                        accepted(lock.withLock { model.pingPong(DraftDirection.CLIENT, clock.now()) })
                    }
                    is ResearchWebSocketEvent.Pong -> accepted(lock.withLock { model.pingPong(DraftDirection.GATEWAY, clock.now()) })
                    is ResearchWebSocketEvent.Text -> {
                        lock.withLock { model.text(DraftDirection.GATEWAY, event.copyBytes(), clock.now()); changed.signalAll() }
                        if (snapshot().phase != DraftControlPhase.ACTIVE) { abort(); return }
                    }
                    is ResearchWebSocketEvent.Close -> {
                        lock.withLock { model.webSocketClosed(event.code ?: 1005, clock.now()); changed.signalAll() }
                        abort(); return
                    }
                    else -> error("Unexpected control binary event")
                }
            } finally { event.release() }
        }
    }

    /** Independent control transport remains usable when a stream's TLS writer is blocked. */
    fun cancel() {
        val bytes = DraftWireCodec.encode(DraftMessage.ControlCancel())
        accepted(lock.withLock { model.text(DraftDirection.CLIENT, bytes, clock.now()).also { changed.signalAll() } })
        // Accept this real outbound intent before the peer can react to it. Interrupt stream I/O
        // immediately, retaining the independent control transport for its actual cancel write.
        try {
            lock.withLock { streams.toList() }.forEach { it.interrupt() }
            writer.text(bytes)
        } finally { abort() }
    }

    private fun abort() {
        workers.stopping.set(true)
        try {
            lock.withLock { streams.toList() }.forEach {
                try { it.interrupt() } catch (_: Exception) { abortFailed.set(true) } catch (_: AssertionError) { abortFailed.set(true) }
            }
        } finally {
            tls.interrupt()
            lock.withLock {
                if (!model.snapshot().webSocketClosed) model.webSocketClosed(1006, clock.now())
                changed.signalAll()
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        lock.withLock { model.cancelLocally(clock.now()); changed.signalAll() }
        // Join every stream's local producer/consumer and all its I/O before model release.
        var cleanupFailed = false
        fun attempt(operation: () -> Unit) {
            try { operation() } catch (_: Exception) { cleanupFailed = true } catch (_: AssertionError) { cleanupFailed = true }
        }
        attempt { abort() }
        lock.withLock { streams.toList() }.forEach { attempt { it.close() } }
        attempt { tls.close() }
        attempt { workers.joinAll() }
        check(!cleanupFailed && !abortFailed.get()) { "Control resource cleanup failed" }
        lock.withLock { model.confirmClosed(clock.now()) }
        credential.verifyKey()
        val resources = budget()
        check(resources.chargedBytes == 0L && resources.streamLeases == 0 && resources.sessionLeases == 0 && workers.alive() == 0) {
            "Control cleanup retained research resources"
        }
    }

    inner class Stream internal constructor(private val stream: DraftStream, val id: String) : AutoCloseable {
        private var connection: DraftStreamingTls? = null
        private var wsReader: ResearchWebSocketReader? = null
        private var wsWriter: ResearchWebSocketWriter? = null
        private val pair = createPair()
        val application = pair.first
        private val bridge = pair.second
        private val owned = DraftStreamingWorkers { failTransport() }
        private val released = AtomicBoolean(false)
        private val interruptFailed = AtomicBoolean(false)
        private val clientEofEffect = AtomicBoolean(false)
        private val gatewayEofEffect = AtomicBoolean(false)
        private val endSent = AtomicBoolean(false)
        private val closeClaimed = AtomicBoolean(false)
        private val closeSent = AtomicBoolean(false)
        val writeEntered = AtomicLong()
        val writeCompleted = AtomicLong()
        val writeInFlight = AtomicLong()
        val pendingClientBytes = AtomicLong()
        val pendingGatewayBytes = AtomicLong()
        val backpressureCount = AtomicLong()
        val applicationWritten = AtomicLong()
        val applicationRead = AtomicLong()
        val producerFinished = AtomicBoolean(false)
        val consumerFinished = AtomicBoolean(false)
        val uploadTailReleased = AtomicBoolean(false)
        private val responseDigest = MessageDigest.getInstance("SHA-256")
        private var responseHash: String? = null

        fun snapshot() = lock.withLock { stream.snapshot() }
        internal fun terminalLocked() = stream.snapshot().phase in TERMINAL

        internal fun start() {
            val upgrade = fixture.upgrade(credential, "/companion/v1/streams", token())
            connection = upgrade.first
            check(upgrade.second == 101) { "Stream upgrade refused" }
            wsReader = ResearchWebSocketReader(upgrade.first.socket.inputStream, EndpointRole.CLIENT, FRAME)
            wsWriter = ResearchWebSocketWriter(upgrade.first.socket.outputStream, EndpointRole.CLIENT, FRAME)
            val open = text("open")
            accepted(lock.withLock { stream.text(DraftDirection.CLIENT, open, clock.now()) })
            wsWriter!!.text(open)
            upgrade.first.socket.soTimeout = 5000
            val ready = wsReader!!.read()
            try {
                check(ready is ResearchWebSocketEvent.Text) { "Stream readiness was not text" }
                accepted(lock.withLock { stream.text(DraftDirection.GATEWAY, ready.copyBytes(), clock.now()).also(::effects) })
                check(snapshot().phase == DraftStreamPhase.OPEN) { "Stream readiness failed" }
            } finally { ready.release() }
            upgrade.first.socket.soTimeout = 0
            owned.launch("stream-reader") { readWebSocket() }
            owned.launch("local-reader") { readApplication() }
            owned.launch("tls-writer") { writeDirection(DraftDirection.CLIENT) }
            owned.launch("local-writer") { writeDirection(DraftDirection.GATEWAY) }
        }

        private fun text(type: String) = DraftWireCodec.encode(DraftMessage.Stream(type, id))
        private fun effects(result: DraftResult) {
            result.eofDirections.forEach {
                if (it == DraftDirection.CLIENT) clientEofEffect.set(true) else gatewayEofEffect.set(true)
            }
            changed.signalAll()
        }

        private fun offer(direction: DraftDirection, bytes: ByteArray) {
            val pending = if (direction == DraftDirection.CLIENT) pendingClientBytes else pendingGatewayBytes
            lock.withLock {
                while (!owned.stopping.get()) {
                    val result = stream.binary(direction, bytes, clock.now())
                    if (result.code == "ok") { pending.set(0); changed.signalAll(); return }
                    if (result.code != "backpressure") { pending.set(0); error("Research ingress rejected") }
                    if (pending.get() == 0L) backpressureCount.incrementAndGet()
                    pending.set(bytes.size.toLong())
                    changed.await(25, TimeUnit.MILLISECONDS)
                }
            }
        }

        private fun readApplication() {
            val chunk = ByteArray(FRAME)
            while (!owned.stopping.get()) {
                val count = bridge.inputStream.read(chunk)
                if (owned.stopping.get()) return
                if (count < 0) {
                    lock.withLock { accepted(stream.text(DraftDirection.CLIENT, text("end_write"), clock.now()).also(::effects)) }
                    return
                }
                check(count > 0)
                offer(DraftDirection.CLIENT, chunk.copyOf(count))
            }
        }

        private fun readWebSocket() {
            while (!owned.stopping.get()) {
                val event = wsReader!!.read()
                try {
                    when (event) {
                        is ResearchWebSocketEvent.Binary -> {
                            offer(DraftDirection.GATEWAY, event.copyBytes())
                            // Pull, do not process a later close ahead of this actual local writer.
                            lock.withLock {
                                while (!owned.stopping.get() && !terminalLocked() && stream.snapshot().gatewayBytes > 0) changed.await(25, TimeUnit.MILLISECONDS)
                            }
                        }
                        is ResearchWebSocketEvent.Text -> {
                            lock.withLock { stream.text(DraftDirection.GATEWAY, event.copyBytes(), clock.now()).also(::effects) }
                            if (snapshot().phase in TERMINAL) { interrupt(); return }
                            lock.withLock {
                                while (!owned.stopping.get() && stream.snapshot().gatewayEof && !bridge.isOutputShutdown) changed.await(25, TimeUnit.MILLISECONDS)
                            }
                        }
                        is ResearchWebSocketEvent.Ping -> wsWriter!!.pong(event.copyBytes())
                        is ResearchWebSocketEvent.Pong -> Unit
                        is ResearchWebSocketEvent.Close -> {
                            lock.withLock { stream.webSocketClosed(event.code ?: 1005, clock.now()); changed.signalAll() }
                            // A close cannot release bytes; close()/join still owns that decision.
                            sendClose()
                            if (snapshot().phase in TERMINAL) interrupt()
                            return
                        }
                    }
                } finally { event.release() }
            }
        }

        private fun writeDirection(direction: DraftDirection) {
            while (!owned.stopping.get()) {
                val bytes = lock.withLock {
                    if (terminalLocked() || stream.snapshot().webSocketClosed) return
                    val peek = stream.peek(direction, FRAME, clock.now())
                    accepted(peek.result)
                    peek.bytes()
                }
                if (bytes.isNotEmpty()) {
                    if (direction == DraftDirection.CLIENT) {
                        val entry = writeEntered.incrementAndGet()
                        writeInFlight.set(entry)
                        try { wsWriter!!.binary(bytes); writeCompleted.set(entry) }
                        finally { writeInFlight.set(0) }
                    } else {
                        bridge.outputStream.write(bytes)
                        bridge.outputStream.flush()
                    }
                    lock.withLock {
                        if (!terminalLocked()) accepted(stream.drain(direction, bytes.size.toLong(), clock.now()).also(::effects))
                        changed.signalAll()
                    }
                    continue
                }
                if (direction == DraftDirection.CLIENT && clientEofEffect.get() && !endSent.get()) {
                    wsWriter!!.text(text("end_write"))
                    // Only this directional writer owns END_WRITE. Publish after actual flush.
                    endSent.set(true)
                }
                if (direction == DraftDirection.GATEWAY && gatewayEofEffect.compareAndSet(true, false)) {
                    bridge.shutdownOutput()
                    lock.withLock { changed.signalAll() }
                }
                maybeClose()
                if ((direction == DraftDirection.CLIENT && endSent.get()) ||
                    (direction == DraftDirection.GATEWAY && bridge.isOutputShutdown)) return
                lock.withLock { if (!owned.stopping.get()) changed.await(25, TimeUnit.MILLISECONDS) }
            }
        }

        private fun maybeClose() {
            val closing = lock.withLock { stream.snapshot().phase == DraftStreamPhase.CLOSING }
            if (closing && endSent.get() && bridge.isOutputShutdown) sendClose()
        }

        private fun sendClose() {
            if (closeClaimed.compareAndSet(false, true)) {
                wsWriter!!.close(byteArrayOf(3, -24))
                closeSent.set(true)
            }
        }

        fun produce(bodyLength: Int, gated: Boolean = false) {
            check(bodyLength in 1..BURST)
            owned.launch("application-producer") {
                val header = uploadHeader(bodyLength)
                application.outputStream.write(header)
                applicationWritten.addAndGet(header.size.toLong())
                val buffer = ByteArray(FRAME)
                var offset = 0
                while (offset < bodyLength && !owned.stopping.get()) {
                    if (gated && offset == FRAME) {
                        while (!uploadTailReleased.get() && !owned.stopping.get()) Thread.sleep(10)
                        if (owned.stopping.get()) return@launch
                    }
                    val count = minOf(FRAME, bodyLength - offset)
                    repeat(count) { index -> buffer[index] = ((offset + index) % 251).toByte() }
                    application.outputStream.write(buffer, 0, count)
                    applicationWritten.addAndGet(count.toLong())
                    offset += count
                }
                if (!owned.stopping.get()) { application.outputStream.flush(); application.shutdownOutput(); producerFinished.set(true) }
            }
        }

        fun consume() {
            owned.launch("application-consumer") {
                val bytes = ByteArray(FRAME)
                while (!owned.stopping.get()) {
                    val count = application.inputStream.read(bytes)
                    if (count < 0) {
                        responseHash = hex(responseDigest.digest())
                        consumerFinished.set(true)
                        return@launch
                    }
                    responseDigest.update(bytes, 0, count)
                    applicationRead.addAndGet(count.toLong())
                    check(applicationRead.get() <= expectedResponseBytes()) { "Response exceeded fixed bound" }
                }
            }
        }

        fun observedBlockedWriter(retainPressureFailure: Boolean = false) {
            var candidate = 0L
            var since = 0L
            var longestCandidateMillis = 0L
            var seenPredicateMask = 0
            val waitStartUtc = System.currentTimeMillis()
            val waitStartElapsed = (System.nanoTime() - readyAtNanos) / 1_000_000
            try {
                draftAwait("observed TLS writer and retained ingress", 20000) {
                    val entry = writeInFlight.get()
                    val state = snapshot()
                    val completed = writeCompleted.get()
                    val pending = pendingClientBytes.get()
                    val observed = entry != 0L && completed < entry && state.chargedBytes > 0 &&
                        pending in 1..FRAME.toLong() && state.chargedBytes <= 8192 && state.chargedFrames <= 4
                    if (entry != 0L && completed < entry) seenPredicateMask = seenPredicateMask or 1
                    if (pending in 1..FRAME.toLong()) seenPredicateMask = seenPredicateMask or 2
                    if (state.chargedBytes in 1..8192 && state.chargedFrames in 1..4) seenPredicateMask = seenPredicateMask or 4
                    if (!observed || candidate != entry) { candidate = entry; since = System.nanoTime() }
                    if (observed) longestCandidateMillis = maxOf(longestCandidateMillis, (System.nanoTime() - since) / 1_000_000)
                    observed && System.nanoTime() - since >= 250_000_000
                }
            } catch (failure: IllegalStateException) {
                if (retainPressureFailure) {
                    try {
                        val failureUtc = System.currentTimeMillis()
                        val failureElapsed = (System.nanoTime() - readyAtNanos) / 1_000_000
                        val facts = lock.withLock {
                            // Read monotonically increasing entered last, so sampled IDs cannot exceed it.
                            val inFlight = writeInFlight.get()
                            val completed = writeCompleted.get()
                            val entered = writeEntered.get()
                            pressureValues(waitStartUtc, waitStartElapsed, failureUtc, failureElapsed, expiresAtMillis,
                                model.snapshot(), stream.snapshot(), entered, completed, inFlight, pendingClientBytes.get(),
                                applicationWritten.get(), producerFinished.get(), owned.stopping.get(), owned.failure.get() != null,
                                deadlineTicks.get(), expiredDeadlineTicks.get(), longestCandidateMillis, seenPredicateMask)
                        }
                        // Binder reporting owns no model lock and performs no additional peer/model operation.
                        val bundle = Bundle().apply { facts.forEach { (key, value) -> putString(key, value) } }
                        InstrumentationRegistry.getInstrumentation().sendStatus(3, bundle)
                    } catch (_: Exception) { /* A reporting failure cannot replace the original failed wait. */ }
                }
                throw failure
            }
        }

        /** Only these fixed negative cases bypass the established framing writer. */
        fun adversarial(kind: String) {
            when (kind) {
                "json" -> wsWriter!!.text("{\"protocolVersion\":1,\"type\":\"open\",\"streamId\":\"bad\",\"extra\":true}".toByteArray())
                "header" -> connection!!.socket.outputStream.write(byteArrayOf(0xc2.toByte(), 0x80.toByte(), 0, 0, 0, 0))
                "oversized" -> connection!!.socket.outputStream.write(byteArrayOf(0x82.toByte(), 0xfe.toByte(), 0x10, 0x01))
                else -> error("Unknown fixed negative case")
            }
            connection!!.socket.outputStream.flush()
        }

        private fun failTransport() {
            interrupt()
        }

        fun interrupt() {
            owned.stopping.set(true)
            connection?.interrupt() // Interrupt Conscrypt write before any potentially blocking TLS close.
            try { application.close() } catch (_: Exception) { interruptFailed.set(true) }
            try { bridge.close() } catch (_: Exception) { interruptFailed.set(true) }
            lock.withLock {
                if (connection?.raw?.isClosed == true && !stream.snapshot().webSocketClosed) stream.webSocketClosed(1006, clock.now())
                changed.signalAll()
            }
        }

        fun finishNormally(timeoutMillis: Long = 15000) {
            draftAwait("both real directional EOFs and close1000", timeoutMillis) {
                val state = snapshot()
                state.phase == DraftStreamPhase.CLOSING && state.webSocketClosed && state.clientEof && state.gatewayEof &&
                    state.chargedBytes == 0L && closeSent.get() && producerFinished.get() && consumerFinished.get()
            }
            check(responseHash == expectedResponseHash()) { "Fixed response ordering or digest mismatch" }
            check(applicationRead.get() == expectedResponseBytes()) { "Fixed response length mismatch" }
            check(owned.failure.get() == null) { "Normal stream worker failed" }
            close()
            check(snapshot().phase == DraftStreamPhase.COMPLETE) { "Normal stream did not complete" }
        }

        override fun close() {
            if (!released.compareAndSet(false, true)) return
            var cleanupFailed = false
            fun attempt(operation: () -> Unit) {
                try { operation() } catch (_: Exception) { cleanupFailed = true } catch (_: AssertionError) { cleanupFailed = true }
            }
            attempt { interrupt() }
            attempt { connection?.close() }
            attempt { owned.joinAll() }
            check(!cleanupFailed && !interruptFailed.get()) { "Stream resource cleanup failed" }
            // The only release call follows actual local sockets/TLS close and every owned join.
            pendingClientBytes.set(0); pendingGatewayBytes.set(0)
            lock.withLock { stream.confirmClosed(clock.now()); changed.signalAll() }
            check(snapshot().resourceClosureConfirmed && !snapshot().streamLease && snapshot().chargedBytes == 0L &&
                owned.alive() == 0 && application.isClosed && bridge.isClosed) { "Stream cleanup retained resources" }
        }
    }

    companion object {
        const val FRAME = 4096
        const val UPLOAD = 16421
        const val BURST = 33554432
        const val RESPONSE = 32787
        val CAPABILITIES = listOf("tcp-http", "tcp-https-connect")
        val LIMITS = DraftLimits(FRAME, 8192, 16384, 2, 4, 64)
        private val TERMINAL = setOf(DraftStreamPhase.COMPLETE, DraftStreamPhase.CANCELLED, DraftStreamPhase.FAILED)
        /** Explicit primitive serialization excludes IDs, credentials, payloads and worker error text. */
        private fun pressureValues(waitStartUtc: Long, waitStartElapsed: Long, failureUtc: Long, failureElapsed: Long,
            expiresUtc: Long, control: DraftSessionSnapshot, stream: DraftStreamSnapshot,
            entered: Long, completed: Long, inFlight: Long, pending: Long, applicationWritten: Long,
            producerFinished: Boolean, stopping: Boolean, workerFailed: Boolean, ticks: Long, expiryTicks: Long,
            longestCandidate: Long, seenMask: Int): Map<String, String> = Collections.unmodifiableMap(linkedMapOf(
            "draftPressureVersion" to "2",
            "draftPressureWaitStartUtcMillis" to waitStartUtc.toString(),
            "draftPressureWaitStartElapsedMillis" to waitStartElapsed.toString(),
            "draftPressureFailureUtcMillis" to failureUtc.toString(),
            "draftPressureFailureElapsedMillis" to failureElapsed.toString(),
            "draftPressureExpiresUtcMillis" to expiresUtc.toString(),
            "draftPressureControlPhase" to control.phase.name.lowercase(),
            "draftPressureControlCause" to (control.cause ?: "null"),
            "draftPressureStreamPhase" to stream.phase.name.lowercase(),
            "draftPressureStreamCause" to (stream.cause ?: "null"),
            "draftPressureWriteEntered" to entered.toString(),
            "draftPressureWriteCompleted" to completed.toString(),
            "draftPressureWriteInFlight" to inFlight.toString(),
            "draftPressureChargedBytes" to stream.chargedBytes.toString(),
            "draftPressureChargedFrames" to stream.chargedFrames.toString(),
            "draftPressurePendingClientBytes" to pending.toString(),
            "draftPressureApplicationWritten" to applicationWritten.toString(),
            "draftPressureProducerFinished" to producerFinished.toString(),
            "draftPressureOwnedStopping" to stopping.toString(),
            "draftPressureWorkerFailed" to workerFailed.toString(),
            "draftPressureLocalTicks" to ticks.toString(),
            "draftPressureLocalExpiryTicks" to expiryTicks.toString(),
            "draftPressureLongestCandidateMillis" to longestCandidate.toString(),
            "draftPressureSeenPredicateMask" to seenMask.toString(),
        ))
        private fun createPair(): Pair<Socket, Socket> {
            val acceptor = ServerSocket()
            val application = Socket()
            var bridge: Socket? = null
            try {
                acceptor.reuseAddress = false
                acceptor.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 1)
                acceptor.soTimeout = 5000
                // Let the local seam feed the TLS boundary, where unfinished writes prove pressure.
                application.sendBufferSize = 64 * 1024; application.receiveBufferSize = 64 * 1024; application.tcpNoDelay = true
                application.connect(acceptor.localSocketAddress, 5000)
                application.soTimeout = 0
                bridge = acceptor.accept().apply { sendBufferSize = 64 * 1024; receiveBufferSize = 64 * 1024; tcpNoDelay = true }
                check(bridge.remoteSocketAddress == application.localSocketAddress && bridge.localSocketAddress == application.remoteSocketAddress) {
                    "Local research socket endpoints did not match"
                }
                return application to bridge
            } catch (failure: Exception) { application.close(); bridge?.close(); throw failure }
            finally { acceptor.close(); check(acceptor.isClosed) { "Local acceptor did not close" } }
        }
        private fun accepted(result: DraftResult) { check(result.code == "ok") { "Draft model rejected research event" } }
        fun uploadHeader(length: Int) = ("POST http://fixture.invalid/research HTTP/1.1\r\nHost: fixture.invalid\r\n" +
            "Content-Length: $length\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)
        private fun responseHeader() = "HTTP/1.1 200 OK\r\nContent-Length: $RESPONSE\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
        fun expectedResponseBytes() = responseHeader().size.toLong() + RESPONSE
        fun expectedResponseHash(): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(responseHeader())
            val buffer = ByteArray(FRAME)
            var offset = 0
            while (offset < RESPONSE) {
                val count = minOf(FRAME, RESPONSE - offset)
                repeat(count) { buffer[it] = (((offset + it) * 7) % 253).toByte() }
                digest.update(buffer, 0, count); offset += count
            }
            return hex(digest.digest())
        }
        fun expectedUploadHash(length: Int): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(uploadHeader(length))
            val buffer = ByteArray(FRAME)
            var offset = 0
            while (offset < length) {
                val count = minOf(FRAME, length - offset)
                repeat(count) { buffer[it] = ((offset + it) % 251).toByte() }
                digest.update(buffer, 0, count); offset += count
            }
            return hex(digest.digest())
        }
        private fun hex(value: ByteArray) = value.joinToString("") { "%02x".format(it) }
    }
}
