package com.httpfreekit.capture.transport

import com.httpfreekit.capture.CaptureException
import com.httpfreekit.capture.CaptureSocketGuard
import com.httpfreekit.capture.CaptureTcpConnection
import com.httpfreekit.capture.InterceptedTcpFactory
import com.httpfreekit.capture.ProtectedEgressFactory
import com.httpfreekit.protocol.DraftBudgetPool
import com.httpfreekit.protocol.DraftChannel
import com.httpfreekit.protocol.DraftClock
import com.httpfreekit.protocol.DraftControlPhase
import com.httpfreekit.protocol.DraftDecodeResult
import com.httpfreekit.protocol.DraftDirection
import com.httpfreekit.protocol.DraftLimits
import com.httpfreekit.protocol.DraftMessage
import com.httpfreekit.protocol.DraftSession
import com.httpfreekit.protocol.DraftStream
import com.httpfreekit.protocol.DraftStreamPhase
import com.httpfreekit.protocol.DraftWireCodec
import com.httpfreekit.protocol.HttpOriginConnect
import com.httpfreekit.security.EnrolledCredentialRecord
import com.httpfreekit.security.EnrolledSessionReadyBound
import com.httpfreekit.security.GatewayTlsConnectionFactory
import com.httpfreekit.security.LoadedEnrolledCredential
import com.httpfreekit.transport.websocket.OwnedGatewayWebSocket
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import kotlin.concurrent.withLock

/** Internal software-key test seam. Production construction always requires a validated saved credential. */
internal class CaptureTransportConfiguration(
    val record: EnrolledCredentialRecord,
    val keyManager: X509ExtendedKeyManager,
    val requireReady: (expiresAtMillis: Long, observedUtcMillis: Long) -> Unit,
    val pool: DraftBudgetPool = EnrolledCaptureTcpFactory.sharedPool,
) {
    override fun toString() = "CaptureTransportConfiguration([REDACTED])"
}

class CaptureTransportSnapshot internal constructor(
    val started: Boolean, val admissionClosed: Boolean, val closed: Boolean, val failureCode: String?,
    val pendingOpens: Int, val pendingCalls: Int, val retainedTransports: Int, val liveWorkers: Int,
    val sessionLease: Boolean, val streamLeases: Int, val chargedBytes: Long,
    val pendingIngressBytes: Long, val backendOutputBytes: Long, val backendIncomingBytes: Long,
) {
    override fun toString() = "CaptureTransportSnapshot(closed=$closed, failureCode=$failureCode)"
}

/** Authenticated, fail-closed TCP80/443 adapter. Construction performs no I/O and starts no workers. */
class EnrolledCaptureTcpFactory internal constructor(
    private val configuration: CaptureTransportConfiguration,
    gateway: InetSocketAddress,
    private val guard: CaptureSocketGuard,
    requiredCapabilities: Set<String> = IMPLEMENTED,
) : InterceptedTcpFactory {
    constructor(loaded: LoadedEnrolledCredential, gateway: InetSocketAddress, guard: CaptureSocketGuard,
        requiredCapabilities: Set<String> = IMPLEMENTED) : this(
        CaptureTransportConfiguration(loaded.record, loaded.clientKeyManager, { expiry, utc ->
            EnrolledSessionReadyBound(loaded, utc + 1_800_000).requireReady(expiry, utc)
        }), gateway, guard, requiredCapabilities)

    private val endpoint = gateway.let {
        if (it.isUnresolved || it.port !in 1..65535 || it.address.address.size !in setOf(4, 16)) invalid()
        InetSocketAddress(InetAddress.getByAddress(it.address.address.copyOf()), it.port)
    }
    private val required = requiredCapabilities.toSet().also { if (it.isEmpty() || !IMPLEMENTED.containsAll(it)) invalid() }
    private val record = configuration.record
    private val device = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256").digest(record.clientCertificateChain.first().publicKey.encoded))
    private val origin = System.nanoTime()
    private val state = ReentrantLock()
    private val changed = state.newCondition()
    private val teardown = ReentrantLock()
    private val transports = LinkedHashSet<Transport>()
    private val opens = LinkedHashSet<OpenCall>()
    private var model: DraftSession? = null
    private var control: Transport? = null
    private var limits = DraftLimits()
    private var negotiated = emptySet<String>()
    private var admissionClosed = false
    private var intentionalClosing = false
    private var workersStopping = false
    private var closed = false
    private var failureCode: String? = null
    private var ticker: Thread? = null
    private var heartbeat: Thread? = null
    private var pendingCalls = 0

    private class OpenCall(val deadline: Long) { var transport: Transport? = null }

    override fun open(originalAddress: InetAddress, originalPort: Int): CaptureTcpConnection {
        val bytes = originalAddress.address.copyOf()
        if (bytes.size !in setOf(4, 16) || originalPort !in setOf(80, 443)) invalid()
        val call = OpenCall(System.nanoTime() + OPEN_NANOS)
        var selected: Transport? = null
        try {
            val parent = state.withLock {
                requireAdmission()
                if (opens.size + transports.count { it.stream != null } >= 31) throw CaptureException("capacity")
                opens.add(call)
                if (ticker == null) ticker = worker("capture-transport-deadline", ::deadlineLoop).also { it.start() }
                control ?: run {
                    model = DraftSession(device, record.desktopId, IMPLEMENTED, configuration.pool, clock())
                    Transport(null, null, null, call.deadline).also { control = it; transports.add(it); it.launch() }
                }
            }
            awaitReady(parent, call.deadline)
            selected = state.withLock {
                requireAdmission()
                if (originalPort == 80 && HttpOriginConnect.CAPABILITY !in negotiated || originalPort == 443 && HTTPS !in negotiated) invalid()
                if (transports.size >= 32) throw CaptureException("capacity")
                val token = model!!.sessionHeader() ?: throw CaptureException("closed")
                val allocation = model!!.allocateStream(device, token, clock())
                if (allocation.result.code != "ok") throw CaptureException(if (allocation.result.code == "stream_limit") "capacity" else "connect_failed")
                Transport(allocation.stream!!, bytes, originalPort, call.deadline, token).also {
                    transports.add(it); call.transport = it; it.launch()
                }
            }
            awaitReady(selected, call.deadline)
            return selected.connection
        } catch (failure: CaptureException) {
            selected?.stop()
            if (failure.code !in setOf("invalid_request", "capacity")) failFactory(failure.code)
            throw failure
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            selected?.stop(); failFactory("connect_failed"); throw CaptureException("connect_failed")
        } finally { state.withLock { opens.remove(call); changed.signalAll() } }
    }

    private fun awaitReady(transport: Transport, deadline: Long) = state.withLock {
        while (!transport.ready && !transport.stopping && !admissionClosed) waitUntil(deadline)
        if (System.nanoTime() - deadline >= 0 || !transport.ready || transport.stopping || admissionClosed) {
            throw CaptureException(transport.failure?.takeIf { it in CAPTURE_CODES } ?: "connect_failed")
        }
    }

    private fun requireAdmission() { if (admissionClosed || closed) throw CaptureException("closed") }
    private fun clock() = DraftClock(System.currentTimeMillis(), TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - origin))
    private fun waitUntil(deadline: Long) {
        val remaining = deadline - System.nanoTime()
        if (remaining <= 0) throw CaptureException("connect_failed")
        changed.awaitNanos(minOf(remaining, TICK_NANOS))
    }

    private fun failFactory(code: String) {
        val current = state.withLock {
            val prior = model?.snapshot()?.cause
            if (failureCode == null && !(intentionalClosing && prior in setOf(null, "cancelled"))) failureCode = prior ?: code
            admissionClosed = true
            model?.webSocketClosed(1006, clock())
            changed.signalAll(); transports.toList()
        }
        current.forEach { it.stop(cancel = false) }
    }

    /** Seal and interrupt without joining; callbacks must still arrange actual [close] afterward. */
    fun interrupt() = interruptOwned(reportClosed = true, stopWorkers = false)

    private fun interruptOwned(reportClosed: Boolean, stopWorkers: Boolean) {
        val current = state.withLock {
            admissionClosed = true
            intentionalClosing = true
            if (stopWorkers) workersStopping = true
            model?.tick(clock())
            val prior = model?.snapshot()?.cause
            if (failureCode == null && prior != null && prior != "cancelled") failureCode = prior
            if (failureCode == null && control?.stopping == false && control?.backend?.snapshot()?.failureCode != null) failureCode = "connect_failed"
            if (failureCode == null && reportClosed) failureCode = "closed"
            model?.cancelLocally(clock())
            changed.signalAll(); transports.toList()
        }
        current.forEach { it.stop(consumerInterrupt = true) }
    }

    private fun deadlineLoop() {
        try {
            while (!state.withLock { workersStopping }) {
                val stop = state.withLock {
                    model?.tick(clock())
                    val terminal = model?.snapshot()?.phase in setOf(DraftControlPhase.CLOSED, DraftControlPhase.FAILED)
                    if (terminal) {
                        admissionClosed = true
                        if (failureCode == null && !intentionalClosing) failureCode = model?.snapshot()?.cause
                    }
                    val now = System.nanoTime()
                    transports.filter { transport ->
                        terminal || !transport.ready && now - transport.openDeadline >= 0 ||
                            transport.stream?.snapshot()?.phase in TERMINAL_STREAMS
                    }.also { changed.signalAll() }
                }
                stop.forEach { it.stop(cancel = false) }
                state.withLock { transports.toList() }.forEach { it.reap(System.nanoTime()) }
                Thread.sleep(100)
            }
        } catch (_: InterruptedException) { /* Explicit close owns and joins this worker. */ }
        catch (_: Exception) { failFactory("connect_failed") }
    }

    private fun heartbeatLoop(parent: Transport) {
        var due = System.nanoTime() + HEARTBEAT_NANOS
        try {
            while (true) {
                state.withLock {
                    while (!admissionClosed && !workersStopping && !parent.stopping && System.nanoTime() - due < 0) {
                        changed.awaitNanos(maxOf(1, minOf(TICK_NANOS, due - System.nanoTime())))
                    }
                    if (admissionClosed || workersStopping || parent.stopping) return
                }
                parent.backend!!.writePing(System.nanoTime() + HEARTBEAT_NANOS)
                state.withLock {
                    if (model!!.pingPong(DraftDirection.CLIENT, clock()).code != "ok") throw CaptureException("closed")
                }
                due = System.nanoTime() + HEARTBEAT_NANOS
            }
        } catch (_: Exception) { if (!state.withLock { admissionClosed || workersStopping }) failFactory("connect_failed") }
    }

    override fun close() {
        val deadline = System.nanoTime() + CLEANUP_NANOS
        interruptOwned(reportClosed = false, stopWorkers = true)
        val acquired = try { teardown.tryLock(maxOf(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); throw CaptureException("cleanup_failed") }
        if (!acquired) throw CaptureException("cleanup_failed")
        try {
            val current = state.withLock {
                if (closed) return
                admissionClosed = true; workersStopping = true
                model?.cancelLocally(clock()); changed.signalAll(); transports.toList()
            }
            current.forEach { it.stop(retry = true) }
            ticker?.interrupt()
            val workers = state.withLock { listOfNotNull(ticker, heartbeat) }
            workers.forEach { join(it, deadline) }
            while (true) {
                state.withLock { transports.toList() }.forEach { it.reap(deadline) }
                state.withLock {
                    if (opens.isEmpty() && pendingCalls == 0 && transports.isEmpty() && workers.none { it.isAlive }) { closed = true; return }
                    val remaining = deadline - System.nanoTime()
                    if (remaining <= 0) throw CaptureException("cleanup_failed")
                    changed.awaitNanos(minOf(remaining, TICK_NANOS))
                }
            }
        } catch (_: InterruptedException) { Thread.currentThread().interrupt(); throw CaptureException("cleanup_failed") }
        finally { teardown.unlock() }
    }

    fun snapshot(): CaptureTransportSnapshot = state.withLock {
        val session = model?.snapshot()
        val backends = transports.mapNotNull { it.backend?.snapshot() }
        CaptureTransportSnapshot(control != null, admissionClosed, closed, failureCode, opens.size, pendingCalls,
            transports.size, listOfNotNull(ticker, heartbeat).count { it.isAlive } + transports.count { it.owner?.isAlive == true } +
                backends.sumOf { (if (it.readerAlive) 1 else 0) + (if (it.writerAlive) 1 else 0) },
            session?.sessionLease == true, session?.streamLeases ?: 0, session?.chargedBytes ?: 0,
            transports.sumOf { it.pendingIngress.toLong() }, backends.sumOf { it.pendingOutputBytes }, backends.sumOf { it.incomingBytes })
    }
    override fun toString() = "EnrolledCaptureTcpFactory([REDACTED])"

    private inner class Transport(
        val stream: DraftStream?, private val address: ByteArray?, private val port: Int?,
        val openDeadline: Long, private val token: String? = null,
    ) {
        @Volatile var raw: Socket? = null
        @Volatile var tls: SSLSocket? = null
        @Volatile var backend: OwnedGatewayWebSocket? = null
        @Volatile var stopping = false
        var ready = false
        var released = false
        var failure: String? = null
        var pendingIngress = 0
        var calls = 0
        var owner: Thread? = null
        private var cleanupGeneration = 0L
        private var unbackedClosed = false
        private var outputEnded = false
        private var outputEnding = false
        private var closeSent = false
        private var frontendClosed = false
        private var consumerInterrupted = false
        private val ioWriter = ReentrantLock()
        private val cleanup = ReentrantLock()
        private var id: String? = null
        private val ack = HttpOriginConnect.Acknowledgement()
        private val egress = ProtectedEgressFactory(object : CaptureSocketGuard {
            override fun protect(socket: Socket): Boolean {
                raw = socket
                if (stopping || System.nanoTime() - openDeadline >= 0) { socket.close(); return false }
                val accepted = guard.protect(socket)
                return accepted && !stopping && System.nanoTime() - openDeadline < 0
            }
            override fun bind(socket: Socket) {
                if (stopping || System.nanoTime() - openDeadline >= 0) throw CaptureException("closed")
                guard.bind(socket)
                if (stopping || System.nanoTime() - openDeadline >= 0) throw CaptureException("closed")
            }
            override fun protect(socket: DatagramSocket) = false
            override fun bind(socket: DatagramSocket): Unit = throw CaptureException("invalid_request")
        })
        val connection = Connection()

        fun launch() { owner = worker(if (stream == null) "capture-control-read" else "capture-stream-read", ::run).also { it.start() } }

        private fun run() {
            try {
                // The retained worker owns potentially blocking entropy acquisition too.
                if (stream != null) id = UUID.randomUUID().toString().replace("-", "")
                val remaining = remainingMillis(openDeadline)
                val factory = GatewayTlsConnectionFactory(record.gatewayCertificate, record.gatewaySpkiSha256, record.logicalServerName,
                    remaining, remaining, rawSocketFactory = egress.rawSocketFactory(), clientKeyManager = configuration.keyManager)
                tls = factory.connect(endpoint)
                if (stopping) throw CaptureException("closed")
                val ws = OwnedGatewayWebSocket(tls!!, ::interruptRaw, "${record.logicalServerName}:${endpoint.port}",
                    if (stream == null) "/companion/v1/control" else "/companion/v1/streams", token)
                backend = ws
                if (stopping) { ws.interrupt(); throw CaptureException("closed") }
                ws.start(openDeadline)
                if (stream == null) runControl(ws) else runStream(ws)
            } catch (error: CaptureException) { if (!stopping) failed(error.code) }
            catch (_: Exception) { if (!stopping) failed("connect_failed") }
            finally {
                if (backend == null) closeUnbacked()
                state.withLock { pendingIngress = 0; changed.signalAll() }
            }
        }

        private fun runControl(ws: OwnedGatewayWebSocket) {
            val hello = DraftWireCodec.encode(DraftMessage.Hello(IMPLEMENTED, required))
            state.withLock { if (model!!.text(DraftDirection.CLIENT, hello, clock()).code != "ok") throw CaptureException("connect_failed") }
            ws.writeText(hello.toString(Charsets.UTF_8), openDeadline)
            while (!stopping) {
                if (!state.withLock { ready }) remainingMillis(openDeadline)
                when (val message = ws.pollIncoming(100)) {
                    null -> Unit
                    is OwnedGatewayWebSocket.Incoming.Text -> {
                        val bytes = message.text().toByteArray(Charsets.UTF_8)
                        state.withLock {
                            if (!ready) {
                                val decoded = DraftWireCodec.decode(DraftChannel.CONTROL, bytes)
                                val accepted = (decoded as? DraftDecodeResult.Accepted)?.message
                                val observed = clock()
                                if (accepted is DraftMessage.SessionReady) configuration.requireReady(accepted.expiresAt.toEpochMilli(), observed.utcMillis)
                                if (System.nanoTime() - openDeadline >= 0 || admissionClosed) throw CaptureException("connect_failed")
                                if (model!!.text(DraftDirection.GATEWAY, bytes, observed).code != "ok" || accepted !is DraftMessage.SessionReady) throw CaptureException("connect_failed")
                                limits = accepted.limits; negotiated = accepted.capabilities.toSet(); ready = true
                                heartbeat = worker("capture-control-heartbeat") { heartbeatLoop(this) }.also { it.start() }
                                changed.signalAll()
                            } else if (model!!.text(DraftDirection.GATEWAY, bytes, clock()).code != "ok" || model!!.snapshot().phase != DraftControlPhase.ACTIVE) {
                                throw CaptureException("connect_failed")
                            }
                        }
                    }
                    is OwnedGatewayWebSocket.Incoming.Ping, is OwnedGatewayWebSocket.Incoming.Pong -> state.withLock {
                        if (model!!.pingPong(DraftDirection.GATEWAY, clock()).code != "ok") throw CaptureException("connect_failed")
                    }
                    is OwnedGatewayWebSocket.Incoming.Closed -> {
                        state.withLock { model!!.webSocketClosed(if (message.normal) 1000 else 1006, clock()) }
                        throw CaptureException("connect_failed")
                    }
                    else -> throw CaptureException("connect_failed")
                }
            }
        }

        private fun runStream(ws: OwnedGatewayWebSocket) {
            val open = DraftWireCodec.encode(DraftMessage.Stream("open", id!!, proxyMode = if (port == 80) HttpOriginConnect.PROXY_MODE else null))
            state.withLock { accepted(stream!!.text(DraftDirection.CLIENT, open, clock()).code) }
            ws.writeText(open.toString(Charsets.UTF_8), openDeadline)
            var streamReady = false
            while (!stopping) {
                if (!ready) remainingMillis(openDeadline)
                when (val message = ws.pollIncoming(100)) {
                    null -> Unit
                    is OwnedGatewayWebSocket.Incoming.Text -> {
                        state.withLock {
                            accepted(stream!!.text(DraftDirection.GATEWAY, message.text().toByteArray(Charsets.UTF_8), clock()).code)
                            if (stream.snapshot().phase in TERMINAL_STREAMS) throw CaptureException("connect_failed")
                            changed.signalAll()
                        }
                        if (!streamReady) {
                            streamReady = true
                            send(if (port == 80) HttpOriginConnect.preface(address!!) else httpsPreface(address!!), openDeadline)
                        }
                        consumeAcknowledgement()
                        maybeClose()
                    }
                    is OwnedGatewayWebSocket.Incoming.Binary -> {
                        val bytes = message.copyBytes()
                        state.withLock { pendingIngress = bytes.size }
                        try {
                            state.withLock {
                                if (!streamReady || bytes.isEmpty() || bytes.size > limits.maxFrameBytes) throw CaptureException("connect_failed")
                                awaitHeadroom(bytes.size, if (ready) System.nanoTime() + IO_NANOS else openDeadline)
                                accepted(stream!!.binary(DraftDirection.GATEWAY, bytes, clock()).code)
                                changed.signalAll()
                            }
                        } finally { state.withLock { pendingIngress = 0; changed.signalAll() } }
                        consumeAcknowledgement()
                    }
                    is OwnedGatewayWebSocket.Incoming.Closed -> {
                        val good = state.withLock {
                            // Own the real received Close while application bytes remain queued.
                            // Applying it early would forbid the model drain required for CLOSING.
                            try {
                                while (message.normal && stream!!.snapshot().phase != DraftStreamPhase.CLOSING) {
                                    usable()
                                    val current = stream.snapshot()
                                    if (!current.gatewaySealed || !current.clientSealed && !outputEnding) throw CaptureException("connect_failed")
                                    changed.awaitNanos(TICK_NANOS)
                                }
                            } finally {
                                stream!!.webSocketClosed(if (message.normal) 1000 else 1006, clock())
                                changed.signalAll()
                            }
                            ready && message.normal && stream.snapshot().phase == DraftStreamPhase.CLOSING
                        }
                        if (!good) throw CaptureException("connect_failed")
                        return
                    }
                    else -> Unit // RFC control frames do not advance stream application progress.
                }
            }
        }

        private fun consumeAcknowledgement(): Unit = state.withLock {
            if (ready) return
            while (!ack.complete && stream!!.snapshot().gatewayBytes > 0) {
                val bytes = stream.peek(DraftDirection.GATEWAY, minOf(8192, limits.maxFrameBytes), clock())
                accepted(bytes.result.code)
                val consumed = ack.accept(bytes.bytes())
                accepted(stream.drain(DraftDirection.GATEWAY, consumed.toLong(), clock()).code)
            }
            if (ack.complete) {
                if (stopping || admissionClosed || System.nanoTime() - openDeadline >= 0) throw CaptureException("connect_failed")
                ready = true; changed.signalAll()
            } else if (stream!!.snapshot().gatewayEof) throw CaptureException("connect_failed")
        }

        private fun awaitHeadroom(size: Int, deadline: Long) {
            while (true) {
                usable()
                val current = stream!!.snapshot(); val session = model!!.snapshot(); val global = configuration.pool.snapshot()
                if (current.chargedFrames < limits.maxQueuedFramesPerStream && size <= limits.maxQueuedBytesPerStream - current.chargedBytes &&
                    size <= limits.maxQueuedBytesPerDevice - session.chargedBytes && size <= configuration.pool.maxBytes - global.chargedBytes) return
                waitUntil(deadline)
            }
        }

        private fun send(bytes: ByteArray, deadline: Long) {
            var offset = 0
            while (offset < bytes.size) {
                val size = state.withLock { minOf(8192, limits.maxFrameBytes, bytes.size - offset) }
                val chunk = bytes.copyOfRange(offset, offset + size)
                state.withLock { awaitHeadroom(size, deadline); accepted(stream!!.binary(DraftDirection.CLIENT, chunk, clock()).code) }
                backend!!.writeBinary(chunk, deadline)
                state.withLock { accepted(stream!!.drain(DraftDirection.CLIENT, size.toLong(), clock()).code); changed.signalAll() }
                offset += size
            }
        }

        private fun maybeClose() {
            val request = state.withLock {
                if (!stopping && !closeSent && outputEnded && stream!!.snapshot().phase == DraftStreamPhase.CLOSING) { closeSent = true; true } else false
            }
            if (request) backend?.requestClose()
        }

        private fun usable() {
            if (stopping || admissionClosed || released || stream!!.snapshot().phase in TERMINAL_STREAMS) throw CaptureException("closed")
            model!!.tick(clock())
            if (model!!.snapshot().phase != DraftControlPhase.ACTIVE || stream.snapshot().phase in TERMINAL_STREAMS) throw CaptureException("closed")
        }

        private fun failed(code: String) {
            state.withLock {
                if (failure == null) failure = code
                stream?.webSocketClosed(1006, clock()); changed.signalAll()
            }
            if (stream == null) failFactory(code) else stop(cancel = false)
        }

        fun stop(cancel: Boolean = true, retry: Boolean = false, consumerInterrupt: Boolean = false) {
            val retryClose = state.withLock {
                val first = !stopping
                if (consumerInterrupt) consumerInterrupted = true
                stopping = true
                if (cancel) stream?.cancelLocally(clock())
                if (first || retry) cleanupGeneration++
                changed.signalAll(); first || retry
            }
            if (retryClose) {
                try { backend?.interrupt() ?: interruptRaw() } catch (_: Exception) { state.withLock { if (failure == null) failure = "cleanup_failed" } }
            }
        }

        private fun interruptRaw() { raw?.close() }

        private fun closeUnbacked() {
            while (true) {
                val generation = state.withLock { cleanupGeneration }
                try {
                    interruptRaw(); tls?.close(); egress.close()
                    state.withLock { unbackedClosed = true; changed.signalAll() }; return
                } catch (_: Exception) {
                    state.withLock {
                        if (failure == null) failure = "cleanup_failed"
                        while (generation == cleanupGeneration) changed.await()
                    }
                }
            }
        }

        fun reap(deadline: Long): Boolean {
            if (!cleanup.tryLock()) return state.withLock { released }
            try {
                if (state.withLock { released }) return true
                val own = owner
                if (own != null && !join(own, deadline)) return false
                if (state.withLock { calls != 0 }) return false
                val ws = backend
                if (ws != null) {
                    if (!ws.awaitJoined(deadline)) return false
                    try { egress.close() } catch (_: Exception) { return false }
                } else if (!state.withLock { unbackedClosed }) return false
                state.withLock {
                    if (calls != 0 || owner?.isAlive == true) return false
                    if (stream == null) model?.confirmClosed(clock()) else stream.confirmClosed(clock())
                    released = true; transports.remove(this); changed.signalAll()
                }
                return true
            } finally { cleanup.unlock() }
        }

        private inline fun <T> call(action: () -> T): T {
            state.withLock { if (frontendClosed) throw safeIo(); calls++; pendingCalls++ }
            try { return action() }
            catch (failure: Exception) {
                if (failure is InterruptedException) Thread.currentThread().interrupt()
                stop(); throw safeIo()
            }
            finally { state.withLock { calls--; pendingCalls--; changed.signalAll() } }
        }

        inner class Connection : CaptureTcpConnection {
            override val input: InputStream = object : InputStream() {
                override fun read(): Int { val byte = ByteArray(1); return if (read(byte) < 0) -1 else byte[0].toInt() and 255 }
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                    if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
                    if (length == 0) return 0
                    var result = 0
                    call {
                        state.withLock {
                            while (true) {
                                val snapshot = stream!!.snapshot()
                                if (snapshot.phase == DraftStreamPhase.COMPLETE && snapshot.gatewayEof && snapshot.gatewayBytes == 0L) { result = -1; break }
                                usable()
                                if (snapshot.gatewayEof && snapshot.gatewayBytes == 0L) { result = -1; break }
                                if (snapshot.gatewayBytes > 0) {
                                    val peek = stream.peek(DraftDirection.GATEWAY, minOf(length, 8192, limits.maxFrameBytes), clock())
                                    accepted(peek.result.code); val data = peek.bytes(); data.copyInto(bytes, offset)
                                    accepted(stream.drain(DraftDirection.GATEWAY, data.size.toLong(), clock()).code)
                                    result = data.size; changed.signalAll(); break
                                }
                                changed.awaitNanos(TICK_NANOS)
                            }
                        }
                    }
                    maybeClose(); return result
                }
                override fun available() = state.withLock { minOf(Int.MAX_VALUE.toLong(), stream!!.snapshot().gatewayBytes).toInt() }
                override fun close() = this@Connection.close()
                override fun toString() = "CaptureGatewayInput([REDACTED])"
            }
            override val output: OutputStream = object : OutputStream() {
                override fun write(value: Int) = write(byteArrayOf(value.toByte()))
                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
                    if (length == 0) return
                    call {
                        ioWriter.lockInterruptibly()
                        try {
                            state.withLock { usable(); if (outputEnded) throw safeIo() }
                            var at = offset
                            while (at < offset + length) {
                                val count = state.withLock { minOf(8192, limits.maxFrameBytes, offset + length - at) }
                                send(bytes.copyOfRange(at, at + count), System.nanoTime() + IO_NANOS); at += count
                            }
                        } finally { ioWriter.unlock() }
                    }
                }
                override fun close() = shutdownOutput()
                override fun toString() = "CaptureGatewayOutput([REDACTED])"
            }
            override fun shutdownOutput() {
                call {
                    ioWriter.lockInterruptibly()
                    try {
                        val wire = state.withLock {
                            if (outputEnded) return@call
                            usable(); outputEnding = true; DraftWireCodec.encode(DraftMessage.Stream("end_write", id!!))
                        }
                        backend!!.writeText(wire.toString(Charsets.UTF_8), System.nanoTime() + IO_NANOS)
                        state.withLock { accepted(stream!!.text(DraftDirection.CLIENT, wire, clock()).code); outputEnded = true; outputEnding = false; changed.signalAll() }
                    } finally { ioWriter.unlock() }
                }
                maybeClose()
            }
            override fun interrupt() = stop(consumerInterrupt = true)
            override fun close() {
                val deadline = System.nanoTime() + CLEANUP_NANOS
                val graceful = state.withLock {
                    if (released) { requireGracefulCompletion(); return }
                    frontendClosed = true
                    outputEnded && stream!!.snapshot().phase == DraftStreamPhase.CLOSING
                }
                if (graceful) maybeClose() else stop(retry = true)
                try {
                    while (System.nanoTime() - deadline < 0) {
                        if (reap(deadline)) { state.withLock { requireGracefulCompletion() }; return }
                        state.withLock { if (!released) changed.awaitNanos(minOf(TICK_NANOS, maxOf(1, deadline - System.nanoTime()))) }
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt(); stop(retry = true); throw CaptureException("cleanup_failed")
                }
                stop(retry = true); throw CaptureException("cleanup_failed")
            }
            override fun toString() = "EnrolledCaptureConnection([REDACTED])"
        }

        private fun requireGracefulCompletion() {
            val snapshot = stream!!.snapshot()
            if (!consumerInterrupted && snapshot.clientEof && snapshot.gatewayEof && snapshot.chargedBytes == 0L &&
                snapshot.phase != DraftStreamPhase.COMPLETE) throw CaptureException("connect_failed")
        }
    }

    companion object {
        private const val HTTPS = "tcp-https-connect"
        private val IMPLEMENTED = setOf(HttpOriginConnect.CAPABILITY, HTTPS)
        internal val sharedPool = DraftBudgetPool()
        private const val OPEN_NANOS = 5_000_000_000L
        private const val CLEANUP_NANOS = 5_000_000_000L
        private const val TICK_NANOS = 100_000_000L
        private const val HEARTBEAT_NANOS = 15_000_000_000L
        private const val IO_NANOS = 60_000_000_000L
        private val TERMINAL_STREAMS = setOf(DraftStreamPhase.COMPLETE, DraftStreamPhase.CANCELLED, DraftStreamPhase.FAILED)
        private val CAPTURE_CODES = setOf("invalid_request", "capacity", "closed", "protect_failed", "bind_failed", "connect_failed", "cleanup_failed", "native_failed")
        private fun invalid(): Nothing = throw CaptureException("invalid_request")
        private fun safeIo() = IOException("Capture transport unavailable")
        private fun accepted(code: String) { if (code != "ok") throw CaptureException("connect_failed") }
        private fun remainingMillis(deadline: Long): Int {
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0) throw CaptureException("connect_failed")
            return minOf(5000, maxOf(1, TimeUnit.NANOSECONDS.toMillis(remaining))).toInt()
        }
        private fun worker(name: String, action: () -> Unit) = Thread(action, name).apply { isDaemon = true }
        private fun join(thread: Thread, deadline: Long): Boolean {
            if (thread === Thread.currentThread()) return false
            val remaining = deadline - System.nanoTime()
            if (thread.isAlive && remaining > 0) TimeUnit.NANOSECONDS.timedJoin(thread, remaining)
            return !thread.isAlive
        }
        private fun httpsPreface(address: ByteArray): ByteArray {
            val host = if (address.size == 4) address.joinToString(".") { (it.toInt() and 255).toString() }
            else "[" + (0 until 8).joinToString(":") { index ->
                (((address[index * 2].toInt() and 255) shl 8) or (address[index * 2 + 1].toInt() and 255)).toString(16)
            } + "]"
            return "CONNECT $host:443 HTTP/1.1\r\nHost: $host:443\r\n\r\n".toByteArray(Charsets.US_ASCII)
        }
    }
}
