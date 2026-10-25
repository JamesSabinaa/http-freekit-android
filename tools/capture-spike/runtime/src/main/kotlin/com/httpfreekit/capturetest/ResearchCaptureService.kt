package com.httpfreekit.capturetest

import android.net.Network
import com.httpfreekit.capture.CaptureServiceSnapshot
import com.httpfreekit.capture.CaptureSocketGuard
import com.httpfreekit.capture.CaptureStartRequest
import com.httpfreekit.capture.CaptureTcpConnection
import com.httpfreekit.capture.CaptureVpnService
import com.httpfreekit.capture.InterceptedTcpFactory
import com.httpfreekit.capture.ProtectedEgressFactory
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class ResearchCaptureService : CaptureVpnService() {
    private val protectAttempts = AtomicInteger()
    private val bindAttempts = AtomicInteger()
    private val requests = AtomicInteger()
    private val rejectedSockets = ArrayList<Socket>()
    @Volatile private var interceptedClosed = false

    override fun onCreate() { super.onCreate(); current = this }

    override fun captureRequest(network: Network, guard: CaptureSocketGuard): CaptureStartRequest {
        requests.incrementAndGet()
        val config = checkNotNull(configuration) { "research_configuration" }
        return CaptureStartRequest(config.selected, ReceiverFactory(config.interceptedPort, guard) { interceptedClosed = true })
    }

    override fun socketGuard(network: Network): CaptureSocketGuard {
        val real = super.socketGuard(network)
        val mode = checkNotNull(configuration).mode
        return object : CaptureSocketGuard {
            override fun protect(socket: Socket): Boolean {
                protectAttempts.incrementAndGet()
                if (mode == Mode.REFUSE_PROTECT) { synchronized(rejectedSockets) { rejectedSockets.add(socket) }; return false }
                return real.protect(socket)
            }
            override fun protect(socket: DatagramSocket): Boolean { protectAttempts.incrementAndGet(); return real.protect(socket) }
            override fun bind(socket: Socket) {
                bindAttempts.incrementAndGet()
                if (mode == Mode.FAIL_BIND) { synchronized(rejectedSockets) { rejectedSockets.add(socket) }; throw IOException("research_bind_refused") }
                real.bind(socket)
            }
            override fun bind(socket: DatagramSocket) { bindAttempts.incrementAndGet(); real.bind(socket) }
        }
    }

    override fun onCaptureStateChanged(snapshot: CaptureServiceSnapshot) { lastState = snapshot.state }

    fun guardObservation(): GuardObservation = synchronized(rejectedSockets) {
        GuardObservation(protectAttempts.get(), bindAttempts.get(), rejectedSockets.size,
            rejectedSockets.isNotEmpty() && rejectedSockets.all { it.isClosed })
    }
    fun interceptedFactoryClosed(): Boolean = interceptedClosed
    fun captureRequestCalls(): Int = requests.get()

    enum class Mode { NORMAL, REFUSE_PROTECT, FAIL_BIND }
    class Config(val interceptedPort: Int, selected: Set<String>, val mode: Mode) {
        val selected: Set<String> = selected.toSet()
        init {
            require(interceptedPort in 1024..65535 && selected in setOf(setOf(TRAFFIC), setOf(INERT))) { "research_configuration" }
        }
        override fun toString() = "CaptureResearchConfig([REDACTED])"
    }
    data class GuardObservation(val protects: Int, val binds: Int, val rejected: Int, val rejectedSocketsClosed: Boolean)
    companion object {
        const val TRAFFIC = "com.httpfreekit.capturetraffic"
        const val INERT = "com.httpfreekit.fixture.installedapps"
        @Volatile var configuration: Config? = null
        @Volatile var current: ResearchCaptureService? = null
            private set
        @Volatile var lastState = "idle"
            private set
    }

    /** Only the three committed original tuples can reach this injected receiver. */
    private class ReceiverFactory(private val port: Int, guard: CaptureSocketGuard, private val onClosed: () -> Unit) : InterceptedTcpFactory {
        private val egress = ProtectedEgressFactory(guard)
        private val lock = ReentrantLock()
        private val settled = lock.newCondition()
        private val connections = LinkedHashSet<Connection>()
        private var pending = 0
        private var closed = false
        override fun open(originalAddress: InetAddress, originalPort: Int): CaptureTcpConnection {
            val role = when {
                originalAddress.address.contentEquals(byteArrayOf(10, 0, 2, 2)) && originalPort == 80 -> 1
                originalAddress.address.contentEquals(byteArrayOf(10, 0, 2, 2)) && originalPort == 443 -> 2
                originalAddress.address.contentEquals(IPV6) && originalPort == 80 -> 3
                else -> error("research_original_tuple")
            }
            lock.withLock { check(!closed) { "research_factory_closed" }; pending++ }
            var raw: CaptureTcpConnection? = null
            try {
                raw = egress.openTcp(InetAddress.getByAddress(byteArrayOf(10, 0, 2, 2)), port)
                raw.output.write(role); raw.output.flush()
                val connection = Connection(raw)
                lock.withLock { check(!closed) { "research_factory_closed" }; connections.add(connection) }
                raw = null
                return connection
            } finally {
                try { raw?.close() } finally { lock.withLock { pending--; settled.signalAll() } }
            }
        }
        private inner class Connection(private val raw: CaptureTcpConnection) : CaptureTcpConnection {
            override val input get() = raw.input
            override val output get() = raw.output
            override fun shutdownOutput() = raw.shutdownOutput()
            override fun interrupt() = raw.interrupt()
            override fun close() { raw.close(); lock.withLock { connections.remove(this) } }
        }
        override fun close() {
            val current = lock.withLock { closed = true; connections.toList() }
            var failed = false
            try { egress.close() } catch (_: Exception) { failed = true }
            current.forEach { try { it.close() } catch (_: Exception) { failed = true } }
            lock.withLock {
                var remaining = TimeUnit.SECONDS.toNanos(6)
                while (pending != 0 && remaining > 0) remaining = settled.awaitNanos(remaining)
                check(!failed && pending == 0 && connections.isEmpty()) { "research_factory_cleanup" }
            }
            onClosed()
        }
        companion object {
            private val IPV6 = byteArrayOf(0x20, 1, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80.toByte())
        }
    }
}
