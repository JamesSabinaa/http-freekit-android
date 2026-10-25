package com.httpfreekit.interop

import android.net.Network
import com.httpfreekit.capture.CaptureSocketGuard
import com.httpfreekit.capture.CaptureStartRequest
import com.httpfreekit.capture.CaptureVpnService
import com.httpfreekit.capture.transport.CaptureTransportSnapshot
import com.httpfreekit.capture.transport.EnrolledCaptureTcpFactory
import com.httpfreekit.security.AndroidEnrolledCredentialStore
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

/** The core service exclusively owns the real enrolled factory and TUN lifecycle. */
class DraftEnrolledTunService : CaptureVpnService() {
    private val protectAttempts = AtomicInteger()
    private val protectSuccesses = AtomicInteger()
    private val bindAttempts = AtomicInteger()
    private val bindSuccesses = AtomicInteger()
    @Volatile private var factory: EnrolledCaptureTcpFactory? = null

    override fun onCreate() { super.onCreate(); current = this }

    override fun socketGuard(network: Network): CaptureSocketGuard {
        val actual = super.socketGuard(network)
        // Observe the same real guard for core direct egress and gateway sockets.
        return object : CaptureSocketGuard {
            override fun protect(socket: Socket): Boolean {
                protectAttempts.incrementAndGet()
                return actual.protect(socket).also { if (it) protectSuccesses.incrementAndGet() }
            }
            override fun bind(socket: Socket) {
                bindAttempts.incrementAndGet(); actual.bind(socket); bindSuccesses.incrementAndGet()
            }
            override fun protect(socket: DatagramSocket): Boolean {
                protectAttempts.incrementAndGet()
                return actual.protect(socket).also { if (it) protectSuccesses.incrementAndGet() }
            }
            override fun bind(socket: DatagramSocket) {
                bindAttempts.incrementAndGet(); actual.bind(socket); bindSuccesses.incrementAndGet()
            }
        }
    }

    override fun captureRequest(network: Network, guard: CaptureSocketGuard): CaptureStartRequest {
        val config = checkNotNull(configuration) { "Enrolled TUN configuration unavailable" }
        check(factory == null) { "Enrolled TUN factory already owned" }
        val loaded = checkNotNull(AndroidEnrolledCredentialStore(this).load(config.desktopId)) {
            "Enrolled TUN credential unavailable"
        }
        // Construction is inert; successful request return transfers ownership to the core service.
        val owned = EnrolledCaptureTcpFactory(loaded, config.gateway, guard).also { factory = it }
        return CaptureStartRequest(setOf(TRAFFIC_PACKAGE), owned)
    }

    fun factorySnapshot(): CaptureTransportSnapshot? = factory?.snapshot()
    fun guardSnapshot(): GuardSnapshot = GuardSnapshot(protectAttempts.get(), protectSuccesses.get(),
        bindAttempts.get(), bindSuccesses.get())

    class GuardSnapshot(val protectAttempts: Int, val protectSuccesses: Int,
        val bindAttempts: Int, val bindSuccesses: Int)

    private class Configuration(val desktopId: String, endpoint: InetSocketAddress) {
        val gateway: InetSocketAddress
        init {
            require(desktopId.matches(Regex("[A-Za-z0-9_-]{1,64}"))) { "Invalid enrolled TUN desktop" }
            require(!endpoint.isUnresolved && endpoint.address.address.contentEquals(byteArrayOf(127, 0, 0, 1)) &&
                endpoint.port in 1024..65535) { "Invalid enrolled TUN endpoint" }
            gateway = InetSocketAddress(InetAddress.getByAddress(endpoint.address.address.copyOf()), endpoint.port)
        }
        override fun toString() = "DraftEnrolledTunConfiguration([REDACTED])"
    }

    companion object {
        const val TRAFFIC_PACKAGE = "com.httpfreekit.capturetraffic"
        @Volatile var current: DraftEnrolledTunService? = null
            private set
        @Volatile private var configuration: Configuration? = null

        fun configure(desktopId: String, gateway: InetSocketAddress) {
            check(configuration == null && current == null) { "Enrolled TUN owner already exists" }
            configuration = Configuration(desktopId, gateway)
        }

        fun clearStoppedConfiguration() {
            val service = current
            check(service == null || service.awaitStopped(1)) { "Enrolled TUN owner remains active" }
            configuration = null; current = null
        }
    }
}
