package com.httpfreekit.capture

import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory

/** Raw ownership precedes setup; every admission is protect, bind, then connect, without fallback. */
class ProtectedEgressFactory(private val guard: CaptureSocketGuard) : AutoCloseable {
    internal val budget = CaptureSocketBudget()
    private val lock = Any()
    private var closed = false
    private var cleanupFailed = false
    private val sockets = LinkedHashSet<AutoCloseable>()
    private val refusedProtect = AtomicInteger()
    private val refusedBind = AtomicInteger()
    val protectFailures get() = refusedProtect.get()
    val bindFailures get() = refusedBind.get()
    private val opening = AtomicInteger()
    internal fun pendingOpens(): Int = opening.get()
    internal fun ownedCount(): Int = synchronized(lock) { sockets.size }

    private inner class Tcp(private val lease: CaptureSocketBudget.Lease) : Socket() {
        private var released = false
        override fun connect(endpoint: java.net.SocketAddress?, timeout: Int) {
            if (timeout < 0 || endpoint !is InetSocketAddress || endpoint.isUnresolved) throw CaptureException("invalid_request")
            super.connect(endpoint, if (timeout == 0) 5000 else minOf(timeout, 5000))
        }
        @Synchronized override fun close() {
            if (released) return
            try { super.close() }
            catch (_: Exception) { synchronized(lock) { cleanupFailed = true }; throw CaptureException("cleanup_failed") }
            synchronized(lock) { sockets.remove(this) }; lease.release(); released = true
        }
    }
    private inner class Udp(private val lease: CaptureSocketBudget.Lease) : DatagramSocket(null as java.net.SocketAddress?) {
        private var released = false
        @Synchronized override fun close() {
            if (released) return
            try { super.close() }
            catch (_: Exception) { synchronized(lock) { cleanupFailed = true }; throw CaptureException("cleanup_failed") }
            synchronized(lock) { sockets.remove(this) }; lease.release(); released = true
        }
    }

    private fun tcp(): Socket {
        val socket = synchronized(lock) {
            if (closed) throw CaptureException("closed")
            val lease = budget.acquire()
            try { Tcp(lease).also(sockets::add) } catch (_: Exception) { lease.release(); throw CaptureException("connect_failed") }
        }
        try {
            val protected = try { guard.protect(socket) } catch (_: Exception) { false }
            if (!protected) { refusedProtect.incrementAndGet(); throw CaptureException("protect_failed") }
            try { guard.bind(socket) } catch (_: Exception) { refusedBind.incrementAndGet(); throw CaptureException("bind_failed") }
            if (synchronized(lock) { closed } || socket.isClosed) throw CaptureException("closed")
            socket.tcpNoDelay = true
            return socket
        } catch (failure: Exception) {
            try { socket.close() } catch (_: Exception) { throw CaptureException("cleanup_failed") }
            throw if (failure is CaptureException) failure else CaptureException("protect_failed")
        }
    }

    fun rawSocketFactory(): SocketFactory = object : SocketFactory() {
        override fun createSocket(): Socket {
            opening.incrementAndGet()
            try { return tcp() } finally { opening.decrementAndGet() }
        }
        override fun createSocket(host: String?, port: Int): Socket = throw CaptureException("invalid_request")
        override fun createSocket(host: String?, port: Int, local: InetAddress?, localPort: Int): Socket = throw CaptureException("invalid_request")
        override fun createSocket(host: InetAddress?, port: Int): Socket = throw CaptureException("invalid_request")
        override fun createSocket(host: InetAddress?, port: Int, local: InetAddress?, localPort: Int): Socket = throw CaptureException("invalid_request")
    }

    fun openTcp(address: InetAddress, port: Int): CaptureTcpConnection {
        numeric(address, port)
        opening.incrementAndGet()
        try {
            val socket = tcp()
            try {
                socket.connect(InetSocketAddress(address, port), 5000)
                if (synchronized(lock) { closed }) throw CaptureException("closed")
                return SocketConnection(socket)
            } catch (_: Exception) { socket.close(); throw CaptureException("connect_failed") }
        } finally { opening.decrementAndGet() }
    }

    fun openUdp(address: InetAddress, port: Int): DatagramSocket {
        numeric(address, port)
        if (port == 443) throw CaptureException("invalid_request")
        opening.incrementAndGet()
        try {
            val socket = synchronized(lock) {
                if (closed) throw CaptureException("closed")
                val lease = budget.acquire()
                try { Udp(lease).also(sockets::add) } catch (_: Exception) { lease.release(); throw CaptureException("connect_failed") }
            }
            try {
                val protected = try { guard.protect(socket) } catch (_: Exception) { false }
                if (!protected) { refusedProtect.incrementAndGet(); throw CaptureException("protect_failed") }
                try { guard.bind(socket) } catch (_: Exception) { refusedBind.incrementAndGet(); throw CaptureException("bind_failed") }
                if (synchronized(lock) { closed } || socket.isClosed) throw CaptureException("closed")
                socket.soTimeout = 1000
                socket.connect(InetSocketAddress(address, port))
                return socket
            } catch (failure: Exception) {
                socket.close()
                throw if (failure is CaptureException) failure else CaptureException("connect_failed")
            }
        } finally { opening.decrementAndGet() }
    }

    override fun close() {
        val current = synchronized(lock) { closed = true; sockets.toList() }
        var failed = false
        current.forEach { try { it.close() } catch (_: Exception) { failed = true } }
        if (failed || synchronized(lock) { cleanupFailed || sockets.isNotEmpty() }) throw CaptureException("cleanup_failed")
    }
    override fun toString() = "ProtectedEgressFactory([REDACTED])"
    private fun numeric(address: InetAddress, port: Int) {
        if (address.address.size !in setOf(4, 16) || port !in 1..65535) throw CaptureException("invalid_request")
    }
    private class SocketConnection(private val socket: Socket) : CaptureTcpConnection {
        override val input get() = socket.getInputStream()
        override val output get() = socket.getOutputStream()
        override fun shutdownOutput() = socket.shutdownOutput()
        override fun interrupt() = socket.close()
        override fun close() = socket.close()
        override fun toString() = "ProtectedTcpConnection([REDACTED])"
    }
}
