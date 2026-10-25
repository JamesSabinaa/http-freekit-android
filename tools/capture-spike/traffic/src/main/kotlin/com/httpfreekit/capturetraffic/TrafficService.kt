package com.httpfreekit.capturetraffic

import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import android.os.SystemClock
import android.system.ErrnoException
import android.system.OsConstants
import java.io.Closeable
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Finite synthetic requests only. The signature permission is the IPC admission boundary. */
class TrafficService : Service() {
    private val busy = AtomicBoolean(false)
    private val executor = Executors.newSingleThreadExecutor { runnable -> Thread(runnable, "capture-fixture-request") }
    @Volatile private var owned: Closeable? = null
    @Volatile private var directPort = 0
    private val messenger = Messenger(Handler(Looper.getMainLooper()) { request ->
        val reply = request.replyTo
        val id = request.arg1
        // Handler recycles the incoming Message after dispatch; the worker owns primitives only.
        val command = request.what
        if (reply == null || id !in 1..1_000_000 || request.what !in COMMANDS) {
            if (reply != null) respond(reply, id, INVALID, 0, null)
            true
        } else if (request.what == CONFIGURE) {
            val data = request.data
            val port = data.getInt("directPort", 0)
            if (busy.get() || data.keySet() != setOf("directPort") || port !in 1024..65535) {
                respond(reply, id, INVALID, 0, null)
            } else {
                directPort = port
                respond(reply, id, OK, 0, null)
            }
            true
        } else if (request.what == FINISH) {
            if (!request.data.isEmpty || busy.get()) respond(reply, id, INVALID, 0, null)
            else {
                executor.shutdown()
                val joined = executor.awaitTermination(2000, TimeUnit.MILLISECONDS)
                respond(reply, id, if (joined && owned == null) OK else FAILED, 0, null)
            }
            true
        } else if (!request.data.isEmpty || directPort == 0 || executor.isShutdown ||
            Build.VERSION.SDK_INT >= 37 && checkSelfPermission("android.permission.ACCESS_LOCAL_NETWORK") != PackageManager.PERMISSION_GRANTED || !busy.compareAndSet(false, true)) {
            respond(reply, id, INVALID, 0, null)
            true
        } else {
            executor.execute {
                var status = FAILED
                var size = 0
                var digest: String? = null
                var failureCode: String? = null
                try {
                    val bytes = when (command) {
                        HTTP -> tcp(HOST, 80, HTTP_BYTES)
                        HTTPS_OPAQUE -> tcp(HOST, 443, BODY)
                        DIRECT_TCP -> tcp(HOST, directPort, BODY)
                        UDP -> udp(53, UDP_BYTES, UDP_BYTES)
                        DNS -> udp(53, DNS_BYTES, DNS_REPLY)
                        UDP_443 -> udp(443, UDP_BYTES, UDP_BYTES)
                        IPV6_HTTP -> tcp(IPV6, 80, HTTP_BYTES)
                        WAIT_VPN -> { awaitRoute(true); ByteArray(0) }
                        WAIT_NON_VPN -> { awaitRoute(false); ByteArray(0) }
                        ENROLLED_HTTP -> enrolledHttp()
                        else -> error("finite_command")
                    }
                    status = OK; size = bytes.size; digest = if (command in WAIT_VPN..WAIT_NON_VPN) null else hash(bytes)
                } catch (failure: TrafficCommandFailure) {
                    status = failure.status; failureCode = failure.code
                } catch (failure: Exception) {
                    status = if (failure is SocketTimeoutException) TIMEOUT else FAILED
                    failureCode = if (command in UDP..UDP_443) "traffic_datagram_${category(failure)}" else "traffic_command_failed"
                } finally {
                    try { owned?.close() } catch (failure: Exception) {
                        status = FAILED; size = 0; digest = null
                        if (failureCode == null) failureCode = if (failure is IOException) "traffic_close_io" else "traffic_command_failed"
                    }
                    owned = null
                    busy.set(false)
                }
                respond(reply, id, status, size, digest, failureCode)
            }
            true
        }
    })

    override fun onBind(intent: Intent): IBinder = messenger.binder

    override fun onDestroy() {
        try { owned?.close() } finally { executor.shutdownNow(); super.onDestroy() }
    }

    private fun tcp(address: ByteArray, port: Int, payload: ByteArray): ByteArray {
        val socket = Socket()
        owned = socket
        var stage = "connect"
        try {
            socket.soTimeout = 5000
            socket.connect(InetSocketAddress(InetAddress.getByAddress(address), port), 5000)
            stage = "write"
            socket.getOutputStream().write(payload)
            socket.getOutputStream().flush()
            stage = "shutdown"
            socket.shutdownOutput()
            stage = "reply"
            val response = socket.getInputStream().readNBytesBounded(REPLY.size)
            check(response.contentEquals(REPLY)) { "fixture_reply" }
            stage = "eof"
            check(socket.getInputStream().read() == -1) { "fixture_trailing" }
            stage = "close"
            socket.close()
            return response
        } catch (failure: Exception) {
            val category = TrafficTcpFailure.category(failure) { cause ->
                if (cause !is ErrnoException) null else when (cause.errno) {
                    OsConstants.ECONNRESET -> TrafficTcpFailure.Errno.RESET
                    OsConstants.ECONNABORTED -> TrafficTcpFailure.Errno.ABORTED
                    OsConstants.EBADF -> TrafficTcpFailure.Errno.BAD_FD
                    OsConstants.ENOTCONN -> TrafficTcpFailure.Errno.NOT_CONNECTED
                    else -> null
                }
            }
            throw TrafficCommandFailure("traffic_tcp_${stage}_$category", if (failure is SocketTimeoutException) TIMEOUT else FAILED)
        }
    }

    /** Separate fixed C5 transaction; the original cold command and its EOF checks stay unchanged. */
    private fun enrolledHttp(): ByteArray {
        val socket = Socket()
        owned = socket
        var stage = "connect"
        try {
            socket.soTimeout = 5000
            socket.connect(InetSocketAddress(InetAddress.getByAddress(ENROLLED_HOST), 80), 5000)
            stage = "write"
            socket.getOutputStream().write(ENROLLED_HTTP_BYTES)
            socket.getOutputStream().flush()
            stage = "shutdown"
            socket.shutdownOutput()
            stage = "reply"
            val response = EnrolledHttpResponse.readBody(socket.getInputStream())
            stage = "eof"
            EnrolledHttpResponse.requireEof(socket.getInputStream())
            stage = "close"
            socket.close()
            return response
        } catch (failure: Exception) {
            val category = TrafficTcpFailure.category(failure) { cause ->
                if (cause !is ErrnoException) null else when (cause.errno) {
                    OsConstants.ECONNRESET -> TrafficTcpFailure.Errno.RESET
                    OsConstants.ECONNABORTED -> TrafficTcpFailure.Errno.ABORTED
                    OsConstants.EBADF -> TrafficTcpFailure.Errno.BAD_FD
                    OsConstants.ENOTCONN -> TrafficTcpFailure.Errno.NOT_CONNECTED
                    else -> null
                }
            }
            throw TrafficCommandFailure("traffic_tcp_${stage}_$category", if (failure is SocketTimeoutException) TIMEOUT else FAILED)
        }
    }

    /** Observe this traffic UID's default network only; never bind, connect or send a probe packet. */
    private fun awaitRoute(expectedVpn: Boolean) {
        val deadline = SystemClock.elapsedRealtimeNanos() + 5_000_000_000L
        var candidate: Network? = null
        var since = 0L
        var present = false
        var internet = false
        var vpn = false
        try {
            val manager = checkNotNull(getSystemService(ConnectivityManager::class.java))
            while (true) {
                val queryStarted = SystemClock.elapsedRealtimeNanos()
                val network = manager.activeNetwork
                val capabilities = network?.let(manager::getNetworkCapabilities)
                present = network != null
                internet = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
                vpn = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                val now = SystemClock.elapsedRealtimeNanos()
                if (now >= deadline) break
                if (network != null && internet && vpn == expectedVpn) {
                    if (candidate != network) { candidate = network; since = now }
                    // The network sample occurred within this query; a slow reply cannot inflate its age.
                    if (queryStarted - since >= 250_000_000L) return
                } else { candidate = null; since = 0L }
                Thread.sleep(25)
            }
        } catch (_: Exception) { throw TrafficCommandFailure("traffic_route_unavailable", FAILED) }
        val expected = if (expectedVpn) "vpn" else "nonvpn"
        throw TrafficCommandFailure("traffic_route_${expected}_timeout_p${if (present) 1 else 0}_i${if (internet) 1 else 0}_v${if (vpn) 1 else 0}", TIMEOUT)
    }

    private fun category(failure: Exception): String = when (failure) {
        is SocketTimeoutException -> "timeout"
        is IOException -> "io"
        is IllegalStateException, is IllegalArgumentException -> "protocol"
        else -> "other"
    }
    private class TrafficCommandFailure(val code: String, val status: Int) : Exception()

    private fun udp(port: Int, payload: ByteArray, expected: ByteArray): ByteArray {
        val socket = DatagramSocket()
        owned = socket
        socket.use {
            it.soTimeout = if (port == 443) 1500 else 5000
            it.connect(InetAddress.getByAddress(HOST), port)
            it.send(DatagramPacket(payload, payload.size))
            val response = DatagramPacket(ByteArray(512), 512)
            it.receive(response)
            val bytes = response.data.copyOf(response.length)
            check(bytes.contentEquals(expected)) { "fixture_datagram" }
            return bytes
        }
    }

    private fun java.io.InputStream.readNBytesBounded(count: Int): ByteArray {
        val result = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val size = read(result, offset, count - offset)
            check(size > 0) { "fixture_eof" }
            offset += size
        }
        return result
    }

    private fun respond(reply: Messenger, id: Int, status: Int, bytes: Int, digest: String?, failureCode: String? = null) {
        val result = Message.obtain(null, RESULT, id, status)
        result.data = Bundle().apply { putInt("bytes", bytes); putString("sha256", digest); putString("failureCode", failureCode) }
        try { reply.send(result) } catch (_: RemoteException) { /* No payload or external error logging. */ }
    }

    companion object {
        const val CONFIGURE = 1
        const val FINISH = 2
        const val HTTP = 10
        const val HTTPS_OPAQUE = 11
        const val DIRECT_TCP = 12
        const val UDP = 13
        const val DNS = 14
        const val UDP_443 = 15
        const val IPV6_HTTP = 16
        const val WAIT_VPN = 17
        const val WAIT_NON_VPN = 18
        const val ENROLLED_HTTP = 19
        const val RESULT = 100
        const val OK = 0
        const val INVALID = 1
        const val TIMEOUT = 2
        const val FAILED = 3
        private val COMMANDS = setOf(CONFIGURE, FINISH, HTTP, HTTPS_OPAQUE, DIRECT_TCP, UDP, DNS, UDP_443, IPV6_HTTP, WAIT_VPN, WAIT_NON_VPN, ENROLLED_HTTP)
        private val HOST = byteArrayOf(10, 0, 2, 2)
        private val IPV6 = byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80.toByte())
        private val BODY = ByteArray(16_421) { ((it * 31 + 7) and 255).toByte() }
        private val REPLY = ByteArray(32_787) { ((it * 17 + 11) and 255).toByte() }
        private val UDP_BYTES = ByteArray(256) { ((it * 13 + 5) and 255).toByte() }
        private val HTTP_BYTES = "POST /capture-fixture HTTP/1.1\r\nHost: capture-fixture.invalid\r\nContent-Length: ${BODY.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII) + BODY
        private val ENROLLED_HOST = byteArrayOf(198.toByte(), 18, 0, 2)
        private val ENROLLED_BODY = ByteArray(16_421) { (it % 251).toByte() }
        private val ENROLLED_HTTP_BYTES = "POST /factory-research HTTP/1.1\r\nHost: capture-origin.invalid\r\nContent-Length: ${ENROLLED_BODY.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII) + ENROLLED_BODY
        private val DNS_BYTES = byteArrayOf(0x43, 0x50, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 7, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0, 0, 1, 0, 1)
        private val DNS_REPLY = DNS_BYTES.copyOf().also { it[2] = 0x81.toByte(); it[3] = 0x80.toByte() }
        private fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
