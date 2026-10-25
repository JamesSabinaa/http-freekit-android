package com.httpfreekit.capturetraffic

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import java.io.Closeable
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
        } else if (!request.data.isEmpty || directPort == 0 || executor.isShutdown || !busy.compareAndSet(false, true)) {
            respond(reply, id, INVALID, 0, null)
            true
        } else {
            executor.execute {
                var status = FAILED
                var size = 0
                var digest: String? = null
                try {
                    val bytes = when (request.what) {
                        HTTP -> tcp(HOST, 80, HTTP_BYTES)
                        HTTPS_OPAQUE -> tcp(HOST, 443, BODY)
                        DIRECT_TCP -> tcp(HOST, directPort, BODY)
                        UDP -> udp(53, UDP_BYTES, UDP_BYTES)
                        DNS -> udp(53, DNS_BYTES, DNS_REPLY)
                        UDP_443 -> udp(443, UDP_BYTES, UDP_BYTES)
                        IPV6_HTTP -> tcp(IPV6, 80, HTTP_BYTES)
                        else -> error("finite_command")
                    }
                    status = OK; size = bytes.size; digest = hash(bytes)
                } catch (_: SocketTimeoutException) {
                    status = TIMEOUT
                } catch (_: Exception) {
                    status = FAILED
                } finally {
                    try { owned?.close() } catch (_: Exception) { status = FAILED; size = 0; digest = null }
                    owned = null
                    busy.set(false)
                }
                respond(reply, id, status, size, digest)
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
        socket.use {
            it.soTimeout = 5000
            it.connect(InetSocketAddress(InetAddress.getByAddress(address), port), 5000)
            it.getOutputStream().write(payload)
            it.getOutputStream().flush()
            it.shutdownOutput()
            val response = it.getInputStream().readNBytesBounded(REPLY.size)
            check(response.contentEquals(REPLY)) { "fixture_reply" }
            check(it.getInputStream().read() == -1) { "fixture_trailing" }
            return response
        }
    }

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

    private fun respond(reply: Messenger, id: Int, status: Int, bytes: Int, digest: String?) {
        val result = Message.obtain(null, RESULT, id, status)
        result.data = Bundle().apply { putInt("bytes", bytes); putString("sha256", digest) }
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
        const val RESULT = 100
        const val OK = 0
        const val INVALID = 1
        const val TIMEOUT = 2
        const val FAILED = 3
        private val COMMANDS = setOf(CONFIGURE, FINISH, HTTP, HTTPS_OPAQUE, DIRECT_TCP, UDP, DNS, UDP_443, IPV6_HTTP)
        private val HOST = byteArrayOf(10, 0, 2, 2)
        private val IPV6 = byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80.toByte())
        private val BODY = ByteArray(16_421) { ((it * 31 + 7) and 255).toByte() }
        private val REPLY = ByteArray(32_787) { ((it * 17 + 11) and 255).toByte() }
        private val UDP_BYTES = ByteArray(256) { ((it * 13 + 5) and 255).toByte() }
        private val HTTP_BYTES = "POST /capture-fixture HTTP/1.1\r\nHost: capture-fixture.invalid\r\nContent-Length: ${BODY.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII) + BODY
        private val DNS_BYTES = byteArrayOf(0x43, 0x50, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 7, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0, 0, 1, 0, 1)
        private val DNS_REPLY = DNS_BYTES.copyOf().also { it[2] = 0x81.toByte(); it[3] = 0x80.toByte() }
        private fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
