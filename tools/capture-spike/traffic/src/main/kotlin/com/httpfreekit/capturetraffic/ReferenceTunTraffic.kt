package com.httpfreekit.capturetraffic

import android.os.Build
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket

/** Inert until called. All sockets belong to this owner; there is no direct-network fallback. */
class ReferenceTunTraffic internal constructor(
    private val socketFactory: () -> Socket,
    private val sdk: () -> Int,
    private val layer: (ReferenceTunTrust, Socket) -> SSLSocket,
    private val now: () -> Date = { Date() },
) : Closeable {
    constructor() : this({ Socket() }, { Build.VERSION.SDK_INT }, { trust, raw ->
        trust.context.socketFactory.createSocket(raw, ReferenceTunHttpResponse.HOST, 443, false) as SSLSocket
    })

    /** Only finite codes cross the service boundary, including suppressed cleanup failures. */
    class Failure internal constructor(val code: String) : Exception(code)

    private val lock = Object()
    private var sealed = false
    private var trust: ReferenceTunTrust? = null
    private var active: Sockets? = null
    private var runner: Thread? = null
    private var stickyClose: Failure? = null

    fun configure(caDer: ByteArray) {
        synchronized(lock) {
            if (sealed || trust != null || runner != null) throw Failure(CONFIGURATION)
            try { trust = ReferenceTunTrust.create(caDer, now()) }
            catch (_: Exception) { throw Failure(CONFIGURATION) }
        }
    }

    fun execute(command: Int, own: (Closeable) -> Unit): ByteArray {
        val session: Sockets
        val context: ReferenceTunTrust?
        synchronized(lock) {
            if (sealed || runner != null || command !in 20..21 || command == 21 && trust == null) throw Failure(CONFIGURATION)
            context = trust
            session = try { Sockets(socketFactory()) } catch (_: Exception) { throw Failure(CONNECT) }
            active = session
            runner = Thread.currentThread()
        }
        var stage = CONNECT
        var primary: Failure? = null
        var cleanupFailure: Failure? = null
        var result: ByteArray? = null
        try {
            // This aggregate already owns the actual unconnected raw socket. A callback failure is fatal.
            own(session)
            val raw = session.raw
            raw.soTimeout = 5000
            raw.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(198.toByte(), 18, 0, 2)), if (command == 20) 80 else 443), 5000)
            val application: Socket = if (command == 21) {
                stage = TLS
                val tls = layer(checkNotNull(context), raw)
                session.attach(tls)
                tls.soTimeout = 5000
                ReferenceTunTrust.prepare(tls, sdk())
                checkNotNull(context).requireCurrent(now())
                tls.startHandshake()
                ReferenceTunTrust.requireH1(tls, sdk())
                tls
            } else raw
            stage = WRITE
            application.getOutputStream().write(ReferenceTunHttpResponse.request())
            application.getOutputStream().flush()
            if (command == 20) {
                stage = SHUTDOWN
                raw.shutdownOutput()
            }
            stage = REPLY
            result = ReferenceTunHttpResponse.readBody(application.getInputStream())
            stage = EOF
            ReferenceTunHttpResponse.requireEof(application.getInputStream())
            if (command == 21) {
                // The backend ends its real TLS write side after the response. Android does not
                // promise SSLSocket.shutdownOutput support, so never invoke or emulate that API.
                // Public platform TLS EOF is NOT proof of authenticated close_notify on Android.
                stage = CLOSE
                session.closeTls()
                stage = SHUTDOWN
                raw.shutdownOutput()
                stage = EOF
                ReferenceTunHttpResponse.requireEof(raw.getInputStream())
            }
            stage = CLOSE
            session.close()
        } catch (failure: Exception) {
            val finite = if (failure is Failure) failure else Failure(stage)
            primary = finite
            cleanupFailure = finite.takeIf { it.code == CLOSE }
        } finally {
            try { session.close() } catch (failure: Exception) {
                val cleanup = if (failure is Failure) failure else Failure(CLOSE)
                if (cleanupFailure == null) cleanupFailure = cleanup
                primary = merge(primary, cleanup)
            }
            synchronized(lock) {
                cleanupFailure?.let { stickyClose = merge(stickyClose, it) }
                active = if (session.joined()) null else session
                runner = null
                if (primary != null) sealed = true
                if (sealed && active == null) trust = null
                lock.notifyAll()
            }
        }
        primary?.let { throw it }
        return checkNotNull(result)
    }

    override fun close() {
        val current: Sockets?
        val executingHere: Boolean
        synchronized(lock) {
            sealed = true
            current = active
            executingHere = runner === Thread.currentThread()
        }
        var primary: Failure? = null
        try { current?.close() } catch (failure: Exception) { primary = if (failure is Failure) failure else Failure(CLOSE) }
        // No worker is invented here: wait for the actual caller to unwind after closing its sockets.
        synchronized(lock) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(6)
            try {
                while (runner != null && !executingHere) {
                    val remaining = deadline - System.nanoTime()
                    if (remaining <= 0) break
                    TimeUnit.NANOSECONDS.timedWait(lock, remaining)
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                val failure = Failure(CLOSE)
                primary = merge(primary, failure)
            }
            if (runner == null && active?.joined() != false) {
                active = null
                trust = null
            } else {
                val failure = Failure(CLOSE)
                primary = merge(primary, failure)
            }
            primary?.let { stickyClose = merge(stickyClose, it) }
            primary = stickyClose
        }
        primary?.let { throw it }
    }

    /** Never hold an ownership monitor during TLS I/O: cancellation must still close the raw socket. */
    private class Sockets(val raw: Socket) : Closeable {
        private var tls: SSLSocket? = null
        private var tlsCloseStarted = false
        private var closeStarted = false
        private val tlsClosed = CountDownLatch(1)
        private val closed = CountDownLatch(1)
        @Volatile private var tlsFailed = false
        @Volatile private var closeFailure: Failure? = null

        fun attach(socket: SSLSocket) {
            val reject = synchronized(this) {
                if (closeStarted) true else {
                    check(tls == null)
                    tls = socket
                    false
                }
            }
            if (reject) {
                try { socket.close() } catch (_: Exception) { throw Failure(CLOSE) }
                throw Failure(CLOSE)
            }
        }

        fun closeTls() {
            var socket: SSLSocket? = null
            val startedHere = synchronized(this) {
                if (tlsCloseStarted) false else {
                    tlsCloseStarted = true
                    socket = tls
                    true
                }
            }
            if (startedHere) {
                try { socket?.close() } catch (_: Exception) { tlsFailed = true }
                finally { tlsClosed.countDown() }
            } else await(tlsClosed)
            if (tlsFailed) throw Failure(CLOSE)
        }

        override fun close() {
            val startedHere = synchronized(this) {
                if (closeStarted) false else { closeStarted = true; true }
            }
            if (startedHere) {
                var failure: Failure? = null
                try {
                    // Cancellation first unblocks an actual raw read/connect/handshake/TLS close.
                    // On success closeTls and both directional EOF observations already completed.
                    try { raw.close() } catch (_: Exception) { failure = Failure(CLOSE) }
                    try { closeTls() } catch (next: Exception) {
                        failure = merge(failure, if (next is Failure) next else Failure(CLOSE))
                    }
                } finally {
                    closeFailure = failure
                    closed.countDown()
                }
            } else await(closed)
            await(tlsClosed)
            closeFailure?.let { throw it }
        }

        fun joined() = closed.count == 0L && tlsClosed.count == 0L

        private fun await(done: CountDownLatch) {
            try {
                if (!done.await(6, TimeUnit.SECONDS)) throw Failure(CLOSE)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                throw Failure(CLOSE)
            }
        }
    }

    private companion object {
        fun merge(primary: Failure?, next: Failure): Failure {
            if (primary == null) return next
            if (primary === next) return primary
            primary.addSuppressed(next)
            return primary
        }

        const val CONFIGURATION = "traffic_reference_configuration"
        const val CONNECT = "traffic_reference_connect"
        const val TLS = "traffic_reference_tls"
        const val WRITE = "traffic_reference_write"
        const val SHUTDOWN = "traffic_reference_shutdown"
        const val REPLY = "traffic_reference_reply"
        const val EOF = "traffic_reference_eof"
        const val CLOSE = "traffic_reference_close"
    }
}
