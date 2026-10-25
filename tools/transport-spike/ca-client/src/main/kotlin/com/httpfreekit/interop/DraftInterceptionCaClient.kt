package com.httpfreekit.interop

import com.httpfreekit.security.EnrolledCredentialRecord
import com.httpfreekit.security.GatewayTlsConnectionFactory
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.SocketFactory
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager

internal class DraftInterceptionCaClientSnapshot(
    val closed: Boolean, val activeCall: Boolean, val rawSocketOwned: Boolean,
    val tlsSocketOwned: Boolean, val deadlineAlive: Boolean, val tlsCloserAlive: Boolean,
    val cleanupFailed: Boolean,
) {
    override fun toString() = "DraftInterceptionCaClientSnapshot([REDACTED])"
}

/** One fresh pinned mTLS request at a time. No retry, installation, global TLS or persistent write. */
internal class DraftInterceptionCaClient(
    record: EnrolledCredentialRecord,
    private val manager: X509ExtendedKeyManager,
    originalDeviceCertificateChain: List<X509Certificate>,
    recovery: DraftEnrollmentRecovery,
    resolvedDialAddress: InetSocketAddress,
) : AutoCloseable {
    private val binding = DraftInterceptionCaBinding(record, originalDeviceCertificateChain, recovery)
    private val dial = DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.BINDING) {
        check(!resolvedDialAddress.isUnresolved && resolvedDialAddress.port in 1..65535)
        InetSocketAddress(resolvedDialAddress.address, resolvedDialAddress.port)
    }
    private val admission = Any()
    private val closed = AtomicBoolean(false)
    private val cleanupFailed = AtomicBoolean(false)
    private val active = AtomicReference<Call?>()
    init { binding.validateCurrent(manager) }

    private class Call {
        val expiresNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        val raw = AtomicReference<Socket?>()
        val tls = AtomicReference<SSLSocket?>()
        val deadline = AtomicReference<Thread?>()
        val closer = AtomicReference<Thread?>()
        val timedOut = AtomicBoolean(false)
        val closeFailed = AtomicBoolean(false)
        val cleaned = AtomicBoolean(false)
        val ownerDone = CountDownLatch(1)
        fun interrupt() {
            try { raw.get()?.close() } catch (_: Exception) { closeFailed.set(true) }
        }
    }

    fun fetch(): DraftInterceptionCa {
        val call = Call()
        synchronized(admission) {
            if (closed.get() || cleanupFailed.get() || !active.compareAndSet(null, call)) fail(DraftInterceptionCaFailure.CLOSED)
        }
        try { return exchange(call) }
        finally {
            // Seal the synchronous call only after final binding checks and all cleanup work.
            synchronized(admission) {
                if (call.cleaned.get()) active.compareAndSet(call, null)
                call.ownerDone.countDown()
            }
        }
    }

    private fun exchange(call: Call): DraftInterceptionCa {
        var result: DraftInterceptionCa? = null
        var failure: DraftInterceptionCaException? = null
        try {
            val deadline = Thread({
                try { Thread.sleep(10000); call.timedOut.set(true); call.interrupt() }
                catch (_: InterruptedException) { /* Joined by this request's cleanup owner. */ }
            }, "interception-ca-deadline").apply { isDaemon = true }
            call.deadline.set(deadline); deadline.start()
            ensureRunning(call)
            binding.validateCurrent(manager)
            val rawFactory = object : SocketFactory() {
                override fun createSocket(): Socket {
                    ensureRunning(call)
                    val socket = Socket()
                    call.raw.set(socket) // Retain ownership before any fallible socket option.
                    socket.tcpNoDelay = true
                    ensureRunning(call)
                    return socket
                }
                override fun createSocket(host: String?, port: Int): Socket = fail(DraftInterceptionCaFailure.TRANSPORT)
                override fun createSocket(host: String?, port: Int, local: InetAddress?, localPort: Int): Socket = fail(DraftInterceptionCaFailure.TRANSPORT)
                override fun createSocket(host: InetAddress?, port: Int): Socket = fail(DraftInterceptionCaFailure.TRANSPORT)
                override fun createSocket(host: InetAddress?, port: Int, local: InetAddress?, localPort: Int): Socket = fail(DraftInterceptionCaFailure.TRANSPORT)
            }
            val record = binding.record
            val tls = GatewayTlsConnectionFactory(record.gatewayCertificate, record.gatewaySpkiSha256,
                record.logicalServerName, 5000, 5000, rawSocketFactory = rawFactory, clientKeyManager = manager).connect(dial)
            call.tls.set(tls); tls.soTimeout = 5000
            ensureRunning(call)
            val request = "GET /companion/v1/ca HTTP/1.1\r\nHost: ${record.logicalServerName}:${dial.port}\r\nAccept: application/pkix-cert\r\nConnection: close\r\n\r\n"
            tls.outputStream.write(request.toByteArray(Charsets.US_ASCII)); tls.outputStream.flush()
            val headers = readHeaders(tls)
            result = response {
                check(headers.first == 200)
                val fields = headers.second
                check(fields["content-type"] == "application/pkix-cert" && fields["cache-control"] == "no-store" &&
                    fields["connection"]?.lowercase(Locale.ROOT) == "close")
                check(setOf("transfer-encoding", "trailer", "content-encoding", "location", "upgrade").none { it in fields })
                val text = checkNotNull(fields["content-length"])
                check(Regex("[1-9][0-9]{0,3}").matches(text))
                val length = text.toInt().also { check(it in 1..4096) }
                val body = ByteArray(length)
                DataInputStream(tls.inputStream).readFully(body)
                check(tls.inputStream.read() == -1)
                binding.bind(body, checkNotNull(fields["x-freekit-ca-sha256"]))
            }
            ensureRunning(call)
            binding.validateCurrent(manager)
            // CA validity is rechecked after all bytes and actual EOF, alongside the credential.
            result.certificate.checkValidity()
        } catch (caught: Exception) {
            failure = when {
                closed.get() -> DraftInterceptionCaException(DraftInterceptionCaFailure.CLOSED)
                call.timedOut.get() || System.nanoTime() - call.expiresNanos >= 0 -> DraftInterceptionCaException(DraftInterceptionCaFailure.TRANSPORT)
                caught is DraftInterceptionCaException -> caught
                else -> DraftInterceptionCaException(DraftInterceptionCaFailure.TRANSPORT)
            }
        } finally {
            try {
                cleanup(call)
            } catch (_: Exception) {
                cleanupFailed.set(true)
                if (failure == null) failure = DraftInterceptionCaException(DraftInterceptionCaFailure.CLEANUP)
            }
        }
        failure?.let { throw it }
        binding.validateCurrent(manager)
        val validated = result ?: fail(DraftInterceptionCaFailure.TRANSPORT)
        DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.RESPONSE) { validated.certificate.checkValidity() }
        synchronized(admission) {
            // Provider work never holds the cancellation/admission lock; check its elapsed time too.
            ensureRunning(call)
            return validated
        }
    }

    private fun readHeaders(tls: SSLSocket): Pair<Int, Map<String, String>> = response {
        val bytes = ByteArrayOutputStream(); var suffix = 0
        val input = tls.inputStream
        while (bytes.size() < 8192 && suffix != 0x0d0a0d0a) {
            val next = input.read()
            if (next < 0) throw EOFException()
            check(next == 9 || next == 10 || next == 13 || next in 32..126)
            bytes.write(next); suffix = (suffix shl 8) or next
        }
        check(suffix == 0x0d0a0d0a)
        val lines = bytes.toString("US-ASCII").split("\r\n")
        check(Regex("HTTP/1\\.1 [1-5][0-9]{2} [A-Za-z ]{1,64}").matches(lines.first()))
        val fields = LinkedHashMap<String, String>()
        for (line in lines.drop(1).dropLast(2)) {
            check(line.length in 1..1024 && fields.size < 32 && ':' in line)
            val name = line.substringBefore(':'); val value = line.substringAfter(':').trim(' ', '\t')
            check(Regex("[A-Za-z0-9-]{1,64}").matches(name) && value.all { it.code in 32..126 })
            check(fields.put(name.lowercase(Locale.ROOT), value) == null)
        }
        lines.first().substring(9, 12).toInt() to fields
    }

    private fun <T> response(action: () -> T): T = try { action() }
        catch (_: SocketTimeoutException) { fail(DraftInterceptionCaFailure.TRANSPORT) }
        catch (failure: DraftInterceptionCaException) { throw failure }
        catch (_: Exception) { fail(DraftInterceptionCaFailure.RESPONSE) }

    private fun ensureRunning(call: Call) {
        if (closed.get() || Thread.currentThread().isInterrupted) fail(DraftInterceptionCaFailure.CLOSED)
        if (call.timedOut.get() || System.nanoTime() - call.expiresNanos >= 0) fail(DraftInterceptionCaFailure.TRANSPORT)
    }

    private fun cleanup(call: Call) {
        // Never flush on teardown: raw interruption must not wait behind a TLS writer.
        call.interrupt()
        try { call.deadline.get()?.interrupt() } catch (_: Exception) { call.closeFailed.set(true) }
        call.tls.get()?.let { tls ->
            val closer = Thread({ try { tls.close() } catch (_: Exception) { call.closeFailed.set(true) } },
                "interception-ca-tls-close").apply { isDaemon = true }
            call.closer.set(closer); closer.start()
        }
        var interrupted = Thread.interrupted()
        val limit = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        try {
            for (worker in listOfNotNull(call.deadline.get(), call.closer.get())) {
                while (worker.isAlive) {
                    val remaining = limit - System.nanoTime()
                    if (remaining <= 0) fail(DraftInterceptionCaFailure.CLEANUP)
                    try { TimeUnit.NANOSECONDS.timedJoin(worker, remaining) }
                    catch (_: InterruptedException) { interrupted = true }
                }
            }
            if (call.closeFailed.get() || call.raw.get()?.isClosed == false || call.tls.get()?.isClosed == false)
                fail(DraftInterceptionCaFailure.CLEANUP)
            call.cleaned.set(true)
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }

    fun snapshot(): DraftInterceptionCaClientSnapshot {
        val call = active.get()
        return DraftInterceptionCaClientSnapshot(closed.get(), call != null, call?.raw?.get() != null,
            call?.tls?.get() != null, call?.deadline?.get()?.isAlive == true, call?.closer?.get()?.isAlive == true, cleanupFailed.get())
    }

    override fun close() {
        val call = synchronized(admission) { closed.set(true); active.get() }
        call?.interrupt()
        var interrupted = Thread.interrupted()
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        try {
            while (call != null && call.ownerDone.count != 0L) {
                val remaining = until - System.nanoTime()
                if (remaining <= 0) { cleanupFailed.set(true); fail(DraftInterceptionCaFailure.CLEANUP) }
                try { call.ownerDone.await(remaining, TimeUnit.NANOSECONDS) }
                catch (_: InterruptedException) { interrupted = true }
            }
            if (active.get() != null || cleanupFailed.get()) fail(DraftInterceptionCaFailure.CLEANUP)
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }

    override fun toString() = "DraftInterceptionCaClient([REDACTED])"
    private fun fail(code: DraftInterceptionCaFailure): Nothing = throw DraftInterceptionCaException(code)
}
