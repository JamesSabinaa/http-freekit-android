package com.httpfreekit.interop

import com.httpfreekit.protocol.*
import com.httpfreekit.security.GatewayTlsConnectionFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.SocketFactory
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager

/** An empty response after a validated TLS connection and completed request; never an automatic retry. */
internal class DraftEnrollmentResponseLost : IOException("Enrollment research response was lost")
internal class DraftEnrollmentTransportFailure : IOException("Enrollment research transport failed")

/** Fixed research routes, fresh scoped TLS and one synchronously owned exchange at a time. */
internal class DraftEnrollmentHttpsClient(
    gatewayCertificate: X509Certificate, private val pin: String, private val logicalName: String,
    private val setupPort: Int, private val credentialPort: Int,
) : AutoCloseable {
    private val gateway = certificate(gatewayCertificate.encoded)
    private val closed = AtomicBoolean(false)
    private val cleanupFailed = AtomicBoolean(false)
    private val active = AtomicReference<Call?>()
    private val admission = Any()
    init { validateTrust(gateway, pin, logicalName); require(setupPort in 1..65535 && credentialPort in 1..65535 && setupPort != credentialPort) }

    fun exchange(request: DraftEnrollmentMessage): DraftEnrollmentMessage {
        val (path, responseChannel) = when (request) {
            is DraftEnrollmentMessage.Pair -> "/companion/v1/pair" to DraftEnrollmentChannel.PAIR_RESPONSE
            is DraftEnrollmentMessage.ChallengeRequest -> "/companion/v1/pair/status" to DraftEnrollmentChannel.CHALLENGE_RESPONSE
            is DraftEnrollmentMessage.StatusRequest -> "/companion/v1/pair/status" to DraftEnrollmentChannel.STATUS_RESPONSE
            is DraftEnrollmentMessage.CancelRequest -> "/companion/v1/pair/cancel" to DraftEnrollmentChannel.CANCEL_RESPONSE
            else -> throw DraftEnrollmentStateException()
        }
        val reply = request("POST", path, setupPort, DraftEnrollmentCodec.encode(request), null)
        val decoded = DraftEnrollmentCodec.decode(responseChannel, reply.body) as? DraftEnrollmentDecodeResult.Accepted
            ?: throw DraftEnrollmentStateException()
        val expected = (decoded.message as? DraftEnrollmentMessage.Error)?.code?.let { code -> when (code) {
            "invalid_message", "unsupported_version", "unsupported_capability" -> 400
            "message_too_large" -> 413
            "authentication_failed" -> 403
            "invitation_expired", "invitation_used" -> 409
            "pairing_limit" -> 429
            "pairing_unavailable" -> 503
            else -> throw DraftEnrollmentStateException()
        } } ?: 200
        check(reply.status == expected) { "Enrollment HTTP and DTO disagreed" }
        return decoded.message
    }

    fun authenticateSaved(manager: X509ExtendedKeyManager) {
        val reply = request("GET", "/research/enrollment/credential", credentialPort, byteArrayOf(), manager)
        check(reply.status == 200 && reply.body.contentEquals("{\"type\":\"credential_admitted\"}".toByteArray(Charsets.US_ASCII))) {
            "Saved enrollment credential was not admitted"
        }
    }

    private class Reply(val status: Int, val body: ByteArray) {
        override fun toString() = "EnrollmentHttpReply([REDACTED])"
    }
    private class Call {
        val raw = AtomicReference<Socket?>()
        val tls = AtomicReference<SSLSocket?>()
        val interruptedFailure = AtomicBoolean(false)
        val timedOut = AtomicBoolean(false)
        val done = CountDownLatch(1)
        var sent = false
        var headerBytes = 0
        fun interrupt() { try { raw.get()?.close() } catch (_: Exception) { interruptedFailure.set(true) } }
    }
    private fun request(method: String, path: String, port: Int, body: ByteArray, manager: X509ExtendedKeyManager?): Reply {
        require(body.size <= 16384)
        val call = Call()
        synchronized(admission) { check(!closed.get() && active.compareAndSet(null, call)) { "Enrollment client admission failed" } }
        val deadline = Thread({
            try { Thread.sleep(10000); call.timedOut.set(true); call.interrupt() }
            catch (_: InterruptedException) { /* The completed owner joins this timer. */ }
        }, "enrollment-http-deadline").apply { isDaemon = true; start() }
        try {
            val rawFactory = object : SocketFactory() {
                override fun createSocket(): Socket {
                    check(!closed.get() && !call.timedOut.get()) { "Enrollment request stopped" }
                    return Socket().also {
                        call.raw.set(it); it.tcpNoDelay = true
                        if (closed.get() || call.timedOut.get()) { call.interrupt(); throw DraftEnrollmentTransportFailure() }
                    }
                }
                override fun createSocket(host: String?, port: Int): Socket = error("Unowned enrollment socket overload")
                override fun createSocket(host: String?, port: Int, local: InetAddress?, localPort: Int): Socket = error("Unowned enrollment socket overload")
                override fun createSocket(host: InetAddress?, port: Int): Socket = error("Unowned enrollment socket overload")
                override fun createSocket(host: InetAddress?, port: Int, local: InetAddress?, localPort: Int): Socket = error("Unowned enrollment socket overload")
            }
            val tls = GatewayTlsConnectionFactory(gateway, pin, logicalName, 5000, 5000,
                rawSocketFactory = rawFactory, clientKeyManager = manager)
                .connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
            call.tls.set(tls); tls.soTimeout = 5000
            val header = buildString {
                append("$method $path HTTP/1.1\r\nHost: $logicalName:$port\r\nConnection: close\r\n")
                if (method == "POST") append("Content-Type: application/json\r\nContent-Length: ${body.size}\r\n")
                append("\r\n")
            }
            tls.outputStream.write(header.toByteArray(Charsets.US_ASCII)); tls.outputStream.write(body); tls.outputStream.flush()
            call.sent = true
            val head = headers(tls, call)
            val lengthText = checkNotNull(head.second["content-length"])
            check(Regex("0|[1-9][0-9]{0,4}").matches(lengthText)) { "Invalid enrollment response length" }
            val length = lengthText.toInt().also { check(it in 1..16384) { "Enrollment response exceeded bound" } }
            check(head.second["content-type"] == "application/json" && head.second["connection"]?.lowercase() == "close" &&
                setOf("transfer-encoding", "trailer", "upgrade").none { it in head.second }) { "Invalid enrollment response framing" }
            val response = ByteArray(length).also { DataInputStream(tls.inputStream).readFully(it) }
            check(tls.inputStream.read() == -1) { "Enrollment response contained trailing bytes" }
            return Reply(head.first, response)
        } catch (failure: IOException) {
            if (call.sent && call.headerBytes == 0 && (failure is EOFException || failure is SocketException) &&
                !call.timedOut.get() && !closed.get() && !Thread.currentThread().isInterrupted) throw DraftEnrollmentResponseLost()
            throw DraftEnrollmentTransportFailure()
        } finally {
            // Raw interruption is independent of any TLS writer/provider close lock.
            call.interrupt(); deadline.interrupt()
            val closeFailed = AtomicBoolean(false)
            val closer = call.tls.get()?.let { tls -> Thread({
                try { tls.close() } catch (_: Exception) { closeFailed.set(true) }
            }, "enrollment-tls-close").apply { isDaemon = true; start() } }
            var joined = true
            try { deadline.join(2000) } catch (_: InterruptedException) { joined = false; Thread.currentThread().interrupt() }
            try { closer?.join(2000) } catch (_: InterruptedException) { joined = false; Thread.currentThread().interrupt() }
            val clean = joined && !deadline.isAlive && closer?.isAlive != true && !closeFailed.get() && !call.interruptedFailure.get() &&
                call.raw.get()?.isClosed != false && call.tls.get()?.isClosed != false
            if (clean) { active.compareAndSet(call, null); call.done.countDown() }
            else { cleanupFailed.set(true); error("Enrollment HTTP resources did not close and join") }
        }
    }

    private fun headers(socket: SSLSocket, call: Call): Pair<Int, Map<String, String>> {
        val bytes = ByteArrayOutputStream(); var suffix = 0
        while (bytes.size() < 8192 && suffix != 0x0d0a0d0a) {
            val next = socket.inputStream.read()
            if (next < 0) throw EOFException("Enrollment response closed")
            call.headerBytes++
            check(next == 9 || next == 10 || next == 13 || next in 32..126) { "Invalid enrollment response byte" }
            bytes.write(next); suffix = (suffix shl 8) or next
        }
        check(suffix == 0x0d0a0d0a) { "Enrollment headers exceeded bound" }
        val lines = bytes.toString("US-ASCII").split("\r\n")
        check(Regex("HTTP/1\\.1 [1-5][0-9]{2} [A-Za-z ]{1,64}").matches(lines[0])) { "Invalid enrollment HTTP status" }
        val fields = linkedMapOf<String, String>()
        for (line in lines.drop(1).filter { it.isNotEmpty() }) {
            check(fields.size < 32 && line.length <= 1024 && ':' in line) { "Invalid enrollment HTTP header" }
            val name = line.substringBefore(':'); val value = line.substringAfter(':').trim()
            check(Regex("[A-Za-z0-9-]{1,64}").matches(name) && value.all { it.code in 32..126 }) { "Invalid enrollment header value" }
            check(fields.put(name.lowercase(), value) == null) { "Duplicate enrollment response header" }
        }
        return lines[0].substring(9, 12).toInt() to fields
    }

    override fun close() {
        val current = synchronized(admission) { closed.set(true); active.get() }
        current?.interrupt()
        check(current == null || current.done.await(5000, TimeUnit.MILLISECONDS)) { "Enrollment client still owns a request" }
        check(active.get() == null && !cleanupFailed.get()) { "Enrollment client cleanup failed" }
    }
    override fun toString() = "DraftEnrollmentHttpsClient([REDACTED])"

    companion object {
        fun certificate(bytes: ByteArray): X509Certificate {
            require(bytes.size in 1..4096)
            val input = ByteArrayInputStream(bytes)
            val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
            check(input.available() == 0 && certificate.encoded.contentEquals(bytes)) { "Invalid research certificate encoding" }
            return certificate
        }
        fun validateTrust(certificate: X509Certificate, pin: String, name: String) {
            GatewayTlsConnectionFactory(certificate, pin, name, 5000, 5000)
            check(certificate.subjectAlternativeNames.orEmpty().any { it.size == 2 && it[0] == 2 &&
                it[1] is String && name.equals(it[1] as String, ignoreCase = true) }) { "Research gateway DNS identity mismatch" }
        }
    }
}
