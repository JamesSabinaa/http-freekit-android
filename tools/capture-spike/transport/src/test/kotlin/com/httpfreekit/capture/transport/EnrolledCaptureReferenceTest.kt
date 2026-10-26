package com.httpfreekit.capture.transport

import com.httpfreekit.capture.CaptureSocketGuard
import com.httpfreekit.capture.CaptureTcpConnection
import com.httpfreekit.capture.transport.CaptureReferenceNodePeer.Companion.bool
import com.httpfreekit.capture.transport.CaptureReferenceNodePeer.Companion.hash
import com.httpfreekit.capture.transport.CaptureReferenceNodePeer.Companion.number
import com.httpfreekit.capture.transport.CaptureReferenceNodePeer.Companion.text
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Separate host-only software-key proof. No desktop checkout, Android trust installation or TUN. */
class EnrolledCaptureReferenceTest {
    @Test(timeout = 90_000) fun actualHttpReachesIndependentOriginAndCompletesBeforeStop() = positive(secure = false)

    @Test(timeout = 90_000) fun strictJsseH1HttpsReachesIndependentOriginAndCompletesBeforeStop() = positive(secure = true)

    @Test(timeout = 90_000) fun wrongScopedInterceptionTrustFailsWithoutOriginDispatch() = rejected(wrongTrust = true)

    @Test(timeout = 90_000) fun wrongVerifiedHostnameWithControlledNoSniFailsWithoutOriginDispatch() = rejected(wrongTrust = false)

    @Test(timeout = 90_000) fun activeOwnerRevocationJoinsAndSubsequentlyRefusesCredential() = runCase(permitFailure = true) { peer, factory, _ ->
        heldFlow(factory) {
            peer.awaitSnapshot { it.backend().number("activeOwners") == 1L }
            peer.revoke()
            val state = peer.awaitSnapshot { value ->
                val stream = value["stream"] as? JsonObject
                stream != null && stream.bool("resourcesReleased") && stream.bool("cleanupComplete") &&
                    value.backend().number("activeOwners") == 0L
            }
            terminalFailure(state)
            noDispatch(state)
            assertEquals(1L, state.backend().number("ownersCreated"))
            assertEquals(1L, state.backend().number("ownersClosed"))
            // New factory, same exact approved credential: a closed old owner is not a refusal proof.
            val subsequent = EnrolledCaptureTcpFactory(peer.configuration, peer.endpoint, Guard())
            val cleanup = ReferenceCleanup()
            cleanup.attempt("subsequent credential refusal") {
                var refused = false
                var unexpected: CaptureTcpConnection? = null
                try { unexpected = subsequent.open(ORIGINAL, 80) }
                catch (_: com.httpfreekit.capture.CaptureException) { refused = true }
                unexpected?.use { it.interrupt(); error("Revoked credential admitted") }
                assertTrue("Subsequent credential must be refused", refused)
            }
            cleanup.attempt("subsequent factory close") { subsequent.close() }
            cleanup.attempt("subsequent factory join") { joined(subsequent, permitFailure = true) }
            cleanup.finish()
            val after = peer.snapshot()
            noDispatch(after)
            assertEquals(1L, after.backend().number("ownersCreated"))
        }
    }

    @Test(timeout = 90_000) fun stopWithHeldBackendOwnerCancelsAndJoinsAllOwners() = runCase(permitFailure = true) { peer, factory, _ ->
        heldFlow(factory) {
            val active = peer.awaitSnapshot { it.backend().number("activeOwners") == 1L }
            assertEquals(1L, active.backend().number("ownersCreated"))
            // No application bytes: CONNECT was already emitted by the real factory.
            noDispatch(active)
            factory.close()
            joined(factory, permitFailure = true)
            val state = peer.awaitSnapshot { value ->
                val stream = value["stream"] as? JsonObject
                stream != null && stream.bool("resourcesReleased") && stream.bool("cleanupComplete") &&
                    value.backend().number("activeOwners") == 0L
            }
            terminalFailure(state)
            noDispatch(state)
            assertEquals(1L, state.backend().number("ownersClosed"))
        }
    }

    private fun positive(secure: Boolean) = runCase { peer, factory, guard ->
        val body = ByteArray(3073) { ((it * 17 + 3) % 251).toByte() }
        val expected = ("reference-origin:" + hex(hash(body))).toByteArray(Charsets.US_ASCII)
        ApplicationBridge(factory.open(ORIGINAL, if (secure) 443 else 80)).use { bridge ->
            val socket = if (secure) tls(bridge.app, peer.interceptionCa) else bridge.app
            socket.use {
                if (socket is SSLSocket) {
                    socket.startHandshake()
                    assertEquals("http/1.1", socket.applicationProtocol)
                    assertTrue(socket.session.protocol in setOf("TLSv1.2", "TLSv1.3"))
                }
                socket.soTimeout = 8_000
                socket.outputStream.write(("POST /reference/proof HTTP/1.1\r\nHost: $HOST\r\n" +
                    "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
                socket.outputStream.write(body)
                socket.outputStream.flush()
                // Actual application half-close, including the TLS close_notify on HTTPS.
                socket.shutdownOutput()
                responseHeader(socket.inputStream, expected.size)
                assertTrue("Full actual response comparison", exactly(socket.inputStream, expected.size).contentEquals(expected))
                // Strict JSSE must observe a real close_notify, not merely transport EOF.
                assertEquals(-1, socket.inputStream.read())
            }
            bridge.finish()
            val state = peer.awaitSnapshot { value ->
                val stream = value["stream"] as? JsonObject
                stream != null && stream.text("phase") == "complete" && stream.bool("resourcesReleased") &&
                    value.backend().number("activeOwners") == 0L
            }
            val stream = state.getValue("stream").jsonObject
            assertTrue(stream.bool("clientEofEmitted")); assertTrue(stream.bool("gatewayEofEmitted"))
            assertFalse(stream.bool("streamLease")); assertEquals(0L, stream.number("chargedBytes"))
            assertEquals(0L, stream.number("fixtureUploadBytesRead")); assertEquals(0L, stream.number("fixtureResponseBytesWritten"))
            successfulEvidence(state, secure, body, expected)
            // Control + stream protection/binding, without any direct destination dial.
            assertEquals(2, guard.protects.get()); assertEquals(2, guard.binds.get())
        }
    }

    private fun rejected(wrongTrust: Boolean) = runCase(permitFailure = true) { peer, factory, _ ->
        ApplicationBridge(factory.open(ORIGINAL, 443)).use { bridge ->
            val trust = if (wrongTrust) HeldCertificate.Builder().certificateAuthority(0).build().certificate else peer.interceptionCa
            // Explicit absence avoids JSSE preferring a valid SNI name over the deliberately wrong peerHost.
            // The fixed default leaf is sent before the backend's secureConnection SNI gate can run.
            tls(bridge.app, trust, if (wrongTrust) HOST else "wrong-reference-target.invalid", sendSni = wrongTrust).use { socket ->
                var rejected = false
                try { socket.startHandshake() } catch (failure: SSLException) {
                    rejected = generateSequence(failure as Throwable?) { it.cause }.take(12).any { it is CertificateException }
                }
                assertTrue("Actual scoped certificate/hostname rejection required", rejected)
            }
        }
        val state = peer.awaitSnapshot { value ->
            val stream = value["stream"] as? JsonObject
            stream != null && stream.bool("resourcesReleased") && value.backend().number("activeOwners") == 0L
        }
        terminalFailure(state)
        noDispatch(state)
        assertEquals(0L, state.backend().number("interceptionTlsHandshakes"))
        assertEquals(1L, state.backend().number("ownersCreated"))
        assertEquals(1L, state.backend().number("ownersClosed"))
    }

    private fun heldFlow(factory: EnrolledCaptureTcpFactory, action: () -> Unit) {
        val flow = factory.open(ORIGINAL, 80)
        val cleanup = ReferenceCleanup()
        cleanup.attempt("held flow case", action)
        cleanup.attempt("held flow interrupt") { flow.interrupt() }
        cleanup.attempt("held flow close") { flow.close() }
        cleanup.finish()
    }

    /** Attempt all independent cleanup and retain sanitized primary + suppressed failures. */
    private fun runCase(permitFailure: Boolean = false, block: (CaptureReferenceNodePeer, EnrolledCaptureTcpFactory, Guard) -> Unit) {
        assertEquals("true", System.getProperty("com.sun.net.ssl.requireCloseNotify"))
        val cleanup = ReferenceCleanup()
        var peer: CaptureReferenceNodePeer? = null
        var factory: EnrolledCaptureTcpFactory? = null
        cleanup.attempt("case") {
            val owner = CaptureReferenceNodePeer().also { peer = it }
            val guard = Guard()
            val transport = EnrolledCaptureTcpFactory(owner.configuration, owner.endpoint, guard).also { factory = it }
            block(owner, transport, guard)
        }
        cleanup.attempt("factory close") { factory?.close() }
        cleanup.attempt("factory join") { factory?.let { joined(it, permitFailure) } }
        cleanup.attempt("JVM budget join") {
            peer?.configuration?.pool?.snapshot()?.let {
                check(it.sessionLeases == 0 && it.streamLeases == 0 && it.chargedBytes == 0L)
            }
        }
        cleanup.attempt("peer close") { peer?.close() }
        cleanup.attempt("peer join") { peer?.let { check(it.joined) } }
        cleanup.finish()
    }

    /** Only actual socket bytes and EOF traverse this bounded synchronous bridge. */
    private class ApplicationBridge(private val flow: CaptureTcpConnection) : AutoCloseable {
        private val pair = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { listener ->
            listener.soTimeout = 3_000
            val client = Socket(InetAddress.getLoopbackAddress(), listener.localPort)
            try { client to listener.accept() } catch (failure: Throwable) { client.close(); throw failure }
        }
        val app: Socket = pair.first
        private val relay = pair.second
        private val workers = Executors.newFixedThreadPool(2)
        private val failures = ConcurrentLinkedQueue<Throwable>()
        private val cleanupFailures = ConcurrentLinkedQueue<Throwable>()
        private val uploadEof = AtomicBoolean()
        private val downloadEof = AtomicBoolean()
        private var finished = false
        private val outgoing = workers.submit {
            try {
                relay.inputStream.copyTo(flow.output, 8192)
                flow.shutdownOutput(); uploadEof.set(true)
            } catch (failure: Throwable) { failed(failure) }
        }
        private val incoming = workers.submit {
            try {
                flow.input.copyTo(relay.outputStream, 8192)
                downloadEof.set(true); relay.shutdownOutput()
            } catch (failure: Throwable) { failed(failure) }
        }
        private fun failed(failure: Throwable) {
            failures.add(referenceFailure("bridge pump", failure))
            try { flow.interrupt() } catch (caught: Throwable) { cleanupFailures.add(referenceFailure("bridge interrupt", caught)) }
            try { relay.close() } catch (caught: Throwable) { cleanupFailures.add(referenceFailure("bridge socket close", caught)) }
        }
        fun finish() {
            val cleanup = ReferenceCleanup()
            cleanup.attempt("application close") { app.close() }
            cleanup.attempt("upload join") { outgoing.get(5, TimeUnit.SECONDS) }
            cleanup.attempt("download join") { incoming.get(5, TimeUnit.SECONDS) }
            for (failure in failures) cleanup.attempt("bridge result") { throw failure }
            cleanup.attempt("directional EOF") { check(uploadEof.get() && downloadEof.get()) }
            // The actual factory close joins its remote 1000 Close/COMPLETE; no synthesized completion.
            cleanup.attempt("graceful flow close") { flow.close() }
            cleanup.finish()
            finished = true
        }
        override fun close() {
            val cleanup = ReferenceCleanup()
            cleanup.attempt("application close") { app.close() }
            if (!finished) cleanup.attempt("flow interrupt") { flow.interrupt() }
            cleanup.attempt("relay close") { relay.close() }
            cleanup.attempt("flow close") { flow.close() }
            cleanup.attempt("upload pump join") { outgoing.get(5, TimeUnit.SECONDS) }
            cleanup.attempt("download pump join") { incoming.get(5, TimeUnit.SECONDS) }
            cleanup.attempt("bridge executor shutdown") { workers.shutdownNow() }
            cleanup.attempt("bridge executor join") { check(workers.awaitTermination(5, TimeUnit.SECONDS)) }
            // Failed/cancelled cases intentionally interrupt their pumps. Positive finish checked every pump error.
            // Independent interrupt/socket cleanup failures remain failures even on negative paths.
            for (failure in cleanupFailures) cleanup.attempt("bridge independent cleanup") { throw failure }
            cleanup.finish()
        }
    }

    private class Guard : CaptureSocketGuard {
        val protects = AtomicInteger(); val binds = AtomicInteger()
        override fun protect(socket: Socket): Boolean { assertFalse(socket.isConnected); protects.incrementAndGet(); return true }
        override fun bind(socket: Socket) { assertFalse(socket.isConnected); binds.incrementAndGet() }
        override fun protect(socket: DatagramSocket) = false
        override fun bind(socket: DatagramSocket): Unit = throw AssertionError("Unexpected reference UDP")
    }

    companion object {
        private const val HOST = "reference-target.invalid"
        private val ORIGINAL = InetAddress.getByAddress(byteArrayOf(198.toByte(), 18, 0, 2))
        private fun JsonObject.backend(): JsonObject = getValue("backend").jsonObject
        private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
        private fun tls(raw: Socket, ca: X509Certificate, verifiedHost: String = HOST, sendSni: Boolean = true): SSLSocket {
            val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null); setCertificateEntry("approved-interception", ca) }
            val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
            val context = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
            return (context.socketFactory.createSocket(raw, verifiedHost, 443, true) as SSLSocket).apply {
                soTimeout = 8_000
                enabledProtocols = supportedProtocols.filter { it in setOf("TLSv1.2", "TLSv1.3") }.toTypedArray()
                sslParameters = sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    serverNames = if (sendSni) listOf(SNIHostName(HOST)) else emptyList()
                    applicationProtocols = arrayOf("http/1.1")
                }
            }
        }
        private fun exactly(input: InputStream, count: Int): ByteArray {
            val bytes = ByteArray(count); var offset = 0
            while (offset < count) { val size = input.read(bytes, offset, count - offset); check(size > 0); offset += size }
            return bytes
        }
        private fun responseHeader(input: InputStream, length: Int) {
            val bytes = ByteArrayOutputStream(); var tail = 0
            while (tail != 0x0d0a0d0a) {
                val value = input.read(); check(value >= 0 && bytes.size() < 4096)
                bytes.write(value); tail = (tail shl 8) or value
            }
            val lines = bytes.toString(Charsets.US_ASCII).split("\r\n")
            assertTrue("Actual origin response status", lines.first() == "HTTP/1.1 200 OK")
            assertEquals(1, lines.count { it.startsWith("content-length:", ignoreCase = true) })
            assertTrue(lines.any { it.equals("content-length: $length", ignoreCase = true) })
            assertFalse(lines.any { it.startsWith("transfer-encoding:", ignoreCase = true) })
        }
        private fun successfulEvidence(state: JsonObject, secure: Boolean, body: ByteArray, expected: ByteArray) {
            val backend = state.backend()
            assertEquals(1L, backend.number("ownersCreated")); assertEquals(1L, backend.number("ownersClosed"))
            assertEquals(0L, backend.number("activeOwners")); assertEquals(1L, backend.number("upstreamDials"))
            for (name in listOf("interceptedHttpRequests", "upstreamHttpRequests")) assertEquals(if (secure) 0L else 1L, backend.number(name))
            for (name in listOf("interceptedHttpsRequests", "upstreamHttpsRequests", "interceptionTlsHandshakes", "upstreamTlsHandshakes"))
                assertEquals(if (secure) 1L else 0L, backend.number(name))
            val rows = state.getValue("evidence").jsonArray
            assertEquals(1, rows.size)
            val row = rows.single().jsonObject
            assertTrue("Private origin mode comparison", row.text("mode") == if (secure) "https" else "http")
            assertEquals(body.size.toLong(), row.number("requestBytes")); assertEquals(expected.size.toLong(), row.number("responseBytes"))
            assertTrue("Private origin upload comparison", row.text("requestSha256") == hex(hash(body)))
            assertTrue("Private origin response comparison", row.text("responseSha256") == hex(hash(expected)))
        }
        private fun noDispatch(state: JsonObject) {
            for (name in listOf("upstreamDials", "interceptedHttpRequests", "interceptedHttpsRequests", "upstreamHttpRequests",
                "upstreamHttpsRequests", "upstreamTlsHandshakes")) assertEquals(0L, state.backend().number(name))
            assertEquals(0, state.getValue("evidence").jsonArray.size)
        }
        private fun terminalFailure(state: JsonObject) {
            val stream = state.getValue("stream").jsonObject
            assertTrue(stream.text("phase") in setOf("failed", "cancelled"))
            assertTrue(stream.bool("resourcesReleased")); assertFalse(stream.bool("streamLease"))
            assertEquals(0L, stream.number("chargedBytes"))
            assertEquals(0L, stream.number("fixtureUploadBytesRead")); assertEquals(0L, stream.number("fixtureResponseBytesWritten"))
        }
        private fun joined(factory: EnrolledCaptureTcpFactory, permitFailure: Boolean) {
            val state = factory.snapshot()
            assertTrue(state.closed); assertTrue(state.admissionClosed)
            if (!permitFailure) assertEquals(null, state.failureCode)
            assertEquals(0, state.pendingOpens); assertEquals(0, state.pendingCalls)
            assertEquals(0, state.retainedTransports); assertEquals(0, state.liveWorkers)
            assertFalse(state.sessionLease); assertEquals(0, state.streamLeases); assertEquals(0L, state.chargedBytes)
            assertEquals(0L, state.pendingIngressBytes); assertEquals(0L, state.backendOutputBytes); assertEquals(0L, state.backendIncomingBytes)
        }
    }
}
