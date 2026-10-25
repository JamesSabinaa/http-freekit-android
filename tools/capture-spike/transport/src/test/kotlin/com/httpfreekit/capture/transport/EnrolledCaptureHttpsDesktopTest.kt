package com.httpfreekit.capture.transport

import com.httpfreekit.capture.CaptureSocketGuard
import com.httpfreekit.capture.CaptureTcpConnection
import com.httpfreekit.capture.transport.CaptureOriginNodePeer.Companion.bool
import com.httpfreekit.capture.transport.CaptureOriginNodePeer.Companion.number
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.json.jsonObject
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Explicit C3 local proof. The factory's default required capability set is preserved. */
class EnrolledCaptureHttpsDesktopTest {
    @Test(timeout = 45_000) fun realVerifiedInnerHttpsUsesOriginalIpv4AndActualInterceptionCa() = positive("ipv4")

    @Test(timeout = 45_000) fun realVerifiedInnerHttpsUsesOriginalIpv6AndActualInterceptionCa() = positive("ipv6")

    @Test(timeout = 45_000) fun wrongInnerCaFailsBeforeOriginEgressWithoutFallback() = rejected(wrongCa = true)

    @Test(timeout = 45_000) fun wrongInnerHostnameFailsBeforeOriginEgressWithoutFallback() = rejected(wrongCa = false)

    @Test(timeout = 45_000) fun actualHttpUpgradePreservesCoalescedMessagesAndPeerClose() = upgrade(secure = false)

    @Test(timeout = 45_000) fun actualHttpsUpgradePreservesCoalescedMessagesAndPeerClose() = upgrade(secure = true)

    private fun upgrade(secure: Boolean) {
        assertEquals("true", System.getProperty("com.sun.net.ssl.requireCloseNotify"))
        CaptureOriginNodePeer(if (secure) "wss-h1" else "http-upgrade").use { peer ->
            val factory = EnrolledCaptureTcpFactory(peer.configuration, peer.endpoint, Guard())
            try {
                ApplicationBridge(factory.open(original("ipv4"), if (secure) 443 else 80)).use { bridge ->
                    val app = if (secure) tls(bridge.app, requireNotNull(peer.interceptionCa)).apply { startHandshake() } else bridge.app.apply { soTimeout = 8_000 }
                    app.use {
                        InnerUpgradePeer(app).exchange()
                        app.shutdownOutput()
                    }
                    bridge.finish()
                }
                val origin = peer.snapshot().getValue("origin").jsonObject
                assertEquals(1L, origin.number("upgradeRequests")); assertTrue(origin.bool("upgradeAccepted"))
                assertEquals(1L, origin.number("clientTextMessages")); assertEquals(1L, origin.number("clientBinaryMessages"))
                assertEquals(4097L, origin.number("clientBinaryBytes"))
                assertEquals(1L, origin.number("clientPings")); assertEquals(1L, origin.number("clientPongs"))
                assertTrue(origin.bool("clientCloseObserved")); assertTrue(origin.bool("serverCloseWritten"))
                assertTrue(origin.bool("originalDestinationMatched")); assertFalse(origin.bool("failed"))
            } finally { factory.close() }
            joined(factory)
        }
    }

    private fun positive(family: String) {
        assertEquals("true", System.getProperty("com.sun.net.ssl.requireCloseNotify"))
        CaptureOriginNodePeer("https-h1", family).use { peer ->
            val guard = Guard()
            val factory = EnrolledCaptureTcpFactory(peer.configuration, peer.endpoint, guard)
            try {
                ApplicationBridge(factory.open(original(family), 443)).use { bridge ->
                    tls(bridge.app, requireNotNull(peer.interceptionCa)).use { socket ->
                        socket.startHandshake()
                        assertEquals("http/1.1", socket.applicationProtocol)
                        socket.outputStream.write(("POST /factory-research HTTP/1.1\r\nHost: $HOST\r\n" +
                            "Content-Length: $REQUEST\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
                        socket.outputStream.write(ByteArray(REQUEST) { (it % 251).toByte() })
                        socket.outputStream.flush()
                        responseHeader(socket.inputStream)
                        assertTrue(exactly(socket.inputStream, RESPONSE).contentEquals(ByteArray(RESPONSE) { ((it * 7) % 253).toByte() }))
                        // JSSE is configured to reject TCP EOF without an actual TLS close_notify.
                        assertEquals(-1, socket.inputStream.read())
                        socket.shutdownOutput()
                    }
                    bridge.finish()
                }
                val snapshot = peer.snapshot()
                val origin = snapshot.getValue("origin").jsonObject
                assertEquals(1L, origin.number("requests"))
                assertEquals(1L, origin.number("tlsConnections"))
                assertTrue(origin.bool("tlsSniMatched")); assertTrue(origin.bool("tlsAlpnH1"))
                assertTrue(origin.bool("requestVerified")); assertTrue(origin.bool("captureMatched"))
                assertTrue(origin.bool("originalDestinationMatched")); assertFalse(origin.bool("failed"))
                assertEquals(REQUEST.toLong(), origin.number("requestBodyBytes"))
                assertEquals(RESPONSE.toLong(), origin.number("responseBodyBytesWritten"))
                assertEquals(2, guard.protects.get()); assertEquals(2, guard.binds.get())
            } finally { factory.close() }
            joined(factory)
        }
    }

    private fun rejected(wrongCa: Boolean) {
        assertEquals("true", System.getProperty("com.sun.net.ssl.requireCloseNotify"))
        CaptureOriginNodePeer("https-h1").use { peer ->
            val factory = EnrolledCaptureTcpFactory(peer.configuration, peer.endpoint, Guard())
            try {
                ApplicationBridge(factory.open(original("ipv4"), 443)).use { bridge ->
                    val trust = if (wrongCa) HeldCertificate.Builder().certificateAuthority(0).build().certificate else requireNotNull(peer.interceptionCa)
                    // Without SNI the MITM presents its numeric-IP leaf, which
                    // cannot identify the expected DNS peer HOST.
                    tls(bridge.app, trust, sendSni = wrongCa).use { socket ->
                        try { socket.startHandshake(); fail("Inner TLS identity must be verified") }
                        catch (failure: SSLException) {
                            assertTrue("Expected certificate rejection, not an arbitrary TLS I/O error",
                                generateSequence(failure as Throwable?) { it.cause }.take(8).any { it is java.security.cert.CertificateException })
                        }
                    }
                }
                val snapshot = peer.snapshot()
                assertEquals(0L, snapshot.getValue("origin").jsonObject.number("connections"))
                assertEquals(0L, snapshot.getValue("origin").jsonObject.number("requests"))
                assertEquals(0L, snapshot.getValue("backend").jsonObject.number("captures"))
            } finally { factory.close() }
            joined(factory, permitFailure = true)
        }
    }

    /** Real loopback app socket keeps JSSE socket semantics; only its bytes enter the factory. */
    private class ApplicationBridge(private val flow: CaptureTcpConnection) : AutoCloseable {
        private val pair = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { listener ->
            listener.soTimeout = 3_000
            val client = Socket(InetAddress.getLoopbackAddress(), listener.localPort)
            try { client to listener.accept() } catch (failure: Exception) { client.close(); throw failure }
        }
        val app: Socket = pair.first
        private val relay = pair.second
        private val workers = Executors.newFixedThreadPool(2)
        private val failed = AtomicBoolean()
        private val inputEof = AtomicBoolean()
        private val outputEof = AtomicBoolean()
        private var finished = false
        private val outgoing = workers.submit {
            try {
                relay.inputStream.copyTo(flow.output, 8192)
                flow.shutdownOutput(); outputEof.set(true)
            } catch (_: Exception) { interruptRelay() }
        }
        private val incoming = workers.submit {
            try {
                flow.input.copyTo(relay.outputStream, 8192)
                inputEof.set(true); relay.shutdownOutput()
            } catch (_: Exception) { interruptRelay() }
        }

        private fun interruptRelay() {
            failed.set(true)
            try { flow.interrupt() } catch (_: Exception) { /* Still close the socket below. */ }
            finally { try { relay.close() } catch (_: Exception) { /* Failure remains latched. */ } }
        }

        fun finish() {
            app.close()
            outgoing.get(5, TimeUnit.SECONDS); incoming.get(5, TimeUnit.SECONDS)
            assertFalse(failed.get()); assertTrue(inputEof.get()); assertTrue(outputEof.get())
            finished = true
        }

        override fun close() {
            var failure: Exception? = null
            var restoreInterrupt = Thread.interrupted()
            fun attempt(action: () -> Unit) {
                try { action() } catch (caught: Exception) {
                    if (caught is InterruptedException) restoreInterrupt = true
                    val previous = failure
                    if (previous == null) failure = caught else if (previous !== caught) previous.addSuppressed(caught)
                }
            }
            attempt { app.close() }
            if (!finished) attempt { flow.interrupt() }
            attempt { relay.close() }; attempt { flow.close() }
            attempt { workers.shutdownNow() }
            var joined = false
            attempt { joined = workers.awaitTermination(5, TimeUnit.SECONDS) }
            if (restoreInterrupt) Thread.currentThread().interrupt()
            assertTrue("Application bridge workers did not join", joined)
            failure?.let { throw it }
        }
    }

    private class Guard : CaptureSocketGuard {
        val protects = AtomicInteger(); val binds = AtomicInteger()
        override fun protect(socket: Socket): Boolean { assertFalse(socket.isConnected); protects.incrementAndGet(); return true }
        override fun bind(socket: Socket) { assertFalse(socket.isConnected); binds.incrementAndGet() }
        override fun protect(socket: DatagramSocket) = false
        override fun bind(socket: DatagramSocket): Unit = throw AssertionError("Unexpected UDP")
    }

    companion object {
        private const val HOST = "capture-origin.invalid"
        private const val REQUEST = 16421
        private const val RESPONSE = 32787
        private fun original(family: String): InetAddress = InetAddress.getByAddress(
            if (family == "ipv4") byteArrayOf(127, 0, 0, 2) else ByteArray(16).apply { this[15] = 1 },
        )
        private fun tls(raw: Socket, ca: X509Certificate, sendSni: Boolean = true): SSLSocket {
            val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null); setCertificateEntry("interception", ca) }
            val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
            val context = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
            return (context.socketFactory.createSocket(raw, HOST, 443, true) as SSLSocket).apply {
                soTimeout = 8_000
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
        private fun responseHeader(input: InputStream) {
            val bytes = ByteArrayOutputStream(); var tail = 0
            while (tail != 0x0d0a0d0a) { val value = input.read(); check(value >= 0 && bytes.size() < 4096); bytes.write(value); tail = (tail shl 8) or value }
            val lines = bytes.toString(Charsets.US_ASCII).split("\r\n")
            assertEquals("HTTP/1.1 200 OK", lines.first())
            assertEquals(1, lines.count { it.startsWith("content-length:", ignoreCase = true) })
            assertTrue(lines.any { it.equals("content-length: $RESPONSE", ignoreCase = true) })
            assertFalse(lines.any { it.startsWith("transfer-encoding:", ignoreCase = true) })
        }
        private fun joined(factory: EnrolledCaptureTcpFactory, permitFailure: Boolean = false) {
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
