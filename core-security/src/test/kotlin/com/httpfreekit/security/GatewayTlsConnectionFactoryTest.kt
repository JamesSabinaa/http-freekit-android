package com.httpfreekit.security

import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.SocketFactory
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class GatewayTlsConnectionFactoryTest {
    private val logicalName = "gateway-fixture.invalid"
    private val loopback = InetAddress.getByName("127.0.0.1")

    @Test(timeout = 15000) fun verifiesLogicalHostnameAndSniWhileDialingLoopbackWithoutGlobalTrustChanges() {
        val identity = identity()
        val serverContext = certificates(identity).sslContext()
        val defaultContext = SSLContext.getDefault()
        val defaultFactory = HttpsURLConnection.getDefaultSSLSocketFactory()
        val defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
        val serverName = CompletableFuture<String>()
        val rawSockets = RecordingSocketFactory()
        val factory = factory(identity, rawSockets = rawSockets)
        tlsPeer(serverContext) { socket ->
            socket.startHandshake()
            val sni = (socket.session as ExtendedSSLSession).requestedServerNames.single() as SNIHostName
            serverName.complete(sni.asciiName)
            socket.outputStream.write(42)
        }.use { peer ->
            factory.connect(peer.endpoint).use { tls ->
                tls.soTimeout = 3000
                assertEquals(42, tls.inputStream.read())
                assertEquals(logicalName, tls.session.peerHost)
                assertEquals(peer.endpoint, tls.remoteSocketAddress)
                assertEquals("HTTPS", tls.sslParameters.endpointIdentificationAlgorithm)
                assertTrue(tls.enabledProtocols.isNotEmpty())
                assertTrue(tls.enabledProtocols.all { it in setOf("TLSv1.2", "TLSv1.3") })
            }
            peer.result.get(5, TimeUnit.SECONDS)
        }
        assertEquals(logicalName, serverName.get(5, TimeUnit.SECONDS))
        assertTrue(rawSockets.sockets.single().isClosed)
        assertSame(defaultContext, SSLContext.getDefault())
        assertSame(defaultFactory, HttpsURLConnection.getDefaultSSLSocketFactory())
        assertSame(defaultVerifier, HttpsURLConnection.getDefaultHostnameVerifier())
    }

    @Test(timeout = 10000) fun reusedFactoryRechecksExpiryBeforeAllocatingAnotherSocket() {
        val identity = identity()
        val clock = MutableClock(Instant.now())
        val rawSockets = RecordingSocketFactory()
        val factory = factory(identity, clock = clock, rawSockets = rawSockets)
        lateinit var endpoint: InetSocketAddress
        tlsPeer(certificates(identity).sslContext()) { socket ->
            socket.startHandshake()
            socket.outputStream.write(42)
        }.use { peer ->
            endpoint = peer.endpoint
            factory.connect(endpoint).use { assertEquals(42, it.inputStream.read()) }
        }
        clock.set(identity.certificate.notAfter.toInstant().plusMillis(1))
        rejected<CertificateExpiredException> { factory.connect(endpoint) }
        assertEquals("Expired trust must fail before a reconnect socket is allocated", 1, rawSockets.sockets.size)
    }

    @Test(timeout = 10000) fun expiryDuringHandshakeDoesNotExposeTheNewConnection() {
        val identity = identity()
        val clock = MutableClock(Instant.now())
        val rawSockets = RecordingSocketFactory()
        val factory = factory(identity, clock = clock, rawSockets = rawSockets)
        tlsPeer(certificates(identity).sslContext()) { socket ->
            clock.set(identity.certificate.notAfter.toInstant().plusMillis(1))
            socket.startHandshake()
            socket.outputStream.write(42)
        }.use { peer ->
            rejected<CertificateExpiredException> { factory.connect(peer.endpoint) }
        }
        assertTrue(rawSockets.sockets.single().isClosed)
    }

    @Test fun wrongConfiguredPinFailsBeforeSocketAllocation() {
        val identity = identity()
        val rawSockets = RecordingSocketFactory()
        rejected<CertificateException> {
            GatewayTlsConnectionFactory(identity.certificate, pin(identity()), logicalName, rawSocketFactory = rawSockets)
        }
        assertTrue(rawSockets.sockets.isEmpty())
    }

    @Test(timeout = 10000) fun wrongLogicalHostnameClosesThePartialConnection() {
        val identity = identity()
        val rawSockets = RecordingSocketFactory()
        val factory = GatewayTlsConnectionFactory(identity.certificate, pin(identity), "other.invalid", rawSocketFactory = rawSockets)
        tlsPeer(certificates(identity).sslContext()) { it.startHandshake() }.use { peer ->
            rejected<IOException> { factory.connect(peer.endpoint) }
        }
        assertTrue(rawSockets.sockets.single().isClosed)
    }

    @Test(timeout = 10000) fun anotherSelfSignedServerKeyIsNotTrusted() {
        val configured = identity()
        val other = identity()
        val rawSockets = RecordingSocketFactory()
        val factory = factory(configured, rawSockets = rawSockets)
        tlsPeer(certificates(other).sslContext()) { it.startHandshake() }.use { peer ->
            rejected<IOException> { factory.connect(peer.endpoint) }
        }
        assertTrue(rawSockets.sockets.single().isClosed)
    }

    @Test(timeout = 10000) fun aChildSignedByThePinnedNonCaLeafCannotReplaceThePinnedPeerKey() {
        val configured = identity()
        val child = HeldCertificate.Builder().commonName(logicalName).addSubjectAlternativeName(logicalName)
            .signedBy(configured).build()
        val server = HandshakeCertificates.Builder().heldCertificate(child, configured.certificate).build()
        val rawSockets = RecordingSocketFactory()
        val factory = factory(configured, rawSockets = rawSockets)
        tlsPeer(server.sslContext()) { it.startHandshake() }.use { peer ->
            val failure = failure { factory.connect(peer.endpoint) }
            assertTrue(failure is IOException || failure is CertificateException)
        }
        assertTrue(rawSockets.sockets.single().isClosed)
    }

    @Test fun tcpConnectReceivesItsOwnTimeoutAndFailureClosesTheSocket() {
        val rawSockets = RecordingSocketFactory(failConnect = true)
        val factory = factory(identity(), rawSockets = rawSockets, connectTimeout = 73, handshakeTimeout = 501)
        rejected<SocketTimeoutException> { factory.connect(InetSocketAddress(loopback, 8766)) }
        assertEquals(73, rawSockets.sockets.single().requestedTimeout)
        assertTrue(rawSockets.sockets.single().isClosed)
        assertTrue(rawSockets.sockets.single().closes.get() > 0)
    }

    @Test fun anAlreadyConnectedProviderSocketCannotBypassTheConfiguredDialAndTimeout() {
        val rawSockets = RecordingSocketFactory(pretendConnected = true)
        val factory = factory(identity(), rawSockets = rawSockets)
        rejected<IllegalArgumentException> { factory.connect(InetSocketAddress(loopback, 8766)) }
        assertEquals(null, rawSockets.sockets.single().requestedTimeout)
        assertTrue(rawSockets.sockets.single().isClosed)
    }

    @Test(timeout = 10000) fun aSilentTlsPeerTimesOutAndTheSocketIsClosed() {
        val rawSockets = RecordingSocketFactory()
        val factory = factory(identity(), rawSockets = rawSockets, handshakeTimeout = 200)
        plainPeer { socket -> while (socket.inputStream.read() != -1) { /* Discard ClientHello and never reply. */ } }.use { peer ->
            val started = System.nanoTime()
            rejected<SocketTimeoutException> { factory.connect(peer.endpoint) }
            assertTrue("TLS handshake exceeded its bounded budget", elapsedMillis(started) < 3000)
        }
        assertTrue(rawSockets.sockets.single().isClosed)
    }

    @Test(timeout = 10000) fun trickledTlsRecordCannotKeepResettingTheHandshakeBudget() {
        val rawSockets = RecordingSocketFactory()
        val factory = factory(identity(), rawSockets = rawSockets, handshakeTimeout = 300)
        plainPeer { socket ->
            // A partial TLS handshake record remains incomplete while bytes arrive faster than SO_TIMEOUT.
            socket.outputStream.write(byteArrayOf(22, 3, 3, 1, 0))
            socket.outputStream.flush()
            repeat(256) {
                Thread.sleep(35)
                socket.outputStream.write(0)
                socket.outputStream.flush()
            }
        }.use { peer ->
            val started = System.nanoTime()
            rejected<SocketTimeoutException> { factory.connect(peer.endpoint) }
            assertTrue("Trickled bytes extended the TLS handshake", elapsedMillis(started) < 3000)
        }
        assertTrue(rawSockets.sockets.single().isClosed)
    }

    @Test(timeout = 10000) fun completedHandshakeCancelsItsWatchdogWithoutClosingTheReturnedSocket() {
        val identity = identity()
        val release = CompletableFuture<Unit>()
        val factory = factory(identity, handshakeTimeout = 1500)
        tlsPeer(certificates(identity).sslContext()) { socket ->
            socket.startHandshake()
            socket.outputStream.write(42)
            release.get(5, TimeUnit.SECONDS)
            socket.outputStream.write(43)
        }.use { peer ->
            factory.connect(peer.endpoint).use { socket ->
                assertEquals("Application idle policy is separate from handshake timeout", 0, socket.soTimeout)
                socket.soTimeout = 3000
                assertEquals(42, socket.inputStream.read())
                Thread.sleep(1700)
                assertFalse(socket.isClosed)
                release.complete(Unit)
                assertEquals(43, socket.inputStream.read())
            }
        }
    }

    @Test fun invalidTimeoutsNamesAndUnresolvedEndpointsAreRejected() {
        val identity = identity()
        val rawSockets = RecordingSocketFactory()
        listOf(-1, 0, GatewayTlsConnectionFactory.MAX_TIMEOUT_MILLIS + 1).forEach { timeout ->
            rejected<IllegalArgumentException> { factory(identity, rawSockets = rawSockets, connectTimeout = timeout) }
            rejected<IllegalArgumentException> { factory(identity, rawSockets = rawSockets, handshakeTimeout = timeout) }
        }
        listOf("", "*.invalid", "gateway.invalid:443", "a".repeat(254)).forEach { name ->
            rejected<IllegalArgumentException> {
                GatewayTlsConnectionFactory(identity.certificate, pin(identity), name, rawSocketFactory = rawSockets)
            }
        }
        val factory = factory(identity, rawSockets = rawSockets)
        rejected<IllegalArgumentException> { factory.connect(InetSocketAddress.createUnresolved(logicalName, 8766)) }
        rejected<IllegalArgumentException> { factory.connect(InetSocketAddress(loopback, 0)) }
        assertTrue(rawSockets.sockets.isEmpty())
    }

    private fun identity(): HeldCertificate = HeldCertificate.Builder()
        .commonName(logicalName).addSubjectAlternativeName(logicalName).build()

    private fun certificates(identity: HeldCertificate): HandshakeCertificates =
        HandshakeCertificates.Builder().heldCertificate(identity).build()

    private fun pin(identity: HeldCertificate): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256").digest(identity.certificate.publicKey.encoded),
    )

    private fun factory(
        identity: HeldCertificate,
        clock: Clock = Clock.systemUTC(),
        rawSockets: SocketFactory = SocketFactory.getDefault(),
        connectTimeout: Int = 2000,
        handshakeTimeout: Int = 3000,
    ): GatewayTlsConnectionFactory = GatewayTlsConnectionFactory(
        identity.certificate, pin(identity), logicalName, connectTimeout, handshakeTimeout, clock, rawSockets,
    )

    private fun plainPeer(handler: (Socket) -> Unit): LoopbackPeer =
        LoopbackPeer(ServerSocket(0, 1, loopback), handler)

    private fun tlsPeer(context: SSLContext, handler: (SSLSocket) -> Unit): LoopbackPeer = LoopbackPeer(
        context.serverSocketFactory.createServerSocket(0, 1, loopback),
    ) { socket -> handler(socket as SSLSocket) }

    private class MutableClock(initial: Instant) : Clock() {
        private val current = AtomicReference(initial)
        fun set(instant: Instant) { current.set(instant) }
        override fun instant(): Instant = current.get()
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
    }

    private class RecordingSocketFactory(
        private val failConnect: Boolean = false,
        private val pretendConnected: Boolean = false,
    ) : SocketFactory() {
        val sockets = CopyOnWriteArrayList<RecordingSocket>()
        override fun createSocket(): Socket = RecordingSocket(failConnect, pretendConnected).also { sockets += it }
        override fun createSocket(host: String, port: Int): Socket = error("Expected an unconnected socket request")
        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket = error("Expected an unconnected socket request")
        override fun createSocket(host: InetAddress, port: Int): Socket = error("Expected an unconnected socket request")
        override fun createSocket(host: InetAddress, port: Int, localHost: InetAddress, localPort: Int): Socket = error("Expected an unconnected socket request")
    }

    private class RecordingSocket(private val failConnect: Boolean, private val pretendConnected: Boolean) : Socket() {
        var requestedTimeout: Int? = null
        val closes = AtomicInteger()
        override fun isConnected(): Boolean = pretendConnected || super.isConnected()
        override fun connect(endpoint: SocketAddress, timeout: Int) {
            requestedTimeout = timeout
            if (failConnect) throw SocketTimeoutException("Synthetic TCP timeout")
            super.connect(endpoint, timeout)
        }
        override fun close() {
            closes.incrementAndGet()
            super.close()
        }
    }

    private class LoopbackPeer(private val server: ServerSocket, handler: (Socket) -> Unit) : Closeable {
        val endpoint = InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.localPort)
        val result = CompletableFuture<Unit>()
        private val accepted = AtomicReference<Socket?>()
        private val worker = Thread({
            try {
                server.soTimeout = 5000
                server.accept().use { socket ->
                    accepted.set(socket)
                    socket.soTimeout = 5000
                    handler(socket)
                }
                result.complete(Unit)
            } catch (failure: Throwable) { result.completeExceptionally(failure) }
        }, "freekit-tls-test-peer").apply { isDaemon = true; start() }

        override fun close() {
            try { server.close() } catch (_: IOException) { }
            try { accepted.get()?.close() } catch (_: IOException) { }
            worker.interrupt()
            worker.join(3000)
            check(!worker.isAlive) { "Loopback peer did not stop" }
        }
    }

    private fun elapsedMillis(started: Long): Long = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

    private fun failure(block: () -> Unit): Exception {
        try { block() } catch (failure: Exception) { return failure }
        throw AssertionError("Expected connection rejection")
    }

    private inline fun <reified T : Exception> rejected(block: () -> Unit) {
        try { block() } catch (failure: Exception) {
            assertTrue("Expected ${T::class.java.simpleName}, got ${failure::class.java.simpleName}", failure is T)
            return
        }
        throw AssertionError("Expected ${T::class.java.simpleName}")
    }
}
