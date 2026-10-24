package com.httpfreekit.security

import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GatewayClientTlsTest {
    private val logicalName = "gateway-fixture.invalid"
    private val loopback = InetAddress.getByName("127.0.0.1")

    @Test(timeout = 30000) fun boundClientAndPinnedGatewayAuthenticateTogetherOnTls12And13() {
        val credential = credential()
        val server = TestEnrollmentCertificates.server(logicalName)
        val serverContext = TestEnrollmentCertificates.serverContext(server, credential.authority.certificate)
        listOf("TLSv1.2", "TLSv1.3").forEach { protocol ->
            Peer(serverContext, true, protocol).use { peer ->
                factory(server, credential.manager).connect(peer.endpoint).use { tls ->
                    tls.soTimeout = 3000
                    assertEquals(protocol, tls.session.protocol)
                    assertArrayEquals(credential.leaf, tls.session.localCertificates.first().encoded)
                    assertArrayEquals(server.certificate.encoded, tls.session.peerCertificates.first().encoded)
                    assertEquals(42, tls.inputStream.read())
                }
                assertArrayEquals(credential.leaf, peer.result.get(5, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun unavailableOrExpiredCredentialIsRejectedBeforeSocketAllocation() {
        val server = TestEnrollmentCertificates.server(logicalName)
        listOf(false, true).forEach { expire ->
            val live = AtomicBoolean(true)
            val time = AtomicReference(Instant.now())
            val credential = credential(live, object : Clock() {
                override fun instant(): Instant = time.get()
                override fun getZone(): ZoneId = ZoneOffset.UTC
                override fun withZone(zone: ZoneId): Clock = this
            })
            if (expire) time.set(Instant.now().plusSeconds(7200)) else live.set(false)
            val sockets = RecordingSockets()
            rejected { factory(server, credential.manager, sockets).connect(InetSocketAddress(loopback, 8766)) }
            assertTrue("Invalid credentials allocated a TCP socket", sockets.created.isEmpty())
        }
    }

    @Test(timeout = 10000) fun serverThatDoesNotRequestTheConfiguredClientCredentialCannotAppearAuthenticated() {
        val credential = credential()
        val server = TestEnrollmentCertificates.server(logicalName)
        val context = TestEnrollmentCertificates.serverContext(server, credential.authority.certificate)
        val sockets = RecordingSockets()
        Peer(context, false, "TLSv1.2").use { peer ->
            rejected { factory(server, credential.manager, sockets).connect(peer.endpoint) }
        }
        assertTrue(sockets.created.single().isClosed)
    }

    @Test(timeout = 10000) fun credentialLostAfterTlsAuthenticationIsRejectedBeforeTheSocketIsExposed() {
        val live = AtomicBoolean(true)
        val credential = credential(live)
        val server = TestEnrollmentCertificates.server(logicalName)
        val context = TestEnrollmentCertificates.serverContext(server, credential.authority.certificate)
        val checks = AtomicInteger()
        // The factory's third gateway-clock read is after startHandshake returns. Simulate
        // Forget at that boundary, after the provider has already used the signing handle.
        val clock = object : Clock() {
            override fun instant(): Instant {
                if (checks.incrementAndGet() == 3) live.set(false)
                return Instant.now()
            }
            override fun getZone(): ZoneId = ZoneOffset.UTC
            override fun withZone(zone: ZoneId): Clock = this
        }
        val sockets = RecordingSockets()
        Peer(context, true, "TLSv1.2").use { peer ->
            rejected { factory(server, credential.manager, sockets, clock).connect(peer.endpoint) }
            assertArrayEquals(credential.leaf, peer.result.get(5, TimeUnit.SECONDS))
        }
        assertTrue(sockets.created.single().isClosed)
    }

    private data class Credential(
        val manager: X509ExtendedKeyManager,
        val authority: TestEnrollmentCertificates.Identity,
        val leaf: ByteArray,
    )

    private fun credential(live: AtomicBoolean = AtomicBoolean(true), clock: Clock = Clock.systemUTC()): Credential {
        val keys = TestEnrollmentCertificates.keyPair()
        val identity = DeviceIdentity(keys.public, keys.private) { live.get() }
        val authority = TestEnrollmentCertificates.authority()
        val leaf = TestEnrollmentCertificates.client(keys.public, authority)
        return Credential(identity.bindEnrolledClientCertificate(listOf(leaf), authority.certificate, clock), authority, leaf.encoded)
    }

    private fun factory(
        server: TestEnrollmentCertificates.Identity,
        manager: X509ExtendedKeyManager,
        sockets: SocketFactory = SocketFactory.getDefault(),
        clock: Clock = Clock.systemUTC(),
    ): GatewayTlsConnectionFactory = GatewayTlsConnectionFactory(
        server.certificate,
        Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(server.keys.public.encoded)),
        logicalName, connectTimeoutMillis = 3000, handshakeTimeoutMillis = 3000,
        clock = clock, rawSocketFactory = sockets, clientKeyManager = manager,
    )

    private inner class Peer(context: SSLContext, clientAuth: Boolean, protocol: String) : Closeable {
        private val listener = (context.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket).apply {
            enabledProtocols = arrayOf(protocol)
            needClientAuth = clientAuth
            soTimeout = 5000
        }
        val endpoint = InetSocketAddress(loopback, listener.localPort)
        val result = CompletableFuture<ByteArray>()
        private val accepted = AtomicReference<SSLSocket?>()
        private val worker = Thread({
            try {
                (listener.accept() as SSLSocket).use { tls ->
                    accepted.set(tls)
                    tls.soTimeout = 5000
                    tls.startHandshake()
                    result.complete(if (clientAuth) tls.session.peerCertificates.first().encoded else ByteArray(0))
                    tls.outputStream.write(42)
                }
            } catch (failure: Throwable) { result.completeExceptionally(failure) }
        }, "freekit-client-tls-peer").apply { isDaemon = true; start() }

        override fun close() {
            listener.close()
            accepted.get()?.close()
            worker.interrupt()
            worker.join(5000)
            check(!worker.isAlive) { "Client TLS peer did not stop" }
        }
    }

    private class RecordingSockets : SocketFactory() {
        val created = ArrayList<Socket>()
        override fun createSocket(): Socket = Socket().also { created += it }
        override fun createSocket(host: String, port: Int): Socket = error("Expected a fresh socket")
        override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int): Socket = error("Expected a fresh socket")
        override fun createSocket(host: InetAddress, port: Int): Socket = error("Expected a fresh socket")
        override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int): Socket = error("Expected a fresh socket")
    }

    private fun rejected(block: () -> Unit) {
        try { block() } catch (_: CertificateException) { return }
        throw AssertionError("Expected client credential rejection")
    }
}
