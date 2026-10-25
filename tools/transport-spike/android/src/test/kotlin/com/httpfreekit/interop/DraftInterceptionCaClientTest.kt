package com.httpfreekit.interop

import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.Principal
import java.security.Security
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import okhttp3.tls.HandshakeCertificates
import org.junit.Assert.*
import org.junit.Test

class DraftInterceptionCaClientTest {
    @Test(timeout = 20000) fun freshPinnedMutualTlsReadsExactRequestBindsDerAndJoinsWithoutGlobalChanges() {
        val f = DraftInterceptionCaFixture()
        val defaults = listOf(SSLContext.getDefault(), HttpsURLConnection.getDefaultSSLSocketFactory(), HttpsURLConnection.getDefaultHostnameVerifier())
        val providers = Security.getProviders().map { it.name }
        CaPeer(f, count = 2) { socket -> socket.outputStream.write(response(f)); socket.outputStream.flush() }.use { peer ->
            f.client(peer.port).use { client ->
                repeat(2) {
                    val ca = client.fetch()
                    assertArrayEquals(f.ca.certificate.encoded, ca.certificateDer)
                    assertIdle(client, false)
                }
                assertEquals(2, peer.connectionCount.get())
                assertEquals("GET /companion/v1/ca HTTP/1.1\r\nHost: ${f.name}:${peer.port}\r\nAccept: application/pkix-cert\r\nConnection: close\r\n\r\n", peer.request.get())
                assertArrayEquals(f.leaf.certificate.encoded, peer.clientLeaf.get())
                assertIdle(client, false)
            }
            peer.await()
        }
        assertSame(defaults[0], SSLContext.getDefault()); assertSame(defaults[1], HttpsURLConnection.getDefaultSSLSocketFactory())
        assertSame(defaults[2], HttpsURLConnection.getDefaultHostnameVerifier()); assertEquals(providers, Security.getProviders().map { it.name })
    }

    @Test(timeout = 30000) fun actualTlsRejectsDuplicateFramingRedirectsBoundsAndTrailingBytes() {
        val f = DraftInterceptionCaFixture()
        val valid = response(f)
        val text = valid.toString(Charsets.ISO_8859_1)
        val invalid = listOf(
            text.replace("Content-Length:", "content-length: 1\r\nContent-Length:"),
            text.replace("200 OK", "302 Found").replace("Cache-Control:", "Location: https://other.invalid/\r\nCache-Control:"),
            text.replace("Content-Length: ${f.ca.certificate.encoded.size}", "Content-Length: 4097"),
            text.replace("Content-Length: ${f.ca.certificate.encoded.size}", "Content-Length: 01"),
            text.replace("Cache-Control: no-store", "Cache-Control: max-age=1"),
            text.replace("application/pkix-cert", "application/json"),
            text.replace("Cache-Control:", "Transfer-Encoding: chunked\r\nCache-Control:"),
            text.replace("Cache-Control:", "Content-Encoding: gzip\r\nCache-Control:"),
            text.replace("Cache-Control:", " X-Folded: invalid\r\nCache-Control:"),
            text.replace("Cache-Control:", "X-Large: ${"a".repeat(1025)}\r\nCache-Control:"),
            text.replace("Cache-Control:", (1..33).joinToString("") { "X-$it: a\r\n" } + "Cache-Control:"),
            text.replace("X-FreeKit-CA-SHA256: ${f.hashText(f.ca.certificate.encoded)}", "X-FreeKit-CA-SHA256: ${"A".repeat(43)}"),
        ).map { it.toByteArray(Charsets.ISO_8859_1) } + listOf(valid + byteArrayOf(42), valid.copyOf(valid.size - 1),
            ("HTTP/1.1 200 OK\r\nX-Large: " + "a".repeat(8200)).toByteArray())
        for (wire in invalid) CaPeer(f) { socket ->
            try { socket.outputStream.write(wire); socket.outputStream.flush() } catch (_: java.io.IOException) { /* Client rejection may close first. */ }
        }.use { peer ->
            f.client(peer.port).use { client ->
                val failure = assertThrows(DraftInterceptionCaException::class.java) { client.fetch() }
                assertEquals(DraftInterceptionCaFailure.RESPONSE, failure.code)
                assertNull(failure.cause); assertEquals(0, failure.suppressed.size); assertIdle(client, false)
            }
            peer.await()
        }
    }

    @Test(timeout = 15000) fun exactBodyWithoutActualEofCannotBecomeSuccessAndCloseInterruptsAndJoins() {
        val f = DraftInterceptionCaFixture()
        val sent = CountDownLatch(1)
        CaPeer(f) { socket ->
            socket.outputStream.write(response(f)); socket.outputStream.flush(); sent.countDown()
            try { assertEquals(-1, socket.inputStream.read()) } catch (_: java.io.IOException) { /* Raw interruption. */ }
        }.use { peer ->
            val caller = Executors.newSingleThreadExecutor()
            val client = f.client(peer.port)
            try {
                val result = caller.submit(Callable { try { client.fetch(); null } catch (failure: DraftInterceptionCaException) { failure } })
                assertTrue(sent.await(5, TimeUnit.SECONDS)); assertFalse(result.isDone)
                assertTrue(client.snapshot().activeCall)
                assertThrows(DraftInterceptionCaException::class.java) { client.fetch() }.also { assertEquals(DraftInterceptionCaFailure.CLOSED, it.code) }
                client.close()
                assertEquals(DraftInterceptionCaFailure.CLOSED, result.get(5, TimeUnit.SECONDS)?.code)
                assertIdle(client, true); client.close()
                assertThrows(DraftInterceptionCaException::class.java) { client.fetch() }.also { assertEquals(DraftInterceptionCaFailure.CLOSED, it.code) }
            } finally {
                client.close(); caller.shutdownNow(); assertTrue(caller.awaitTermination(5, TimeUnit.SECONDS))
            }
            peer.await()
        }
    }

    @Test(timeout = 15000) fun fiveSecondReadDeadlineFailsAndActuallyJoins() {
        val f = DraftInterceptionCaFixture()
        CaPeer(f) { socket ->
            try { socket.inputStream.read() } catch (_: java.io.IOException) { /* Read timeout interrupts the owned raw connection. */ }
        }.use { peer ->
            f.client(peer.port).use { client ->
                val started = System.nanoTime()
                assertThrows(DraftInterceptionCaException::class.java) { client.fetch() }.also {
                    assertEquals(DraftInterceptionCaFailure.TRANSPORT, it.code)
                }
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) >= 4500)
                assertIdle(client, false)
            }
            peer.await()
        }
    }

    @Test fun unresolvedRoutingAndApprovalMismatchFailBeforeNetworkAdmission() {
        val f = DraftInterceptionCaFixture()
        for (address in listOf(InetSocketAddress.createUnresolved("PRIVATE_DIAL_CANARY.invalid", 31235), InetSocketAddress(0))) {
            val failure = assertThrows(DraftInterceptionCaException::class.java) {
                DraftInterceptionCaClient(f.record(), f.manager, listOf(f.original.certificate), f.recovery(), address)
            }
            assertEquals(DraftInterceptionCaFailure.BINDING, failure.code); assertNull(failure.cause)
            assertFalse(failure.toString().contains("PRIVATE_DIAL_CANARY"))
        }
    }

    @Test(timeout = 20000) fun blockedFinalProviderCannotHoldCancellationLockOrReportFalseCleanup() {
        val f = DraftInterceptionCaFixture()
        val reached = CountDownLatch(1); val release = CountDownLatch(1)
        val current = AtomicReference<DraftInterceptionCaClient?>()
        val manager = observingManager(f.manager) {
            val s = current.get()?.snapshot()
            if (s?.activeCall == true && s.tlsSocketOwned && !s.deadlineAlive && !s.tlsCloserAlive) {
                reached.countDown(); check(release.await(15, TimeUnit.SECONDS))
            }
        }
        CaPeer(f) { socket -> socket.outputStream.write(response(f)); socket.outputStream.flush() }.use { peer ->
            val client = DraftInterceptionCaClient(f.record(), manager, listOf(f.original.certificate), f.recovery(peer.port),
                InetSocketAddress("127.0.0.1", peer.port)).also(current::set)
            val caller = Executors.newSingleThreadExecutor()
            try {
                val result = caller.submit(Callable { try { client.fetch(); null } catch (failure: DraftInterceptionCaException) { failure } })
                assertTrue(reached.await(5, TimeUnit.SECONDS))
                val started = System.nanoTime()
                val failure = assertThrows(DraftInterceptionCaException::class.java) { client.close() }
                assertEquals(DraftInterceptionCaFailure.CLEANUP, failure.code)
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 6500)
                assertTrue(client.snapshot().activeCall); assertTrue(client.snapshot().cleanupFailed); assertFalse(result.isDone)
                release.countDown()
                assertEquals(DraftInterceptionCaFailure.CLOSED, result.get(5, TimeUnit.SECONDS)?.code)
                assertFalse(client.snapshot().activeCall)
                assertThrows(DraftInterceptionCaException::class.java) { client.close() }.also { assertEquals(DraftInterceptionCaFailure.CLEANUP, it.code) }
            } finally {
                release.countDown(); caller.shutdownNow(); assertTrue(caller.awaitTermination(5, TimeUnit.SECONDS))
            }
            peer.await()
        }
    }

    @Test(timeout = 18000) fun finalProviderResultPastWholeDeadlineCannotBePublished() {
        val f = DraftInterceptionCaFixture()
        val current = AtomicReference<DraftInterceptionCaClient?>()
        val delay = CountDownLatch(1)
        val hookReached = AtomicBoolean()
        val delayCompleted = AtomicBoolean()
        val delayElapsedMillis = AtomicLong()
        val manager = observingManager(f.manager) {
            val s = current.get()?.snapshot()
            if (s?.activeCall == true && s.tlsSocketOwned && !s.deadlineAlive && !s.tlsCloserAlive) {
                hookReached.set(true)
                val started = System.nanoTime()
                delayCompleted.set(!delay.await(10200, TimeUnit.MILLISECONDS))
                delayElapsedMillis.set(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started))
            }
        }
        CaPeer(f) { socket -> socket.outputStream.write(response(f)); socket.outputStream.flush() }.use { peer ->
            DraftInterceptionCaClient(f.record(), manager, listOf(f.original.certificate), f.recovery(peer.port),
                InetSocketAddress("127.0.0.1", peer.port)).also(current::set).use { client ->
                val started = System.nanoTime()
                val failure = assertThrows(DraftInterceptionCaException::class.java) { client.fetch() }
                assertTrue(hookReached.get()); assertTrue(delayCompleted.get())
                assertTrue(delayElapsedMillis.get() >= 10000)
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) >= 10000)
                assertEquals(DraftInterceptionCaFailure.TRANSPORT, failure.code); assertIdle(client, false)
            }
            peer.await()
        }
    }

    private fun observingManager(delegate: X509ExtendedKeyManager, beforeChoose: () -> Unit) = object : X509ExtendedKeyManager() {
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? {
            beforeChoose(); return delegate.chooseClientAlias(keyType, issuers, socket)
        }
        override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) =
            delegate.chooseEngineClientAlias(keyType, issuers, engine)
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = delegate.getClientAliases(keyType, issuers)
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = delegate.getServerAliases(keyType, issuers)
        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?) = delegate.chooseServerAlias(keyType, issuers, socket)
        override fun getCertificateChain(alias: String?) = delegate.getCertificateChain(alias)
        override fun getPrivateKey(alias: String?) = delegate.getPrivateKey(alias)
    }

    private fun assertIdle(client: DraftInterceptionCaClient, closed: Boolean) {
        val s = client.snapshot()
        assertEquals(closed, s.closed)
        assertFalse(s.activeCall || s.rawSocketOwned || s.tlsSocketOwned || s.deadlineAlive || s.tlsCloserAlive || s.cleanupFailed)
    }

    private fun response(f: DraftInterceptionCaFixture): ByteArray {
        val der = f.ca.certificate.encoded
        return ("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\nContent-Length: ${der.size}\r\n" +
            "X-FreeKit-CA-SHA256: ${f.hashText(der)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").toByteArray() + der
    }

    private class CaPeer(f: DraftInterceptionCaFixture, count: Int = 1, action: (SSLSocket) -> Unit) : AutoCloseable {
        private val context = HandshakeCertificates.Builder().heldCertificate(f.gateway).addTrustedCertificate(f.authority.certificate).build().sslContext()
        private val listener = (context.serverSocketFactory.createServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")) as SSLServerSocket).apply { needClientAuth = true }
        val port = listener.localPort
        val request = AtomicReference<String>()
        val clientLeaf = AtomicReference<ByteArray>()
        val connectionCount = AtomicInteger()
        private val accepted = AtomicReference<SSLSocket?>()
        private val executor = Executors.newSingleThreadExecutor()
        private val result: Future<*> = executor.submit {
          repeat(count) {
            (listener.accept() as SSLSocket).also(accepted::set).use { socket ->
                socket.soTimeout = 12000; socket.startHandshake()
                connectionCount.incrementAndGet()
                clientLeaf.set(socket.session.peerCertificates.first().encoded)
                val bytes = ByteArrayOutputStream(); var suffix = 0
                while (suffix != 0x0d0a0d0a) {
                    check(bytes.size() < 8192)
                    val next = socket.inputStream.read(); check(next >= 0)
                    bytes.write(next); suffix = (suffix shl 8) or next
                }
                request.set(bytes.toString("US-ASCII")); action(socket)
            }
          }
        }
        fun await() { result.get(5, TimeUnit.SECONDS) }
        override fun close() {
            var failure: Exception? = null
            try { listener.close() } catch (caught: Exception) { failure = caught }
            try { accepted.get()?.close() } catch (caught: Exception) { if (failure == null) failure = caught }
            executor.shutdownNow()
            check(executor.awaitTermination(5, TimeUnit.SECONDS))
            failure?.let { throw it }
        }
    }
}
