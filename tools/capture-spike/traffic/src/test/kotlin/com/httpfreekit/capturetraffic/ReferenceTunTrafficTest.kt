package com.httpfreekit.capturetraffic

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import org.junit.Assert.*
import org.junit.Test

/** Socket doubles check ordering/ownership, not Android provider or network acceptance. */
class ReferenceTunTrafficTest {
    private fun owner(raw: Raw, tls: Tls? = null, api: Int = 26) = ReferenceTunTraffic({ raw }, { api }, { _, _ -> checkNotNull(tls) })
    private fun ca() = ReferenceTunTestCertificates.authority().certificate.encoded

    @Test fun fixedHttpPublishesActualOwnerBeforeConnectAndRequiresDirectionalClose() {
        val raw = Raw(false)
        val traffic = owner(raw)
        var published: Closeable? = null
        val result = traffic.execute(20) {
            assertFalse(raw.connected)
            published = it
        }
        assertNotNull(published)
        assertArrayEquals(ReferenceTunHttpResponse.expectedBody(), result)
        assertArrayEquals(ReferenceTunHttpResponse.request(), raw.written.toByteArray())
        assertEquals(listOf("connect", "raw-shutdown", "raw-eof", "raw-close"), raw.events)
        assertEquals("198.18.0.2", raw.destination!!.address.hostAddress)
        assertEquals(80, raw.destination!!.port)
        published!!.close()
        traffic.close()
        traffic.close()
        assertCode("configuration") { traffic.execute(20) {} }
    }

    @Test fun publishedAggregateActuallyCancelsTheSocketBeforeConnection() {
        val raw = Raw(false)
        val traffic = owner(raw)
        assertCode("connect") { traffic.execute(20) { it.close() } }
        assertTrue(raw.closed)
        assertFalse(raw.connected)
        traffic.close()
    }

    @Test fun hostileCommandsAndDuplicateConfigurationNeverConnect() {
        val raw = Raw(false)
        val traffic = owner(raw)
        for (command in listOf(Int.MIN_VALUE, 0, 3, 19, 22, Int.MAX_VALUE)) assertCode("configuration") { traffic.execute(command) {} }
        assertCode("configuration") { traffic.execute(21) {} }
        for (bytes in listOf(ByteArray(0), ByteArray(4097), "canary".toByteArray())) assertCode("configuration") { traffic.configure(bytes) }
        val bytes = ca()
        traffic.configure(bytes)
        bytes.fill(0)
        assertCode("configuration") { traffic.configure(ca()) }
        assertFalse(raw.connected)
        traffic.close()
        assertCode("configuration") { traffic.configure(ca()) }
    }

    @Test fun scopedTlsAndRawEofAreDistinctAndNeverUseTlsShutdownOutput() {
        for (api in listOf(26, 29, 37)) {
            val raw = Raw(true)
            val tls = Tls(raw.events)
            val traffic = owner(raw, tls, api)
            traffic.configure(ca())
            assertArrayEquals(ReferenceTunHttpResponse.expectedBody(), traffic.execute(21) { assertFalse(raw.connected) })
            assertEquals(443, raw.destination!!.port)
            assertArrayEquals(ReferenceTunHttpResponse.request(), tls.written.toByteArray())
            assertEquals(listOf("connect", "handshake", "tls-eof", "tls-close", "raw-shutdown", "raw-eof", "raw-close"), raw.events)
            assertEquals("HTTPS", tls.sslParameters.endpointIdentificationAlgorithm)
            assertEquals(ReferenceTunHttpResponse.HOST, (tls.sslParameters.serverNames.single() as javax.net.ssl.SNIHostName).asciiName)
            assertTrue(tls.enabledProtocols.all { it in listOf("TLSv1.2", "TLSv1.3") })
            if (api >= 29) assertArrayEquals(arrayOf("http/1.1"), tls.sslParameters.applicationProtocols)
            traffic.close()
        }
    }

    @Test fun caValidityCrossingDuringConnectFailsBeforeHandshakeOrApplicationDispatch() {
        val authority = ReferenceTunTestCertificates.authority().certificate
        val initiallyValid = authority.notBefore.time + 1000
        for (atHandshake in listOf(authority.notAfter.time + 1, authority.notBefore.time - 1, initiallyValid)) {
            val clock = java.util.concurrent.atomic.AtomicLong(initiallyValid)
            val raw = Raw(true).apply { afterConnect = { clock.set(atHandshake) } }
            val tls = Tls(raw.events)
            val traffic = ReferenceTunTraffic({ raw }, { 26 }, { _, _ -> tls }, { java.util.Date(clock.get()) })
            try {
                traffic.configure(authority.encoded)
                if (atHandshake == initiallyValid) {
                    assertArrayEquals(ReferenceTunHttpResponse.expectedBody(), traffic.execute(21) {})
                    assertTrue(raw.events.contains("handshake"))
                } else {
                    val failure = assertCode("tls") { traffic.execute(21) {} }
                    assertEquals("traffic_reference_tls", failure.message)
                    assertEquals(0, failure.suppressed.size)
                    assertTrue(raw.connected)
                    assertFalse(raw.events.contains("handshake"))
                    assertEquals(0, tls.written.size())
                    assertEquals(0, raw.written.size())
                }
                assertTrue(raw.closed)
                assertTrue(tls.closed)
            } finally { traffic.close() }
        }
    }

    @Test fun hostileAlpnHandshakeAndRawEofCannotBecomeSuccess() {
        for (mode in 0..3) {
            val raw = Raw(true)
            val tls = Tls(raw.events)
            when (mode) {
                0 -> tls.selectedProtocol = "h2"
                1 -> tls.handshakeFailure = true
                2 -> raw.eofFailure = true
                3 -> tls.eofFailure = true
            }
            val traffic = owner(raw, tls, 29)
            traffic.configure(ca())
            assertCode(if (mode < 2) "tls" else "eof") { traffic.execute(21) {} }
            assertTrue(raw.closed)
            assertTrue(tls.closed)
            traffic.close()
        }
    }

    @Test fun providerDetailsNeverEscapeAndPrimarySurvivesIndependentCleanupFailures() {
        val raw = Raw(false).apply { shutdownFailure = true; closeFailure = true }
        val traffic = owner(raw)
        val failure = assertCode("shutdown") { traffic.execute(20) {} }
        assertEquals(1, failure.suppressed.size)
        assertEquals("traffic_reference_close", (failure.suppressed.single() as ReferenceTunTraffic.Failure).code)
        assertNull(failure.cause)
        assertFalse(failure.toString().contains("canary"))
        assertTrue(failure.suppressed.all { it.cause == null && !it.toString().contains("canary") })
        val cleanup = assertCode("close") { traffic.close() }
        assertSame(cleanup, assertCode("close") { traffic.close() })
    }

    @Test fun closeCancelsActualBlockedConnectAndJoinsCallerBeforeReturning() {
        val entered = CountDownLatch(1)
        val released = CountDownLatch(1)
        val raw = Raw(false).apply { connectEntered = entered; connectRelease = released }
        val traffic = owner(raw)
        val result = AtomicReference<Throwable?>()
        val worker = Thread {
            try { traffic.execute(20) {} } catch (failure: Throwable) { result.set(failure) }
        }
        worker.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertCode("configuration") { traffic.execute(20) {} }
            assertCode("configuration") { traffic.configure(ca()) }
            traffic.close()
        } finally {
            released.countDown()
            worker.join(3000)
        }
        assertFalse(worker.isAlive)
        assertEquals("traffic_reference_connect", (result.get() as ReferenceTunTraffic.Failure).code)
        assertTrue(raw.closed)
    }

    @Test fun independentRawAndTlsCleanupFailuresAreBothSanitizedAndRetained() {
        val raw = Raw(true).apply { closeFailure = true }
        val tls = Tls(raw.events).apply { handshakeFailure = true; closeFailure = true }
        val traffic = owner(raw, tls)
        traffic.configure(ca())
        val primary = assertCode("tls") { traffic.execute(21) {} }
        val rawCleanup = primary.suppressed.single() as ReferenceTunTraffic.Failure
        assertEquals("traffic_reference_close", rawCleanup.code)
        assertEquals("traffic_reference_close", (rawCleanup.suppressed.single() as ReferenceTunTraffic.Failure).code)
        assertNull(rawCleanup.cause)
        assertNull(rawCleanup.suppressed.single().cause)
        assertCode("close") { traffic.close() }
        assertCode("close") { traffic.close() }
    }

    @Test fun cancellationCanCloseRawWhileActualTlsCloseIsInProgress() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val raw = Raw(true).apply { closeRelease = release }
        val tls = Tls(raw.events).apply { closeEntered = entered; closeRelease = release }
        val traffic = owner(raw, tls)
        traffic.configure(ca())
        val result = AtomicReference<Throwable?>()
        val worker = Thread { try { traffic.execute(21) {} } catch (failure: Throwable) { result.set(failure) } }
        worker.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            traffic.close()
        } finally {
            release.countDown()
            worker.join(3000)
        }
        assertFalse(worker.isAlive)
        assertTrue(raw.closed)
        assertTrue(tls.closed)
        // Real cancellation can invalidate subsequent raw SHUT_WR/EOF; never require success.
        assertTrue(result.get() == null || result.get() is ReferenceTunTraffic.Failure)
    }

    /** Actual loopback sockets, including layered TLS; not Android routing/provider acceptance. */
    @Test fun actualLoopbackHttpAndScopedTlsTransactionsOwnTheirSockets() {
        val authority = ReferenceTunTestCertificates.authority()
        val leaf = ReferenceTunTestCertificates.leaf(authority, ReferenceTunHttpResponse.HOST)
        val serverContext = ReferenceTunTestCertificates.serverContext(leaf, authority)
        for (command in listOf(20, 21)) {
            val listener = java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())
            val serverFailure = AtomicReference<Throwable?>()
            val worker = Thread {
                try {
                    listener.accept().use { raw ->
                        raw.soTimeout = 5000
                        val tls = if (command == 21) (serverContext.socketFactory.createSocket(raw,
                            ReferenceTunHttpResponse.HOST, listener.localPort, false) as SSLSocket).apply {
                            useClientMode = false
                            soTimeout = 5000
                            startHandshake()
                        } else null
                        try {
                            val application = tls ?: raw
                            val request = ReferenceTunHttpResponse.request()
                            val received = ByteArray(request.size)
                            var offset = 0
                            while (offset < received.size) {
                                val size = application.getInputStream().read(received, offset, received.size - offset)
                                check(size > 0)
                                offset += size
                            }
                            assertArrayEquals(request, received)
                            if (command == 20) assertEquals(-1, raw.getInputStream().read())
                            application.getOutputStream().write(response())
                            application.getOutputStream().flush()
                            tls?.close()
                            raw.shutdownOutput()
                            if (command == 21) assertEquals(-1, raw.getInputStream().read())
                        } finally { tls?.close() }
                    }
                } catch (failure: Throwable) { serverFailure.set(failure) }
            }
            worker.start()
            val raw = object : Socket() {
                override fun connect(endpoint: SocketAddress, timeout: Int) {
                    val target = endpoint as InetSocketAddress
                    assertEquals("198.18.0.2", target.address.hostAddress)
                    assertEquals(if (command == 20) 80 else 443, target.port)
                    super.connect(InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), listener.localPort), timeout)
                }
            }
            val traffic = ReferenceTunTraffic({ raw }, { 26 }, { trust, socket ->
                trust.context.socketFactory.createSocket(socket, ReferenceTunHttpResponse.HOST, 443, false) as SSLSocket
            })
            try {
                traffic.configure(authority.certificate.encoded)
                assertArrayEquals(ReferenceTunHttpResponse.expectedBody(), traffic.execute(command) { assertFalse(raw.isConnected) })
                assertTrue(raw.isClosed)
            } finally {
                try { traffic.close() } finally {
                    listener.close()
                    worker.join(6000)
                    assertFalse(worker.isAlive)
                }
            }
            if (serverFailure.get() != null) throw AssertionError("loopback server failed")
        }
    }

    private fun assertCode(suffix: String, action: () -> Unit): ReferenceTunTraffic.Failure {
        val failure = assertThrows(ReferenceTunTraffic.Failure::class.java, action)
        assertEquals("traffic_reference_$suffix", failure.code)
        assertNull(failure.cause)
        return failure
    }

    private class Raw(tls: Boolean) : Socket() {
        val events: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf())
        val written = ByteArrayOutputStream()
        var connected = false
        var closed = false
        var destination: InetSocketAddress? = null
        var shutdownFailure = false
        var closeFailure = false
        var eofFailure = false
        var connectEntered: CountDownLatch? = null
        var connectRelease: CountDownLatch? = null
        var closeRelease: CountDownLatch? = null
        var afterConnect: (() -> Unit)? = null
        private val input = responseInput(if (tls) byteArrayOf() else response(), { eofFailure }, { events.add("raw-eof") })
        override fun connect(endpoint: SocketAddress, timeout: Int) {
            destination = endpoint as InetSocketAddress
            assertEquals(5000, timeout)
            connectEntered?.countDown()
            connectRelease?.let { check(it.await(3, TimeUnit.SECONDS)) }
            if (closed) throw SocketException("canary-closed")
            connected = true
            events.add("connect")
            afterConnect?.invoke()
        }
        override fun setSoTimeout(timeout: Int) { assertEquals(5000, timeout) }
        override fun getOutputStream() = written
        override fun getInputStream(): InputStream = input
        override fun shutdownOutput() {
            if (shutdownFailure) throw SocketException("canary-shutdown")
            events.add("raw-shutdown")
        }
        override fun close() {
            closed = true
            events.add("raw-close")
            connectRelease?.countDown()
            closeRelease?.countDown()
            if (closeFailure) throw SocketException("canary-close")
        }
    }

    private class Tls(private val events: MutableList<String>) : SSLSocket() {
        private val delegate = SSLContext.getDefault().socketFactory.createSocket() as SSLSocket
        val written = ByteArrayOutputStream()
        var selectedProtocol = ""
        var closed = false
        var handshakeFailure = false
        var eofFailure = false
        var closeFailure = false
        var closeEntered: CountDownLatch? = null
        var closeRelease: CountDownLatch? = null
        private val input = responseInput(response(), { eofFailure }, { events.add("tls-eof") })
        override fun getOutputStream() = written
        override fun getInputStream(): InputStream = input
        override fun shutdownOutput(): Unit = throw AssertionError("Android TLS shutdownOutput must not be assumed")
        override fun setSoTimeout(timeout: Int) { assertEquals(5000, timeout) }
        override fun startHandshake() {
            if (handshakeFailure) throw javax.net.ssl.SSLException("canary-provider")
            events.add("handshake")
        }
        override fun close() {
            events.add("tls-close")
            closeEntered?.countDown()
            closeRelease?.let { check(it.await(3, TimeUnit.SECONDS)) }
            closed = true
            delegate.close()
            if (closeFailure) throw SocketException("canary-tls-close")
        }
        override fun getApplicationProtocol() = selectedProtocol
        override fun getSSLParameters(): SSLParameters = delegate.sslParameters
        override fun setSSLParameters(parameters: SSLParameters) { delegate.sslParameters = parameters }
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites
        override fun getEnabledCipherSuites(): Array<String> = delegate.enabledCipherSuites
        override fun setEnabledCipherSuites(suites: Array<out String>) { delegate.enabledCipherSuites = suites }
        override fun getSupportedProtocols(): Array<String> = delegate.supportedProtocols
        override fun getEnabledProtocols(): Array<String> = delegate.enabledProtocols
        override fun setEnabledProtocols(protocols: Array<out String>) { delegate.enabledProtocols = protocols }
        override fun getSession(): SSLSession = delegate.session
        override fun addHandshakeCompletedListener(listener: HandshakeCompletedListener) { delegate.addHandshakeCompletedListener(listener) }
        override fun removeHandshakeCompletedListener(listener: HandshakeCompletedListener) { delegate.removeHandshakeCompletedListener(listener) }
        override fun setUseClientMode(mode: Boolean) { delegate.useClientMode = mode }
        override fun getUseClientMode() = delegate.useClientMode
        override fun setNeedClientAuth(need: Boolean) { delegate.needClientAuth = need }
        override fun getNeedClientAuth() = delegate.needClientAuth
        override fun setWantClientAuth(want: Boolean) { delegate.wantClientAuth = want }
        override fun getWantClientAuth() = delegate.wantClientAuth
        override fun setEnableSessionCreation(flag: Boolean) { delegate.enableSessionCreation = flag }
        override fun getEnableSessionCreation() = delegate.enableSessionCreation
    }

    private companion object {
        fun response() = "HTTP/1.1 200 OK\r\nContent-Length: 81\r\nConnection: close\r\n\r\n".toByteArray() + ReferenceTunHttpResponse.expectedBody()
        fun responseInput(bytes: ByteArray, fails: () -> Boolean, eof: () -> Unit): InputStream = object : ByteArrayInputStream(bytes) {
            override fun read(): Int {
                val value = super.read()
                if (value == -1) {
                    if (fails()) throw SocketException("canary-reset")
                    eof()
                }
                return value
            }
        }
    }
}
