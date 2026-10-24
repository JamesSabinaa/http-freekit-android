package com.httpfreekit.security

import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.Date
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket

/**
 * Scoped server-authenticated TLS spike, independent of companion routes and framing.
 *
 * A fresh platform trust manager/context and validity checks belong to every connection,
 * even when this factory is reused. [connect] accepts an already resolved dial address:
 * DNS resolution, VPN socket protection, stream I/O budgets, client credentials, and
 * active-session expiry are separate integration responsibilities. Call off the main thread.
 */
class GatewayTlsConnectionFactory(
    certificate: X509Certificate,
    private val expectedSpkiSha256: String,
    logicalServerName: String,
    private val connectTimeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS,
    private val handshakeTimeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS,
    private val clock: Clock = Clock.systemUTC(),
    private val rawSocketFactory: SocketFactory = SocketFactory.getDefault(),
) {
    private val gatewayCertificate = copyCertificate(certificate)
    private val serverName = logicalServerName.also {
        require(logicalServerName.length in 1..253 && logicalServerName.all { it.code in 33..126 }) {
            "Expected an ASCII logical TLS server name"
        }
    }.let(::SNIHostName)

    init {
        require(connectTimeoutMillis in 1..MAX_TIMEOUT_MILLIS) { "Invalid TCP connect timeout" }
        require(handshakeTimeoutMillis in 1..MAX_TIMEOUT_MILLIS) { "Invalid TLS handshake timeout" }
        GatewayTrust.verifyPinnedCertificate(gatewayCertificate, expectedSpkiSha256, now())
    }

    /** The caller owns the returned socket and must close it. No default TLS settings are changed. */
    fun connect(dialAddress: InetSocketAddress): SSLSocket {
        require(!dialAddress.isUnresolved && dialAddress.port in 1..65535) { "Expected a resolved gateway endpoint" }
        // A trust anchor can skip normal PKIX validity checks. Never cache this check or manager.
        val trust = GatewayTrust.forCertificate(gatewayCertificate, expectedSpkiSha256, now())
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
        val raw = rawSocketFactory.createSocket()
        var tls: SSLSocket? = null
        var deadline: HandshakeDeadline? = null
        var connected = false
        try {
            require(!raw.isConnected && !raw.isClosed && raw !is SSLSocket) { "Expected a fresh plain TCP socket" }
            // Keep watchdog cleanup non-blocking instead of inheriting a provider's linger policy.
            raw.setSoLinger(false, 0)
            raw.connect(dialAddress, connectTimeoutMillis)
            deadline = HandshakeDeadline(raw, handshakeTimeoutMillis)
            tls = context.socketFactory.createSocket(raw, serverName.asciiName, dialAddress.port, true) as? SSLSocket
                ?: throw SSLException("TLS socket creation failed")
            tls.useClientMode = true
            tls.enabledProtocols = tls.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }.toTypedArray()
                .also { if (it.isEmpty()) throw SSLException("TLS 1.2 or later is required") }
            tls.sslParameters = tls.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"
                serverNames = listOf(serverName)
            }
            tls.soTimeout = handshakeTimeoutMillis
            tls.startHandshake()
            // Check both the configured anchor and the actual peer after the handshake. This also
            // rejects a different child key even on platforms that treat a leaf anchor as an issuer.
            val currentTime = now()
            GatewayTrust.verifyPinnedCertificate(gatewayCertificate, expectedSpkiSha256, currentTime)
            val peer = tls.session.peerCertificates.firstOrNull() as? X509Certificate
                ?: throw CertificateException("Missing gateway peer certificate")
            GatewayTrust.verifyPinnedCertificate(peer, expectedSpkiSha256, currentTime)
            deadline.complete()
            // The handshake budget does not silently define an application-stream idle policy.
            tls.soTimeout = 0
            connected = true
            return tls
        } catch (failure: Exception) {
            if (deadline?.timedOut == true && failure !is SocketTimeoutException) {
                throw SocketTimeoutException("Gateway TLS handshake timed out").apply { initCause(failure) }
            }
            throw failure
        } finally {
            deadline?.cancel()
            if (!connected) {
                closeQuietly(raw)
                closeQuietly(tls)
            }
        }
    }

    private fun now(): Date = Date.from(clock.instant())

    private class HandshakeDeadline(private val raw: Socket, timeoutMillis: Int) {
        private val startedAt = System.nanoTime()
        private val timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis.toLong())
        private val finished = AtomicBoolean(false)
        private val expired = AtomicBoolean(false)
        val timedOut: Boolean get() = expired.get()
        private val timer = deadlines.schedule({
            if (finished.compareAndSet(false, true)) {
                expired.set(true)
                closeQuietly(raw)
            }
        }, timeoutMillis.toLong(), TimeUnit.MILLISECONDS)

        fun complete() {
            if (System.nanoTime() - startedAt >= timeoutNanos || !finished.compareAndSet(false, true)) {
                expired.set(true)
                throw SocketTimeoutException("Gateway TLS handshake timed out")
            }
            timer.cancel(false)
        }

        fun cancel() {
            finished.set(true)
            timer.cancel(false)
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 15_000
        const val MAX_TIMEOUT_MILLIS = 60_000
        private const val MAX_CERTIFICATE_BYTES = 4096
        private val deadlines = ScheduledThreadPoolExecutor(1, ThreadFactory { task ->
            Thread(task, "freekit-tls-deadline").apply { isDaemon = true }
        }).apply { removeOnCancelPolicy = true }

        private fun copyCertificate(certificate: X509Certificate): X509Certificate {
            val encoded = certificate.encoded
            if (encoded.size !in 1..MAX_CERTIFICATE_BYTES) throw CertificateException("Invalid gateway certificate size")
            val input = ByteArrayInputStream(encoded.copyOf())
            val copy = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
            if (input.available() != 0) throw CertificateException("Expected one gateway certificate")
            return copy
        }

        private fun closeQuietly(socket: Socket?) {
            try { socket?.close() } catch (_: IOException) { /* Preserve the connection failure. */ }
        }
    }
}
