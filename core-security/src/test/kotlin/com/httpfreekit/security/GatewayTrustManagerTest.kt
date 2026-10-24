package com.httpfreekit.security

import java.net.InetAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GatewayTrustManagerTest {
    private fun pin(identity: HeldCertificate): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256").digest(identity.certificate.publicKey.encoded),
    )

    @Test fun acceptsOnlyTheConfiguredLeafKeyAndChecksExpiry() {
        val identity = HeldCertificate.Builder().commonName("gateway.invalid").build()
        val trust = GatewayTrust.forCertificate(identity.certificate, pin(identity))
        trust.checkServerTrusted(arrayOf(identity.certificate), "EC")
        rejected { GatewayTrust.forCertificate(HeldCertificate.Builder().build().certificate, pin(identity)) }
        rejected { trust.checkServerTrusted(arrayOf(HeldCertificate.Builder().build().certificate), "EC") }
        val expired = HeldCertificate.Builder().validityInterval(1, 1000).build()
        rejected { GatewayTrust.forCertificate(expired.certificate, pin(expired)) }
        assertEquals(1, trust.acceptedIssuers.size)
    }

    @Test fun aPinnedIssuerCannotAuthorizeAnUnpinnedLeaf() {
        val issuer = HeldCertificate.Builder().certificateAuthority(1).build()
        val leaf = HeldCertificate.Builder().signedBy(issuer).build()
        rejected { GatewayTrust.forCertificate(issuer.certificate, pin(issuer)) }
        rejected { GatewayTrust.forCertificate(leaf.certificate, pin(leaf)) }
    }

    @Test fun scopedPinningWorksWhileHostnameVerificationStillRejectsAnotherHost() {
        val identity = HeldCertificate.Builder().commonName("gateway.invalid").addSubjectAlternativeName("gateway.invalid").build()
        val serverCertificates = HandshakeCertificates.Builder().heldCertificate(identity).build()
        val context = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(GatewayTrust.forCertificate(identity.certificate, pin(identity))), null)
        }
        val defaultContext = SSLContext.getDefault()
        assertEquals(42, handshake(serverCertificates, context, "gateway.invalid").get(5, TimeUnit.SECONDS))
        var wrongNameRejected = false
        try { handshake(serverCertificates, context, "wrong.invalid").get(5, TimeUnit.SECONDS) }
        catch (_: java.util.concurrent.ExecutionException) { wrongNameRejected = true }
        assertTrue(wrongNameRejected)
        assertTrue("Global SSL context was replaced", defaultContext === SSLContext.getDefault())
        assertFalse(context === defaultContext)
    }

    private fun handshake(serverCertificates: HandshakeCertificates, context: SSLContext, logicalHost: String): CompletableFuture<Int> {
        val result = CompletableFuture<Int>()
        val server = serverCertificates.sslContext().serverSocketFactory.createServerSocket(
            0, 1, InetAddress.getByName("127.0.0.1"),
        ) as SSLServerSocket
        server.soTimeout = 5000
        val serverResult = CompletableFuture.runAsync {
            server.use {
                try {
                    (it.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = 5000
                        socket.startHandshake()
                        socket.outputStream.write(42)
                    }
                } catch (_: java.io.IOException) { /* Client may reject the identity. */ }
            }
        }
        CompletableFuture.runAsync {
            try {
                Socket("127.0.0.1", server.localPort).use { raw ->
                    (context.socketFactory.createSocket(raw, logicalHost, server.localPort, true) as SSLSocket).use { tls ->
                        tls.soTimeout = 5000
                        tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                        tls.startHandshake()
                        result.complete(tls.inputStream.read())
                    }
                }
            } catch (exception: Exception) { result.completeExceptionally(exception) }
            finally {
                server.close()
                serverResult.get(5, TimeUnit.SECONDS)
            }
        }
        return result
    }

    private fun rejected(block: () -> Unit) {
        var rejected = false
        try { block() } catch (_: CertificateException) { rejected = true }
        assertTrue("Expected certificate rejection", rejected)
    }
}
