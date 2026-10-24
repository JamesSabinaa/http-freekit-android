package com.httpfreekit.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Compiling these tests is not evidence of Android Keystore TLS execution. */
@RunWith(AndroidJUnit4::class)
class AndroidDeviceClientCredentialTest {
    @Test(timeout = 60000) fun nonexportableKeyAuthenticatesWithIssuedChainWithoutReplacingItsKeystoreCertificate() {
        val id = "client-test-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            val identity = store.create(id)
            val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = Collections.list(keystore.aliases()).single { candidate ->
                keystore.getCertificate(candidate)?.publicKey?.encoded?.contentEquals(identity.publicKey.encoded) == true
            }
            val before = keystore.getCertificateChain(alias).map { it.encoded }
            val authority = TestEnrollmentCertificates.authority()
            val leaf = TestEnrollmentCertificates.client(identity.publicKey, authority)
            val manager = identity.bindEnrolledClientCertificate(listOf(leaf), authority.certificate)
            val clientAlias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
            val key = checkNotNull(manager.getPrivateKey(clientAlias))
            assertNull(key.encoded)
            assertTrue("Original nonexportable handle was replaced", key === manager.getPrivateKey(clientAlias))
            val serverIdentity = TestEnrollmentCertificates.server()
            val serverContext = TestEnrollmentCertificates.serverContext(serverIdentity, authority.certificate)
            val trust = TestEnrollmentCertificates.trust(serverIdentity.certificate)
            val clientContext = SSLContext.getInstance("TLS").apply { init(arrayOf(manager), arrayOf(trust), null) }
            val protocols = listOf("TLSv1.2", "TLSv1.3").filter {
                it in clientContext.supportedSSLParameters.protocols && it in serverContext.supportedSSLParameters.protocols
            }
            assertTrue("TLS 1.2 is required by the foundation", "TLSv1.2" in protocols)
            protocols.forEach { protocol ->
                authenticate(serverContext, clientContext, protocol, identity.publicKey.encoded, leaf.encoded)
            }
            val after = keystore.getCertificateChain(alias).map { it.encoded }
            assertEquals(before.size, after.size)
            before.zip(after).forEach { (original, current) -> assertArrayEquals(original, current) }
        } finally { store.delete(id) }
    }

    @Test fun deletedOrRecreatedAliasCannotBeSelectedByTheOldCredential() {
        val id = "client-delete-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            val first = store.create(id)
            val authority = TestEnrollmentCertificates.authority()
            val manager = first.bindEnrolledClientCertificate(
                listOf(TestEnrollmentCertificates.client(first.publicKey, authority)), authority.certificate,
            )
            val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
            store.delete(id)
            assertNull(store.load(id))
            assertNull(manager.getClientAliases("EC", null))
            assertNull(manager.chooseEngineClientAlias(arrayOf("EC"), null, null))
            assertNull(manager.getCertificateChain(alias))
            assertNull(manager.getPrivateKey(alias))
            assertNull(store.load(id))
            var rejected = false
            try { first.signChallenge(byteArrayOf(1)) } catch (_: IllegalStateException) { rejected = true }
            assertTrue(rejected)
            val replacement = store.create(id)
            assertFalse(first.publicKey.encoded.contentEquals(replacement.publicKey.encoded))
            assertNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
            assertNull(manager.getPrivateKey(alias))
            assertArrayEquals(replacement.publicKey.encoded, checkNotNull(store.load(id)).publicKey.encoded)
        } finally { store.delete(id) }
    }

    private fun authenticate(
        serverContext: SSLContext,
        clientContext: SSLContext,
        protocol: String,
        expectedPublicKey: ByteArray,
        expectedClientCertificate: ByteArray,
    ) {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = serverContext.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket
        server.enabledProtocols = arrayOf(protocol)
        server.needClientAuth = true
        server.soTimeout = 5000
        val accepted = AtomicReference<SSLSocket?>()
        val receivedIdentity = CompletableFuture<ByteArray>()
        val worker = Thread({
            try {
                (server.accept() as SSLSocket).use { socket ->
                    accepted.set(socket)
                    socket.soTimeout = 5000
                    socket.startHandshake()
                    assertEquals(42, socket.inputStream.read())
                    receivedIdentity.complete(socket.session.peerCertificates.first().publicKey.encoded)
                    socket.outputStream.write(43)
                }
            } catch (failure: Throwable) { receivedIdentity.completeExceptionally(failure) }
        }, "freekit-keystore-tls-peer").apply { isDaemon = true; start() }
        var reportedFailure: Throwable? = null
        try {
            Socket().use { raw ->
                raw.connect(InetSocketAddress(loopback, server.localPort), 5000)
                (clientContext.socketFactory.createSocket(raw, "gateway-fixture.invalid", server.localPort, true) as SSLSocket).use { tls ->
                    tls.enabledProtocols = arrayOf(protocol)
                    tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    tls.soTimeout = 5000
                    tls.startHandshake()
                    assertEquals(protocol, tls.session.protocol)
                    assertArrayEquals(expectedClientCertificate, tls.session.localCertificates.first().encoded)
                    tls.outputStream.write(42)
                    assertEquals(43, tls.inputStream.read())
                }
            }
            assertArrayEquals(expectedPublicKey, receivedIdentity.get(10, TimeUnit.SECONDS))
        } catch (clientFailure: Throwable) {
            val diagnostic = AssertionError("Android Keystore mutual TLS failed using $protocol", clientFailure)
            reportedFailure = diagnostic
            try {
                receivedIdentity.get(5, TimeUnit.SECONDS)
            } catch (peerFailure: ExecutionException) {
                diagnostic.addSuppressed(AssertionError("Loopback TLS server failed using $protocol", peerFailure.cause ?: peerFailure))
            } catch (timeout: TimeoutException) {
                diagnostic.addSuppressed(AssertionError("Loopback TLS server did not report within five seconds using $protocol", timeout))
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                diagnostic.addSuppressed(interrupted)
            }
            throw diagnostic
        } finally {
            try {
                server.close()
                accepted.get()?.close()
                worker.interrupt()
                worker.join(5000)
                check(!worker.isAlive) { "Keystore TLS test peer did not stop" }
            } catch (cleanupFailure: Throwable) {
                if (reportedFailure == null) throw cleanupFailure
                reportedFailure.addSuppressed(cleanupFailure)
            }
        }
    }
}
