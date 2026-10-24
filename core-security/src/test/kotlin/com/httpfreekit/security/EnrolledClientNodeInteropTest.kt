package com.httpfreekit.security

import java.io.File
import java.net.InetAddress
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import okhttp3.CertificatePinner
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Host JCA key proof; real Android Keystore execution remains a separate gate. */
class EnrolledClientNodeInteropTest {
    @Test(timeout = 45000) fun issuedChainAndOriginalSigningHandleAuthenticateToTheNodeWebSocketPeer() {
        val logicalName = "gateway-fixture.invalid"
        val authority = TestEnrollmentCertificates.authority()
        val keys = TestEnrollmentCertificates.keyPair()
        val lookups = AtomicInteger()
        val identity = DeviceIdentity(keys.public, keys.private) { lookups.incrementAndGet(); true }
        val leaf = TestEnrollmentCertificates.client(identity.publicKey, authority)
        val manager = identity.bindEnrolledClientCertificate(listOf(leaf), authority.certificate)
        val lookupsBeforeTls = lookups.get()
        val server = TestEnrollmentCertificates.server(logicalName)
        val directory = Files.createTempDirectory("freekit-enrolled-client-").toFile()
        var process: Process? = null
        var client: OkHttpClient? = null
        try {
            // Only the synthetic Node server key crosses the process boundary. The client key does not.
            File(directory, "server-key.pem").writeText(pem("PRIVATE KEY", server.keys.private.encoded))
            File(directory, "server.pem").writeText(pem("CERTIFICATE", server.certificate.encoded))
            File(directory, "client-ca.pem").writeText(pem("CERTIFICATE", authority.certificate.encoded))
            val script = File("tools/transport-spike/server.mjs").absoluteFile
            check(script.isFile) { "Missing Node transport peer" }
            val peer = ProcessBuilder("node", script.absolutePath, directory.absolutePath)
                .redirectError(ProcessBuilder.Redirect.INHERIT).start().also { process = it }
            val port = CompletableFuture.supplyAsync { peer.inputStream.bufferedReader().readLine()?.toIntOrNull() }
                .get(10, TimeUnit.SECONDS) ?: error("Node TLS peer did not start")
            val trust = TestEnrollmentCertificates.trust(server.certificate)
            val context = SSLContext.getInstance("TLS").apply { init(arrayOf(manager), arrayOf(trust), null) }
            val pin = "sha256/" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(server.certificate.publicKey.encoded))
            client = OkHttpClient.Builder()
                .sslSocketFactory(context.socketFactory, trust)
                .certificatePinner(CertificatePinner.Builder().add(logicalName, pin).build())
                .dns(object : Dns {
                    override fun lookup(hostname: String): List<InetAddress> = listOf(InetAddress.getByName("127.0.0.1"))
                })
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build()
            val payload = ByteArray(65536) { (it % 251).toByte() }
            val result = CompletableFuture<ByteString>()
            client.newWebSocket(Request.Builder().url("wss://$logicalName:$port/spike").build(), object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    if (!webSocket.send(payload.toByteString())) {
                        result.completeExceptionally(IllegalStateException("WebSocket send rejected"))
                        webSocket.cancel()
                    }
                }
                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                    result.complete(bytes)
                    webSocket.close(1000, "done")
                }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    result.completeExceptionally(t)
                }
            })
            assertArrayEquals(payload, result.get(10, TimeUnit.SECONDS).toByteArray())
            assertTrue("TLS did not consult the bound identity", lookups.get() > lookupsBeforeTls)
        } finally {
            client?.dispatcher?.executorService?.shutdownNow()
            client?.connectionPool?.evictAll()
            process?.let { peer ->
                peer.destroyForcibly()
                check(peer.waitFor(10, TimeUnit.SECONDS) && !peer.isAlive) { "Node TLS peer did not stop" }
            }
            val tempRoot = File(checkNotNull(System.getProperty("java.io.tmpdir"))).canonicalFile
            check(directory.canonicalFile.parentFile == tempRoot && directory.name.startsWith("freekit-enrolled-client-"))
            check(directory.deleteRecursively()) { "Synthetic TLS material could not be removed" }
        }
    }

    private fun pem(type: String, bytes: ByteArray): String =
        "-----BEGIN $type-----\n" + Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(bytes) + "\n-----END $type-----\n"
}
