package com.httpfreekit.protocol

import java.io.File
import java.net.InetAddress
import java.nio.file.Files
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import okhttp3.CertificatePinner
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** JVM interoperability evidence only; does not prove Android Keystore or a VPN. */
class NodeTransportSpikeTest {
    @Test fun pinnedMutualTlsAndBinaryWebSocketsInteroperateWithNode() {
        val directory = Files.createTempDirectory("freekit-transport-").toFile()
        val serverIdentity = HeldCertificate.Builder().commonName("gateway-fixture.invalid")
            .addSubjectAlternativeName("gateway-fixture.invalid").build()
        val clientAuthority = HeldCertificate.Builder().certificateAuthority(1).commonName("fixture-enrollment").build()
        val clientIdentity = HeldCertificate.Builder().commonName("fixture-device").signedBy(clientAuthority).build()
        File(directory, "server.pem").writeText(serverIdentity.certificatePem())
        File(directory, "server-key.pem").writeText(serverIdentity.privateKeyPkcs8Pem())
        File(directory, "client-ca.pem").writeText(clientAuthority.certificatePem())
        val process = ProcessBuilder("node", "tools/transport-spike/server.mjs", directory.absolutePath)
            .redirectError(ProcessBuilder.Redirect.INHERIT).start()
        try {
            val port = CompletableFuture.supplyAsync { process.inputStream.bufferedReader().readLine()?.toInt() }
                .get(10, TimeUnit.SECONDS) ?: error("Node peer did not start")
            val trustedClient = HandshakeCertificates.Builder().addTrustedCertificate(serverIdentity.certificate)
                .heldCertificate(clientIdentity, clientAuthority.certificate).build()
            val client = client(trustedClient, "gateway-fixture.invalid", CertificatePinner.pin(serverIdentity.certificate))
            try {
                val payload = ByteArray(65536) { (it % 251).toByte() }
                val result = exchange(client, port, "gateway-fixture.invalid", payload)
                assertArrayEquals(payload, result.get(10, TimeUnit.SECONDS).toByteArray())
            } finally { close(client) }

            val wrongPin = client(trustedClient, "gateway-fixture.invalid", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            try { assertRejected(wrongPin, port, "gateway-fixture.invalid", "pin") } finally { close(wrongPin) }

            val wrongHost = client(trustedClient, "wrong.invalid", CertificatePinner.pin(serverIdentity.certificate))
            try { assertRejected(wrongHost, port, "wrong.invalid", "hostname") } finally { close(wrongHost) }

            val anonymous = HandshakeCertificates.Builder().addTrustedCertificate(serverIdentity.certificate).build()
            val noCertificate = client(anonymous, "gateway-fixture.invalid", CertificatePinner.pin(serverIdentity.certificate))
            try { assertRejected(noCertificate, port, "gateway-fixture.invalid", "missing device certificate") } finally { close(noCertificate) }

            val stranger = HeldCertificate.Builder().commonName("untrusted-device").build()
            val untrustedIdentity = HandshakeCertificates.Builder().addTrustedCertificate(serverIdentity.certificate)
                .heldCertificate(stranger).build()
            val untrusted = client(untrustedIdentity, "gateway-fixture.invalid", CertificatePinner.pin(serverIdentity.certificate))
            try { assertRejected(untrusted, port, "gateway-fixture.invalid", "untrusted device certificate") } finally { close(untrusted) }
        } finally {
            process.destroyForcibly()
            process.waitFor(10, TimeUnit.SECONDS)
            check(!process.isAlive) { "Node peer did not stop" }
            directory.deleteRecursively()
        }
    }

    private fun client(identity: HandshakeCertificates, serverName: String, pin: String): OkHttpClient =
        OkHttpClient.Builder()
            .sslSocketFactory(identity.sslSocketFactory(), identity.trustManager)
            .certificatePinner(CertificatePinner.Builder().add(serverName, pin).build())
            .dns(object : Dns {
                override fun lookup(hostname: String): List<InetAddress> = listOf(InetAddress.getByName("127.0.0.1"))
            })
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()

    private fun exchange(client: OkHttpClient, port: Int, serverName: String, payload: ByteArray): CompletableFuture<ByteString> {
        val result = CompletableFuture<ByteString>()
        client.newWebSocket(Request.Builder().url("wss://$serverName:$port/spike").build(), object : WebSocketListener() {
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
        return result
    }

    private fun assertRejected(client: OkHttpClient, port: Int, host: String, reason: String) {
        try {
            exchange(client, port, host, byteArrayOf(1)).get(10, TimeUnit.SECONDS)
            throw AssertionError("Accepted $reason")
        } catch (exception: java.util.concurrent.ExecutionException) {
            assertTrue("Expected TLS rejection for $reason: ${exception.cause}", exception.cause is java.io.IOException)
        }
    }

    private fun close(client: OkHttpClient) {
        client.dispatcher.executorService.shutdownNow()
        client.connectionPool.evictAll()
    }
}
