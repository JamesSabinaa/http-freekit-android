package com.httpfreekit.interop

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.security.AndroidDeviceIdentityStore
import com.httpfreekit.security.GatewayTlsConnectionFactory
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Collections
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Fixture-only interoperability. No VPN, companion enrollment, or arbitrary destination access. */
@RunWith(AndroidJUnit4::class)
class AndroidNodeInteropTest {
    private val arguments = InstrumentationRegistry.getArguments()
    private fun argument(name: String): String = checkNotNull(arguments.getString(name)) { "Missing research peer argument: $name" }
    private val gateway by lazy { certificate(Base64.getUrlDecoder().decode(argument("gatewayDer"))) }
    private val pin by lazy { argument("gatewayPin") }
    private fun port(name: String): Int = argument(name).toInt().also { require(it in 1..65535) }
    private fun factory(name: String = NAME, expectedPin: String = pin, manager: X509ExtendedKeyManager? = null) =
        GatewayTlsConnectionFactory(gateway, expectedPin, name, 5000, 5000, clientKeyManager = manager)
    private fun connect(factory: GatewayTlsConnectionFactory, portName: String): SSLSocket =
        factory.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port(portName)))

    @Test(timeout = 60000) fun nonexportableIdentityEnrollsAndEchoes64KiB() {
        val id = "node-research-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            val identity = store.create(id)
            val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = Collections.list(keystore.aliases()).single {
                keystore.getCertificate(it)?.publicKey?.encoded?.contentEquals(identity.publicKey.encoded) == true
            }
            val originalCertificates = keystore.getCertificateChain(alias).map { it.encoded }
            val csr = identity.enrollmentRequest().also { require(it.size in 1..4096) }
            val altered = csr.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            assertEquals(400, enroll(altered).status)
            val reply = enroll(csr)
            assertEquals(200, reply.status)
            val input = DataInputStream(ByteArrayInputStream(reply.body))
            assertEquals(1, input.readUnsignedByte())
            fun readCertificate(): X509Certificate = certificate(ByteArray(input.readInt().also { require(it in 1..4096) }).also(input::readFully))
            val authority = readCertificate()
            val leaf = readCertificate()
            assertEquals(-1, input.read())
            assertArrayEquals(identity.publicKey.encoded, leaf.publicKey.encoded)
            val manager = identity.bindEnrolledClientCertificate(listOf(leaf), authority)
            val clientAlias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
            val signingHandle = checkNotNull(manager.getPrivateKey(clientAlias))
            assertNull(signingHandle.encoded)
            val scopedFactory = factory(manager = manager)
            connect(scopedFactory, "webSocketPort").use { socket ->
                boundedIo(socket) {
                    assertTrue(socket.session.protocol in setOf("TLSv1.2", "TLSv1.3"))
                    assertArrayEquals(leaf.encoded, socket.session.localCertificates.first().encoded)
                    val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
                    val key = Base64.getEncoder().encodeToString(nonce)
                    socket.outputStream.write(("GET /research/echo HTTP/1.1\r\nHost: $NAME\r\nUpgrade: websocket\r\n" +
                        "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: $key\r\n\r\n").toByteArray(Charsets.US_ASCII))
                    val headers = headers(socket)
                    assertEquals("HTTP/1.1 101 Switching Protocols", headers.first)
                    assertEquals("websocket", headers.second["upgrade"]?.lowercase())
                    assertTrue(headers.second["connection"]!!.split(',').any { it.trim().equals("upgrade", true) })
                    val accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + GUID).toByteArray(Charsets.US_ASCII)))
                    assertEquals(accept, headers.second["sec-websocket-accept"])
                    val payload = ByteArray(65536) { (it % 251).toByte() }
                    writeMaskedFrame(socket, 2, payload)
                    assertArrayEquals(payload, readFrame(socket, 2, 65536))
                    writeMaskedFrame(socket, 8, byteArrayOf(3, -24))
                    val close = readFrame(socket, 8, 125)
                    assertTrue(close.size >= 2 && close[0] == 3.toByte() && close[1] == (-24).toByte())
                }
            }
            assertTrue(signingHandle === manager.getPrivateKey(clientAlias))
            assertNull(signingHandle.encoded)
            val currentCertificates = keystore.getCertificateChain(alias).map { it.encoded }
            assertEquals(originalCertificates.size, currentCertificates.size)
            originalCertificates.zip(currentCertificates).forEach { (before, after) -> assertArrayEquals(before, after) }
        } finally { store.delete(id); assertNull(store.load(id)) }
    }

    @Test(timeout = 20000) fun wrongPinIsRejected() {
        assertPeerReachable()
        val wrongPin = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))
        var rejected = false
        try { factory(expectedPin = wrongPin) } catch (_: CertificateException) { rejected = true }
        assertTrue("Wrong gateway pin was accepted", rejected)
    }

    @Test(timeout = 20000) fun wrongHostnameIsRejected() {
        assertPeerReachable()
        var rejected = false
        try { connect(factory(name = "wrong-research.invalid"), "enrollmentPort").close() }
        catch (_: SSLException) { rejected = true }
        assertTrue("Wrong logical hostname was accepted", rejected)
    }

    @Test(timeout = 20000) fun missingClientCertificateIsRejected() {
        assertPeerReachable()
        var connected = false
        var rejected = false
        try {
            connect(factory(), "webSocketPort").use { socket ->
                connected = true
                boundedIo(socket) {
                    socket.outputStream.write("GET /research/echo HTTP/1.1\r\nHost: $NAME\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    headers(socket)
                }
            }
        } catch (_: SSLException) { rejected = true }
        catch (failure: EOFException) { if (!connected) throw failure; rejected = true }
        catch (failure: SocketException) { if (!connected) throw failure; rejected = true }
        assertTrue("Node accepted an unauthenticated client", rejected)
    }

    private fun assertPeerReachable() { connect(factory(), "enrollmentPort").use { assertTrue(it.isConnected) } }
    private data class Reply(val status: Int, val body: ByteArray)
    private fun enroll(csr: ByteArray): Reply = connect(factory(), "enrollmentPort").use { socket ->
        boundedIo(socket) {
            socket.outputStream.write(("POST /research/enroll HTTP/1.1\r\nHost: $NAME\r\nContent-Type: application/pkcs10\r\n" +
                "Content-Length: ${csr.size}\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
            socket.outputStream.write(csr)
            val headers = headers(socket)
            val status = headers.first.split(' ')[1].toInt()
            if (status != 200) Reply(status, byteArrayOf()) else {
                require(headers.second["content-type"] == "application/octet-stream" && "transfer-encoding" !in headers.second)
                val length = checkNotNull(headers.second["content-length"]).toInt().also { require(it in 1..8201) }
                Reply(status, ByteArray(length).also { DataInputStream(socket.inputStream).readFully(it) })
            }
        }
    }
    private fun <T> boundedIo(socket: SSLSocket, block: () -> T): T {
        socket.soTimeout = 5000
        val timer = Executors.newSingleThreadScheduledExecutor()
        val deadline = timer.schedule({ socket.close() }, 10000, TimeUnit.MILLISECONDS)
        try { return block() } finally { deadline.cancel(false); timer.shutdownNow() }
    }
    private fun headers(socket: SSLSocket): Pair<String, Map<String, String>> {
        val bytes = ArrayList<Byte>()
        while (bytes.size < 8192) {
            val next = socket.inputStream.read()
            if (next == -1) throw EOFException("Peer closed before HTTP headers")
            if (next !in 9..126) throw IOException("Invalid research HTTP header")
            bytes.add(next.toByte())
            if (bytes.size >= 4 && bytes.takeLast(4) == listOf<Byte>(13, 10, 13, 10)) break
        }
        require(bytes.takeLast(4) == listOf<Byte>(13, 10, 13, 10)) { "Research headers exceed limit" }
        val lines = bytes.toByteArray().toString(Charsets.US_ASCII).split("\r\n")
        val result = linkedMapOf<String, String>()
        lines.drop(1).filter { it.isNotEmpty() }.forEach { line ->
            require(line.length <= 1024 && ':' in line)
            val name = line.substringBefore(':').lowercase()
            require(name !in result)
            result[name] = line.substringAfter(':').trim()
        }
        return lines.first() to result
    }
    private fun writeMaskedFrame(socket: SSLSocket, opcode: Int, payload: ByteArray) {
        require(payload.size <= 65536)
        val mask = ByteArray(4).also { SecureRandom().nextBytes(it) }
        val output = socket.outputStream
        output.write(128 or opcode)
        if (payload.size < 126) output.write(128 or payload.size) else {
            output.write(128 or 127)
            repeat(8) { index -> output.write((payload.size.toLong() ushr ((7 - index) * 8)).toInt() and 255) }
        }
        output.write(mask)
        output.write(ByteArray(payload.size) { (payload[it].toInt() xor mask[it % 4].toInt()).toByte() })
    }
    private fun readFrame(socket: SSLSocket, opcode: Int, maximum: Int): ByteArray {
        val input = DataInputStream(socket.inputStream)
        require(input.readUnsignedByte() == (128 or opcode))
        val second = input.readUnsignedByte()
        require(second and 128 == 0)
        val length = when (second) { 126 -> input.readUnsignedShort().toLong(); 127 -> input.readLong(); else -> second.toLong() }
        require(length in 0..maximum.toLong())
        return ByteArray(length.toInt()).also(input::readFully)
    }
    private fun certificate(bytes: ByteArray): X509Certificate {
        require(bytes.size in 1..4096)
        val input = ByteArrayInputStream(bytes)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        require(input.available() == 0 && bytes.contentEquals(certificate.encoded))
        return certificate
    }
    companion object {
        private const val NAME = "android-node-research.invalid"
        private const val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    }
}
