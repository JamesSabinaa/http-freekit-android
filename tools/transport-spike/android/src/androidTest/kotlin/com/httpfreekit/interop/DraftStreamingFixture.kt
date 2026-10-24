package com.httpfreekit.interop

import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.protocol.DraftClock
import com.httpfreekit.security.AndroidDeviceIdentityStore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager

/** All identities, HTTP routes and bytes here belong only to the isolated synthetic fixture. */
internal class DraftStreamingFixture : AutoCloseable {
    private val args = InstrumentationRegistry.getArguments()
    private val store = AndroidDeviceIdentityStore()
    private val identityIds = ArrayList<String>()
    private val gateway = certificate(Base64.getUrlDecoder().decode(argument("gatewayDer")))
    private val pin = argument("gatewayPin")
    val enrollmentPort = argument("enrollmentPort").toInt().also { require(it in 1..65535) }
    val streamPort = argument("webSocketPort").toInt().also { require(it in 1..65535) }

    private fun argument(name: String) = checkNotNull(args.getString(name)) { "Missing fixed streaming argument" }

    fun enroll(): Credential {
        check(identityIds.size < 2) { "Research identity limit exceeded" }
        val id = "draft-stream-${UUID.randomUUID()}"
        identityIds.add(id)
        val identity = store.create(id)
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = Collections.list(keys.aliases()).single {
            keys.getCertificate(it)?.publicKey?.encoded?.contentEquals(identity.publicKey.encoded) == true
        }
        val before = keys.getCertificateChain(alias).map { it.encoded }
        val csr = identity.enrollmentRequest().also { check(it.size in 1..4096) }
        val reply = request(null, enrollmentPort, "POST", "/research/enroll", csr,
            mapOf("Content-Type" to "application/pkcs10"))
        check(reply.status == 200) { "Research issuance failed" }
        val input = DataInputStream(ByteArrayInputStream(reply.body))
        check(input.readUnsignedByte() == 1) { "Invalid research issuance version" }
        fun readCertificate() = certificate(ByteArray(input.readInt().also { check(it in 1..4096) }).also(input::readFully))
        val authority = readCertificate()
        val leaf = readCertificate()
        check(input.read() == -1 && leaf.publicKey.encoded.contentEquals(identity.publicKey.encoded)) { "Issued key mismatch" }
        val manager = identity.bindEnrolledClientCertificate(listOf(leaf), authority)
        val clientAlias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        val key = checkNotNull(manager.getPrivateKey(clientAlias))
        check(key.encoded == null) { "Research key was exportable" }
        val deviceId = "dev_" + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(identity.publicKey.encoded))
        return Credential(manager, deviceId) {
            check(key === manager.getPrivateKey(clientAlias) && key.encoded == null) { "Signing handle changed" }
            val after = keys.getCertificateChain(alias).map { it.encoded }
            check(before.size == after.size && before.zip(after).all { (a, b) -> a.contentEquals(b) }) { "Keystore chain changed" }
        }
    }

    class Credential(val manager: X509ExtendedKeyManager, val deviceId: String, val verifyKey: () -> Unit) {
        override fun toString() = "ResearchCredential([NONEXPORTABLE])"
    }

    fun connect(credential: Credential?, port: Int = streamPort, rawSendBufferBytes: Int = 1024): DraftStreamingTls =
        draftStreamingConnect(gateway, pin, NAME, port, credential?.manager, rawSendBufferBytes)

    data class Reply(val status: Int, val headers: Map<String, String>, val body: ByteArray) {
        override fun toString() = "ResearchReply(status=$status, body=[REDACTED])"
    }

    fun request(credential: Credential?, port: Int = streamPort, method: String, path: String,
        body: ByteArray = byteArrayOf(), headers: Map<String, String> = emptyMap()): Reply = connect(credential, port).use { tls ->
        check(method in setOf("GET", "POST") && path in setOf("/research/enroll", "/research/probe", "/research/command"))
        check(body.size <= 8201)
        tls.socket.soTimeout = 5000
        val timer = Thread({
            try { Thread.sleep(10000); tls.interrupt() } catch (_: InterruptedException) { /* Completed HTTP. */ }
        }, "draft-http-deadline").apply { isDaemon = true; start() }
        try {
            val head = buildString {
                append("$method $path HTTP/1.1\r\nHost: $NAME\r\nConnection: close\r\n")
                if (method == "POST") append("Content-Length: ${body.size}\r\n")
                headers.forEach { (key, value) ->
                    check(key.matches(Regex("[A-Za-z0-9-]{1,64}")) && value.length <= 256 && value.all { it.code in 32..126 })
                    append("$key: $value\r\n")
                }
                append("\r\n")
            }
            tls.socket.outputStream.write(head.toByteArray(Charsets.US_ASCII))
            tls.socket.outputStream.write(body)
            tls.socket.outputStream.flush()
            val parsed = readHeaders(tls.socket)
            val length = checkNotNull(parsed.second["content-length"]).toInt().also { check(it in 0..16384) }
            check("transfer-encoding" !in parsed.second) { "Unexpected research transfer encoding" }
            Reply(parsed.first, parsed.second, ByteArray(length).also { DataInputStream(tls.socket.inputStream).readFully(it) })
        } finally {
            timer.interrupt()
            timer.join(2000)
            check(!timer.isAlive) { "HTTP deadline did not join" }
        }
    }

    fun upgrade(credential: Credential, route: String, session: String? = null, scenario: String? = null,
        extraHeaders: List<Pair<String, String>> = emptyList(), rawSendBufferBytes: Int = 1024): Pair<DraftStreamingTls, Int> {
        check(route in setOf("/companion/v1/control", "/companion/v1/streams"))
        return draftStreamingUpgrade(connect(credential, rawSendBufferBytes = rawSendBufferBytes), NAME, route, session, scenario, extraHeaders)
    }

    override fun close() {
        var failed = false
        identityIds.forEach { id ->
            try { store.delete(id); check(store.load(id) == null) { "Research identity survived cleanup" } }
            catch (_: Exception) { failed = true }
        }
        identityIds.clear()
        check(!failed) { "Research identity cleanup failed" }
    }

    companion object {
        const val NAME = "android-node-research.invalid"
        private fun certificate(bytes: ByteArray): X509Certificate {
            check(bytes.size in 1..4096)
            val input = ByteArrayInputStream(bytes)
            val value = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
            check(input.available() == 0 && value.encoded.contentEquals(bytes))
            return value
        }
        fun readHeaders(socket: SSLSocket): Pair<Int, Map<String, String>> {
            val bytes = ByteArrayOutputStream()
            var suffix = 0
            while (bytes.size() < 8192 && suffix != 0x0d0a0d0a) {
                val next = socket.inputStream.read()
                if (next < 0) throw EOFException("Research HTTP closed")
                check(next in 9..126) { "Invalid research HTTP byte" }
                bytes.write(next); suffix = (suffix shl 8) or next
            }
            check(suffix == 0x0d0a0d0a) { "Research HTTP headers exceeded bound" }
            val lines = bytes.toString("US-ASCII").split("\r\n")
            check(lines[0].matches(Regex("HTTP/1\\.1 [0-9]{3} [A-Za-z ]{1,64}"))) { "Invalid research HTTP status" }
            val headers = LinkedHashMap<String, String>()
            lines.drop(1).filter { it.isNotEmpty() }.forEach { line ->
                check(line.length <= 1024 && ':' in line)
                val name = line.substringBefore(':').lowercase()
                check(name !in headers) { "Duplicate research HTTP header" }
                headers[name] = line.substringAfter(':').trim()
            }
            return lines[0].split(' ')[1].toInt() to headers
        }
    }
}

internal class DraftStreamingTls(val raw: Socket, val socket: SSLSocket) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val interruptFailed = AtomicBoolean(false)
    fun interrupt() { try { raw.close() } catch (_: Exception) { interruptFailed.set(true) } }
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        interrupt()
        val failed = AtomicBoolean(false)
        val closer = Thread({ try { socket.close() } catch (_: Exception) { failed.set(true) } }, "draft-tls-close")
            .apply { isDaemon = true; start() }
        closer.join(2000)
        check(!closer.isAlive && !failed.get() && !interruptFailed.get() && raw.isClosed && socket.isClosed) { "TLS close did not finish" }
    }
    override fun toString() = "ResearchTls([SCOPED])"
}

/** A single real monotonic origin belongs to the controller and all its streams. */
internal class DraftStreamingClock {
    private val origin = System.nanoTime()
    fun now() = DraftClock(System.currentTimeMillis(), (System.nanoTime() - origin) / 1_000_000)
}

internal fun draftAwait(label: String, timeoutMillis: Long = 15000, condition: () -> Boolean) {
    val end = System.nanoTime() + timeoutMillis * 1_000_000
    while (!condition()) {
        check(System.nanoTime() < end) { "Research wait failed: $label" }
        Thread.sleep(10)
    }
}

/** Bounded registration precedes start; failure text never includes sockets, payloads or credentials. */
internal class DraftStreamingWorkers(private val onFailure: () -> Unit) {
    private val threads = ArrayList<Thread>()
    val stopping = AtomicBoolean(false)
    val failure = AtomicReference<String?>()
    @Synchronized fun launch(role: String, action: () -> Unit): Thread {
        check(!stopping.get() && threads.size < 12) { "Research worker admission failed" }
        return Thread({
            try { action() } catch (problem: Exception) {
                if (!stopping.get()) { failure.compareAndSet(null, "$role:${problem.javaClass.simpleName}"); onFailure() }
            } catch (_: AssertionError) {
                if (!stopping.get()) { failure.compareAndSet(null, "$role:AssertionError"); onFailure() }
            }
        }, "draft-$role").apply { isDaemon = true; threads.add(this); start() }
    }
    fun joinAll() {
        val end = System.nanoTime() + 5_000_000_000
        val owned = synchronized(this) { stopping.set(true); threads.toList() }
        owned.forEach { thread ->
            if (thread !== Thread.currentThread()) thread.join(((end - System.nanoTime()) / 1_000_000).coerceAtLeast(1))
        }
        check(owned.none { it.isAlive }) { "Research worker join failed" }
    }
    @Synchronized fun alive() = threads.count { it.isAlive }
    @Synchronized fun alive(role: String) = threads.count { it.isAlive && it.name == "draft-$role" }
}
