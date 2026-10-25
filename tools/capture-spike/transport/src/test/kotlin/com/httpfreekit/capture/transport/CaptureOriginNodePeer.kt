package com.httpfreekit.capture.transport

import com.httpfreekit.protocol.DraftBudgetPool
import com.httpfreekit.protocol.DraftEnrollmentChannel
import com.httpfreekit.protocol.DraftEnrollmentCodec
import com.httpfreekit.protocol.DraftEnrollmentDecodeResult
import com.httpfreekit.protocol.DraftEnrollmentMessage
import com.httpfreekit.security.EnrolledCredentialRecord
import com.httpfreekit.security.EnrollmentRequest
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Explicit local fixture IPC. It never sends a private key or retains raw child diagnostics. */
internal class CaptureOriginNodePeer(private val profile: String? = null, private val family: String = "ipv4") : AutoCloseable {
    private val executor = Executors.newFixedThreadPool(2)
    private val events = ArrayBlockingQueue<JsonObject>(4)
    private val failed = AtomicBoolean()
    private val process: Process
    private val output: Future<*>
    private val errors: Future<*>
    private val metadata: JsonObject
    private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val configuration: CaptureTransportConfiguration
    val credentialExpiresAt: Long
    val endpoint: InetSocketAddress
    val interceptionCa: X509Certificate?
    private val desktopCommit = if (profile == null) DESKTOP_COMMIT else C3_DESKTOP_COMMIT
    private var commands = 0
    private var closed = false

    init {
        check(profile == null || profile in setOf("http-h1", "https-h1", "http-upgrade", "wss-h1"))
        check(family in setOf("ipv4", "ipv6") && (profile != null || family == "ipv4"))
        val desktop = System.getenv("FREEKIT_DESKTOP_ROOT")
        check(desktop != null && Path.of(desktop).isAbsolute && Files.isDirectory(Path.of(desktop))) { "Explicit desktop checkout required" }
        check(Files.isRegularFile(Path.of("tools/transport-spike/gateway-origin-fixture.mjs"))) { "Checked origin fixture required" }
        process = try {
            val command = mutableListOf(System.getenv("FREEKIT_NODE") ?: "node", "tools/transport-spike/gateway-origin-fixture.mjs",
                "--desktop-root", desktop, "--desktop-commit", desktopCommit)
            if (profile != null) command.addAll(listOf("--profile", profile, "--family", family))
            ProcessBuilder(command).start()
        } catch (_: Exception) { executor.shutdownNow(); throw AssertionError("Origin fixture process unavailable") }
        output = executor.submit {
            try {
                var total = 0
                while (true) {
                    val line = readLine(process.inputStream) ?: break
                    total += line.size
                    check(total <= 147456 && events.offer(decode(line)))
                }
            } catch (_: Exception) { failed.set(true) }
        }
        errors = executor.submit {
            try {
                val buffer = ByteArray(1024); var total = 0
                while (true) {
                    val count = process.errorStream.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > 32768) { failed.set(true); process.errorStream.close(); break }
                }
            } catch (_: Exception) { failed.set(true) }
        }
        try {
            val ready = next("ready")
            val profileFields = if (profile == null) emptySet() else setOf("profile", "family", "interceptionCaCertificateDer")
            check(ready.keys == setOf("format", "revision", "event", "metadata", "desktopCommit") + profileFields)
            check(ready.text("desktopCommit") == desktopCommit)
            metadata = ready.getValue("metadata").jsonObject
            check(metadata.keys == setOf("desktopId", "logicalName", "gatewayCertificateDer", "gatewaySpkiSha256", "enrollmentAuthorityDer",
                "interceptionCaCertificateSha256", "setupPort", "credentialPort", "webSocketPort"))
            interceptionCa = if (profile == null) null else {
                check(ready.text("profile") == profile && ready.text("family") == family)
                certificate(ready.text("interceptionCaCertificateDer")).also {
                    check(it.basicConstraints >= 0); it.checkValidity(); it.verify(it.publicKey)
                    val hash = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(it.encoded))
                    check(hash == metadata.text("interceptionCaCertificateSha256"))
                }
            }
            val port = metadata.getValue("webSocketPort").jsonPrimitive.content.toInt().also { check(it in 1..65535) }
            endpoint = InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port)
            val csr = EnrollmentRequest.create(key.public, key.private)
            command(JsonObject(linkedMapOf("op" to JsonPrimitive("enroll"), "csrDer" to JsonPrimitive(Base64.getUrlEncoder().withoutPadding().encodeToString(csr)))))
            val enrolled = next("enrolled")
            check(enrolled.keys == setOf("format", "revision", "event", "approved", "metadata") + profileFields)
            check(enrolled.getValue("metadata") == metadata)
            if (profile != null) check(profileFields.all { enrolled[it] == ready[it] })
            val result = DraftEnrollmentCodec.decode(DraftEnrollmentChannel.STATUS_RESPONSE, enrolled.getValue("approved").toString().toByteArray(Charsets.UTF_8))
            val approved = (result as? DraftEnrollmentDecodeResult.Accepted)?.message as? DraftEnrollmentMessage.Approved
                ?: error("Invalid approved fixture record")
            check(approved.desktopId == metadata.text("desktopId") && approved.enrollmentAuthorityDer == metadata.text("enrollmentAuthorityDer"))
            check(approved.capabilities == if (profile == null) listOf("tcp-http-origin-connect") else listOf("tcp-http-origin-connect", "tcp-https-connect"))
            check(approved.interceptionCaCertificateSha256 == metadata.text("interceptionCaCertificateSha256"))
            val client = certificate(approved.clientCertificateDer); val authority = certificate(approved.enrollmentAuthorityDer)
            check(client.publicKey.encoded.contentEquals(key.public.encoded)); client.verify(authority.publicKey); client.checkValidity()
            credentialExpiresAt = client.notAfter.time
            check(java.time.Instant.parse(approved.credentialExpiresAt).toEpochMilli() == credentialExpiresAt)
            val record = EnrolledCredentialRecord(approved.desktopId, certificate(metadata.text("gatewayCertificateDer")), metadata.text("gatewaySpkiSha256"),
                metadata.text("logicalName"), listOf(client), authority)
            if (interceptionCa != null) check(!interceptionCa.encoded.contentEquals(authority.encoded) &&
                !interceptionCa.encoded.contentEquals(record.gatewayCertificate.encoded))
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null); setKeyEntry("client", key.private, CharArray(0), arrayOf(client, authority))
            }
            val manager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keyStore, CharArray(0)) }
                .keyManagers.filterIsInstance<X509ExtendedKeyManager>().single()
            configuration = CaptureTransportConfiguration(record, manager, { expiry, utc ->
                val all = listOf(record.gatewayCertificate, authority, client)
                check(expiry > utc && all.all { utc >= it.notBefore.time && expiry <= it.notAfter.time })
            }, DraftBudgetPool())
        } catch (_: Exception) {
            abort(); throw AssertionError("Origin fixture startup failed")
        }
    }

    fun release() { command(JsonObject(linkedMapOf("op" to JsonPrimitive("release")))); next("released") }
    fun snapshot(timeoutMillis: Long = 20_000): JsonObject {
        command(JsonObject(linkedMapOf("op" to JsonPrimitive("snapshot"))))
        return next("snapshot", timeoutMillis)["snapshot"] as? JsonObject ?: error("Invalid origin fixture snapshot")
    }

    /** Observe actual peer completion before Stop without replaying a request or increasing the IPC bound. */
    fun completedSnapshot(): JsonObject {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        repeat(4) { index ->
            if (index > 0) {
                try { Thread.sleep(250L shl (index - 1)) }
                catch (failure: InterruptedException) { Thread.currentThread().interrupt(); throw failure }
            }
            val remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
            check(remaining > 0) { "Origin stream did not complete" }
            val state = snapshot(remaining)
            if (state.bool("gatewayStreamComplete")) return state
        }
        error("Origin stream did not complete")
    }

    private fun command(value: JsonObject) {
        check(++commands <= 8 && process.isAlive)
        val bytes = (value.toString() + "\n").toByteArray(Charsets.US_ASCII)
        check(bytes.size <= 8192)
        process.outputStream.write(bytes); process.outputStream.flush()
    }

    private fun next(event: String, timeoutMillis: Long = 20_000): JsonObject {
        try {
            val value = events.poll(timeoutMillis, TimeUnit.MILLISECONDS)
            check(value != null && !failed.get() && value.text("format") == "http-freekit-origin-gateway-fixture" &&
                value.number("revision") == 1L && value.text("event") == event)
            return value
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            // Keep startup failures inside the constructor's owned cleanup path.
            throw IllegalStateException("Invalid origin fixture event")
        }
    }

    override fun close() {
        if (closed) return
        var valid = true
        try {
            command(JsonObject(linkedMapOf("op" to JsonPrimitive("stop"))))
            val done = next("closed").getValue("snapshot").jsonObject
            check(done.bool("admissionClosed") && done.bool("listenerClosed") && done.bool("privateDirectoryRemoved"))
            check(listOf("activeSockets", "pendingCallbacks", "pendingTimers", "workers").all { done.number(it) == 0L })
            val backend = done.getValue("backend").jsonObject
            check(backend.number("activeOwners") == 0L && backend.number("admitted") == backend.number("settled"))
            val enrollment = done.getValue("enrollment").jsonObject
            check(enrollment.bool("storeClosed") && enrollment.bool("listenersClosed") && enrollment.bool("issuerChildrenJoined"))
            val stream = enrollment.getValue("stream").jsonObject
            check(listOf("sessionLeases", "streamLeases", "chargedBytes", "workers", "pendingCallbacks", "timers", "listeners").all { stream.number(it) == 0L })
            check(process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0)
            output.get(5, TimeUnit.SECONDS); errors.get(5, TimeUnit.SECONDS); check(!failed.get()); closed = true
        } catch (_: Exception) { valid = false }
        finally {
            try { if (process.isAlive) { abort(); valid = false } } catch (_: Exception) { valid = false }
            for (stream in listOf(process.outputStream, process.inputStream, process.errorStream)) {
                try { stream.close() } catch (_: Exception) { valid = false }
            }
            try { executor.shutdownNow() } catch (_: Exception) { valid = false }
            try { if (!executor.awaitTermination(5, TimeUnit.SECONDS)) valid = false }
            catch (_: InterruptedException) { Thread.currentThread().interrupt(); valid = false }
        }
        check(valid) { "Origin fixture cleanup failed" }
    }

    private fun abort() {
        // The Node owner joins its own issuer groups before natural exit. Forced
        // leader termination is failure-only and never attests child cleanup.
        var valid = true
        var restoreInterrupt = Thread.interrupted()
        try {
            if (process.isAlive) {
                process.outputStream.write("{\"op\":\"stop\"}\n".toByteArray(Charsets.US_ASCII)); process.outputStream.flush()
            }
        } catch (_: Exception) { /* Preserve the fixed original fixture failure. */ }
        try {
            if (!process.waitFor(20, TimeUnit.SECONDS)) {
                valid = false; process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS)
            }
        } catch (_: InterruptedException) {
            restoreInterrupt = true; valid = false
            try { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
            catch (_: Exception) { /* Attempt every independent cleanup below. */ }
        } catch (_: Exception) { valid = false }
        for (stream in listOf(process.outputStream, process.inputStream, process.errorStream)) {
            try { stream.close() } catch (_: Exception) { valid = false }
        }
        try { executor.shutdownNow() } catch (_: Exception) { valid = false }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        for (future in listOf(output, errors)) {
            try { future.get(maxOf(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS) }
            catch (_: InterruptedException) { restoreInterrupt = true; valid = false }
            catch (_: Exception) { valid = false }
        }
        try { if (!executor.awaitTermination(maxOf(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS)) valid = false }
        catch (_: InterruptedException) { restoreInterrupt = true; valid = false }
        if (process.isAlive) valid = false
        if (restoreInterrupt) Thread.currentThread().interrupt()
        check(valid) { "Origin fixture startup cleanup failed" }
    }
    override fun toString() = "CaptureOriginNodePeer([REDACTED])"

    companion object {
        const val DESKTOP_COMMIT = "fd63f6940226c8e3401a165082dfa9325abaca69"
        const val C3_DESKTOP_COMMIT = "2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6"
        private fun certificate(value: String): X509Certificate {
            check(Regex("[A-Za-z0-9_-]{1,5462}").matches(value))
            val bytes = Base64.getUrlDecoder().decode(value)
            check(bytes.size in 1..4096 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == value)
            val input = bytes.inputStream()
            val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
            check(input.available() == 0 && certificate.encoded.contentEquals(bytes)); return certificate
        }
        private fun readLine(input: InputStream): ByteArray? {
            val result = ByteArrayOutputStream()
            while (true) {
                val value = input.read()
                if (value < 0) { check(result.size() == 0); return null }
                if (value == 10) return result.toByteArray()
                check(value in 32..126 && result.size() < 16384); result.write(value)
            }
        }
        private fun decode(bytes: ByteArray): JsonObject {
            // Bound allocation first. Canonical re-encoding rejects duplicate members and
            // alternate spellings without implementing a second JSON parser.
            var depth = 0; var quoted = false; var escaped = false
            for (byte in bytes) {
                val char = byte.toInt().toChar()
                if (quoted) {
                    if (escaped) escaped = false else if (char == '\\') escaped = true else if (char == '"') quoted = false
                } else when (char) {
                    '"' -> quoted = true
                    '{', '[' -> { depth++; check(depth <= 8) }
                    '}', ']' -> { depth--; check(depth >= 0) }
                }
            }
            check(depth == 0 && !quoted)
            val text = bytes.toString(Charsets.US_ASCII)
            val value = Json.parseToJsonElement(text) as? JsonObject ?: error("Invalid fixture envelope")
            check(value.toString() == text); return value
        }
        fun JsonObject.text(name: String): String = (get(name) as? JsonPrimitive ?: error("Invalid fixture string")).let { check(it.isString); it.content }
        fun JsonObject.number(name: String): Long = (get(name) as? JsonPrimitive ?: error("Invalid fixture number")).let {
            check(!it.isString); (it.content.toLongOrNull() ?: error("Invalid fixture number")).also { number -> check(number >= 0) }
        }
        fun JsonObject.bool(name: String): Boolean = (get(name) as? JsonPrimitive ?: error("Invalid fixture boolean")).let {
            check(!it.isString && it.content in setOf("true", "false")); it.content == "true"
        }
    }
}
