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
internal class CaptureOriginNodePeer : AutoCloseable {
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
    private var commands = 0
    private var closed = false

    init {
        val desktop = System.getenv("FREEKIT_DESKTOP_ROOT")
        check(desktop != null && Path.of(desktop).isAbsolute && Files.isDirectory(Path.of(desktop))) { "Explicit desktop checkout required" }
        check(Files.isRegularFile(Path.of("tools/transport-spike/gateway-origin-fixture.mjs"))) { "Checked origin fixture required" }
        process = try {
            ProcessBuilder(System.getenv("FREEKIT_NODE") ?: "node", "tools/transport-spike/gateway-origin-fixture.mjs",
                "--desktop-root", desktop, "--desktop-commit", DESKTOP_COMMIT).start()
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
            check(ready.keys == setOf("format", "revision", "event", "metadata", "desktopCommit"))
            check(ready.text("desktopCommit") == DESKTOP_COMMIT)
            metadata = ready.getValue("metadata").jsonObject
            check(metadata.keys == setOf("desktopId", "logicalName", "gatewayCertificateDer", "gatewaySpkiSha256", "enrollmentAuthorityDer",
                "interceptionCaCertificateSha256", "setupPort", "credentialPort", "webSocketPort"))
            val port = metadata.getValue("webSocketPort").jsonPrimitive.content.toInt().also { check(it in 1..65535) }
            endpoint = InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port)
            val csr = EnrollmentRequest.create(key.public, key.private)
            command(JsonObject(linkedMapOf("op" to JsonPrimitive("enroll"), "csrDer" to JsonPrimitive(Base64.getUrlEncoder().withoutPadding().encodeToString(csr)))))
            val enrolled = next("enrolled")
            check(enrolled.keys == setOf("format", "revision", "event", "approved", "metadata"))
            check(enrolled.getValue("metadata") == metadata)
            val result = DraftEnrollmentCodec.decode(DraftEnrollmentChannel.STATUS_RESPONSE, enrolled.getValue("approved").toString().toByteArray(Charsets.UTF_8))
            val approved = (result as? DraftEnrollmentDecodeResult.Accepted)?.message as? DraftEnrollmentMessage.Approved
                ?: error("Invalid approved fixture record")
            check(approved.desktopId == metadata.text("desktopId") && approved.enrollmentAuthorityDer == metadata.text("enrollmentAuthorityDer"))
            check(approved.capabilities == listOf("tcp-http-origin-connect"))
            val client = certificate(approved.clientCertificateDer); val authority = certificate(approved.enrollmentAuthorityDer)
            check(client.publicKey.encoded.contentEquals(key.public.encoded)); client.verify(authority.publicKey); client.checkValidity()
            credentialExpiresAt = client.notAfter.time
            check(java.time.Instant.parse(approved.credentialExpiresAt).toEpochMilli() == credentialExpiresAt)
            val record = EnrolledCredentialRecord(approved.desktopId, certificate(metadata.text("gatewayCertificateDer")), metadata.text("gatewaySpkiSha256"),
                metadata.text("logicalName"), listOf(client), authority)
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
    fun snapshot(): JsonObject {
        command(JsonObject(linkedMapOf("op" to JsonPrimitive("snapshot"))))
        return next("snapshot")["snapshot"] as? JsonObject ?: error("Invalid origin fixture snapshot")
    }

    private fun command(value: JsonObject) {
        check(++commands <= 8 && process.isAlive)
        val bytes = (value.toString() + "\n").toByteArray(Charsets.US_ASCII)
        check(bytes.size <= 8192)
        process.outputStream.write(bytes); process.outputStream.flush()
    }

    private fun next(event: String): JsonObject {
        try {
            val value = events.poll(20, TimeUnit.SECONDS)
            check(value != null && !failed.get() && value.text("format") == "http-freekit-origin-gateway-fixture" &&
                value.number("revision") == 1L && value.text("event") == event)
            return value
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            throw AssertionError("Invalid origin fixture event")
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
        try {
            if (process.isAlive) {
                process.outputStream.write("{\"op\":\"stop\"}\n".toByteArray(Charsets.US_ASCII)); process.outputStream.flush()
            }
        } catch (_: Exception) { /* Preserve the fixed original fixture failure. */ }
        if (!process.waitFor(20, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
        executor.shutdownNow(); executor.awaitTermination(5, TimeUnit.SECONDS)
    }
    override fun toString() = "CaptureOriginNodePeer([REDACTED])"

    companion object {
        const val DESKTOP_COMMIT = "fd63f6940226c8e3401a165082dfa9325abaca69"
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
