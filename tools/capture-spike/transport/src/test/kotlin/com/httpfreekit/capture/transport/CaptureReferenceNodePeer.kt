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
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Private research IPC only. Neither JVM key material nor raw diagnostics enter child IPC/reports. */
internal class CaptureReferenceNodePeer : AutoCloseable {
    private val process = ProcessBuilder(System.getenv("FREEKIT_NODE") ?: "node", "--disable-warning=ExperimentalWarning",
        "tools/transport-spike/reference-interception-peer.mjs").start()
    private val executor = Executors.newFixedThreadPool(3)
    private val events = ArrayBlockingQueue<JsonObject>(4)
    private val output: Future<*> = executor.submit {
        var total = 0
        while (true) {
            val bytes = line(process.inputStream) ?: break
            total += bytes.size
            check(total <= 1048576 && events.offer(decode(bytes))) { "Reference output bound" }
        }
    }
    private val errors: Future<*> = executor.submit {
        val buffer = ByteArray(1024)
        var total = 0
        while (true) {
            val count = process.errorStream.read(buffer)
            if (count < 0) break
            total += count
            check(total <= 32768) { "Reference diagnostics bound" }
        }
        // The peer contract forbids diagnostics, including on failure.
        check(total == 0) { "Unexpected reference diagnostics" }
    }
    private var commands = 0
    private var commandBytes = 0
    private var closeAttempted = false
    private var closeFailure: Throwable? = null
    var joined = false
        private set
    lateinit var configuration: CaptureTransportConfiguration
        private set
    lateinit var endpoint: InetSocketAddress
        private set
    lateinit var interceptionCa: X509Certificate
        private set

    init {
        try {
            val ready = next("ready")
            check(ready.keys == ENVELOPE + setOf("metadata", "interceptionCaDer", "nodeVersion", "nodeOpenSsl"))
            check(ready.text("nodeVersion") == "v24.22.1") { "Pinned reference Node required" }
            check(Regex("[0-9]+\\.[0-9]+\\.[0-9]+[a-z0-9.-]*").matches(ready.text("nodeOpenSsl")))
            val metadata = ready.getValue("metadata").jsonObject
            check(metadata.keys == setOf("desktopId", "logicalName", "gatewayCertificateDer", "gatewaySpkiSha256",
                "enrollmentAuthorityDer", "interceptionCaCertificateSha256", "setupPort", "credentialPort", "webSocketPort"))
            val port = metadata.number("webSocketPort").also { check(it in 1..65535) }
            endpoint = InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port.toInt())
            interceptionCa = certificate(ready.text("interceptionCaDer")).also {
                check(it.basicConstraints >= 0); it.checkValidity(); it.verify(it.publicKey)
                check(b64(hash(it.encoded)) == metadata.text("interceptionCaCertificateSha256")) { "Reference CA binding" }
            }
            val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            val csr = EnrollmentRequest.create(keys.public, keys.private).also { check(it.size in 1..4096) }
            command(JsonObject(linkedMapOf("op" to JsonPrimitive("enroll"), "csrDer" to JsonPrimitive(b64(csr)))))
            val enrolled = next("enrolled")
            check(enrolled.keys == ENVELOPE + "approved")
            val result = DraftEnrollmentCodec.decode(DraftEnrollmentChannel.STATUS_RESPONSE,
                enrolled.getValue("approved").toString().toByteArray(Charsets.UTF_8))
            val approved = (result as? DraftEnrollmentDecodeResult.Accepted)?.message as? DraftEnrollmentMessage.Approved
                ?: error("Invalid reference approval")
            check(approved.desktopId == metadata.text("desktopId") && approved.enrollmentAuthorityDer == metadata.text("enrollmentAuthorityDer"))
            check(approved.interceptionCaCertificateSha256 == b64(hash(interceptionCa.encoded))) { "Approved CA binding" }
            check(approved.capabilities == listOf("tcp-http-origin-connect", "tcp-https-connect"))
            val client = certificate(approved.clientCertificateDer)
            val authority = certificate(approved.enrollmentAuthorityDer)
            check(client.publicKey.encoded.contentEquals(keys.public.encoded)) { "Approved JVM public-key binding" }
            client.verify(authority.publicKey); client.checkValidity(); authority.checkValidity()
            check(java.time.Instant.parse(approved.credentialExpiresAt).toEpochMilli() == client.notAfter.time)
            val record = EnrolledCredentialRecord(approved.desktopId, certificate(metadata.text("gatewayCertificateDer")),
                metadata.text("gatewaySpkiSha256"), metadata.text("logicalName"), listOf(client), authority)
            check(!interceptionCa.encoded.contentEquals(authority.encoded) && !interceptionCa.encoded.contentEquals(record.gatewayCertificate.encoded))
            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null); setKeyEntry("client", keys.private, CharArray(0), arrayOf(client, authority))
            }
            val manager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
                .keyManagers.filterIsInstance<X509ExtendedKeyManager>().single()
            configuration = CaptureTransportConfiguration(record, manager, { expiry, utc ->
                check(expiry > utc && listOf(record.gatewayCertificate, authority, client).all {
                    utc >= it.notBefore.time && expiry <= it.notAfter.time
                }) { "Reference credential readiness" }
            }, DraftBudgetPool())
        } catch (failure: Throwable) {
            val primary = referenceFailure("startup", failure)
            try { close() } catch (cleanup: Throwable) { primary.addSuppressed(referenceFailure("startup cleanup", cleanup)) }
            throw primary
        }
    }

    fun snapshot(): JsonObject {
        command(op("snapshot"))
        return next("snapshot").also { check(it.keys == ENVELOPE + "snapshot") }.getValue("snapshot").jsonObject
    }

    fun revoke() {
        command(op("revoke"))
        val event = next("revoked")
        check(event.keys == ENVELOPE + "revoked" && event.bool("revoked"))
    }

    /** Bounded observation of real asynchronous owners, never an injected model event. */
    fun awaitSnapshot(predicate: (JsonObject) -> Boolean): JsonObject {
        repeat(24) {
            val value = snapshot()
            if (predicate(value)) return value
            Thread.sleep(100)
        }
        error("Reference observation deadline")
    }

    private fun command(value: JsonObject) {
        val bytes = (value.toString() + "\n").toByteArray(Charsets.US_ASCII)
        commandBytes += bytes.size
        check(++commands <= 64 && commandBytes <= 262144 && bytes.size <= 8192 && process.isAlive)
        // A separate, joined pump bounds even a child that stops reading stdin.
        executor.submit { process.outputStream.write(bytes); process.outputStream.flush() }.get(5, TimeUnit.SECONDS)
    }

    private fun next(event: String): JsonObject {
        val value = events.poll(20, TimeUnit.SECONDS) ?: error("Reference event deadline")
        check(value.text("format") == "http-freekit-reference-interception-peer" && value.number("revision") == 1L)
        if (value.text("event") == "failed") {
            check(value.keys == ENVELOPE + setOf("code", "joined") && value.text("code") in FAILURE_CODES)
            value.bool("joined") // Validate; a joined failure is still not successful closure.
            error("Reference peer failed")
        }
        check(value.text("event") == event) { "Unexpected reference event" }
        return value
    }

    override fun close() {
        if (closeAttempted) { closeFailure?.let { throw it }; check(joined); return }
        closeAttempted = true
        val cleanup = ReferenceCleanup()
        cleanup.attempt("peer stop") {
            command(op("stop"))
            process.outputStream.close()
            val event = next("closed")
            check(event.keys == ENVELOPE + "snapshot")
            assertClosed(event.getValue("snapshot").jsonObject)
        }
        cleanup.attempt("peer exit") {
            check(process.waitFor(20, TimeUnit.SECONDS) && process.exitValue() == 0) { "Reference process exit" }
        }
        if (process.isAlive) {
            cleanup.attempt("peer forced termination") {
                process.destroyForcibly()
                check(process.waitFor(5, TimeUnit.SECONDS))
                error("Forced reference termination is not joined success")
            }
        }
        for (stream in listOf(process.outputStream, process.inputStream, process.errorStream)) cleanup.attempt("peer pipe close") { stream.close() }
        for (future in listOf(output, errors)) cleanup.attempt("peer pump join") { future.get(5, TimeUnit.SECONDS) }
        cleanup.attempt("peer executor shutdown") { executor.shutdownNow() }
        cleanup.attempt("peer executor join") { check(executor.awaitTermination(5, TimeUnit.SECONDS)) }
        closeFailure = cleanup.failure
        joined = cleanup.failure == null && !process.isAlive
        cleanup.finish()
    }

    override fun toString() = "CaptureReferenceNodePeer([REDACTED])"

    companion object {
        private val ENVELOPE = setOf("format", "revision", "event")
        private val FAILURE_CODES = setOf("peer_configuration", "peer_input", "peer_unavailable", "peer_enrollment",
            "peer_revocation", "peer_cleanup", "peer_watchdog", "peer_output")
        fun hash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
        fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        private fun certificate(value: String): X509Certificate {
            check(Regex("[A-Za-z0-9_-]{1,5462}").matches(value))
            val bytes = Base64.getUrlDecoder().decode(value)
            check(bytes.size in 1..4096 && b64(bytes) == value)
            val input = bytes.inputStream()
            return (CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate).also {
                check(input.available() == 0 && it.encoded.contentEquals(bytes))
            }
        }
        private fun op(name: String) = JsonObject(linkedMapOf("op" to JsonPrimitive(name)))
        private fun line(input: InputStream): ByteArray? {
            val bytes = ByteArrayOutputStream()
            while (true) {
                val value = input.read()
                if (value < 0) { check(bytes.size() == 0); return null }
                if (value == 10) return bytes.toByteArray()
                check(value in 32..126 && bytes.size() < 16384)
                bytes.write(value)
            }
        }
        private fun decode(bytes: ByteArray): JsonObject {
            var depth = 0; var quoted = false; var escaped = false
            for (byte in bytes) {
                val char = byte.toInt().toChar()
                if (quoted) {
                    if (escaped) escaped = false else if (char == '\\') escaped = true else if (char == '"') quoted = false
                } else when (char) {
                    '"' -> quoted = true
                    '{', '[' -> { depth++; check(depth <= 12) }
                    '}', ']' -> { depth--; check(depth >= 0) }
                }
            }
            check(depth == 0 && !quoted)
            val text = bytes.toString(Charsets.US_ASCII)
            return Json.parseToJsonElement(text).jsonObject.also { check(it.toString() == text) }
        }
        private fun assertClosed(snapshot: JsonObject) {
            check(snapshot.bool("privateDirectoryRemoved"))
            val backend = snapshot.getValue("backend").jsonObject
            check(backend.bool("closed") && backend.number("ownersCreated") == backend.number("ownersClosed"))
            check(listOf("activeOwners", "activeSockets", "activeRequests", "listeners").all { backend.number(it) == 0L })
            val assets = snapshot.getValue("assets").jsonObject
            check(assets.bool("closed") && assets.number("commandsStarted") == assets.number("commandsClosed") &&
                assets.number("commandsStarted") == assets.number("processGroupsClosed"))
            val gateway = snapshot.getValue("gateway").jsonObject
            check(listOf("closed", "admissionClosed", "listenersClosed", "storeClosed", "authorityClosed", "issuerChildrenJoined").all { gateway.bool(it) })
            check(listOf("activeSockets", "pendingCallbacks", "pendingTimers", "workers", "issuerJobs", "signerGroups",
                "acceptedSockets", "tlsSockets", "bodyReaders", "requestTasks", "pendingWriteCallbacks", "timers",
                "registrationWaiters", "listeners").all { gateway.number(it) == 0L })
            val aggregate = gateway.getValue("stream").jsonObject
            check(listOf("sessionLeases", "streamLeases", "chargedBytes", "ownerRecords", "authenticatedSockets",
                "proxySockets", "listeners", "workers", "timers", "pendingCallbacks").all { aggregate.number(it) == 0L })
            (snapshot["stream"] as? JsonObject)?.let { stream ->
                check(stream.bool("resourcesReleased") && stream.bool("cleanupComplete") && !stream.bool("streamLease"))
                check(listOf("chargedBytes", "fixtureUploadBytesRead", "fixtureResponseBytesWritten").all { stream.number(it) == 0L })
            }
            val issuer = gateway.getValue("issuer").jsonObject
            check(issuer.bool("closed") && listOf("activeJobs", "unjoinedChildren", "jobDirectories").all { issuer.number(it) == 0L } &&
                issuer.number("commandsStarted") == issuer.number("commandsClosed") && issuer.number("commandsStarted") == issuer.number("processGroupsClosed"))
        }
        fun JsonObject.text(key: String): String = getValue(key).jsonPrimitive.let { check(it.isString); it.content }
        fun JsonObject.number(key: String): Long = getValue(key).jsonPrimitive.let {
            check(!it.isString && Regex("0|[1-9][0-9]{0,15}").matches(it.content)); it.content.toLong()
        }
        fun JsonObject.bool(key: String): Boolean = getValue(key).jsonPrimitive.let {
            check(!it.isString && it.content in setOf("true", "false")); it.content == "true"
        }
    }
}

/** Preserve primary/suppressed structure without retaining provider messages, traffic or private IPC. */
internal fun referenceFailure(stage: String, failure: Throwable): AssertionError = AssertionError("Reference $stage failed").also {
    it.stackTrace = failure.stackTrace
    failure.suppressed.take(16).forEach { suppressed -> it.addSuppressed(referenceFailure("suppressed cleanup", suppressed)) }
}

internal class ReferenceCleanup {
    var failure: Throwable? = null
        private set
    private var interrupted = Thread.interrupted()
    fun attempt(stage: String, action: () -> Unit) {
        try { action() } catch (caught: Throwable) {
            if (caught is InterruptedException) interrupted = true
            val safe = referenceFailure(stage, caught)
            val prior = failure
            if (prior == null) failure = safe else prior.addSuppressed(safe)
        }
    }
    fun finish() {
        if (interrupted) Thread.currentThread().interrupt()
        failure?.let { throw it }
    }
}
