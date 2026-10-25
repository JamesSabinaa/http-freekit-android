package com.httpfreekit.interop

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
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.tls.HeldCertificate

/** Private, bounded process IPC. Software private keys stay in this JVM. */
internal class DraftInterceptionCaNodePeer(val scenario: String) : AutoCloseable {
    private val executor = Executors.newFixedThreadPool(2)
    private val events = ArrayBlockingQueue<JsonObject>(4)
    private val failed = AtomicBoolean()
    private val process: Process
    private val output: Future<*>
    private val errors: Future<*>
    private val metadata: JsonObject
    private var commands = 0
    private var closed = false
    private val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val original: List<X509Certificate> = listOf(HeldCertificate.Builder().keyPair(keys).commonName("Software original identity").build().certificate)
    val record: EnrolledCredentialRecord
    val recovery: DraftEnrollmentRecovery
    val manager: X509ExtendedKeyManager
    val referenceDer: ByteArray
    val responseHash: ByteArray
    var endpoint: InetSocketAddress
        private set
    val credentialExpiresAt: Long
    val nodeVersion: String
    val nodeOpenSsl: String
    val joined: Boolean get() = closed

    init {
        check(Regex("[a-z-]{1,40}").matches(scenario)) { "Invalid CA fixture case" }
        process = try {
            ProcessBuilder(System.getenv("FREEKIT_NODE") ?: "node", "tools/transport-spike/companion-interception-ca-peer.mjs", "--case", scenario).start()
        } catch (_: Exception) { executor.shutdownNow(); throw AssertionError("CA fixture unavailable") }
        output = executor.submit {
            try {
                var total = 0
                while (true) {
                    val line = line(process.inputStream) ?: break
                    total += line.size; check(total <= 1048576 && events.offer(decode(line)))
                }
            } catch (_: Exception) { failed.set(true) }
        }
        errors = executor.submit {
            try {
                val buffer = ByteArray(1024); var total = 0
                while (true) {
                    val size = process.errorStream.read(buffer); if (size < 0) break
                    total += size; check(total <= 32768)
                }
            } catch (_: Exception) { failed.set(true) }
        }
        try {
            val ready = next("ready")
            check(ready.keys == setOf("format", "revision", "event", "metadata", "peerPort", "referenceCaDer", "responseHash", "nodeVersion", "nodeOpenSsl"))
            nodeVersion = ready.text("nodeVersion").also { check(it == "v24.22.1") }
            nodeOpenSsl = ready.text("nodeOpenSsl").also { check(Regex("[0-9]+\\.[0-9]+\\.[0-9]+[a-z0-9.-]*").matches(it)) }
            metadata = ready.getValue("metadata").jsonObject
            check(metadata.keys == setOf("desktopId", "logicalName", "gatewayCertificateDer", "gatewaySpkiSha256", "enrollmentAuthorityDer",
                "interceptionCaCertificateSha256", "setupPort", "credentialPort"))
            referenceDer = binary(ready.text("referenceCaDer"), 1, 4096)
            responseHash = binary(ready.text("responseHash"), 32, 32)
            check(b64(hash(referenceDer)) == metadata.text("interceptionCaCertificateSha256"))
            endpoint = endpoint(ready.number("peerPort"))
            command(JsonObject(linkedMapOf("op" to JsonPrimitive("enroll"), "csrDer" to JsonPrimitive(b64(EnrollmentRequest.create(keys.public, keys.private))))))
            val enrolled = next("enrolled")
            check(enrolled.keys == setOf("format", "revision", "event", "registered", "approved"))
            val registration = accepted(DraftEnrollmentChannel.PAIR_RESPONSE, enrolled.getValue("registered").jsonObject) as? DraftEnrollmentMessage.Registered
                ?: error("Invalid fixture registration")
            val approved = accepted(DraftEnrollmentChannel.STATUS_RESPONSE, enrolled.getValue("approved").jsonObject) as? DraftEnrollmentMessage.Approved
                ?: error("Invalid fixture approval")
            check(registration.desktopId == metadata.text("desktopId") && approved.desktopId == registration.desktopId && approved.enrollmentId == registration.enrollmentId)
            check(approved.enrollmentAuthorityDer == metadata.text("enrollmentAuthorityDer") && approved.interceptionCaCertificateSha256 == metadata.text("interceptionCaCertificateSha256"))
            check(approved.capabilities == listOf("tcp-http", "tcp-https-connect"))
            val client = certificate(approved.clientCertificateDer); val authority = certificate(approved.enrollmentAuthorityDer)
            check(client.publicKey.encoded.contentEquals(keys.public.encoded)); client.verify(authority.publicKey); client.checkValidity()
            check(!client.encoded.contentEquals(original.single().encoded))
            credentialExpiresAt = client.notAfter.time
            check(java.time.Instant.parse(approved.credentialExpiresAt).toEpochMilli() == credentialExpiresAt)
            record = EnrolledCredentialRecord(approved.desktopId, certificate(metadata.text("gatewayCertificateDer")), metadata.text("gatewaySpkiSha256"),
                metadata.text("logicalName"), listOf(client), authority)
            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null); setKeyEntry("client", keys.private, CharArray(0), arrayOf(client, authority))
            }
            manager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
                .keyManagers.filterIsInstance<X509ExtendedKeyManager>().single()
            recovery = DraftEnrollmentRecovery(metadata.number("setupPort").toInt(), metadata.number("credentialPort").toInt(), record.desktopId,
                binary(record.gatewaySpkiSha256, 32, 32), record.logicalServerName, registration.invitationId, approved.enrollmentId, approved.deviceId,
                keys.public.encoded, original.map { hash(it.encoded) }, hash(client.encoded), hash(authority.encoded), hash(referenceDer), approved.capabilities,
                registration.reservationExpiresAt, registration.resultExpiresAt, approved.credentialExpiresAt)
        } catch (_: Exception) {
            abort(); throw AssertionError("CA fixture startup failed")
        }
    }

    fun client(approval: DraftEnrollmentRecovery = recovery, keyManager: X509ExtendedKeyManager = manager,
        credential: EnrolledCredentialRecord = record, originals: List<X509Certificate> = original) =
        DraftInterceptionCaClient(credential, keyManager, originals, approval, endpoint)

    fun snapshot(): JsonObject { command(op("snapshot")); return next("snapshot").getValue("snapshot").jsonObject }
    fun pause() { command(op("pause")); next("paused") }
    fun reopen() {
        command(op("reopen")); val value = next("reopened")
        check(value.getValue("metadata") == metadata && binary(value.text("referenceCaDer"), 1, 4096).contentEquals(referenceDer))
        endpoint = endpoint(value.number("peerPort"))
    }
    fun revoke() { command(op("revoke")); check(next("revoked").bool("revoked")) }
    fun status(): JsonObject { command(op("status")); return next("status") }
    fun awaitQuiet(): JsonObject = awaitSnapshot { value ->
        val fixture = value.getValue("fixture").jsonObject
        listOf("activeSockets", "pendingCallbacks", "pendingTimers", "workers").all { fixture.number(it) == 0L }
    }
    fun awaitRequest(): JsonObject = awaitSnapshot { it.getValue("hostile").jsonObject.number("requests") == 1L }
    private fun awaitSnapshot(predicate: (JsonObject) -> Boolean): JsonObject {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
        repeat(24) {
            val value = snapshot(); if (predicate(value)) return value
            check(System.nanoTime() < deadline); Thread.sleep(50)
        }
        error("CA fixture observation unavailable")
    }
    fun copyRecovery(caHash: ByteArray = recovery.interceptionCaCertificateSha256,
        desktop: String = recovery.desktopId, pin: ByteArray = binary(recovery.gatewaySpkiSha256, 32, 32),
        name: String = recovery.logicalName, spki: ByteArray = recovery.originalDeviceSpki,
        originalHashes: List<ByteArray> = recovery.originalKeystoreCertificateHashes,
        leafHash: ByteArray = recovery.clientCertificateSha256, authorityHash: ByteArray = recovery.authorityCertificateSha256,
        expiresAt: String = recovery.credentialExpiresAt, oldRecoveryDeadlines: Boolean = false) = DraftEnrollmentRecovery(
            recovery.setupPort, recovery.credentialPort, desktop, pin, name, recovery.invitationId, recovery.enrollmentId, recovery.deviceId,
            spki, originalHashes, leafHash, authorityHash, caHash, recovery.capabilities,
            if (oldRecoveryDeadlines) "2020-01-01T00:00:00Z" else recovery.reservationExpiresAt,
            if (oldRecoveryDeadlines) "2020-01-01T00:01:00Z" else recovery.resultExpiresAt, expiresAt)

    private fun command(value: JsonObject) {
        check(++commands <= 64 && process.isAlive)
        val bytes = (value.toString() + "\n").toByteArray(Charsets.US_ASCII); check(bytes.size <= 8192)
        process.outputStream.write(bytes); process.outputStream.flush()
    }
    private fun next(event: String): JsonObject {
        val value = events.poll(20, TimeUnit.SECONDS)
        check(value != null && !failed.get() && value.text("format") == "http-freekit-interception-ca-fixture" && value.number("revision") == 1L && value.text("event") == event)
        return value
    }
    override fun close() {
        if (closed) return
        var valid = true; var interrupted = Thread.interrupted()
        try {
            command(op("stop")); process.outputStream.close()
            val done = next("closed").getValue("snapshot").jsonObject
            check(done.bool("privateDirectoryRemoved")); val fixture = done.getValue("fixture").jsonObject
            check(fixture.bool("closed") && fixture.bool("storeClosed") && fixture.bool("listenersClosed") && fixture.bool("issuerChildrenJoined"))
            check(listOf("activeSockets", "pendingCallbacks", "pendingTimers", "workers", "issuerJobs", "signerGroups").all { fixture.number(it) == 0L })
            check(process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0)
            output.get(5, TimeUnit.SECONDS); errors.get(5, TimeUnit.SECONDS); check(!failed.get())
        } catch (failure: Exception) { if (failure is InterruptedException) interrupted = true; valid = false }
        finally {
            if (process.isAlive) { try { abort() } catch (_: Exception) { /* Failure remains latched. */ }; valid = false }
            for (stream in listOf(process.outputStream, process.inputStream, process.errorStream)) try { stream.close() } catch (_: Exception) { valid = false }
            executor.shutdownNow()
            try { if (!executor.awaitTermination(5, TimeUnit.SECONDS)) valid = false }
            catch (_: InterruptedException) { interrupted = true; valid = false }
            if (interrupted) Thread.currentThread().interrupt()
        }
        check(valid) { "CA fixture cleanup failed" }
        closed = true
    }
    private fun abort() {
        var interrupted = Thread.interrupted(); var valid = true
        try { if (process.isAlive) { process.outputStream.write("{\"op\":\"stop\"}\n".toByteArray()); process.outputStream.flush() } } catch (_: Exception) { valid = false }
        try { if (!process.waitFor(20, TimeUnit.SECONDS)) { valid = false; process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) } }
        catch (_: InterruptedException) { interrupted = true; valid = false; process.destroyForcibly() }
        catch (_: Exception) { valid = false; process.destroyForcibly() }
        if (process.isAlive) {
            try { if (!process.waitFor(5, TimeUnit.SECONDS)) valid = false }
            catch (_: InterruptedException) { interrupted = true; valid = false }
        }
        for (stream in listOf(process.outputStream, process.inputStream, process.errorStream)) try { stream.close() } catch (_: Exception) { valid = false }
        for (future in listOf(output, errors)) try { future.get(5, TimeUnit.SECONDS) } catch (_: InterruptedException) { interrupted = true; valid = false } catch (_: Exception) { valid = false }
        executor.shutdownNow()
        try { if (!executor.awaitTermination(5, TimeUnit.SECONDS)) valid = false } catch (_: InterruptedException) { interrupted = true; valid = false }
        if (process.isAlive) valid = false; if (interrupted) Thread.currentThread().interrupt()
        check(valid) { "CA fixture startup cleanup failed" }
    }
    override fun toString() = "DraftInterceptionCaNodePeer([REDACTED])"
    companion object {
        fun hash(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)
        fun b64(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
        fun binary(value: String, min: Int, max: Int): ByteArray {
            check(Regex("[A-Za-z0-9_-]+").matches(value) && value.length <= 5462)
            return Base64.getUrlDecoder().decode(value).also { check(it.size in min..max && b64(it) == value) }
        }
        private fun certificate(value: String): X509Certificate {
            val bytes = binary(value, 1, 4096); val input = bytes.inputStream()
            return (CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate).also { check(input.available() == 0 && it.encoded.contentEquals(bytes)) }
        }
        private fun accepted(channel: DraftEnrollmentChannel, value: JsonObject): DraftEnrollmentMessage =
            (DraftEnrollmentCodec.decode(channel, value.toString().toByteArray(Charsets.UTF_8)) as? DraftEnrollmentDecodeResult.Accepted)?.message
                ?: error("Invalid CA fixture enrollment message")
        private fun endpoint(value: Long): InetSocketAddress { check(value in 1..65535); return InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127,0,0,1)), value.toInt()) }
        private fun op(value: String) = JsonObject(linkedMapOf("op" to JsonPrimitive(value)))
        private fun line(input: InputStream): ByteArray? {
            val result = ByteArrayOutputStream()
            while (true) {
                val value = input.read(); if (value < 0) { check(result.size() == 0); return null }
                if (value == 10) return result.toByteArray()
                check(value in 32..126 && result.size() < 16384); result.write(value)
            }
        }
        private fun decode(bytes: ByteArray): JsonObject {
            var depth = 0; var quoted = false; var escaped = false
            for (byte in bytes) { val char = byte.toInt().toChar()
                if (quoted) { if (escaped) escaped = false else if (char == '\\') escaped = true else if (char == '"') quoted = false }
                else when (char) { '"' -> quoted = true; '{', '[' -> { depth++; check(depth <= 8) }; '}', ']' -> { depth--; check(depth >= 0) } }
            }
            check(!quoted && depth == 0)
            return Json.parseToJsonElement(bytes.toString(Charsets.US_ASCII)).jsonObject.also { check(it.toString().toByteArray(Charsets.US_ASCII).contentEquals(bytes)) }
        }
    }
}
internal fun JsonObject.text(key: String): String = getValue(key).jsonPrimitive.let { check(it.isString); it.content }
internal fun JsonObject.number(key: String): Long = getValue(key).jsonPrimitive.let { check(!it.isString && Regex("0|[1-9][0-9]{0,8}").matches(it.content)); it.content.toLong() }
internal fun JsonObject.bool(key: String): Boolean = getValue(key).jsonPrimitive.let { check(!it.isString && it.content in setOf("true","false")); it.content == "true" }
