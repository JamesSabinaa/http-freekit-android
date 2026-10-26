package com.httpfreekit.security

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyPair
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull

/** Synthetic public evidence only: a real caller must authenticate enrollment BEFORE this API. */
internal class ApprovedCredentialTestFixture {
    val id = "approved-computer"
    val keys = TestEnrollmentCertificates.keyPair()
    val gateway = TestEnrollmentCertificates.server()
    // Anchor all checks to certificate time, not wall-clock scheduling or sleeps.
    val now: Instant = gateway.certificate.notBefore.toInstant().plusSeconds(60)
    val authority = TestEnrollmentCertificates.authority(notBefore = now.minusSeconds(60), notAfter = now.plusSeconds(7200))
    val leaf = client()
    private val originalIssuer = TestEnrollmentCertificates.authority(
        "CN=Original synthetic keystore issuer", notBefore = now.minusSeconds(60), notAfter = now.plusSeconds(7200),
    )
    val original = TestEnrollmentCertificates.client(
        keys.public, originalIssuer, name = "CN=Original synthetic key certificate",
        notBefore = now.minusSeconds(60), notAfter = now.plusSeconds(7200),
    )
    val clock = ApprovedTestClock(now)
    val identities = Identities().apply {
        currentKeys[id] = keys
        originals[id] = listOf(original)
    }
    val files = Files(identities)
    val record: ApprovedEnrolledCredentialRecord get() = combined()

    fun client(pair: KeyPair = keys, issuer: TestEnrollmentCertificates.Identity = authority): X509Certificate =
        TestEnrollmentCertificates.client(pair.public, issuer, notBefore = now.minusSeconds(60), notAfter = now.plusSeconds(1800))

    fun credential(
        desktop: String = id,
        name: String = "gateway-fixture.invalid",
        pin: String = approvedPin(gateway.certificate),
        gatewayCertificate: X509Certificate = gateway.certificate,
        clientCertificate: X509Certificate = leaf,
        authorityCertificate: X509Certificate = authority.certificate,
    ) = EnrolledCredentialRecord(desktop, gatewayCertificate, pin, name, listOf(clientCertificate), authorityCertificate)

    fun approval(
        desktop: String = id,
        name: String = "gateway-fixture.invalid",
        pin: String = approvedPin(gateway.certificate),
        enrollment: String = "approved-enrollment",
        device: String = "approved-device",
        spki: ByteArray = keys.public.encoded,
        originalHashes: List<ByteArray> = listOf(approvedHash(original.encoded)),
        clientHash: ByteArray = approvedHash(leaf.encoded),
        authorityHash: ByteArray = approvedHash(authority.certificate.encoded),
        caHash: ByteArray = ByteArray(32) { (it + 1).toByte() },
        capabilities: List<String> = listOf("stream", "capture"),
        expires: Long = leaf.notAfter.time,
    ) = AuthenticatedEnrollmentApproval(
        desktop, name, pin, enrollment, device, spki, originalHashes,
        clientHash, authorityHash, caHash, capabilities, expires,
    )

    fun combined(
        credential: EnrolledCredentialRecord = credential(),
        approval: AuthenticatedEnrollmentApproval = approval(),
    ) = ApprovedEnrolledCredentialRecord(credential, approval)

    fun store() = AndroidApprovedEnrolledCredentialStore(identities, files, clock)
    fun legacyStore(legacyFiles: CredentialRecordFiles) = AndroidEnrolledCredentialStore(identities, legacyFiles, clock)

    class Identities : ApprovedCredentialIdentities {
        val monitor = Any()
        val currentKeys = ConcurrentHashMap<String, KeyPair>()
        val originals = ConcurrentHashMap<String, List<X509Certificate>>()
        val events = mutableListOf<String>()
        var deleteFailure: Throwable? = null
        var loadFailure: Throwable? = null
        var originalFailure: Throwable? = null
        var beforeTransaction: (() -> Unit)? = null
        var loads = 0
        var originalReads = 0
        var transactions = 0
        override fun <T> transaction(desktopId: String, operation: () -> T): T {
            check(!Thread.holdsLock(monitor)) { "Nested public store transaction" }
            beforeTransaction?.invoke()
            return synchronized(monitor) { transactions++; operation() }
        }
        fun locked() { check(Thread.holdsLock(monitor)) { "Operation escaped identity transaction" } }
        override fun load(desktopId: String): DeviceIdentity? {
            locked()
            loads++
            loadFailure?.let { throw it }
            val pair = currentKeys[desktopId] ?: return null
            return DeviceIdentity(pair.public, pair.private) {
                synchronized(monitor) { currentKeys[desktopId] === pair }
            }
        }
        override fun originalCertificateChain(desktopId: String): List<X509Certificate>? {
            locked()
            originalReads++
            originalFailure?.let { throw it }
            return originals[desktopId]?.toList()
        }
        override fun delete(desktopId: String) {
            locked()
            events += "key-delete"
            deleteFailure?.let { throw it }
            currentKeys.remove(desktopId)
            originals.remove(desktopId)
        }
    }

    class Files(private val identities: Identities) : CredentialRecordFiles {
        val entries = ConcurrentHashMap<String, ByteArray>()
        var readFailure: Throwable? = null
        var publishFailure: Throwable? = null
        var deleteFailure: Throwable? = null
        var beforePublish: (() -> Unit)? = null
        var beforeDelete: (() -> Unit)? = null
        override fun read(name: String): ByteArray? {
            identities.locked()
            readFailure?.let { throw it }
            return entries[name]?.copyOf()
        }
        override fun publish(name: String, encoded: ByteArray) {
            identities.locked()
            beforePublish?.invoke()
            publishFailure?.let { throw it }
            entries[name] = encoded.copyOf()
            identities.events += "publish"
        }
        override fun delete(name: String) {
            identities.locked()
            identities.events += "metadata-delete"
            beforeDelete?.invoke()
            deleteFailure?.let { throw it }
            entries.remove(name)
        }
    }
}

internal class ApprovedTestClock(initial: Instant) : Clock() {
    private val current = AtomicReference(initial)
    fun set(value: Instant) { current.set(value) }
    override fun instant(): Instant = current.get()
    override fun getZone(): ZoneId = ZoneOffset.UTC
    override fun withZone(zone: ZoneId): Clock = this
}

internal fun approvedHash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
internal fun approvedPin(certificate: X509Certificate): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(approvedHash(certificate.publicKey.encoded))

internal fun approvedRejected(operation: () -> Unit): Exception {
    try { operation() } catch (failure: Exception) { return failure }
    throw AssertionError("Expected rejected approval material")
}

internal fun approvedUnavailable(code: EnrolledCredentialError, operation: () -> Unit): EnrolledCredentialUnavailableException {
    val failure = approvedRejected(operation)
    if (failure !is EnrolledCredentialUnavailableException) throw AssertionError("Expected finite credential failure", failure)
    org.junit.Assert.assertEquals(code, failure.code)
    assertNull(failure.cause)
    return failure
}

internal fun approvedRedacted(text: String, fixture: ApprovedCredentialTestFixture) {
    val approval = fixture.approval()
    val certificates = listOf(fixture.leaf, fixture.original, fixture.gateway.certificate, fixture.authority.certificate)
    val binary = listOf(approval.originalDeviceSpki, approval.clientCertificateSha256,
        approval.authorityCertificateSha256, approval.interceptionCaCertificateSha256) + approval.originalKeystoreCertificateHashes
    val renderedBinary = binary.flatMap { bytes -> listOf(
        Base64.getEncoder().encodeToString(bytes),
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
        bytes.joinToString("") { "%02x".format(it) }, bytes.contentToString(),
    ) }
    for (secret in listOf(
        fixture.id, approval.logicalServerName, approval.gatewaySpkiSha256, approval.enrollmentId,
        approval.deviceId, "capture", "stream",
    ) + certificates.flatMap { listOf(it.subjectX500Principal.name, Base64.getEncoder().encodeToString(it.encoded)) } + renderedBinary) {
        assertFalse("Public rendering disclosed retained material", text.contains(secret))
    }
}

/** Independent writer for the frozen FKAR byte layout, not a second production model. */
internal fun approvedEnvelope(
    record: ApprovedEnrolledCredentialRecord,
    legacy: ByteArray = EnrolledCredentialCodec.encode(record.credential),
    fields: Map<String, ByteArray> = emptyMap(),
    originalHashes: List<ByteArray> = record.approval.originalKeystoreCertificateHashes,
    capabilities: List<String> = record.approval.capabilities,
    expiry: Long = record.approval.credentialExpiresAtMillis,
): ByteArray {
    val bytes = ByteArrayOutputStream()
    DataOutputStream(bytes).use { out ->
        fun blob(name: String, value: ByteArray) {
            val actual = fields[name] ?: value
            out.writeInt(actual.size)
            out.write(actual)
        }
        fun ascii(name: String, value: String) = blob(name, value.toByteArray(Charsets.US_ASCII))
        val a = record.approval
        out.writeInt(0x464b4152)
        out.writeInt(1)
        blob("legacy", legacy)
        ascii("desktop", a.desktopId)
        ascii("name", a.logicalServerName)
        ascii("pin", a.gatewaySpkiSha256)
        ascii("enrollment", a.enrollmentId)
        ascii("device", a.deviceId)
        blob("spki", a.originalDeviceSpki)
        out.writeInt(originalHashes.size)
        originalHashes.forEach { blob("originalHash", it) }
        blob("clientHash", a.clientCertificateSha256)
        blob("authorityHash", a.authorityCertificateSha256)
        blob("caHash", a.interceptionCaCertificateSha256)
        out.writeInt(capabilities.size)
        capabilities.forEach { ascii("capability", it) }
        out.writeLong(expiry)
    }
    return bytes.toByteArray()
}
