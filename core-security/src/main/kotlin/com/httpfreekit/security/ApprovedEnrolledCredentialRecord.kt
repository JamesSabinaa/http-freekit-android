package com.httpfreekit.security

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/**
 * Cross-bound public credential and approval evidence, not proof of authenticated provenance.
 * Current time, key possession and original Keystore evidence are checked by the opt-in store.
 * The interception CA hash is only a commitment; no CA is fetched, validated or installed here.
 */
class ApprovedEnrolledCredentialRecord(
    val credential: EnrolledCredentialRecord,
    val approval: AuthenticatedEnrollmentApproval,
) {
    init {
        try {
            require(credential.desktopId == approval.desktopId &&
                credential.logicalServerName == approval.logicalServerName &&
                credential.gatewaySpkiSha256 == approval.gatewaySpkiSha256)
            val gateway = credential.gatewayCertificate
            val authority = credential.authenticatedEnrollmentAuthority
            val leaf = credential.clientCertificateChain.first()
            val gatewaySpki = gateway.publicKey.encoded
            val deviceSpki = leaf.publicKey.encoded
            val pin = Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(gatewaySpki))
            require(pin == approval.gatewaySpkiSha256)
            require(MessageDigest.isEqual(deviceSpki, approval.originalDeviceSpki))
            require(MessageDigest.isEqual(sha256(leaf.encoded), approval.clientCertificateSha256))
            require(MessageDigest.isEqual(sha256(authority.encoded), approval.authorityCertificateSha256))
            require(leaf.notAfter.time == approval.credentialExpiresAtMillis)
            require(!samePublicKey(gateway.publicKey, authority.publicKey) &&
                !samePublicKey(gateway.publicKey, leaf.publicKey) &&
                !samePublicKey(authority.publicKey, leaf.publicKey))
        } catch (_: Exception) {
            throw IllegalArgumentException("Invalid approved credential record")
        }
    }

    override fun toString(): String = "ApprovedEnrolledCredentialRecord(publicMaterial=[REDACTED])"
}

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private fun samePublicKey(first: PublicKey, second: PublicKey): Boolean {
    if (first == second || MessageDigest.isEqual(first.encoded, second.encoded)) return true
    // Key separation concerns mathematical keys, even with alternative parameter encodings.
    return when {
        first is ECPublicKey && second is ECPublicKey -> first.w == second.w &&
            first.params.curve == second.params.curve && first.params.generator == second.params.generator &&
            first.params.order == second.params.order && first.params.cofactor == second.params.cofactor
        first is RSAPublicKey && second is RSAPublicKey ->
            first.modulus == second.modulus && first.publicExponent == second.publicExponent
        first is DSAPublicKey && second is DSAPublicKey -> first.y == second.y &&
            first.params.p == second.params.p && first.params.q == second.params.q && first.params.g == second.params.g
        else -> false
    }
}

/** Strict FKAR v1 application-local envelope. Never interprets legacy FKCR bytes as approval. */
internal object ApprovedEnrolledCredentialCodec {
    const val MAX_RECORD_BYTES = 32768
    private const val MAGIC = 0x464b4152 // FKAR
    private const val VERSION = 1

    fun encode(record: ApprovedEnrolledCredentialRecord): ByteArray = try {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { output ->
            fun field(value: ByteArray) {
                require(value.isNotEmpty() && value.size <= MAX_RECORD_BYTES - bytes.size() - 4)
                output.writeInt(value.size)
                output.write(value)
            }
            fun ascii(value: String) = field(value.toByteArray(Charsets.US_ASCII))
            output.writeInt(MAGIC)
            output.writeInt(VERSION)
            field(EnrolledCredentialCodec.encode(record.credential))
            val approval = record.approval
            ascii(approval.desktopId)
            ascii(approval.logicalServerName)
            ascii(approval.gatewaySpkiSha256)
            ascii(approval.enrollmentId)
            ascii(approval.deviceId)
            field(approval.originalDeviceSpki)
            val originalHashes = approval.originalKeystoreCertificateHashes
            output.writeInt(originalHashes.size)
            originalHashes.forEach { field(it) }
            field(approval.clientCertificateSha256)
            field(approval.authorityCertificateSha256)
            field(approval.interceptionCaCertificateSha256)
            val capabilities = approval.capabilities
            output.writeInt(capabilities.size)
            capabilities.forEach { ascii(it) }
            output.writeLong(approval.credentialExpiresAtMillis)
        }
        bytes.toByteArray().also { require(it.size <= MAX_RECORD_BYTES) }
    } catch (_: Exception) {
        throw IllegalArgumentException("Invalid approved credential record encoding")
    }

    fun decode(encoded: ByteArray): ApprovedEnrolledCredentialRecord = try {
        require(encoded.size in 1..MAX_RECORD_BYTES)
        val input = DataInputStream(ByteArrayInputStream(encoded.copyOf()))
        require(input.readInt() == MAGIC && input.readInt() == VERSION)
        fun field(maximum: Int): ByteArray {
            val length = input.readInt()
            require(length in 1..maximum && length <= input.available())
            return ByteArray(length).also { input.readFully(it) }
        }
        fun ascii(maximum: Int): String = field(maximum).also { value ->
            require(value.all { it.toInt() in 33..126 })
        }.toString(Charsets.US_ASCII)
        val credential = EnrolledCredentialCodec.decode(field(EnrolledCredentialCodec.MAX_RECORD_BYTES))
        val desktopId = ascii(128)
        val logicalServerName = ascii(253)
        val pin = ascii(43)
        val enrollmentId = ascii(128)
        val deviceId = ascii(128)
        val spki = field(91)
        val hashCount = input.readInt()
        require(hashCount in 1..4)
        val originalHashes = ArrayList<ByteArray>(hashCount)
        repeat(hashCount) { originalHashes.add(field(32)) }
        val clientHash = field(32)
        val authorityHash = field(32)
        val caHash = field(32)
        val capabilityCount = input.readInt()
        require(capabilityCount in 1..16)
        val capabilities = ArrayList<String>(capabilityCount)
        repeat(capabilityCount) { capabilities.add(ascii(32)) }
        // A canonical envelope has the same deterministic capability order as its model.
        require(capabilities == capabilities.sorted() && capabilities.distinct().size == capabilities.size)
        val expiry = input.readLong()
        require(input.available() == 0)
        val approval = AuthenticatedEnrollmentApproval(desktopId, logicalServerName, pin,
            enrollmentId, deviceId, spki, originalHashes, clientHash, authorityHash, caHash,
            capabilities, expiry)
        ApprovedEnrolledCredentialRecord(credential, approval)
    } catch (_: Exception) {
        throw IllegalArgumentException("Invalid approved credential record encoding")
    }
}
