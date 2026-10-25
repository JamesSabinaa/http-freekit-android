package com.httpfreekit.interop

import com.httpfreekit.security.EnrolledCredentialRecord
import com.httpfreekit.security.GatewayTlsConnectionFactory
import java.io.ByteArrayInputStream
import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.time.Instant
import java.util.Base64
import java.util.Date
import javax.net.ssl.X509ExtendedKeyManager

internal enum class DraftInterceptionCaFailure { BINDING, RESPONSE, TRANSPORT, CLOSED, CLEANUP }

/** Provider exceptions, identifying certificate material and causes never cross this boundary. */
internal class DraftInterceptionCaException(val code: DraftInterceptionCaFailure) :
    IllegalStateException("Interception CA research failed: $code")

/** Public material only; every accessor returns a fresh copy. No installation or trust mutation. */
internal class DraftInterceptionCa internal constructor(certificate: X509Certificate) {
    private val der = certificate.encoded.copyOf()
    val certificateDer: ByteArray get() = der.copyOf()
    val certificateSha256: ByteArray get() = DraftInterceptionCaChecks.hash(der)
    val certificate: X509Certificate get() = DraftInterceptionCaChecks.certificate(der)
    override fun toString() = "DraftInterceptionCa([PUBLIC MATERIAL REDACTED])"
}

/** A credential alone is deliberately insufficient: the saved authenticated approval is required. */
internal class DraftInterceptionCaBinding(
    val record: EnrolledCredentialRecord,
    originalDeviceCertificateChain: List<X509Certificate>,
    recovery: DraftEnrollmentRecovery,
) {
    private val original = DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.BINDING) {
        DraftInterceptionCaChecks.chain(originalDeviceCertificateChain)
    }
    private val approval = DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.BINDING) {
        DraftEnrollmentStateCodec.decodeRecovery(DraftEnrollmentStateCodec.encodeRecovery(recovery))
    }
    val credentialPort: Int get() = approval.credentialPort
    private val expectedHash = approval.interceptionCaCertificateSha256

    init { validateContext() }

    fun validateCurrent(manager: X509ExtendedKeyManager) = DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.BINDING) {
        validateContext()
        val now = Date()
        // Gateway trust-anchor expiry is checked explicitly rather than delegated to PKIX.
        GatewayTlsConnectionFactory(record.gatewayCertificate, record.gatewaySpkiSha256, record.logicalServerName, 5000, 5000)
        (record.clientCertificateChain + record.authenticatedEnrollmentAuthority).forEach { it.checkValidity(now) }
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        checkNotNull(manager.getPrivateKey(alias))
        val actual = DraftInterceptionCaChecks.chain(checkNotNull(manager.getCertificateChain(alias)).toList())
        val expected = record.clientCertificateChain
        // Bound managers may omit the trust anchor that was included in a saved issued chain.
        fun withoutAnchor(chain: List<X509Certificate>) = if (chain.last().encoded.contentEquals(record.authenticatedEnrollmentAuthority.encoded)) chain.dropLast(1) else chain
        val presented = withoutAnchor(actual); val saved = withoutAnchor(expected)
        check(presented.isNotEmpty() && presented.size == saved.size)
        check(presented.indices.all { presented[it].encoded.contentEquals(saved[it].encoded) })
    }

    fun bind(der: ByteArray, headerHash: String): DraftInterceptionCa = DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.RESPONSE) {
        check(headerHash == DraftInterceptionCaChecks.b64(expectedHash))
        check(MessageDigest.isEqual(expectedHash, DraftInterceptionCaChecks.hash(der)))
        val ca = DraftInterceptionCaChecks.certificate(der)
        ca.checkValidity(Date())
        check(ca.notBefore.before(ca.notAfter) && ca.basicConstraints >= 0)
        check(ca.subjectX500Principal == ca.issuerX500Principal)
        ca.verify(ca.publicKey)
        check(ca.keyUsage?.getOrElse(5) { false } != false)
        // Match the existing interception-CA profile, not the separate enrollment authority.
        check(ca.extendedKeyUsage?.let { it == listOf("1.3.6.1.5.5.7.3.1") } != false)
        when (val key = ca.publicKey) {
            is ECPublicKey -> {
                val expected = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                    .getParameterSpec(ECParameterSpec::class.java)
                check(key.params.curve == expected.curve && key.params.generator == expected.generator &&
                    key.params.order == expected.order && key.params.cofactor == expected.cofactor)
            }
            is RSAPublicKey -> check(key.modulus.bitLength() in 2048..4096)
            else -> error("Unsupported interception CA key")
        }
        val forbidden = listOf(record.gatewayCertificate, record.authenticatedEnrollmentAuthority) + original + record.clientCertificateChain
        check(forbidden.none { it.publicKey.encoded.contentEquals(ca.publicKey.encoded) })
        DraftInterceptionCa(ca)
    }

    private fun validateContext() = DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.BINDING) {
        check(record.desktopId == approval.desktopId && record.logicalServerName == approval.logicalName &&
            record.gatewaySpkiSha256 == approval.gatewaySpkiSha256)
        val gateway = record.gatewayCertificate
        check(DraftInterceptionCaChecks.b64(DraftInterceptionCaChecks.hash(gateway.publicKey.encoded)) == approval.gatewaySpkiSha256)
        check(gateway.subjectAlternativeNames.orEmpty().any { it.size == 2 && it[0] == 2 && it[1] is String &&
            record.logicalServerName.equals(it[1] as String, ignoreCase = true) })
        check(original.first().publicKey.encoded.contentEquals(approval.originalDeviceSpki))
        check(original.size == approval.originalKeystoreCertificateHashes.size)
        check(original.indices.all { MessageDigest.isEqual(DraftInterceptionCaChecks.hash(original[it].encoded), approval.originalKeystoreCertificateHashes[it]) })
        val leaf = record.clientCertificateChain.first()
        check(leaf.publicKey.encoded.contentEquals(approval.originalDeviceSpki))
        check(MessageDigest.isEqual(DraftInterceptionCaChecks.hash(leaf.encoded), approval.clientCertificateSha256))
        check(MessageDigest.isEqual(DraftInterceptionCaChecks.hash(record.authenticatedEnrollmentAuthority.encoded), approval.authorityCertificateSha256))
        check(leaf.notAfter.toInstant() == Instant.parse(approval.credentialExpiresAt))
        check(!gateway.publicKey.encoded.contentEquals(leaf.publicKey.encoded) &&
            !record.authenticatedEnrollmentAuthority.publicKey.encoded.contentEquals(leaf.publicKey.encoded) &&
            !gateway.publicKey.encoded.contentEquals(record.authenticatedEnrollmentAuthority.publicKey.encoded))
        // Reservation/result TTLs govern result recovery, not an already active saved credential.
    }

    override fun toString() = "DraftInterceptionCaBinding([REDACTED])"
}

internal object DraftInterceptionCaChecks {
    fun <T> fixed(code: DraftInterceptionCaFailure, action: () -> T): T = try { action() }
        catch (_: Exception) { throw DraftInterceptionCaException(code) }
    fun hash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun certificate(bytes: ByteArray): X509Certificate {
        check(bytes.size in 1..4096)
        val copy = bytes.copyOf(); val input = ByteArrayInputStream(copy)
        DraftInterceptionCaDer.requireCanonical(copy)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        check(input.available() == 0 && certificate.encoded.contentEquals(copy))
        return certificate
    }
    fun chain(input: List<X509Certificate>): List<X509Certificate> {
        check(input.size in 1..4)
        val result = ArrayList<X509Certificate>(4); var total = 0
        val iterator = input.iterator()
        while (iterator.hasNext()) {
            check(result.size < 4)
            val copy = certificate(iterator.next().encoded); total += copy.encoded.size
            check(total <= 16384); result += copy
        }
        check(result.isNotEmpty()); return result
    }
}
