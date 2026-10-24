package com.httpfreekit.security

import java.io.ByteArrayInputStream
import java.net.Socket
import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.time.Clock
import java.util.Date
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import javax.security.auth.x500.X500Principal

/** One computer's verified client chain and original key handle, never a server identity. */
internal class EnrolledClientKeyManager private constructor(
    private val identity: DeviceIdentity,
    private val chain: List<X509Certificate>,
    private val authority: X509Certificate,
    private val clock: Clock,
) : X509ExtendedKeyManager() {
    private val acceptableIssuers = (chain.drop(1) + authority).map { it.subjectX500Principal }.toSet()

    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? =
        if (keyType == "EC" && matchesIssuers(issuers) && usableKey() != null) arrayOf(ALIAS) else null

    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? =
        if (keyType?.contains("EC") == true) getClientAliases("EC", issuers)?.single() else null

    override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? =
        chooseClientAlias(keyType, issuers, null)

    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
    override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = null

    override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
        if (alias == ALIAS && usableKey() != null) chain.toTypedArray() else null

    override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == ALIAS) usableKey() else null

    private fun usableKey(): PrivateKey? = try {
        val key = identity.keyForClientAuthentication()
        if (key == null) null else {
            val now = Date.from(clock.instant())
            (chain + authority).forEach { it.checkValidity(now) }
            key
        }
    } catch (_: Exception) { null }

    private fun matchesIssuers(issuers: Array<out Principal>?): Boolean = issuers.isNullOrEmpty() || issuers.any { issuer ->
        val name = try {
            if (issuer is X500Principal) issuer else issuer.name.takeIf { it.length in 1..1024 }?.let(::X500Principal)
        } catch (_: Exception) { null }
        name in acceptableIssuers
    }

    companion object {
        private const val ALIAS = "http-freekit-device-client"
        private const val CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
        private const val MAX_CHAIN_CERTIFICATES = 4
        private const val MAX_CERTIFICATE_BYTES = 4096
        private const val MAX_TOTAL_BYTES = 16 * 1024
        private val handledAnchorCriticalExtensions = setOf("2.5.29.19", "2.5.29.15", "2.5.29.37")
        private val unsupportedAnchorConstraints = setOf("2.5.29.30", "2.5.29.36", "2.5.29.54")

        fun bind(
            identity: DeviceIdentity,
            certificates: List<X509Certificate>,
            trustedAuthority: X509Certificate,
            clock: Clock,
        ): X509ExtendedKeyManager {
            if (certificates.size !in 1..MAX_CHAIN_CERTIFICATES) throw CertificateException("Invalid client chain length")
            val input = ArrayList<X509Certificate>(MAX_CHAIN_CERTIFICATES)
            val iterator = certificates.iterator()
            while (iterator.hasNext()) {
                if (input.size == MAX_CHAIN_CERTIFICATES) throw CertificateException("Invalid client chain length")
                input += iterator.next()
            }
            if (input.size !in 1..MAX_CHAIN_CERTIFICATES) throw CertificateException("Invalid client chain length")
            var total = 0
            fun copy(certificate: X509Certificate): X509Certificate {
                val encoded = certificate.encoded
                if (encoded.size !in 1..MAX_CERTIFICATE_BYTES) throw CertificateException("Invalid certificate size")
                total += encoded.size
                if (total > MAX_TOTAL_BYTES) throw CertificateException("Client certificate material is too large")
                val data = ByteArrayInputStream(encoded.copyOf())
                val result = CertificateFactory.getInstance("X.509").generateCertificate(data) as X509Certificate
                if (data.available() != 0 || !MessageDigest.isEqual(encoded, result.encoded)) {
                    throw CertificateException("Expected one canonical DER certificate")
                }
                return result
            }
            val authority = copy(trustedAuthority)
            val copied = input.map(::copy)
            if (copied.indices.any { index -> copied.take(index).any { it == copied[index] } }) {
                throw CertificateException("Duplicate client certificate")
            }
            val chain = if (copied.last() == authority) copied.dropLast(1) else copied
            if (chain.isEmpty()) throw CertificateException("Missing client leaf")
            val now = Date.from(clock.instant())
            (chain + authority).forEach { it.checkValidity(now) }
            validateAuthority(authority)
            if (authority.subjectX500Principal != authority.issuerX500Principal) throw CertificateException("Expected a self-signed enrollment authority")
            authority.verify(authority.publicKey)
            if (!authority.criticalExtensionOIDs.orEmpty().all { it in handledAnchorCriticalExtensions } ||
                unsupportedAnchorConstraints.any { authority.getExtensionValue(it) != null }) {
                throw CertificateException("Unsupported enrollment authority constraints")
            }
            if (chain.drop(1).size > authority.basicConstraints) throw CertificateException("Enrollment authority path limit exceeded")
            chain.forEachIndexed { index, certificate ->
                if (certificate.subjectX500Principal == certificate.issuerX500Principal) throw CertificateException("Unexpected self-issued client chain certificate")
                val issuer = chain.getOrNull(index + 1) ?: authority
                if (certificate.issuerX500Principal != issuer.subjectX500Principal) throw CertificateException("Client chain order or issuer mismatch")
                certificate.verify(issuer.publicKey)
                if (index > 0) validateAuthority(certificate)
            }
            val leaf = chain.first()
            requireP256(identity)
            if (!MessageDigest.isEqual(identity.publicKey.encoded, leaf.publicKey.encoded)) throw CertificateException("Client certificate key mismatch")
            if (leaf.basicConstraints >= 0 || leaf.extendedKeyUsage?.toSet() != setOf(CLIENT_AUTH)) throw CertificateException("Expected a client-only leaf certificate")
            val usage = leaf.keyUsage
            if (usage == null || usage.isEmpty() || !usage[0] || usage.getOrElse(5) { false } || usage.getOrElse(6) { false }) {
                throw CertificateException("Invalid client certificate signing usage")
            }
            val path = CertificateFactory.getInstance("X.509").generateCertPath(chain)
            val parameters = PKIXParameters(setOf(TrustAnchor(authority, null))).apply {
                date = now
                isRevocationEnabled = false // Desktop registry/active revocation is a separate, still-required gate.
                targetCertConstraints = X509CertSelector().apply { certificate = leaf; extendedKeyUsage = setOf(CLIENT_AUTH) }
            }
            CertPathValidator.getInstance("PKIX").validate(path, parameters)
            val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val signature = try { identity.signChallenge(challenge) } catch (failure: Exception) {
                throw CertificateException("Device identity is unavailable", failure)
            }
            if (!Signature.getInstance("SHA256withECDSA").run {
                    initVerify(leaf.publicKey); update(challenge); verify(signature)
                }) throw CertificateException("Device key does not match the client certificate")
            return EnrolledClientKeyManager(identity, chain, authority, clock)
        }

        private fun validateAuthority(certificate: X509Certificate) {
            val usage = certificate.keyUsage
            if (certificate.basicConstraints < 0 || usage == null || !usage.getOrElse(5) { false } ||
                certificate.extendedKeyUsage?.let { CLIENT_AUTH !in it } == true) {
                throw CertificateException("Invalid enrollment authority role or signing usage")
            }
        }

        private fun requireP256(identity: DeviceIdentity) {
            val key = identity.publicKey as? ECPublicKey ?: throw CertificateException("Client identity requires P-256")
            val parameters = key.params ?: throw CertificateException("Client identity requires explicit P-256 parameters")
            val expected = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
            if (parameters.curve != expected.curve || parameters.generator != expected.generator ||
                parameters.order != expected.order || parameters.cofactor != expected.cofactor) {
                throw CertificateException("Client identity requires P-256")
            }
        }
    }
}
