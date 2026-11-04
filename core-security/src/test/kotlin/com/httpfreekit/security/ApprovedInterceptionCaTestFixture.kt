package com.httpfreekit.security

import java.io.ByteArrayInputStream
import java.net.Socket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Principal
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Date
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers

/** Software-only public evidence, not an Android Keystore or authenticated approval fixture. */
internal class ApprovedInterceptionCaTestFixture {
    val saved = ApprovedCredentialTestFixture()
    val now: Instant = saved.now
    val manager = UnusedCaKeyManager()
    val caKeys = TestEnrollmentCertificates.keyPair()
    val ca = certificate()

    fun loaded(
        der: ByteArray = ca.encoded,
        credential: EnrolledCredentialRecord = saved.credential(),
        digest: ByteArray = approvedHash(der),
    ): LoadedApprovedEnrolledCredential {
        val leaf = credential.clientCertificateChain.first()
        val approval = saved.approval(
            pin = credential.gatewaySpkiSha256,
            spki = leaf.publicKey.encoded,
            clientHash = approvedHash(leaf.encoded),
            authorityHash = approvedHash(credential.authenticatedEnrollmentAuthority.encoded),
            caHash = digest,
            expires = leaf.notAfter.time,
        )
        return LoadedApprovedEnrolledCredential(ApprovedEnrolledCredentialRecord(credential, approval), manager)
    }

    fun prepare(
        der: ByteArray = ca.encoded,
        loaded: LoadedApprovedEnrolledCredential = loaded(der),
        clock: Clock = Clock.fixed(now, ZoneOffset.UTC),
    ): ApprovedInterceptionCa = ApprovedInterceptionCaPreparation.prepare(loaded, der, clock)

    /** The shared builder cannot issue RSA or arbitrary-owner self-signed CA certificates. */
    fun certificate(
        keys: KeyPair = caKeys,
        ca: Boolean? = true,
        usage: Int? = KeyUsage.keyCertSign or KeyUsage.cRLSign,
        purposes: List<KeyPurposeId>? = listOf(KeyPurposeId.id_kp_serverAuth),
        before: Instant = now.minusSeconds(60),
        after: Instant = now.plusSeconds(20000),
        subject: String = "CN=PRIVATE_INTERCEPTION_CA_CANARY",
        issuer: String = subject,
        signingKey: PrivateKey = keys.private,
        spki: SubjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keys.public.encoded),
    ): X509Certificate {
        val algorithm = when (signingKey.algorithm) {
            "RSA" -> AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE)
            "DSA" -> AlgorithmIdentifier(NISTObjectIdentifiers.dsa_with_sha256)
            else -> AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)
        }
        val extensions = ExtensionsGenerator().apply {
            ca?.let { addExtension(Extension.basicConstraints, true, BasicConstraints(it)) }
            usage?.let { addExtension(Extension.keyUsage, true, KeyUsage(it)) }
            purposes?.let { addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(it.toTypedArray())) }
        }
        val tbs = V3TBSCertificateGenerator().apply {
            setSerialNumber(ASN1Integer(17))
            setSignature(algorithm)
            setIssuer(X500Name(issuer))
            setStartDate(Time(Date.from(before)))
            setEndDate(Time(Date.from(after)))
            setSubject(X500Name(subject))
            setSubjectPublicKeyInfo(spki)
            setExtensions(extensions.generate())
        }.generateTBSCertificate()
        val signatureAlgorithm = when (signingKey.algorithm) {
            "RSA" -> "SHA256withRSA"
            "DSA" -> "SHA256withDSA"
            else -> "SHA256withECDSA"
        }
        val signature = Signature.getInstance(signatureAlgorithm).run {
            initSign(signingKey)
            update(tbs.encoded)
            sign()
        }
        return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(
            DERSequence(arrayOf(tbs, algorithm, DERBitString(signature))).encoded,
        )) as X509Certificate
    }

    fun rsa(bits: Int): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()
}

/** Every manager entry point fails the test, even if production catches ordinary exceptions. */
internal class UnusedCaKeyManager : X509ExtendedKeyManager() {
    var calls = 0
        private set
    private fun unused(): Nothing {
        calls++
        throw AssertionError("Public CA preparation invoked a key manager")
    }
    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = unused()
    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? = unused()
    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = unused()
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = unused()
    override fun getCertificateChain(alias: String?): Array<X509Certificate>? = unused()
    override fun getPrivateKey(alias: String?): PrivateKey? = unused()
    override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = unused()
    override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = unused()
}

internal class SingleObservationCaClock(private val at: Instant) : Clock() {
    var observations = 0
        private set
    override fun instant(): Instant {
        check(++observations == 1) { "Preparation observed time more than once" }
        return at
    }
    override fun getZone(): ZoneId = ZoneOffset.UTC
    override fun withZone(zone: ZoneId): Clock = this
}
