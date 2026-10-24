package com.httpfreekit.security

import java.io.ByteArrayInputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers

/** Runtime-generated software identities exclusively for JVM/instrumentation tests. Never shipped. */
internal object TestEnrollmentCertificates {
    data class Identity(val keys: KeyPair, val certificate: X509Certificate)
    private val serials = AtomicLong(1)

    fun keyPair(curve: String = "secp256r1"): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec(curve))
    }.generateKeyPair()

    fun authority(
        name: String = "CN=Test enrollment authority",
        issuer: Identity? = null,
        pathLength: Int = 2,
        notBefore: Instant = Instant.now().minusSeconds(60),
        notAfter: Instant = Instant.now().plusSeconds(86400),
        ca: Boolean = true,
        usage: Int? = KeyUsage.keyCertSign or KeyUsage.cRLSign,
        unknownCritical: Boolean = false,
        paddingBytes: Int = 0,
        nameConstraints: Boolean = false,
    ): Identity {
        val keys = keyPair()
        val subject = X500Principal(name)
        return Identity(keys, issue(
            keys.public, subject, issuer?.certificate?.subjectX500Principal ?: subject,
            issuer?.keys?.private ?: keys.private, ca, pathLength, usage, null,
            notBefore, notAfter, unknownCritical = unknownCritical, paddingBytes = paddingBytes, nameConstraints = nameConstraints,
        ))
    }

    fun client(
        publicKey: PublicKey,
        issuer: Identity,
        name: String = "CN=HTTP FreeKit test device",
        notBefore: Instant = Instant.now().minusSeconds(60),
        notAfter: Instant = Instant.now().plusSeconds(3600),
        ca: Boolean = false,
        usage: Int? = KeyUsage.digitalSignature,
        purposes: List<KeyPurposeId>? = listOf(KeyPurposeId.id_kp_clientAuth),
        signingKey: PrivateKey = issuer.keys.private,
        unknownCritical: Boolean = false,
        paddingBytes: Int = 0,
    ): X509Certificate = issue(
        publicKey, X500Principal(name), issuer.certificate.subjectX500Principal,
        signingKey, ca, 0, usage, purposes, notBefore, notAfter,
        unknownCritical = unknownCritical, paddingBytes = paddingBytes,
    )

    fun server(name: String = "gateway-fixture.invalid"): Identity {
        val keys = keyPair()
        val subject = X500Principal("CN=$name")
        return Identity(keys, issue(
            keys.public, subject, subject, keys.private, false, 0, KeyUsage.digitalSignature,
            listOf(KeyPurposeId.id_kp_serverAuth), Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600),
            dnsName = name,
        ))
    }

    fun trust(certificate: X509Certificate): X509TrustManager {
        val store = KeyStore.getInstance("PKCS12").apply { load(null); setCertificateEntry("test-anchor", certificate) }
        return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).run {
            init(store)
            trustManagers.filterIsInstance<X509TrustManager>().single()
        }
    }

    fun serverContext(server: Identity, clientAuthority: X509Certificate): SSLContext {
        val random = SecureRandom()
        val password = CharArray(24) { (33 + random.nextInt(94)).toChar() }
        return try {
            val store = KeyStore.getInstance("PKCS12").apply {
                load(null)
                setKeyEntry("synthetic-server", server.keys.private, password, arrayOf(server.certificate))
            }
            val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, password) }
            SSLContext.getInstance("TLS").apply { init(keys.keyManagers, arrayOf(trust(clientAuthority)), null) }
        } finally { password.fill('\u0000') }
    }

    private fun issue(
        publicKey: PublicKey,
        subject: X500Principal,
        issuer: X500Principal,
        signingKey: PrivateKey,
        ca: Boolean,
        pathLength: Int,
        usage: Int?,
        purposes: List<KeyPurposeId>?,
        notBefore: Instant,
        notAfter: Instant,
        dnsName: String? = null,
        unknownCritical: Boolean = false,
        paddingBytes: Int = 0,
        nameConstraints: Boolean = false,
    ): X509Certificate {
        val algorithm = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)
        val extensions = ExtensionsGenerator().apply {
            addExtension(Extension.basicConstraints, true, if (ca) BasicConstraints(pathLength) else BasicConstraints(false))
            usage?.let { addExtension(Extension.keyUsage, true, KeyUsage(it)) }
            purposes?.let { addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(it.toTypedArray())) }
            dnsName?.let { addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, it))) }
            if (unknownCritical) addExtension(ASN1ObjectIdentifier("1.3.6.1.4.1.55555.99"), true, DERNull.INSTANCE)
            if (paddingBytes > 0) addExtension(ASN1ObjectIdentifier("1.3.6.1.4.1.55555.100"), false, DEROctetString(ByteArray(paddingBytes)))
            if (nameConstraints) addExtension(Extension.nameConstraints, false, DERSequence())
        }
        val tbs = V3TBSCertificateGenerator().apply {
            setSerialNumber(ASN1Integer(serials.getAndIncrement()))
            setSignature(algorithm)
            setIssuer(X500Name.getInstance(issuer.encoded))
            setStartDate(Time(Date.from(notBefore)))
            setEndDate(Time(Date.from(notAfter)))
            setSubject(X500Name.getInstance(subject.encoded))
            setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(publicKey.encoded))
            setExtensions(extensions.generate())
        }.generateTBSCertificate()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signingKey); update(tbs.encoded); sign()
        }
        val encoded = DERSequence(arrayOf(tbs, algorithm, DERBitString(signature))).encoded
        return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
    }
}
