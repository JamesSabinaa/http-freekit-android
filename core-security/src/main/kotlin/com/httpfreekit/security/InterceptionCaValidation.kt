package com.httpfreekit.security

import java.io.ByteArrayInputStream
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Date

/** Narrow adaptation of the project-authored MIT research CA checks; not enrollment CA policy. */
internal object InterceptionCaValidation {
    fun <T> fixed(action: () -> T): T = try {
        action()
    } catch (_: Exception) {
        throw IllegalArgumentException("Invalid approved interception CA")
    }

    fun hash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun certificate(bytes: ByteArray): X509Certificate {
        check(bytes.size in 1..4096)
        val copy = bytes.copyOf()
        val input = ByteArrayInputStream(copy)
        InterceptionCaDer.requireCanonical(copy)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        check(input.available() == 0 && certificate.encoded.contentEquals(copy))
        return certificate
    }

    fun validate(record: ApprovedEnrolledCredentialRecord, bytes: ByteArray, now: Date): X509Certificate {
        check(MessageDigest.isEqual(record.approval.interceptionCaCertificateSha256, hash(bytes)))
        val ca = certificate(bytes)
        ca.checkValidity(now)
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
        val credential = record.credential
        val saved = listOf(credential.gatewayCertificate, credential.authenticatedEnrollmentAuthority) +
            credential.clientCertificateChain
        saved.forEach { it.checkValidity(now) }
        check(saved.none { samePublicKey(it.publicKey, ca.publicKey) })
        val originalDeviceKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(record.approval.originalDeviceSpki))
        check(!samePublicKey(originalDeviceKey, ca.publicKey))
        return ca
    }
}
