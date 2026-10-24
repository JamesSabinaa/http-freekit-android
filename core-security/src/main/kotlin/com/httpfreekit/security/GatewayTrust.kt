package com.httpfreekit.security

import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Creates a scoped platform trust manager from the public certificate in an
 * approved pairing payload. Rebuild on reconnect to recheck expiry; retain
 * normal TLS hostname verification. Never install this in the global context.
 */
object GatewayTrust {
    fun forCertificate(certificate: X509Certificate, expectedSpkiSha256: String, now: Date = Date()): X509TrustManager {
        require(Regex("[A-Za-z0-9_-]{43}").matches(expectedSpkiSha256)) { "Invalid desktop pin" }
        val expected = Base64.getUrlDecoder().decode(expectedSpkiSha256)
        require(expected.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(expected) == expectedSpkiSha256) {
            "Invalid desktop pin"
        }
        certificate.checkValidity(now)
        val actual = MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded)
        if (!MessageDigest.isEqual(expected, actual)) throw CertificateException("Desktop identity mismatch")
        if (certificate.subjectX500Principal != certificate.issuerX500Principal || certificate.basicConstraints >= 0) {
            throw CertificateException("Expected a dedicated self-signed gateway leaf")
        }
        certificate.verify(certificate.publicKey)
        val purposes = certificate.extendedKeyUsage
        if (purposes != null && "1.3.6.1.5.5.7.3.1" !in purposes) throw CertificateException("Invalid gateway certificate purpose")
        val usage = certificate.keyUsage
        if (usage != null && (usage.isEmpty() || !usage[0])) throw CertificateException("Invalid gateway signing usage")
        val anchor = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("gateway", certificate)
        }
        return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).run {
            init(anchor)
            trustManagers.filterIsInstance<X509TrustManager>().single()
        }
    }
}
