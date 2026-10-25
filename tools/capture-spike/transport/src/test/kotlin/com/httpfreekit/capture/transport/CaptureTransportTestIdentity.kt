package com.httpfreekit.capture.transport

import com.httpfreekit.protocol.DraftBudgetPool
import com.httpfreekit.security.EnrolledCredentialRecord
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import okhttp3.tls.HeldCertificate

/** Software keys remain in this JVM. This helper is not enrollment or Android Keystore evidence. */
internal class CaptureTransportTestIdentity {
    val gateway = HeldCertificate.Builder().ecdsa256().commonName(NAME).addSubjectAlternativeName(NAME).build()
    private val authority = HeldCertificate.Builder().ecdsa256().commonName("Transport test authority").certificateAuthority(0).build()
    private val client = HeldCertificate.Builder().ecdsa256().commonName("Transport test client").signedBy(authority).build()
    val record = EnrolledCredentialRecord("transport-test-desktop", gateway.certificate, pin(gateway.certificate.publicKey.encoded), NAME,
        listOf(client.certificate), authority.certificate)
    private val keyManager: X509ExtendedKeyManager

    init {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry("client", client.keyPair.private, CharArray(0), arrayOf(client.certificate, authority.certificate))
        }
        keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
            .keyManagers.filterIsInstance<X509ExtendedKeyManager>().single()
    }

    fun configuration(pool: DraftBudgetPool = DraftBudgetPool()) = CaptureTransportConfiguration(record, keyManager, { expiry, utc ->
        val certificates = listOf(record.gatewayCertificate, record.authenticatedEnrollmentAuthority) + record.clientCertificateChain
        check(certificates.all { utc >= it.notBefore.time && expiry <= it.notAfter.time } && expiry > utc)
    }, pool)
    override fun toString() = "CaptureTransportTestIdentity([REDACTED])"

    companion object {
        const val NAME = "capture-transport-test.invalid"
        fun pin(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes))
    }
}
