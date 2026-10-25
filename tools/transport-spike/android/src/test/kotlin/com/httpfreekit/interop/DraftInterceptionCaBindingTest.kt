package com.httpfreekit.interop

import com.httpfreekit.security.EnrolledCredentialRecord
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.io.ByteArrayInputStream
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import javax.net.ssl.X509ExtendedKeyManager
import javax.security.auth.x500.X500Principal
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.*
import org.junit.Test

class DraftInterceptionCaBindingTest {
    @Test fun originalIdentityAndApprovedContextBindWithoutExtendingRecoveryDeadlines() {
        val f = DraftInterceptionCaFixture()
        val original = arrayListOf(f.original.certificate)
        val recovery = f.recovery()
        val binding = DraftInterceptionCaBinding(f.record(), original, recovery)
        original.clear()
        binding.validateCurrent(f.manager)
        val bytes = f.ca.certificate.encoded
        val actual = binding.bind(bytes, f.hashText(bytes))
        bytes.fill(0); actual.certificateDer.fill(0); actual.certificateSha256.fill(0)
        assertArrayEquals(f.ca.certificate.encoded, actual.certificateDer)
        assertArrayEquals(f.hash(f.ca.certificate.encoded), actual.certificateSha256)
        assertArrayEquals(f.ca.certificate.encoded, actual.certificate.encoded)
        assertEquals("2020-01-01T00:00:00Z", recovery.resultExpiresAt)
        listOf(binding, actual, recovery).forEach { assertFalse(it.toString().contains(f.desktop)) }
    }

    @Test fun eachSavedApprovalOwnerMustMatchIncludingOriginalRatherThanIssuedChain() {
        val f = DraftInterceptionCaFixture()
        val other = DraftInterceptionCaFixture()
        val bad = listOf(
            f.recovery(desktop = "other"), f.recovery(name = "other.invalid"), f.recovery(pin = ByteArray(32)),
            f.recovery(spki = other.original.certificate.publicKey.encoded),
            f.recovery(originalHashes = listOf(f.hash(f.leaf.certificate.encoded))),
            f.recovery(originalHashes = listOf(f.hash(f.original.certificate.encoded), ByteArray(32))),
            f.recovery(leafHash = ByteArray(32)), f.recovery(authorityHash = ByteArray(32)),
            f.recovery(expiry = "2020-01-01T00:00:00Z"),
        )
        for (recovery in bad) rejected(DraftInterceptionCaFailure.BINDING) {
            DraftInterceptionCaBinding(f.record(), listOf(f.original.certificate), recovery)
        }
        rejected(DraftInterceptionCaFailure.BINDING) {
            DraftInterceptionCaBinding(f.record(), listOf(f.leaf.certificate), f.recovery())
        }
        val binding = f.binding()
        rejected(DraftInterceptionCaFailure.BINDING) { binding.validateCurrent(other.manager) }
    }

    @Test fun boundedOriginalCertificateSnapshotRejectsMissingExcessAndDishonestCollections() {
        val f = DraftInterceptionCaFixture()
        for (chain in listOf(emptyList(), List(5) { f.original.certificate })) rejected(DraftInterceptionCaFailure.BINDING) {
            DraftInterceptionCaBinding(f.record(), chain, f.recovery())
        }
        var reads = 0
        val endless = object : AbstractList<X509Certificate>() {
            override val size get() = 1
            override fun get(index: Int) = f.original.certificate
            override fun iterator() = object : Iterator<X509Certificate> {
                override fun hasNext() = true
                override fun next(): X509Certificate { check(++reads <= 5); return f.original.certificate }
            }
        }
        rejected(DraftInterceptionCaFailure.BINDING) { DraftInterceptionCaBinding(f.record(), endless, f.recovery()) }
        assertEquals(4, reads)
    }

    @Test fun completeDerAndResponseHashMustBothMatchApproval() {
        val f = DraftInterceptionCaFixture()
        val der = f.ca.certificate.encoded
        for (bytes in listOf(byteArrayOf(), ByteArray(4097), der + byteArrayOf(0), der + der, "PEM".toByteArray())) {
            rejected(DraftInterceptionCaFailure.RESPONSE) { f.binding(caHash = f.hash(bytes)).bind(bytes, f.hashText(bytes)) }
        }
        for (header in listOf("", f.hashText(der) + "=", "A".repeat(43))) rejected(DraftInterceptionCaFailure.RESPONSE) {
            f.binding().bind(der, header)
        }
        val changed = HeldCertificate.Builder().certificateAuthority(0).commonName("Changed CA").build().certificate.encoded
        rejected(DraftInterceptionCaFailure.RESPONSE) { f.binding().bind(changed, f.hashText(changed)) }
    }

    @Test fun malformedOuterDerIsRejectedEvenWhenApprovalAndHeaderHashMatchThoseBytes() {
        val f = DraftInterceptionCaFixture()
        val der = f.ca.certificate.encoded
        val count = der[1].toInt() and 127
        check(der[1].toInt() and 128 != 0 && count in 1..2)
        // Both variants leave the signed TBS and signature bytes untouched.
        val overlong = byteArrayOf(0x30, (0x80 or (count + 1)).toByte(), 0) + der.copyOfRange(2, der.size)
        val indefinite = byteArrayOf(0x30, 0x80.toByte()) + der.copyOfRange(2 + count, der.size) + byteArrayOf(0, 0)
        for (bytes in listOf(overlong, indefinite)) {
            rejected(DraftInterceptionCaFailure.RESPONSE) { f.binding(caHash = f.hash(bytes)).bind(bytes, f.hashText(bytes)) }
        }
    }

    @Test fun caRoleValiditySignatureSupportedKeyAndSeparateTrustOwnersAreRequired() {
        val f = DraftInterceptionCaFixture()
        val expired = HeldCertificate.Builder().certificateAuthority(0).commonName("Expired CA")
            .validityInterval(0, 1000).build().certificate
        val future = HeldCertificate.Builder().certificateAuthority(0).commonName("Future CA")
            .validityInterval(System.currentTimeMillis() + 60000, System.currentTimeMillis() + 120000).build().certificate
        val p384 = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        val wrongCurve = selfSignedCa(p384)
        wrongCurve.checkValidity(); wrongCurve.verify(wrongCurve.publicKey)
        assertTrue(wrongCurve.basicConstraints >= 0)
        val rsa1024 = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val smallRsa = HeldCertificate.Builder().certificateAuthority(0).keyPair(rsa1024).build().certificate
        val childCa = HeldCertificate.Builder().certificateAuthority(0).signedBy(f.ca).build().certificate
        for (ca in listOf(f.gateway.certificate, expired, future, wrongCurve, smallRsa, childCa, f.authority.certificate)) {
            val der = ca.encoded
            rejected(DraftInterceptionCaFailure.RESPONSE) { f.binding(caHash = f.hash(der)).bind(der, f.hashText(der)) }
        }
        val tampered = f.ca.certificate.encoded.also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        rejected(DraftInterceptionCaFailure.RESPONSE) { f.binding(caHash = f.hash(tampered)).bind(tampered, f.hashText(tampered)) }
        val rsa = HeldCertificate.Builder().rsa2048().certificateAuthority(0).commonName("RSA CA").build().certificate.encoded
        assertArrayEquals(rsa, f.binding(caHash = f.hash(rsa)).bind(rsa, f.hashText(rsa)).certificateDer)
    }

    @Test fun failuresExposeOnlyFixedCodeAndNoProviderCause() {
        val f = DraftInterceptionCaFixture()
        val failure = rejected(DraftInterceptionCaFailure.RESPONSE) { f.binding().bind(byteArrayOf(1), "PRIVATE_CANARY") }
        assertNull(failure.cause); assertEquals(0, failure.suppressed.size)
        assertEquals("Interception CA research failed: RESPONSE", failure.message)
        assertFalse(failure.toString().contains("PRIVATE_CANARY"))
    }

    private fun rejected(code: DraftInterceptionCaFailure, action: () -> Unit): DraftInterceptionCaException =
        assertThrows(DraftInterceptionCaException::class.java) { action() }.also { assertEquals(code, it.code) }

    /** A small runtime-generated fixture: JDK SPKI/Signature/X509 parsing, no installed provider. */
    private fun selfSignedCa(keys: KeyPair): X509Certificate {
        fun der(tag: Int, content: ByteArray): ByteArray {
            val length = when {
                content.size < 128 -> byteArrayOf(content.size.toByte())
                content.size < 256 -> byteArrayOf(0x81.toByte(), content.size.toByte())
                else -> byteArrayOf(0x82.toByte(), (content.size ushr 8).toByte(), content.size.toByte())
            }
            return byteArrayOf(tag.toByte()) + length + content
        }
        val algorithm = der(0x30, der(6, byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 4, 3, 2)))
        val name = X500Principal("CN=Alternate curve CA").encoded
        val format = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC)
        val validity = der(0x30, der(23, format.format(Instant.now().minusSeconds(60)).toByteArray()) +
            der(23, format.format(Instant.now().plusSeconds(3600)).toByteArray()))
        val basicConstraints = der(0x30, der(6, byteArrayOf(0x55, 0x1d, 0x13)) + der(1, byteArrayOf(0xff.toByte())) +
            der(4, der(0x30, der(1, byteArrayOf(0xff.toByte())))))
        val tbs = der(0x30, der(0xa0, der(2, byteArrayOf(2))) + der(2, byteArrayOf(1)) + algorithm + name + validity + name +
            keys.public.encoded + der(0xa3, der(0x30, basicConstraints)))
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(keys.private); update(tbs); sign() }
        val encoded = der(0x30, tbs + algorithm + der(3, byteArrayOf(0) + signature))
        return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
    }
}

/** Runtime-generated software material only, independent of the reference Node issuer/proof. */
internal class DraftInterceptionCaFixture {
    val name = "ca-gateway-research.invalid"
    val desktop = "PRIVATE_DESKTOP_CANARY"
    val gateway = HeldCertificate.Builder().commonName(name).addSubjectAlternativeName(name).build()
    val original = HeldCertificate.Builder().commonName("Original device identity").build()
    val authority = HeldCertificate.Builder().certificateAuthority(0).commonName("Enrollment authority").build()
    val leaf = HeldCertificate.Builder().keyPair(original.keyPair).commonName("Enrolled device").signedBy(authority).build()
    val ca = HeldCertificate.Builder().certificateAuthority(0).commonName("Interception CA").build()
    val manager = HandshakeCertificates.Builder().heldCertificate(leaf, authority.certificate).build().keyManager as X509ExtendedKeyManager
    fun hash(value: ByteArray) = DraftInterceptionCaChecks.hash(value)
    fun hashText(value: ByteArray) = DraftInterceptionCaChecks.b64(hash(value))
    fun record() = EnrolledCredentialRecord(desktop, gateway.certificate, hashText(gateway.certificate.publicKey.encoded),
        name, listOf(leaf.certificate), authority.certificate)
    fun recovery(port: Int = 31235, desktop: String = this.desktop, name: String = this.name,
        pin: ByteArray = hash(gateway.certificate.publicKey.encoded), spki: ByteArray = original.certificate.publicKey.encoded,
        originalHashes: List<ByteArray> = listOf(hash(original.certificate.encoded)), leafHash: ByteArray = hash(leaf.certificate.encoded),
        authorityHash: ByteArray = hash(authority.certificate.encoded), caHash: ByteArray = hash(ca.certificate.encoded),
        expiry: String = leaf.certificate.notAfter.toInstant().toString()) = DraftEnrollmentRecovery(
        if (port == 31234) 31233 else 31234, port, desktop, pin, name, "invitation", "enr_" + "A".repeat(43), "dev_" + "A".repeat(43),
        spki, originalHashes, leafHash, authorityHash, caHash, listOf("tcp-http", "tcp-https-connect"),
        "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z", expiry)
    fun binding(caHash: ByteArray = hash(ca.certificate.encoded)) = DraftInterceptionCaBinding(record(), listOf(original.certificate), recovery(caHash = caHash))
    fun client(port: Int) = DraftInterceptionCaClient(record(), manager, listOf(original.certificate), recovery(port),
        InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
}
