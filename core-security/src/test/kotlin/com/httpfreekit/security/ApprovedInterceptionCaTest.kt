package com.httpfreekit.security

import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.junit.Assert.*
import org.junit.Test

/** Independent frozen-API checks. No software fixture establishes Android Keystore behavior. */
class ApprovedInterceptionCaTest {
    @Test fun distinctP256CaMatchesExactApprovedDerAndDigest() {
        val f = ApprovedInterceptionCaTestFixture()
        val expected = f.ca.encoded
        val actual = f.prepare()
        assertArrayEquals(expected, actual.certificateDer)
        assertArrayEquals(approvedHash(expected), actual.certificateSha256)
        assertArrayEquals(expected, actual.certificate.encoded)
        assertEquals(0, f.manager.calls)
    }

    @Test fun distinctRsa2048And4096CasAreAccepted() {
        val f = ApprovedInterceptionCaTestFixture()
        for (bits in listOf(2048, 4096)) {
            val ca = f.certificate(keys = f.rsa(bits))
            assertEquals(bits, (ca.publicKey as RSAPublicKey).modulus.bitLength())
            assertArrayEquals(ca.encoded, f.prepare(ca.encoded).certificateDer)
        }
        assertEquals(0, f.manager.calls)
    }

    @Test fun absentOptionalKuAndEkuAreAccepted() {
        val f = ApprovedInterceptionCaTestFixture()
        for (ca in listOf(f.certificate(usage = null), f.certificate(purposes = null),
            f.certificate(usage = null, purposes = null))) {
            assertArrayEquals(ca.encoded, f.prepare(ca.encoded).certificateDer)
        }
    }

    @Test fun approvalIsTheOnlyExpectedDigestAndAnotherValidCaCannotReplaceIt() {
        val f = ApprovedInterceptionCaTestFixture()
        val loaded = f.loaded()
        val replacement = f.certificate(keys = TestEnrollmentCertificates.keyPair()).encoded
        rejected(f) { f.prepare(replacement, loaded) }
        rejected(f) { f.prepare(loaded = f.loaded(digest = ByteArray(32))) }
        assertArrayEquals(replacement, f.prepare(replacement).certificateDer)
    }

    @Test fun emptyMalformedPemTruncatedTrailingAndConcatenatedDerFailUnderTheirOwnApprovedHashes() {
        val f = ApprovedInterceptionCaTestFixture()
        val der = f.ca.encoded
        val malformed = listOf(byteArrayOf(), byteArrayOf(0x30, 0), byteArrayOf(1, 2, 3),
            "-----BEGIN CERTIFICATE-----\nPRIVATE_CANARY\n-----END CERTIFICATE-----".toByteArray(),
            der.copyOf(der.size - 1), der + byteArrayOf(0), der + der)
        for (bytes in malformed) rejected(f) { f.prepare(bytes, f.loaded(bytes)) }
    }

    @Test fun oversizedDerFailsEvenWhenApprovalCommitsToAllBytes() {
        val f = ApprovedInterceptionCaTestFixture()
        val large = TestEnrollmentCertificates.authority(notBefore = f.now.minusSeconds(60),
            notAfter = f.now.plusSeconds(60), paddingBytes = 4096).certificate
        large.verify(large.publicKey)
        assertCurrent(f.now, large)
        assertTrue(large.encoded.size > 4096)
        for (bytes in listOf(large.encoded, f.ca.encoded.copyOf(4097))) {
            rejected(f) { f.prepare(bytes, f.loaded(bytes)) }
        }
    }

    @Test fun overlongAndIndefiniteDerLengthsFailUnderTheirOwnApprovedHashes() {
        val f = ApprovedInterceptionCaTestFixture()
        val der = f.ca.encoded
        val count = der[1].toInt() and 127
        assertTrue(der[1].toInt() and 128 != 0 && count in 1..2)
        // Leave the signed TBS/signature untouched; only the outer length is noncanonical.
        val overlong = byteArrayOf(0x30, (0x80 or (count + 1)).toByte(), 0) + der.copyOfRange(2, der.size)
        val indefinite = byteArrayOf(0x30, 0x80.toByte()) + der.copyOfRange(2 + count, der.size) + byteArrayOf(0, 0)
        for (bytes in listOf(overlong, indefinite)) rejected(f) { f.prepare(bytes, f.loaded(bytes)) }
    }

    @Test fun expiredCaIsRejectedAtInjectedTime() {
        val f = ApprovedInterceptionCaTestFixture()
        val ca = f.certificate(after = f.now.minusSeconds(1))
        rejected(f) { f.prepare(ca.encoded) }
    }

    @Test fun futureCaIsRejectedAtInjectedTime() {
        val f = ApprovedInterceptionCaTestFixture()
        val ca = f.certificate(before = f.now.plusSeconds(1))
        rejected(f) { f.prepare(ca.encoded) }
    }

    @Test fun nonemptyCaValidityIncludesBothExactEndpointsAtInjectedTime() {
        val f = ApprovedInterceptionCaTestFixture()
        for (ca in listOf(f.certificate(before = f.now, after = f.now.plusSeconds(60)),
            f.certificate(before = f.now.minusSeconds(60), after = f.now))) {
            assertArrayEquals(ca.encoded, f.prepare(ca.encoded).certificateDer)
        }
    }

    @Test fun emptyAndReversedCaValidityIntervalsAreRejected() {
        val f = ApprovedInterceptionCaTestFixture()
        for (ca in listOf(f.certificate(before = f.now, after = f.now),
            f.certificate(before = f.now.plusSeconds(1), after = f.now.minusSeconds(1)))) {
            rejected(f) { f.prepare(ca.encoded) }
        }
    }

    @Test fun missingOrLeafBasicConstraintsAreRejected() {
        val f = ApprovedInterceptionCaTestFixture()
        for (ca in listOf(f.certificate(ca = null), f.certificate(ca = false))) {
            rejected(f) { f.prepare(ca.encoded) }
        }
    }

    @Test fun externallyIssuedCaIsRejectedDespiteValidIssuerSignature() {
        val f = ApprovedInterceptionCaTestFixture()
        val ca = f.certificate(issuer = f.saved.authority.certificate.subjectX500Principal.name,
            signingKey = f.saved.authority.keys.private)
        ca.verify(f.saved.authority.keys.public)
        assertNotEquals(ca.subjectX500Principal, ca.issuerX500Principal)
        rejected(f) { f.prepare(ca.encoded) }
    }

    @Test fun selfIssuedButNotSelfSignedCaIsRejected() {
        val f = ApprovedInterceptionCaTestFixture()
        val ca = f.certificate(signingKey = TestEnrollmentCertificates.keyPair().private)
        assertEquals(ca.subjectX500Principal, ca.issuerX500Principal)
        rejected(f) { f.prepare(ca.encoded) }
    }

    @Test fun corruptedSelfSignatureIsRejectedWithItsApprovedDigest() {
        val f = ApprovedInterceptionCaTestFixture()
        val bytes = f.ca.encoded.also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        rejected(f) { f.prepare(bytes) }
    }

    @Test fun presentKeyUsageMustPermitCertificateSigning() {
        val f = ApprovedInterceptionCaTestFixture()
        for (usage in listOf(KeyUsage.digitalSignature, KeyUsage.cRLSign)) {
            val ca = f.certificate(usage = usage)
            ca.verify(ca.publicKey)
            rejected(f) { f.prepare(ca.encoded) }
        }
    }

    @Test fun presentExtendedKeyUsageMustBeExactlyServerAuth() {
        val f = ApprovedInterceptionCaTestFixture()
        for (purposes in listOf(listOf(KeyPurposeId.id_kp_clientAuth),
            listOf(KeyPurposeId.anyExtendedKeyUsage),
            listOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth))) {
            val ca = f.certificate(purposes = purposes)
            rejected(f) { f.prepare(ca.encoded) }
        }
    }

    @Test fun p384AndP521CaKeysAreRejectedDespiteValidSelfSignatures() {
        val f = ApprovedInterceptionCaTestFixture()
        for (curve in listOf("secp384r1", "secp521r1")) {
            val ca = f.certificate(keys = TestEnrollmentCertificates.keyPair(curve))
            ca.verify(ca.publicKey)
            rejected(f) { f.prepare(ca.encoded) }
        }
    }

    @Test fun rsaBelow2048AndAbove4096AreRejectedDespiteValidSelfSignatures() {
        val f = ApprovedInterceptionCaTestFixture()
        for (bits in listOf(1024, 4608)) {
            val ca = f.certificate(keys = f.rsa(bits))
            assertEquals(bits, (ca.publicKey as RSAPublicKey).modulus.bitLength())
            ca.verify(ca.publicKey)
            rejected(f) { f.prepare(ca.encoded) }
        }
    }

    @Test fun unsupportedDsaCaKeyIsRejectedDespiteValidSelfSignature() {
        val f = ApprovedInterceptionCaTestFixture()
        val keys = KeyPairGenerator.getInstance("DSA").apply { initialize(2048) }.generateKeyPair()
        val ca = f.certificate(keys = keys)
        ca.verify(ca.publicKey)
        rejected(f) { f.prepare(ca.encoded) }
    }

    @Test fun expiredSavedGatewayIsRecheckedEvenThoughOtherCertificatesRemainCurrent() {
        val f = ApprovedInterceptionCaTestFixture()
        val at = f.saved.gateway.certificate.notAfter.toInstant().plusSeconds(1)
        val authority = TestEnrollmentCertificates.authority(notBefore = f.now.minusSeconds(60), notAfter = at.plusSeconds(100))
        val leaf = TestEnrollmentCertificates.client(f.saved.keys.public, authority,
            notBefore = f.now.minusSeconds(60), notAfter = at.plusSeconds(100))
        val credential = f.saved.credential(clientCertificate = leaf, authorityCertificate = authority.certificate)
        assertCurrent(at, f.ca, authority.certificate, leaf)
        rejected(f) { f.prepare(loaded = f.loaded(credential = credential), clock = fixed(at)) }
    }

    @Test fun expiredSavedAuthorityIsRecheckedEvenThoughLeafRemainsCurrent() {
        val f = ApprovedInterceptionCaTestFixture()
        val authority = TestEnrollmentCertificates.authority(notBefore = f.now.minusSeconds(60), notAfter = f.now.minusSeconds(1))
        val leaf = f.saved.client(issuer = authority)
        val credential = f.saved.credential(clientCertificate = leaf, authorityCertificate = authority.certificate)
        assertCurrent(f.now, f.ca, f.saved.gateway.certificate, leaf)
        rejected(f) { f.prepare(loaded = f.loaded(credential = credential)) }
    }

    @Test fun expiredSavedIssuedLeafIsRechecked() {
        val f = ApprovedInterceptionCaTestFixture()
        val leaf = TestEnrollmentCertificates.client(f.saved.keys.public, f.saved.authority,
            notBefore = f.now.minusSeconds(60), notAfter = f.now.minusSeconds(1))
        assertCurrent(f.now, f.ca, f.saved.gateway.certificate, f.saved.authority.certificate)
        rejected(f) { f.prepare(loaded = f.loaded(credential = f.saved.credential(clientCertificate = leaf))) }
    }

    @Test fun expiredSavedNonLeafIssuedCertificateIsRechecked() {
        val f = ApprovedInterceptionCaTestFixture()
        val intermediate = TestEnrollmentCertificates.authority(issuer = f.saved.authority,
            notBefore = f.now.minusSeconds(60), notAfter = f.now.minusSeconds(1))
        val leaf = f.saved.client(issuer = intermediate)
        val credential = chainCredential(f, listOf(leaf, intermediate.certificate))
        assertCurrent(f.now, f.ca, f.saved.gateway.certificate, f.saved.authority.certificate, leaf)
        rejected(f) { f.prepare(loaded = f.loaded(credential = credential)) }
    }

    @Test fun futureSavedAuthorityAndEveryIssuedCertificateAreRechecked() {
        val f = ApprovedInterceptionCaTestFixture()
        val authority = TestEnrollmentCertificates.authority(notBefore = f.now.plusSeconds(1), notAfter = f.now.plusSeconds(7200))
        val authorityLeaf = f.saved.client(issuer = authority)
        val futureLeaf = TestEnrollmentCertificates.client(f.saved.keys.public, f.saved.authority,
            notBefore = f.now.plusSeconds(1), notAfter = f.now.plusSeconds(1800))
        val intermediate = TestEnrollmentCertificates.authority(issuer = f.saved.authority,
            notBefore = f.now.plusSeconds(1), notAfter = f.now.plusSeconds(7200))
        val intermediateLeaf = f.saved.client(issuer = intermediate)
        for (credential in listOf(
            f.saved.credential(clientCertificate = authorityLeaf, authorityCertificate = authority.certificate),
            f.saved.credential(clientCertificate = futureLeaf),
            chainCredential(f, listOf(intermediateLeaf, intermediate.certificate)),
        )) rejected(f) { f.prepare(loaded = f.loaded(credential = credential)) }
    }

    @Test fun otherwiseValidCaCannotReuseGatewayMathematicalKey() {
        val f = ApprovedInterceptionCaTestFixture()
        rejectReuse(f, f.certificate(keys = f.saved.gateway.keys))
    }

    @Test fun otherwiseValidCaCannotReuseEnrollmentAuthorityMathematicalKey() {
        val f = ApprovedInterceptionCaTestFixture()
        rejectReuse(f, f.certificate(keys = f.saved.authority.keys))
    }

    @Test fun otherwiseValidCaCannotReuseOriginalDeviceMathematicalKey() {
        val f = ApprovedInterceptionCaTestFixture()
        assertArrayEquals(f.saved.keys.public.encoded, f.saved.approval().originalDeviceSpki)
        rejectReuse(f, f.certificate(keys = f.saved.keys))
    }

    @Test fun otherwiseValidCaCannotReuseIssuedLeafMathematicalKey() {
        val f = ApprovedInterceptionCaTestFixture()
        // B7 binds the issued leaf and original-device SPKI to the same key; both roles matter.
        assertArrayEquals(f.saved.keys.public.encoded, f.saved.leaf.publicKey.encoded)
        rejectReuse(f, f.certificate(keys = f.saved.keys))
    }

    @Test fun otherwiseValidCaCannotReuseNonLeafIssuedChainMathematicalKey() {
        val f = ApprovedInterceptionCaTestFixture()
        val intermediate = TestEnrollmentCertificates.authority(issuer = f.saved.authority,
            notBefore = f.now.minusSeconds(60), notAfter = f.now.plusSeconds(7200))
        val leaf = f.saved.client(issuer = intermediate)
        val credential = chainCredential(f, listOf(leaf, intermediate.certificate))
        rejectReuse(f, f.certificate(keys = intermediate.keys), credential)
    }

    @Test fun equivalentRsaParameterEncodingCannotEvadeAuthorityKeySeparation() {
        val f = ApprovedInterceptionCaTestFixture()
        val keys = f.rsa(2048)
        val authority = f.certificate(keys = keys, purposes = null, subject = "CN=RSA saved authority")
        val leaf = f.certificate(keys = f.saved.keys, ca = false, usage = KeyUsage.digitalSignature,
            purposes = listOf(KeyPurposeId.id_kp_clientAuth), issuer = authority.subjectX500Principal.name,
            signingKey = keys.private)
        val originalSpki = SubjectPublicKeyInfo.getInstance(keys.public.encoded)
        val withoutNull = SubjectPublicKeyInfo(AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            originalSpki.parsePublicKey())
        assertFalse(originalSpki.encoded.contentEquals(withoutNull.encoded))
        val ca = f.certificate(keys = keys, spki = withoutNull)
        val expectedKey = authority.publicKey as RSAPublicKey
        val actualKey = ca.publicKey as RSAPublicKey
        assertEquals(expectedKey.modulus, actualKey.modulus)
        assertEquals(expectedKey.publicExponent, actualKey.publicExponent)
        val credential = f.saved.credential(clientCertificate = leaf, authorityCertificate = authority)
        rejectReuse(f, ca, credential)
    }

    @Test fun inputArraysReturnedArraysCertificatesAndDatesAreDefensiveSnapshots() {
        val f = ApprovedInterceptionCaTestFixture()
        val input = f.ca.encoded
        val expected = input.copyOf()
        val expectedSignature = f.ca.signature.copyOf()
        val expectedSpki = f.ca.publicKey.encoded.copyOf()
        val expectedNotBeforeMillis = f.ca.notBefore.time
        val expectedNotAfterMillis = f.ca.notAfter.time
        val actual = f.prepare(input)
        input.fill(0)
        actual.certificateDer.fill(0)
        actual.certificateSha256.fill(0)
        val first = actual.certificate
        val second = actual.certificate
        // Providers may intern immutable certificates; isolation is about public material, not identity.
        first.encoded.fill(0)
        first.signature.fill(0)
        first.publicKey.encoded.fill(0)
        first.notBefore.time = 0
        first.notAfter.time = 0
        assertArrayEquals(expected, actual.certificateDer)
        assertArrayEquals(approvedHash(expected), actual.certificateSha256)
        assertArrayEquals(expected, second.encoded)
        assertArrayEquals(expected, actual.certificate.encoded)
        assertEquals(f.ca.notBefore, actual.certificate.notBefore)
        assertEquals(f.ca.notAfter, actual.certificate.notAfter)
        for (certificate in listOf(first, second, actual.certificate)) {
            assertArrayEquals(expectedSignature, certificate.signature)
            assertArrayEquals(expectedSpki, certificate.publicKey.encoded)
            assertEquals(expectedNotBeforeMillis, certificate.notBefore.time)
            assertEquals(expectedNotAfterMillis, certificate.notAfter.time)
        }
    }

    @Test fun successfulAndStalePreparationsObserveInjectedClockExactlyOnceWithoutManagerCalls() {
        val f = ApprovedInterceptionCaTestFixture()
        val current = SingleObservationCaClock(f.now)
        f.prepare(clock = current)
        assertEquals(1, current.observations)
        val stale = SingleObservationCaClock(f.now.plusSeconds(1801))
        rejected(f) { f.prepare(clock = stale) }
        assertEquals(1, stale.observations)
        assertEquals(0, f.manager.calls)
    }

    @Test fun snapshotRenderingIsFixedRedactedAndIndependentOfPublicMaterial() {
        val f = ApprovedInterceptionCaTestFixture()
        val first = f.prepare()
        val second = f.prepare(f.certificate(subject = "CN=OTHER_CA_CANARY").encoded)
        assertEquals(first.toString(), second.toString())
        assertTrue(first.toString().contains("REDACTED"))
        assertFalse(first.toString().contains("PRIVATE_INTERCEPTION_CA_CANARY"))
        approvedRedacted(first.toString(), f.saved)
    }

    @Test fun failuresAreFreshFixedCauseFreeAndRedactedWithoutManagerCalls() {
        val f = ApprovedInterceptionCaTestFixture()
        val loaded = f.loaded()
        val first = rejected(f) { f.prepare(byteArrayOf(1), loaded) }
        val second = rejected(f) { f.prepare(byteArrayOf(1), loaded) }
        assertNotSame(first, second)
        approvedRedacted(first.toString(), f.saved)
        assertFalse(first.toString().contains("PRIVATE_INTERCEPTION_CA_CANARY"))
        assertEquals(0, f.manager.calls)
    }

    private fun rejectReuse(
        f: ApprovedInterceptionCaTestFixture,
        ca: X509Certificate,
        credential: EnrolledCredentialRecord = f.saved.credential(),
    ) {
        // These certificates pass the complete positive profile before testing owner separation.
        assertCurrent(f.now, ca)
        assertTrue(ca.notBefore.before(ca.notAfter))
        assertTrue(ca.basicConstraints >= 0)
        assertEquals(ca.subjectX500Principal, ca.issuerX500Principal)
        ca.verify(ca.publicKey)
        assertTrue(ca.keyUsage[5])
        assertEquals(listOf("1.3.6.1.5.5.7.3.1"), ca.extendedKeyUsage)
        val der = ca.encoded
        val loaded = f.loaded(der, credential)
        assertArrayEquals(approvedHash(der), loaded.record.approval.interceptionCaCertificateSha256)
        rejected(f) { f.prepare(der, loaded) }
    }

    private fun chainCredential(f: ApprovedInterceptionCaTestFixture, chain: List<X509Certificate>) =
        EnrolledCredentialRecord(f.saved.id, f.saved.gateway.certificate, approvedPin(f.saved.gateway.certificate),
            "gateway-fixture.invalid", chain, f.saved.authority.certificate)

    private fun fixed(at: Instant): Clock = Clock.fixed(at, ZoneOffset.UTC)

    private fun assertCurrent(at: Instant, vararg certificates: X509Certificate) {
        certificates.forEach { it.checkValidity(Date.from(at)) }
    }

    private fun rejected(f: ApprovedInterceptionCaTestFixture, action: () -> Unit): IllegalArgumentException {
        val failure = assertThrows(IllegalArgumentException::class.java) { action() }
        assertEquals(IllegalArgumentException::class.java, failure.javaClass)
        assertEquals("Invalid approved interception CA", failure.message)
        assertNull(failure.cause)
        assertEquals(0, failure.suppressed.size)
        assertEquals(0, f.manager.calls)
        return failure
    }
}
