package com.httpfreekit.security

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthenticatedEnrollmentApprovalTest {
    @Test fun snapshotsEveryBinaryInputAndBothCollectionLayers() {
        val f = ApprovedCredentialTestFixture()
        val spki = f.keys.public.encoded.copyOf()
        val original = approvedHash(f.original.encoded)
        val hashes = mutableListOf(original)
        val client = approvedHash(f.leaf.encoded)
        val authority = approvedHash(f.authority.certificate.encoded)
        val ca = ByteArray(32) { (it + 1).toByte() }
        val capabilities = mutableListOf("stream", "capture")
        val a = f.approval(spki = spki, originalHashes = hashes, clientHash = client,
            authorityHash = authority, caHash = ca, capabilities = capabilities)
        listOf(spki, original, client, authority, ca).forEach { it.fill(0) }
        hashes.clear()
        capabilities.clear()
        assertArrayEquals(f.keys.public.encoded, a.originalDeviceSpki)
        assertArrayEquals(approvedHash(f.original.encoded), a.originalKeystoreCertificateHashes.single())
        assertArrayEquals(approvedHash(f.leaf.encoded), a.clientCertificateSha256)
        assertArrayEquals(approvedHash(f.authority.certificate.encoded), a.authorityCertificateSha256)
        assertArrayEquals(ByteArray(32) { (it + 1).toByte() }, a.interceptionCaCertificateSha256)
        assertEquals(listOf("capture", "stream"), a.capabilities)
        val binaryGetters = listOf<() -> ByteArray>(
            { a.originalDeviceSpki }, { a.originalKeystoreCertificateHashes.single() },
            { a.clientCertificateSha256 }, { a.authorityCertificateSha256 }, { a.interceptionCaCertificateSha256 },
        )
        binaryGetters.forEach { getter ->
            val expected = getter()
            val returned = getter()
            assertNotSame(expected, returned)
            returned.fill(0)
            assertArrayEquals(expected, getter())
        }
        // Immutable or fresh mutable returned lists are both valid; retained state must not change.
        try { (a.capabilities as MutableList<String>).clear() } catch (_: UnsupportedOperationException) { }
        try { (a.originalKeystoreCertificateHashes as MutableList<ByteArray>).clear() } catch (_: UnsupportedOperationException) { }
        assertEquals(listOf("capture", "stream"), a.capabilities)
        assertEquals(1, a.originalKeystoreCertificateHashes.size)
    }

    @Test fun identifierBoundsApplySeparatelyToDesktopEnrollmentAndDevice() {
        val f = ApprovedCredentialTestFixture()
        for (id in listOf("", "x".repeat(129), "with space", "a/b", "a.b", "\n", "é")) {
            approvedRejected { f.approval(desktop = id) }
            approvedRejected { f.approval(enrollment = id) }
            approvedRejected { f.approval(device = id) }
        }
        for (id in listOf("a", "A_-09", "x".repeat(128))) {
            assertEquals(id, f.approval(desktop = id).desktopId)
            assertEquals(id, f.approval(enrollment = id).enrollmentId)
            assertEquals(id, f.approval(device = id).deviceId)
        }
    }

    @Test fun logicalNameUsesAsciiSniRulesAndLengthBound() {
        val f = ApprovedCredentialTestFixture()
        val longest = List(3) { "a".repeat(63) }.plus("b".repeat(61)).joinToString(".")
        assertEquals(253, longest.length)
        assertEquals(longest, f.approval(name = longest).logicalServerName)
        assertEquals("a", f.approval(name = "a").logicalServerName)
        for (name in listOf("", longest + "x", "a".repeat(64), "a..b", "-host.invalid", "host_.invalid", "*.invalid", "a b", "a\u0000b", "é.invalid")) {
            approvedRejected { f.approval(name = name) }
        }
    }

    @Test fun gatewayPinIsExactlyCanonicalUnpaddedBase64urlOf32Bytes() {
        val f = ApprovedCredentialTestFixture()
        val pin = approvedPin(f.gateway.certificate)
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val alternate = pin.dropLast(1) + alphabet[alphabet.indexOf(pin.last()) xor 1]
        assertArrayEquals(Base64.getUrlDecoder().decode(pin), Base64.getUrlDecoder().decode(alternate))
        for (invalid in listOf(pin + "=", alternate, "A".repeat(42), "A".repeat(44), "+" + pin.drop(1), "/" + pin.drop(1), " " + pin.drop(1))) {
            approvedRejected { f.approval(pin = invalid) }
        }
        assertEquals(pin, f.approval().gatewaySpkiSha256)
    }

    @Test fun originalSpkiRequiresCanonical91ByteP256DerNotJustAnEcLabel() {
        val f = ApprovedCredentialTestFixture()
        val spki = f.keys.public.encoded
        assertEquals(91, spki.size)
        for (invalid in listOf(
            spki.copyOf(90), spki + byteArrayOf(0), ByteArray(91),
            spki.copyOf().apply { this[0] = 0 },
            spki.copyOf().apply { fill(0, size - 64, size) }, // (0, 0) is not on P-256.
            TestEnrollmentCertificates.keyPair("secp384r1").public.encoded,
        )) approvedRejected { f.approval(spki = invalid) }
    }

    @Test fun everyHashAndExpiryAndChainCountHasExactBounds() {
        val f = ApprovedCredentialTestFixture()
        for (length in listOf(0, 31, 33, 4096)) {
            val hash = ByteArray(length)
            approvedRejected { f.approval(originalHashes = listOf(hash)) }
            approvedRejected { f.approval(clientHash = hash) }
            approvedRejected { f.approval(authorityHash = hash) }
            approvedRejected { f.approval(caHash = hash) }
        }
        approvedRejected { f.approval(originalHashes = emptyList()) }
        approvedRejected { f.approval(originalHashes = List(5) { ByteArray(32) }) }
        assertEquals(4, f.approval(originalHashes = List(4) { ByteArray(32) { it.toByte() } }).originalKeystoreCertificateHashes.size)
        for (expiry in listOf(0L, -1L, Long.MIN_VALUE)) approvedRejected { f.approval(expires = expiry) }
        assertEquals(1L, f.approval(expires = 1).credentialExpiresAtMillis)
        assertEquals(Long.MAX_VALUE, f.approval(expires = Long.MAX_VALUE).credentialExpiresAtMillis)
    }

    @Test fun capabilitiesAreUniqueBoundedGrammarCheckedAndDeterministicallySorted() {
        val f = ApprovedCredentialTestFixture()
        for (values in listOf(emptyList(), listOf("same", "same"), List(17) { "cap-$it" },
            listOf(""), listOf("A"), listOf("1cap"), listOf("a_b"), listOf("with space"), listOf("é"), listOf("a".repeat(33)))) {
            approvedRejected { f.approval(capabilities = values) }
        }
        val full = (0..15).map { "cap-$it" }.reversed()
        assertEquals(full.sorted(), f.approval(capabilities = full).capabilities)
        assertEquals(listOf("a".repeat(32)), f.approval(capabilities = listOf("a".repeat(32))).capabilities)
    }

    @Test fun dishonestCollectionIterationIsBoundedWithoutTrustingReportedSize() {
        val f = ApprovedCredentialTestFixture()
        fun <T> endless(value: (Int) -> T, limit: Int): List<T> = object : AbstractList<T>() {
            override val size: Int get() = 1
            override fun get(index: Int): T = value(index)
            override fun iterator(): Iterator<T> = object : Iterator<T> {
                private var reads = 0
                override fun hasNext() = true
                override fun next(): T {
                    if (++reads > limit + 1) throw AssertionError("Unbounded snapshot iteration")
                    return value(reads)
                }
            }
        }
        approvedRejected { f.approval(originalHashes = endless({ ByteArray(32) }, 4)) }
        approvedRejected { f.approval(capabilities = endless({ "cap-$it" }, 16)) }
        val lyingEmpty = object : AbstractList<String>() {
            override val size = 1
            override fun get(index: Int): String = throw IndexOutOfBoundsException()
            override fun iterator(): Iterator<String> = emptyList<String>().iterator()
        }
        approvedRejected { f.approval(capabilities = lyingEmpty) }
    }

    @Test fun callerCollectionExceptionsAreRedactedButFatalErrorsEscape() {
        val f = ApprovedCredentialTestFixture()
        val detail = "private-provider ${f.id}"
        fun failing(failure: Throwable) = object : AbstractList<String>() {
            override val size = 1
            override fun get(index: Int): String = throw failure
            override fun iterator(): Iterator<String> = throw failure
        }
        val failure = approvedRejected { f.approval(capabilities = failing(IllegalStateException(detail))) }
        assertNull(failure.cause)
        assertTrue(!failure.toString().contains(detail))
        val fatal = AssertionError("synthetic fatal")
        try {
            f.approval(capabilities = failing(fatal))
            throw AssertionError("Fatal error was swallowed")
        } catch (caught: AssertionError) { assertSame(fatal, caught) }
    }

    @Test fun combinedRecordRejectsEveryLocallyCheckableApprovalSubstitution() {
        val f = ApprovedCredentialTestFixture()
        val substitutions = listOf(
            f.approval(desktop = "other-owner"), f.approval(name = "other.invalid"),
            f.approval(pin = approvedPin(TestEnrollmentCertificates.server().certificate)),
            f.approval(spki = TestEnrollmentCertificates.keyPair().public.encoded),
            f.approval(clientHash = ByteArray(32)), f.approval(authorityHash = ByteArray(32)),
            f.approval(expires = f.leaf.notAfter.time + 1),
        )
        substitutions.forEach { approval ->
            val failure = approvedRejected { f.combined(approval = approval) }
            assertNull(failure.cause)
            approvedRedacted(failure.toString(), f)
        }
        val otherLeaf = f.client()
        approvedRejected { f.combined(credential = f.credential(clientCertificate = otherLeaf)) }
        val otherAuthority = TestEnrollmentCertificates.authority()
        approvedRejected { f.combined(credential = f.credential(authorityCertificate = otherAuthority.certificate)) }
        // Matching textual pin in both objects still cannot mask a different gateway's actual SPKI.
        val wrongPin = approvedPin(otherAuthority.certificate)
        approvedRejected { f.combined(f.credential(pin = wrongPin), f.approval(pin = wrongPin)) }
    }

    @Test fun combinedRecordRejectsAllThreePublicKeyReusePairs() {
        val f = ApprovedCredentialTestFixture()
        val sameGatewayAuthority = f.credential(gatewayCertificate = f.authority.certificate, pin = approvedPin(f.authority.certificate))
        approvedRejected { f.combined(sameGatewayAuthority, f.approval(pin = approvedPin(f.authority.certificate))) }
        for (pair in listOf(f.gateway.keys, f.authority.keys)) {
            val leaf = f.client(pair)
            approvedRejected {
                f.combined(f.credential(clientCertificate = leaf), f.approval(spki = pair.public.encoded,
                    clientHash = approvedHash(leaf.encoded), expires = leaf.notAfter.time))
            }
        }
    }

    @Test fun localSnapshotDoesNotAuthenticateProvenanceOrInventAnInterceptionCaCheck() {
        val f = ApprovedCredentialTestFixture()
        // This syntactically valid synthetic grant is NOT an authenticated enrollment response.
        // No local constructor can authenticate these otherwise uncheckable fields without context.
        val a = f.approval(enrollment = "synthetic-grant", device = "synthetic-device", caHash = ByteArray(32) { 42 })
        val record = f.combined(approval = a)
        assertEquals("synthetic-grant", record.approval.enrollmentId)
        assertArrayEquals(ByteArray(32) { 42 }, record.approval.interceptionCaCertificateSha256)
        approvedRedacted(a.toString(), f)
        approvedRedacted(record.toString(), f)
        assertTrue(!a.toString().contains("synthetic-grant"))
        assertTrue(!record.toString().contains("synthetic-device"))
    }
}
