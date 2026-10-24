package com.httpfreekit.security

import java.security.KeyPairGenerator
import java.security.Principal
import java.security.PublicKey
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Date
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.SSLContext
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrolledClientKeyManagerTest {
    private val keys = TestEnrollmentCertificates.keyPair()
    private val identity = DeviceIdentity(keys.public, keys.private)
    private val root = TestEnrollmentCertificates.authority()
    private fun leaf(issuer: TestEnrollmentCertificates.Identity = root): X509Certificate =
        TestEnrollmentCertificates.client(keys.public, issuer)
    private fun alias(manager: X509ExtendedKeyManager): String = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))

    @Test fun aValidDirectChainUsesTheOriginalPrivateKeyWithoutAnImportedKeystoreEntry() {
        val leaf = leaf()
        val manager = identity.bindEnrolledClientCertificate(listOf(leaf), root.certificate)
        val alias = alias(manager)
        assertTrue("Original signing handle was replaced", keys.private === manager.getPrivateKey(alias))
        assertArrayEquals(leaf.encoded, manager.getCertificateChain(alias)!!.single().encoded)
    }

    @Test fun anIntermediateChainPreservesOrderAndOmitsAnOptionalRoot() {
        val intermediate = TestEnrollmentCertificates.authority("CN=Intermediate", root, pathLength = 0)
        val leaf = leaf(intermediate)
        val manager = identity.bindEnrolledClientCertificate(listOf(leaf, intermediate.certificate, root.certificate), root.certificate)
        val chain = manager.getCertificateChain(alias(manager))!!
        assertEquals(2, chain.size)
        assertArrayEquals(leaf.encoded, chain[0].encoded)
        assertArrayEquals(intermediate.certificate.encoded, chain[1].encoded)
        assertEquals(alias(manager), manager.chooseClientAlias(arrayOf("EC"), arrayOf(root.certificate.subjectX500Principal), null))
        assertEquals(alias(manager), manager.chooseEngineClientAlias(arrayOf("EC"), arrayOf(intermediate.certificate.subjectX500Principal), null))
    }

    @Test fun onlyClientEcAliasesWithMatchingCanonicalIssuersAreSelected() {
        val manager = identity.bindEnrolledClientCertificate(listOf(leaf()), root.certificate)
        val alias = alias(manager)
        assertEquals(alias, manager.chooseClientAlias(arrayOf("RSA", "EC"), emptyArray(), null))
        assertEquals(alias, manager.chooseEngineClientAlias(arrayOf("EC"), null, null))
        assertEquals(alias, manager.getClientAliases("EC", arrayOf(root.certificate.subjectX500Principal))!!.single())
        assertEquals(alias, manager.chooseClientAlias(arrayOf("EC"), arrayOf(Principal { root.certificate.subjectX500Principal.name }), null))
        assertNull(manager.getClientAliases("RSA", null))
        assertNull(manager.chooseClientAlias(arrayOf("RSA"), null, null))
        assertNull(manager.chooseEngineClientAlias(emptyArray(), null, null))
        assertNull(manager.chooseClientAlias(null, null, null))
        assertNull(manager.getClientAliases("EC", arrayOf(X500Principal("CN=Other authority"))))
        assertNull(manager.chooseClientAlias(arrayOf("EC"), arrayOf(Principal { "not a distinguished name" }), null))
        assertNull(manager.getServerAliases("EC", null))
        assertNull(manager.chooseServerAlias("EC", null, null))
        assertNull(manager.chooseEngineServerAlias("EC", null, null))
        assertNull(manager.getPrivateKey("unknown"))
        assertNull(manager.getCertificateChain(null))
    }

    @Test fun wrongLeafKeyAndMismatchedSigningHandleCannotBind() {
        val other = TestEnrollmentCertificates.keyPair()
        rejected { identity.bindEnrolledClientCertificate(listOf(TestEnrollmentCertificates.client(other.public, root)), root.certificate) }
        val mismatched = DeviceIdentity(keys.public, other.private)
        rejected { mismatched.bindEnrolledClientCertificate(listOf(leaf()), root.certificate) }
    }

    @Test fun theIdentityMustHaveFullP256Parameters() {
        val p384 = TestEnrollmentCertificates.keyPair("secp384r1")
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        listOf(p384, rsa).forEach { pair ->
            rejected { DeviceIdentity(pair.public, pair.private).bindEnrolledClientCertificate(
                listOf(TestEnrollmentCertificates.client(pair.public, root)), root.certificate,
            ) }
        }
    }

    @Test fun wrongIssuerSignatureOrderDuplicateAndExtraCertificatesAreRejected() {
        val other = TestEnrollmentCertificates.authority("CN=Other authority")
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf(other)), root.certificate) }
        rejected { identity.bindEnrolledClientCertificate(listOf(TestEnrollmentCertificates.client(keys.public, root, signingKey = other.keys.private)), root.certificate) }
        val intermediate = TestEnrollmentCertificates.authority("CN=Intermediate", root, pathLength = 0)
        val leaf = leaf(intermediate)
        rejected { identity.bindEnrolledClientCertificate(listOf(intermediate.certificate, leaf), root.certificate) }
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf, leaf), root.certificate) }
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf, other.certificate), root.certificate) }
    }

    @Test fun clientLeafRolePurposeAndSigningUsageAreRequired() {
        val invalid = listOf(
            TestEnrollmentCertificates.client(keys.public, root, ca = true),
            TestEnrollmentCertificates.client(keys.public, root, purposes = null),
            TestEnrollmentCertificates.client(keys.public, root, purposes = listOf(KeyPurposeId.id_kp_serverAuth)),
            TestEnrollmentCertificates.client(keys.public, root, purposes = listOf(KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth)),
            TestEnrollmentCertificates.client(keys.public, root, usage = null),
            TestEnrollmentCertificates.client(keys.public, root, usage = KeyUsage.keyEncipherment),
            TestEnrollmentCertificates.client(keys.public, root, usage = KeyUsage.digitalSignature or KeyUsage.keyCertSign),
        )
        invalid.forEach { certificate -> rejected { identity.bindEnrolledClientCertificate(listOf(certificate), root.certificate) } }
    }

    @Test fun authoritiesNeedCaSigningUsageAndSupportedAnchorConstraints() {
        val invalidRoots = listOf(
            TestEnrollmentCertificates.authority(ca = false),
            TestEnrollmentCertificates.authority(usage = null),
            TestEnrollmentCertificates.authority(usage = KeyUsage.digitalSignature),
            TestEnrollmentCertificates.authority(unknownCritical = true),
            TestEnrollmentCertificates.authority(nameConstraints = true),
        )
        invalidRoots.forEach { authority -> rejected { identity.bindEnrolledClientCertificate(listOf(leaf(authority)), authority.certificate) } }
        val nonCa = TestEnrollmentCertificates.authority("CN=Not a CA", root, ca = false)
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf(nonCa), nonCa.certificate), root.certificate) }
        val noCertSign = TestEnrollmentCertificates.authority("CN=No cert sign", root, usage = KeyUsage.digitalSignature)
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf(noCertSign), noCertSign.certificate), root.certificate) }
    }

    @Test fun rootAndIntermediatePathLimitsAndUnknownCriticalExtensionsAreEnforced() {
        val directOnly = TestEnrollmentCertificates.authority(pathLength = 0)
        val intermediate = TestEnrollmentCertificates.authority("CN=Intermediate", directOnly, pathLength = 0)
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf(intermediate), intermediate.certificate), directOnly.certificate) }
        val outer = TestEnrollmentCertificates.authority("CN=Outer", root, pathLength = 0)
        val inner = TestEnrollmentCertificates.authority("CN=Inner", outer, pathLength = 0)
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf(inner), inner.certificate, outer.certificate), root.certificate) }
        val critical = TestEnrollmentCertificates.authority("CN=Critical", root, unknownCritical = true)
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf(critical), critical.certificate), root.certificate) }
        rejected { identity.bindEnrolledClientCertificate(listOf(TestEnrollmentCertificates.client(keys.public, root, unknownCritical = true)), root.certificate) }
    }

    @Test fun everyCertificateIncludingTheAnchorMustBeCurrentlyValid() {
        val now = Instant.now()
        val expiredRoot = TestEnrollmentCertificates.authority(notBefore = now.minusSeconds(120), notAfter = now.minusSeconds(60))
        val futureRoot = TestEnrollmentCertificates.authority(notBefore = now.plusSeconds(60), notAfter = now.plusSeconds(120))
        listOf(expiredRoot, futureRoot).forEach { authority -> rejected { identity.bindEnrolledClientCertificate(listOf(leaf(authority)), authority.certificate) } }
        val expiredIntermediate = TestEnrollmentCertificates.authority("CN=Expired", root, notBefore = now.minusSeconds(120), notAfter = now.minusSeconds(60))
        rejected { identity.bindEnrolledClientCertificate(listOf(leaf(expiredIntermediate), expiredIntermediate.certificate), root.certificate) }
        listOf(
            TestEnrollmentCertificates.client(keys.public, root, notBefore = now.minusSeconds(120), notAfter = now.minusSeconds(60)),
            TestEnrollmentCertificates.client(keys.public, root, notBefore = now.plusSeconds(60), notAfter = now.plusSeconds(120)),
        ).forEach { leaf -> rejected { identity.bindEnrolledClientCertificate(listOf(leaf), root.certificate) } }
    }

    @Test fun clockExpiryAfterBindingDeniesSocketEngineAliasesAndBothGetters() {
        val leaf = leaf()
        val clock = MutableClock(Instant.now())
        val manager = identity.bindEnrolledClientCertificate(listOf(leaf), root.certificate, clock)
        val alias = alias(manager)
        clock.set(leaf.notAfter.toInstant().plusMillis(1))
        assertUnavailable(manager, alias)
        val shortRoot = TestEnrollmentCertificates.authority(notAfter = Instant.now().plusSeconds(60))
        val shortClock = MutableClock(Instant.now())
        val manager2 = identity.bindEnrolledClientCertificate(listOf(leaf(shortRoot)), shortRoot.certificate, shortClock)
        val alias2 = alias(manager2)
        shortClock.set(shortRoot.certificate.notAfter.toInstant().plusMillis(1))
        assertUnavailable(manager2, alias2)
    }

    @Test fun missingOrFailedLivenessDeniesSelectionWithoutCreatingAKey() {
        val present = AtomicBoolean(true)
        val lookups = AtomicInteger()
        val liveIdentity = DeviceIdentity(keys.public, keys.private) { lookups.incrementAndGet(); present.get() }
        val manager = liveIdentity.bindEnrolledClientCertificate(listOf(leaf()), root.certificate)
        val alias = alias(manager)
        val beforeUnknown = lookups.get()
        assertNull(manager.getPrivateKey("unknown"))
        assertEquals(beforeUnknown, lookups.get())
        present.set(false)
        assertUnavailable(manager, alias)
        rejected { liveIdentity.enrollmentRequest() }
        rejected { liveIdentity.bindEnrolledClientCertificate(listOf(leaf()), root.certificate) }
        val failedLookup = AtomicBoolean(false)
        val unstableIdentity = DeviceIdentity(keys.public, keys.private) { if (failedLookup.get()) error("Synthetic store failure") else true }
        val unstable = unstableIdentity.bindEnrolledClientCertificate(listOf(leaf()), root.certificate)
        val unstableAlias = alias(unstable)
        failedLookup.set(true)
        assertUnavailable(unstable, unstableAlias)
    }

    @Test fun inputAndReturnedCollectionsAreDefensiveAndEncodedInputsAreSnapshotted() {
        val leaf = leaf()
        val encoded = leaf.encoded
        val input = mutableListOf<X509Certificate>(EncodingCertificate(leaf, encoded))
        val manager = identity.bindEnrolledClientCertificate(input, root.certificate)
        val alias = alias(manager)
        input.clear()
        encoded.fill(0)
        val first = manager.getCertificateChain(alias)!!
        assertArrayEquals(leaf.encoded, first.single().encoded)
        first[0] = root.certificate
        val second = manager.getCertificateChain(alias)!!
        assertNotSame(first, second)
        assertArrayEquals(leaf.encoded, second.single().encoded)
        val aliases = manager.getClientAliases("EC", null)!!
        aliases[0] = "changed"
        assertEquals(alias, alias(manager))
    }

    @Test fun chainCertificateAndAggregateBoundsRejectMalformedMaterial() {
        val leaf = leaf()
        rejected { identity.bindEnrolledClientCertificate(emptyList(), root.certificate) }
        rejected { identity.bindEnrolledClientCertificate(List(5) { leaf }, root.certificate) }
        rejected { identity.bindEnrolledClientCertificate(listOf(EncodingCertificate(leaf, ByteArray(4097))), root.certificate) }
        rejected { identity.bindEnrolledClientCertificate(listOf(EncodingCertificate(leaf, leaf.encoded + byteArrayOf(0))), root.certificate) }
        rejected { identity.bindEnrolledClientCertificate(listOf(EncodingCertificate(leaf, leaf.encoded + root.certificate.encoded)), root.certificate) }
        val paddedRoot = TestEnrollmentCertificates.authority(pathLength = 3, paddingBytes = 3200)
        val outer = TestEnrollmentCertificates.authority("CN=Outer", paddedRoot, pathLength = 2, paddingBytes = 3200)
        val middle = TestEnrollmentCertificates.authority("CN=Middle", outer, pathLength = 1, paddingBytes = 3200)
        val inner = TestEnrollmentCertificates.authority("CN=Inner", middle, pathLength = 0, paddingBytes = 3200)
        val paddedLeaf = TestEnrollmentCertificates.client(keys.public, inner, paddingBytes = 3200)
        rejected { identity.bindEnrolledClientCertificate(listOf(paddedLeaf, inner.certificate, middle.certificate, outer.certificate), paddedRoot.certificate) }
    }

    @Test fun bindingDoesNotChangeGlobalProvidersOrTlsDefaults() {
        val providers = Security.getProviders().map { it.name }
        val context = SSLContext.getDefault()
        identity.bindEnrolledClientCertificate(listOf(leaf()), root.certificate)
        assertEquals(providers, Security.getProviders().map { it.name })
        assertSame(context, SSLContext.getDefault())
    }

    @Test fun snapshotIterationIsBoundedEvenIfACollectionMisreportsItsSize() {
        val leaf = leaf()
        val reads = AtomicInteger()
        val inconsistent = object : AbstractList<X509Certificate>() {
            override val size: Int get() = 1
            override fun get(index: Int): X509Certificate = leaf
            override fun iterator(): Iterator<X509Certificate> = object : Iterator<X509Certificate> {
                override fun hasNext(): Boolean = true
                override fun next(): X509Certificate {
                    if (reads.incrementAndGet() > 5) throw AssertionError("Certificate snapshot was not bounded")
                    return leaf
                }
            }
        }
        rejected { identity.bindEnrolledClientCertificate(inconsistent, root.certificate) }
        assertEquals(4, reads.get())
    }

    private fun assertUnavailable(manager: X509ExtendedKeyManager, alias: String) {
        assertNull(manager.getClientAliases("EC", null))
        assertNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        assertNull(manager.chooseEngineClientAlias(arrayOf("EC"), null, null))
        assertNull(manager.getPrivateKey(alias))
        assertNull(manager.getCertificateChain(alias))
    }

    private fun rejected(block: () -> Unit) {
        try { block() } catch (_: Exception) { return }
        throw AssertionError("Expected credential rejection")
    }

    private class MutableClock(initial: Instant) : Clock() {
        private val current = AtomicReference(initial)
        fun set(instant: Instant) { current.set(instant) }
        override fun instant(): Instant = current.get()
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
    }

    private class EncodingCertificate(private val source: X509Certificate, private val bytes: ByteArray) : X509Certificate() {
        override fun getEncoded(): ByteArray = bytes
        override fun checkValidity() = source.checkValidity()
        override fun checkValidity(date: Date) = source.checkValidity(date)
        override fun getVersion() = source.version
        override fun getSerialNumber() = source.serialNumber
        @Deprecated("Required legacy X509Certificate override") override fun getIssuerDN(): Principal = source.issuerX500Principal
        @Deprecated("Required legacy X509Certificate override") override fun getSubjectDN(): Principal = source.subjectX500Principal
        override fun getNotBefore() = source.notBefore
        override fun getNotAfter() = source.notAfter
        override fun getTBSCertificate() = source.tbsCertificate
        override fun getSignature() = source.signature
        override fun getSigAlgName() = source.sigAlgName
        override fun getSigAlgOID() = source.sigAlgOID
        override fun getSigAlgParams(): ByteArray? = source.sigAlgParams
        override fun getIssuerUniqueID(): BooleanArray? = source.issuerUniqueID
        override fun getSubjectUniqueID(): BooleanArray? = source.subjectUniqueID
        override fun getKeyUsage(): BooleanArray? = source.keyUsage
        override fun getBasicConstraints() = source.basicConstraints
        override fun verify(key: PublicKey) = source.verify(key)
        override fun verify(key: PublicKey, provider: String) = source.verify(key, provider)
        override fun getPublicKey(): PublicKey = source.publicKey
        override fun hasUnsupportedCriticalExtension() = source.hasUnsupportedCriticalExtension()
        override fun getCriticalExtensionOIDs(): Set<String>? = source.criticalExtensionOIDs
        override fun getNonCriticalExtensionOIDs(): Set<String>? = source.nonCriticalExtensionOIDs
        override fun getExtensionValue(oid: String): ByteArray? = source.getExtensionValue(oid)
        override fun toString(): String = "Synthetic DER wrapper"
    }
}
