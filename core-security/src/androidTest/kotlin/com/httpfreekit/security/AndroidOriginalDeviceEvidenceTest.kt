package com.httpfreekit.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.Signature
import java.security.cert.X509Certificate
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real owned-alias evidence only, not approved-store lifecycle or approval provenance. */
@RunWith(AndroidJUnit4::class)
class AndroidOriginalDeviceEvidenceTest {
    @Test fun originalPublicEvidenceSurvivesReopenAndCopiesCannotMutateIt() {
        val desktopId = "original-evidence-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            assertNull(store.load(desktopId))
            val identity = store.create(desktopId)
            val original = checkNotNull(store.originalCertificateChain(desktopId))
            assertTrue(original.size in 1..4)
            val expected = original.map { it.encoded.copyOf() }
            assertTrue(expected.all { it.size in 1..4096 })
            assertTrue(expected.sumOf { it.size } <= 16384)
            val expectedSpki = identity.publicKey.encoded.copyOf()
            assertArrayEquals(expectedSpki, original.first().publicKey.encoded)

            val reopenedStore = AndroidDeviceIdentityStore()
            val reopened = checkNotNull(reopenedStore.load(desktopId))
            val evidence = checkNotNull(reopenedStore.originalCertificateChain(desktopId))
            assertChainEquals(expected, evidence)
            assertArrayEquals(expectedSpki, reopened.publicKey.encoded)
            assertArrayEquals(expectedSpki, evidence.first().publicKey.encoded)
            assertNotSame(original, evidence)
            original.zip(evidence).forEach { (before, after) -> assertNotSame(before, after) }
            val challenge = ByteArray(32) { (it + 1).toByte() }
            assertTrue(verifies(evidence.first(), challenge, reopened.signChallenge(challenge)))

            // Mutate only caller-visible public copies, never any Keystore entry.
            original.forEach { certificate ->
                certificate.encoded.fill(0)
                certificate.publicKey.encoded.fill(0)
            }
            try {
                (original as MutableList<X509Certificate>).clear()
            } catch (_: UnsupportedOperationException) {
                // An unmodifiable returned list also protects retained state.
            }
            assertChainEquals(expected, evidence)
            assertChainEquals(expected, checkNotNull(store.originalCertificateChain(desktopId)))
            val after = checkNotNull(AndroidDeviceIdentityStore().originalCertificateChain(desktopId))
            assertChainEquals(expected, after)
            assertArrayEquals(expectedSpki, after.first().publicKey.encoded)
            val current = checkNotNull(AndroidDeviceIdentityStore().load(desktopId))
            assertArrayEquals(expectedSpki, current.publicKey.encoded)
            assertTrue(verifies(after.first(), challenge, current.signChallenge(challenge)))
        } finally { deleteOwnedKeys(store, desktopId) }
    }

    @Test fun absentAndDeletedIdentityEvidenceNeverCreatesOrReplacesAKey() {
        val desktopId = "absent-evidence-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            listOf(store, AndroidDeviceIdentityStore()).forEach { reader ->
                assertNull(reader.load(desktopId))
                assertNull(reader.originalCertificateChain(desktopId))
                assertNull(reader.originalCertificateChain(desktopId))
                assertNull(reader.load(desktopId))
            }
            val identity = store.create(desktopId)
            val expectedSpki = identity.publicKey.encoded.copyOf()
            val expected = checkNotNull(store.originalCertificateChain(desktopId)).map { it.encoded.copyOf() }
            val reopened = AndroidDeviceIdentityStore()
            assertChainEquals(expected, checkNotNull(reopened.originalCertificateChain(desktopId)))
            val current = checkNotNull(reopened.load(desktopId))
            assertArrayEquals(expectedSpki, current.publicKey.encoded)
            val challenge = ByteArray(32) { (it + 2).toByte() }
            val evidence = checkNotNull(reopened.originalCertificateChain(desktopId))
            assertTrue(verifies(evidence.first(), challenge, current.signChallenge(challenge)))

            store.delete(desktopId)
            listOf(store, reopened, AndroidDeviceIdentityStore()).forEach { reader ->
                assertNull(reader.load(desktopId))
                assertNull(reader.originalCertificateChain(desktopId))
                assertNull(reader.originalCertificateChain(desktopId))
                assertNull(reader.load(desktopId))
            }
        } finally { deleteOwnedKeys(store, desktopId) }
    }

    @Test fun evidenceRemainsBoundToTheRequestedComputer() {
        val firstId = "first-evidence-${UUID.randomUUID()}"
        val secondId = "second-evidence-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            assertNull(store.load(firstId))
            assertNull(store.load(secondId))
            val first = store.create(firstId)
            // A different existing computer must not supply evidence for an absent one.
            assertNull(store.originalCertificateChain(secondId))
            assertNull(store.load(secondId))
            val second = store.create(secondId)
            val firstSpki = first.publicKey.encoded.copyOf()
            val secondSpki = second.publicKey.encoded.copyOf()
            assertFalse(firstSpki.contentEquals(secondSpki))
            val firstChain = checkNotNull(store.originalCertificateChain(firstId)).map { it.encoded.copyOf() }
            val secondChain = checkNotNull(store.originalCertificateChain(secondId)).map { it.encoded.copyOf() }
            val reader = AndroidDeviceIdentityStore()
            val firstEvidence = checkNotNull(reader.originalCertificateChain(firstId))
            val secondEvidence = checkNotNull(reader.originalCertificateChain(secondId))
            assertChainEquals(firstChain, firstEvidence)
            assertChainEquals(secondChain, secondEvidence)
            assertArrayEquals(firstSpki, firstEvidence.first().publicKey.encoded)
            assertArrayEquals(secondSpki, secondEvidence.first().publicKey.encoded)
            val challenge = ByteArray(32) { (it + 3).toByte() }
            val firstSignature = checkNotNull(reader.load(firstId)).signChallenge(challenge)
            val secondSignature = checkNotNull(reader.load(secondId)).signChallenge(challenge)
            assertTrue(verifies(firstEvidence.first(), challenge, firstSignature))
            assertTrue(verifies(secondEvidence.first(), challenge, secondSignature))
            assertFalse(verifies(secondEvidence.first(), challenge, firstSignature))
            assertFalse(verifies(firstEvidence.first(), challenge, secondSignature))

            store.delete(firstId)
            val afterDelete = AndroidDeviceIdentityStore()
            assertNull(afterDelete.originalCertificateChain(firstId))
            assertNull(afterDelete.load(firstId))
            val remaining = checkNotNull(afterDelete.originalCertificateChain(secondId))
            assertChainEquals(secondChain, remaining)
            val remainingIdentity = checkNotNull(afterDelete.load(secondId))
            assertArrayEquals(secondSpki, remainingIdentity.publicKey.encoded)
            assertTrue(verifies(remaining.first(), challenge, remainingIdentity.signChallenge(challenge)))
        } finally { deleteOwnedKeys(store, firstId, secondId) }
    }

    private fun assertChainEquals(expected: List<ByteArray>, actual: List<X509Certificate>) {
        assertEquals(expected.size, actual.size)
        expected.zip(actual).forEach { (encoded, certificate) -> assertArrayEquals(encoded, certificate.encoded) }
    }

    private fun verifies(certificate: X509Certificate, challenge: ByteArray, signature: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(certificate.publicKey)
            update(challenge)
            verify(signature)
        }

    private fun deleteOwnedKeys(store: AndroidDeviceIdentityStore, vararg desktopIds: String) {
        var cleanupFailed = false
        desktopIds.forEach { desktopId ->
            try {
                store.delete(desktopId)
                if (store.load(desktopId) != null) cleanupFailed = true
            } catch (_: Exception) {
                cleanupFailed = true
            }
        }
        assertFalse("Owned test key cleanup failed", cleanupFailed)
    }
}
