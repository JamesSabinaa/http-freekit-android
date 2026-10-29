package com.httpfreekit.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.security.Signature
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID
import javax.net.ssl.X509ExtendedKeyManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Synthetic caller-approved snapshots do not authenticate approval provenance or CA trust.
 * Fresh-instance reopen is not process death; pending files simulate interruption, not power loss.
 */
@RunWith(AndroidJUnit4::class)
class AndroidApprovedEnrolledCredentialStoreTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val directory get() = File(context.noBackupFilesDir, "approved-enrolled-credentials-v1")
    private val legacyDirectory get() = File(context.noBackupFilesDir, "enrolled-credentials-v1")

    @Test fun reopenedApprovalUsesOriginalNonexportableKeyAndPreservesOriginalEvidence() {
        val id = ownedId()
        withOwnedResources(id) {
            verifyCleanupFailurePrecedence()
            val fixture = fixture(id)
            val before = originalHashes(id)
            publicStore(fixture.clock).save(fixture.record)
            val published = published(id)
            assertEquals(context.noBackupFilesDir.canonicalFile, directory.parentFile?.canonicalFile)
            assertTrue(published.isFile)
            sameBytes(ApprovedEnrolledCredentialCodec.encode(fixture.record), published.readBytes())
            val reopenedIdentity = checkNotNull(AndroidDeviceIdentityStore().load(id))
            sameBytes(fixture.record.approval.originalDeviceSpki, reopenedIdentity.publicKey.encoded)
            val reopened = checkNotNull(publicStore(fixture.clock).load(id))
            sameBytes(ApprovedEnrolledCredentialCodec.encode(fixture.record),
                ApprovedEnrolledCredentialCodec.encode(reopened.record))
            assertUsable(reopened)
            sameHashes(before, originalHashes(id))
            assertFalse(before.first().contentEquals(fixture.record.approval.clientCertificateSha256))
        }
    }

    @Test fun issuedChainCannotSubstituteForOriginalApprovalEvidence() {
        val id = ownedId()
        withOwnedResources(id) {
            val fixture = fixture(id)
            val before = originalHashes(id)
            val substituted = withOriginalHashes(fixture.record,
                listOf(fixture.record.approval.clientCertificateSha256))
            val store = publicStore(fixture.clock)
            unavailable { store.save(substituted) }
            assertFalse(published(id).exists())
            assertNull(store.load(id))
            sameIdentity(fixture)
            sameHashes(before, originalHashes(id))
            store.save(fixture.record)
            // An otherwise cross-bound valid envelope with wrong original evidence on disk.
            AtomicCredentialRecordFiles(directory, 32768).publish(name(id),
                ApprovedEnrolledCredentialCodec.encode(substituted))
            unavailable { publicStore(fixture.clock).load(id) }
            sameIdentity(fixture)
            sameHashes(before, originalHashes(id))
        }
    }

    @Test fun missingReplacedAndExpiredIdentityStatesFailClosedWithoutRepair() {
        val missingId = ownedId()
        val replacedId = ownedId()
        val expiredId = ownedId()
        withOwnedResources(missingId, replacedId, expiredId) {
            val missing = fixture(missingId)
            publicStore(missing.clock).save(missing.record)
            val missingLoaded = checkNotNull(publicStore(missing.clock).load(missingId))
            val missingAlias = selectedAlias(missingLoaded.clientKeyManager)
            AndroidDeviceIdentityStore().delete(missingId)
            unavailable { publicStore(missing.clock).load(missingId) }
            assertNull(AndroidDeviceIdentityStore().load(missingId))
            assertNull(AndroidDeviceIdentityStore().originalCertificateChain(missingId))
            assertUnselectable(missingLoaded.clientKeyManager, missingAlias)

            val replaced = fixture(replacedId)
            publicStore(replaced.clock).save(replaced.record)
            val replacedLoaded = checkNotNull(publicStore(replaced.clock).load(replacedId))
            val replacedAlias = selectedAlias(replacedLoaded.clientKeyManager)
            val identities = AndroidDeviceIdentityStore()
            identities.delete(replacedId)
            val replacement = identities.create(replacedId)
            val replacementSpki = replacement.publicKey.encoded
            val replacementHashes = originalHashes(replacedId)
            assertFalse(replacementSpki.contentEquals(replaced.record.approval.originalDeviceSpki))
            unavailable { publicStore(replaced.clock).load(replacedId) }
            sameBytes(replacementSpki, checkNotNull(identities.load(replacedId)).publicKey.encoded)
            sameHashes(replacementHashes, originalHashes(replacedId))
            assertUnselectable(replacedLoaded.clientKeyManager, replacedAlias)

            val expired = fixture(expiredId)
            publicStore(expired.clock).save(expired.record)
            val before = published(expiredId).readBytes()
            // Exact leaf expiry + one second; gateway and authority remain valid at this instant.
            val afterExpiry = Clock.fixed(Instant.ofEpochMilli(
                expired.record.approval.credentialExpiresAtMillis).plusSeconds(1), ZoneOffset.UTC)
            unavailable { publicStore(afterExpiry).load(expiredId) }
            unavailable { publicStore(afterExpiry).save(expired.record) }
            sameBytes(before, published(expiredId).readBytes())
            sameIdentity(expired)
            sameHashes(expired.record.approval.originalKeystoreCertificateHashes, originalHashes(expiredId))
            assertUsable(checkNotNull(publicStore(expired.clock).load(expiredId)))
        }
    }

    @Test fun corruptEnvelopeAndInterruptedPendingCannotReplacePublishedApproval() {
        val id = ownedId()
        withOwnedResources(id) {
            val fixture = fixture(id)
            val store = publicStore(fixture.clock)
            store.save(fixture.record)
            val published = published(id)
            val exact = published.readBytes()
            val pending = File(directory, "${name(id)}.interrupted.pending")
            pending.writeBytes(byteArrayOf(1, 2, 3))
            sameBytes(exact, ApprovedEnrolledCredentialCodec.encode(checkNotNull(
                publicStore(fixture.clock).load(id)).record))
            sameBytes(exact, published.readBytes())
            listOf(exact.copyOf(exact.size / 2), ByteArray(32769)).forEach { corrupt ->
                published.writeBytes(corrupt)
                unavailable { publicStore(fixture.clock).load(id) }
                sameIdentity(fixture)
                sameHashes(fixture.record.approval.originalKeystoreCertificateHashes, originalHashes(id))
                published.writeBytes(exact)
                val restored = checkNotNull(publicStore(fixture.clock).load(id))
                sameBytes(exact, ApprovedEnrolledCredentialCodec.encode(restored.record))
                assertUsable(restored)
            }
            store.forget(id)
            assertFalse(pending.exists())
            assertFalse(published.exists())
            assertNull(AndroidDeviceIdentityStore().load(id))
            assertNull(store.load(id))
        }
    }

    @Test fun legacyNeverSynthesizesApprovalAndForgetInvalidatesOnlyItsSharedIdentity() {
        val id = ownedId()
        val otherId = ownedId()
        withOwnedResources(id, otherId) {
            val fixture = fixture(id)
            val other = fixture(otherId)
            val legacy = AndroidEnrolledCredentialStore(context, fixture.clock)
            legacy.save(fixture.record.credential)
            val retainedLegacy = checkNotNull(legacy.load(id)).clientKeyManager
            val retainedAlias = selectedAlias(retainedLegacy)
            val approved = publicStore(fixture.clock)
            assertNull(approved.load(id))
            assertFalse(published(id).exists())
            sameIdentity(fixture)
            approved.save(fixture.record)
            assertUsable(checkNotNull(approved.load(id)))
            publicStore(other.clock).save(other.record)
            val otherBytes = published(otherId).readBytes()
            val otherHashes = originalHashes(otherId)
            val retainedApproved = checkNotNull(approved.load(id)).clientKeyManager
            val approvedAlias = selectedAlias(retainedApproved)
            approved.forget(id)
            approved.forget(id)
            assertNull(AndroidDeviceIdentityStore().load(id))
            assertNull(approved.load(id))
            assertFalse(published(id).exists())
            assertTrue(File(legacyDirectory, name(id)).isFile)
            unavailable { legacy.load(id) }
            assertUnselectable(retainedLegacy, retainedAlias)
            assertUnselectable(retainedApproved, approvedAlias)
            sameBytes(otherBytes, published(otherId).readBytes())
            sameHashes(otherHashes, originalHashes(otherId))
            sameIdentity(other)
            assertUsable(checkNotNull(publicStore(other.clock).load(otherId)))
            legacy.forget(id)
            assertNull(legacy.load(id))
            assertFalse(File(legacyDirectory, name(id)).exists())
        }
    }

    @Test fun metadataCleanupFailureDeletesKeyFirstAndCanBeRetried() {
        val id = ownedId()
        withOwnedResources(id) {
            val fixture = fixture(id)
            val normal = publicStore(fixture.clock)
            normal.save(fixture.record)
            val before = published(id).readBytes()
            val retained = checkNotNull(normal.load(id)).clientKeyManager
            val alias = selectedAlias(retained)
            val identities = AndroidDeviceIdentityStore()
            val files = AtomicCredentialRecordFiles(directory, 32768)
            var deleteObserved = false
            val failingDelete = object : CredentialRecordFiles by files {
                override fun delete(name: String) {
                    deleteObserved = true
                    assertNull(identities.load(id))
                    assertNull(identities.originalCertificateChain(id))
                    throw IOException("Synthetic private deletion detail")
                }
            }
            val failing = AndroidApprovedEnrolledCredentialStore(access(identities), failingDelete, fixture.clock)
            unavailable(EnrolledCredentialError.STORAGE_FAILURE) { failing.forget(id) }
            assertTrue(deleteObserved)
            assertNull(identities.load(id))
            sameBytes(before, published(id).readBytes())
            unavailable { normal.load(id) }
            assertUnselectable(retained, alias)
            publicStore(fixture.clock).forget(id)
            publicStore(fixture.clock).forget(id)
            assertFalse(published(id).exists())
            assertNull(normal.load(id))
            assertNull(identities.load(id))
        }
    }

    private data class Fixture(val record: ApprovedEnrolledCredentialRecord, val clock: Clock)

    private fun fixture(id: String): Fixture {
        val identity = AndroidDeviceIdentityStore().create(id)
        val gateway = TestEnrollmentCertificates.server()
        val now = gateway.certificate.notBefore.toInstant().plusSeconds(60)
        val authority = TestEnrollmentCertificates.authority(
            notBefore = now.minusSeconds(60), notAfter = now.plusSeconds(7200))
        val leaf = TestEnrollmentCertificates.client(identity.publicKey, authority,
            notBefore = now.minusSeconds(60), notAfter = now.plusSeconds(600))
        val pin = Base64.getUrlEncoder().withoutPadding().encodeToString(hash(gateway.keys.public.encoded))
        val credential = EnrolledCredentialRecord(id, gateway.certificate, pin, "gateway-fixture.invalid",
            listOf(leaf), authority.certificate)
        val approval = AuthenticatedEnrollmentApproval(id, credential.logicalServerName, pin,
            "synthetic-enrollment", "synthetic-device", identity.publicKey.encoded, originalHashes(id),
            hash(leaf.encoded), hash(authority.certificate.encoded),
            hash("synthetic-interception-ca-commitment".toByteArray(Charsets.US_ASCII)),
            listOf("tcp-http", "tcp-https-connect"), leaf.notAfter.time)
        return Fixture(ApprovedEnrolledCredentialRecord(credential, approval), Clock.fixed(now, ZoneOffset.UTC))
    }

    private fun withOriginalHashes(record: ApprovedEnrolledCredentialRecord, hashes: List<ByteArray>): ApprovedEnrolledCredentialRecord {
        val a = record.approval
        return ApprovedEnrolledCredentialRecord(record.credential, AuthenticatedEnrollmentApproval(
            a.desktopId, a.logicalServerName, a.gatewaySpkiSha256, a.enrollmentId, a.deviceId,
            a.originalDeviceSpki, hashes, a.clientCertificateSha256, a.authorityCertificateSha256,
            a.interceptionCaCertificateSha256, a.capabilities, a.credentialExpiresAtMillis))
    }

    private fun publicStore(clock: Clock) = AndroidApprovedEnrolledCredentialStore(context, clock)
    private fun ownedId() = "approved-${UUID.randomUUID()}"
    private fun hash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun name(id: String): String = hash(id.toByteArray(Charsets.US_ASCII))
        .joinToString("") { "%02x".format(it) } + ".credential"
    private fun published(id: String) = File(directory, name(id))
    private fun originalHashes(id: String): List<ByteArray> =
        checkNotNull(AndroidDeviceIdentityStore().originalCertificateChain(id)).map { hash(it.encoded) }

    private fun sameBytes(expected: ByteArray, actual: ByteArray) {
        assertTrue("Public material mismatch [REDACTED]", expected.contentEquals(actual))
    }

    private fun sameHashes(expected: List<ByteArray>, actual: List<ByteArray>) {
        assertEquals(expected.size, actual.size)
        expected.zip(actual).forEach { (first, second) -> sameBytes(first, second) }
    }

    private fun sameIdentity(fixture: Fixture) {
        sameBytes(fixture.record.approval.originalDeviceSpki,
            checkNotNull(AndroidDeviceIdentityStore().load(fixture.record.credential.desktopId)).publicKey.encoded)
    }

    private fun selectedAlias(manager: X509ExtendedKeyManager): String =
        checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))

    private fun assertUsable(loaded: LoadedApprovedEnrolledCredential) {
        val manager = loaded.clientKeyManager
        val alias = selectedAlias(manager)
        val chain = checkNotNull(manager.getCertificateChain(alias))
        val expected = loaded.record.credential.clientCertificateChain
        assertEquals(expected.size, chain.size)
        expected.zip(chain).forEach { (first, second) -> sameBytes(first.encoded, second.encoded) }
        chain.first().verify(loaded.record.credential.authenticatedEnrollmentAuthority.publicKey)
        val privateKey = checkNotNull(manager.getPrivateKey(alias))
        assertNull(privateKey.encoded)
        val challenge = ByteArray(32) { (it + 1).toByte() }
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey); update(challenge); sign()
        }
        assertTrue("Issued client challenge verification failed", Signature.getInstance("SHA256withECDSA").run {
            initVerify(chain.first().publicKey); update(challenge); verify(signature)
        })
    }

    private fun assertUnselectable(manager: X509ExtendedKeyManager, alias: String) {
        assertNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        assertNull(manager.chooseEngineClientAlias(arrayOf("EC"), null, null))
        assertNull(manager.getClientAliases("EC", null))
        assertNull(manager.getPrivateKey(alias))
        assertNull(manager.getCertificateChain(alias))
    }

    private fun access(store: AndroidDeviceIdentityStore): ApprovedCredentialIdentities = object : ApprovedCredentialIdentities {
        override fun <T> transaction(desktopId: String, operation: () -> T): T =
            store.withExistingIdentityTransaction(desktopId, operation)
        override fun load(desktopId: String): DeviceIdentity? = store.load(desktopId)
        override fun delete(desktopId: String) = store.delete(desktopId)
        override fun originalCertificateChain(desktopId: String) = store.originalCertificateChain(desktopId)
    }

    private fun unavailable(code: EnrolledCredentialError = EnrolledCredentialError.INVALID_CREDENTIAL,
        action: () -> Any?) {
        try {
            action()
        } catch (expected: EnrolledCredentialUnavailableException) {
            assertEquals(code, expected.code)
            assertNull(expected.cause)
            assertTrue(expected.suppressed.isEmpty())
            assertEquals("Saved credential is unavailable: $code", expected.message)
            return
        }
        throw AssertionError("Unusable approved credential accepted")
    }

    private fun withOwnedResources(vararg ids: String, action: () -> Unit) {
        preservingPrimaryFailure(action) { cleanup(*ids) }
    }

    /** Never replace a body failure or retain identifying cleanup exception details. */
    private fun preservingPrimaryFailure(action: () -> Unit, release: () -> Unit) {
        var primary: Throwable? = null
        try {
            action()
        } catch (failure: Throwable) {
            primary = failure
            throw failure
        } finally {
            try {
                release()
            } catch (_: Throwable) {
                val redacted = AssertionError("Owned approved credential cleanup failed [REDACTED]")
                if (primary == null) throw redacted else primary.addSuppressed(redacted)
            }
        }
    }

    /** Deterministic regression inside the frozen manifest; no keys/files are created here. */
    private fun verifyCleanupFailurePrecedence() {
        listOf(false, true).forEach { bodyFails ->
            listOf(false, true).forEach { cleanupFails ->
                val primary = AssertionError("Synthetic primary failure")
                var releaseCalls = 0
                var observed: Throwable? = null
                try {
                    preservingPrimaryFailure(
                        action = { if (bodyFails) throw primary },
                        release = {
                            releaseCalls++
                            if (cleanupFails) throw IOException("Synthetic private cleanup detail")
                        },
                    )
                } catch (failure: Throwable) {
                    observed = failure
                }
                assertEquals(1, releaseCalls)
                if (bodyFails) {
                    assertTrue("Primary failure was replaced", observed === primary)
                    assertEquals(if (cleanupFails) 1 else 0, primary.suppressed.size)
                } else if (!cleanupFails) {
                    assertNull(observed)
                }
                if (cleanupFails) {
                    val redacted = if (bodyFails) primary.suppressed.single() else checkNotNull(observed)
                    assertTrue(redacted is AssertionError)
                    assertEquals("Owned approved credential cleanup failed [REDACTED]", redacted.message)
                    assertNull(redacted.cause)
                    assertTrue(redacted.suppressed.isEmpty())
                }
            }
        }
    }

    /** Attempt every owned key and both metadata families, regardless of earlier cleanup failures. */
    private fun cleanup(vararg ids: String) {
        var failed = false
        fun attempt(action: () -> Unit) {
            try { action() } catch (_: Throwable) { failed = true }
        }
        ids.forEach { id ->
            attempt {
                val identities = AndroidDeviceIdentityStore()
                identities.delete(id)
                check(identities.load(id) == null)
                check(identities.originalCertificateChain(id) == null)
            }
            listOf(directory, legacyDirectory).forEach { ownedDirectory ->
                attempt { AtomicCredentialRecordFiles(ownedDirectory, 32768).delete(name(id)) }
                attempt {
                    val file = File(ownedDirectory, name(id))
                    if (file.exists()) check(file.delete())
                    check(!file.exists())
                }
            }
            attempt {
                val pending = File(directory, "${name(id)}.interrupted.pending")
                if (pending.exists()) check(pending.delete())
                check(!pending.exists())
            }
        }
        assertFalse("Owned approved credential cleanup failed [REDACTED]", failed)
    }
}
