package com.httpfreekit.security

import java.io.IOException
import java.security.KeyPair
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ApprovedEnrolledCredentialStoreTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun saveReopenUsesExistingHandleOriginalEvidenceAndOneHashedCompleteEnvelope() {
        val f = ApprovedCredentialTestFixture()
        val record = f.record
        f.store().save(record)
        val loaded = checkNotNull(f.store().load(f.id))
        val alias = checkNotNull(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null))
        assertSame(f.keys.private, loaded.clientKeyManager.getPrivateKey(alias))
        assertArrayEquals(f.leaf.encoded, loaded.clientKeyManager.getCertificateChain(alias)!!.single().encoded)
        assertArrayEquals(approvedHash(f.original.encoded), loaded.record.approval.originalKeystoreCertificateHashes.single())
        assertArrayEquals(approvedEnvelope(record), f.files.entries.values.single())
        val expectedName = approvedHash(f.id.toByteArray(Charsets.US_ASCII)).joinToString("") { "%02x".format(it) } + ".credential"
        assertEquals(expectedName, f.files.entries.keys.single())
        assertEquals(2, f.identities.originalReads)
        assertEquals(2, f.identities.transactions)
        assertSame(f.keys, f.identities.currentKeys[f.id])
        approvedRedacted(loaded.toString(), f)
    }

    @Test fun nullMeansOnlyAbsentNewMetadataEvenIfNoIdentityExists() {
        val f = ApprovedCredentialTestFixture()
        f.identities.currentKeys.clear()
        f.identities.originals.clear()
        assertNull(f.store().load(f.id))
        assertEquals(0, f.identities.loads)
        assertEquals(0, f.identities.originalReads)
        assertTrue(f.files.entries.isEmpty())
        assertTrue(f.identities.currentKeys.isEmpty())
    }

    @Test fun legacyMetadataNeverSynthesizesApprovalAndForgetInvalidatesItsSharedKey() {
        val f = ApprovedCredentialTestFixture()
        val legacyFiles = ApprovedCredentialTestFixture.Files(f.identities)
        f.legacyStore(legacyFiles).save(f.credential())
        val legacyBytes = legacyFiles.entries.values.single().copyOf()
        assertNull(f.store().load(f.id))
        assertTrue(f.files.entries.isEmpty())
        assertSame(f.keys, f.identities.currentKeys[f.id])
        assertEquals(f.id, checkNotNull(f.legacyStore(legacyFiles).load(f.id)).record.desktopId)
        f.store().save(f.record)
        f.store().forget(f.id)
        assertArrayEquals(legacyBytes, legacyFiles.entries.values.single())
        invalid { f.legacyStore(legacyFiles).load(f.id) }
        assertNull(f.store().load(f.id))
        assertTrue(f.identities.currentKeys.isEmpty())
    }

    @Test fun legacyBytesInNewNamespaceFailRatherThanAdoptFetchedOrSidecarApproval() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val name = f.files.entries.keys.single()
        f.files.entries[name] = EnrolledCredentialCodec.encode(f.credential())
        invalid { f.store().load(f.id) }
        assertSame(f.keys, f.identities.currentKeys[f.id])
    }

    @Test fun malformedOversizedMixedAndWrongOwnerEnvelopesFailClosed() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val name = f.files.entries.keys.single()
        val anotherOwner = f.combined(f.credential(desktop = "other-owner"), f.approval(desktop = "other-owner"))
        val corrupted = listOf(
            byteArrayOf(1), ByteArray(32769), approvedEnvelope(f.record) + byteArrayOf(0),
            approvedEnvelope(f.record, fields = mapOf("clientHash" to ByteArray(32))),
            approvedEnvelope(f.record, fields = mapOf("authorityHash" to ByteArray(32))),
            approvedEnvelope(f.record, fields = mapOf("spki" to TestEnrollmentCertificates.keyPair().public.encoded)),
            approvedEnvelope(anotherOwner),
        )
        corrupted.forEach { bytes ->
            f.files.entries[name] = bytes
            invalid { f.store().load(f.id) }
            assertSame(f.keys, f.identities.currentKeys[f.id])
        }
    }

    @Test fun missingReplacedAndMismatchedPrivateKeysRejectSaveAndLoadAndOldManagers() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val manager = checkNotNull(f.store().load(f.id)).clientKeyManager
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        val previous = f.files.entries.values.single().copyOf()
        f.identities.currentKeys.remove(f.id)
        invalid { f.store().load(f.id) }
        invalid { f.store().save(f.record) }
        assertNull(manager.getPrivateKey(alias))
        val other = TestEnrollmentCertificates.keyPair()
        for (replacement in listOf(other, KeyPair(f.keys.public, other.private))) {
            f.identities.currentKeys[f.id] = replacement
            invalid { f.store().save(f.record) }
            invalid { f.store().load(f.id) }
            assertArrayEquals(previous, f.files.entries.values.single())
            assertSame(replacement, f.identities.currentKeys[f.id])
        }
        assertNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
    }

    @Test fun exactOriginalChainIsNotTheIssuedChainOrAReissuedCertificateWithTheSameKey() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val old = f.files.entries.values.single().copyOf()
        // The issued certificate has the same device public key, but different exact DER/provenance.
        val sameKeyDifferentDer = f.client()
        for (chain in listOf(listOf(f.leaf), listOf(sameKeyDifferentDer), emptyList())) {
            f.identities.originals[f.id] = chain
            invalid { f.store().load(f.id) }
            invalid { f.store().save(f.record) }
            assertArrayEquals(old, f.files.entries.values.single())
        }
        f.identities.originals.remove(f.id)
        invalid { f.store().load(f.id) }
        invalid { f.store().save(f.record) }
        f.identities.originals[f.id] = listOf(f.original)
        assertEquals(f.id, checkNotNull(f.store().load(f.id)).record.approval.desktopId)
    }

    @Test fun everyOriginalChainHashAndItsOrderAreCheckedNotOnlyTheFirstCertificateKey() {
        val f = ApprovedCredentialTestFixture()
        val second = TestEnrollmentCertificates.authority("CN=Original chain second certificate").certificate
        val third = TestEnrollmentCertificates.authority("CN=Original chain third certificate").certificate
        f.identities.originals[f.id] = listOf(f.original, second, third)
        val record = f.combined(approval = f.approval(originalHashes = listOf(f.original, second, third).map { approvedHash(it.encoded) }))
        f.store().save(record)
        for (chain in listOf(listOf(f.original, third, second), listOf(f.original, second), listOf(f.original, second, second))) {
            f.identities.originals[f.id] = chain
            invalid { f.store().load(f.id) }
            invalid { f.store().save(record) }
        }
    }

    @Test fun originalEvidenceMismatchFailsBeforeAnyFirstPublication() {
        val f = ApprovedCredentialTestFixture()
        invalid { f.store().save(f.combined(approval = f.approval(originalHashes = listOf(ByteArray(32))))) }
        assertTrue(f.files.entries.isEmpty())
        assertSame(f.keys, f.identities.currentKeys[f.id])
    }

    @Test fun matchingOriginalHashCannotHideAFirstCertificateForADifferentKey() {
        val f = ApprovedCredentialTestFixture()
        val other = f.client(TestEnrollmentCertificates.keyPair())
        f.identities.originals[f.id] = listOf(other)
        val record = f.combined(approval = f.approval(originalHashes = listOf(approvedHash(other.encoded))))
        invalid { f.store().save(record) }
        assertTrue(f.files.entries.isEmpty())
        val name = approvedHash(f.id.toByteArray()).joinToString("") { "%02x".format(it) } + ".credential"
        f.files.entries[name] = approvedEnvelope(record)
        invalid { f.store().load(f.id) }
    }

    @Test fun activeCredentialOutlivesHistoricalSetupTtlsWithoutInventedDeadlineFields() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        f.clock.set(f.now.plusSeconds(600))
        val loaded = checkNotNull(f.store().load(f.id))
        assertEquals(f.leaf.notAfter.time, loaded.record.approval.credentialExpiresAtMillis)
        assertTrue(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null) != null)
    }

    @Test fun consistentSnapshotsStillRequireGatewaySanChainSignatureAndPrivateKeyValidation() {
        val f = ApprovedCredentialTestFixture()
        val wrongAuthority = TestEnrollmentCertificates.authority()
        val wrongSignature = TestEnrollmentCertificates.client(f.keys.public, f.authority,
            signingKey = wrongAuthority.keys.private, notBefore = f.now.minusSeconds(60), notAfter = f.now.plusSeconds(1800))
        val foreignLeaf = f.client(TestEnrollmentCertificates.keyPair())
        val invalidCredentials = listOf(
            f.credential(name = "wrong-san.invalid"),
            f.credential(clientCertificate = wrongSignature),
            f.credential(clientCertificate = foreignLeaf),
            f.credential(authorityCertificate = wrongAuthority.certificate),
        )
        invalidCredentials.forEach { credential ->
            val record = matching(f, credential)
            invalid { f.store().save(record) }
            assertTrue(f.files.entries.isEmpty())
            // Bypass save: load must independently perform the same validation.
            val name = approvedHash(f.id.toByteArray()).joinToString("") { "%02x".format(it) } + ".credential"
            f.files.entries[name] = approvedEnvelope(record)
            invalid { f.store().load(f.id) }
            f.files.entries.clear()
        }
    }

    @Test fun leafGatewayAndAuthorityExpiryAreRecheckedWithoutSleeping() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val manager = checkNotNull(f.store().load(f.id)).clientKeyManager
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        for (certificate in listOf(f.leaf, f.gateway.certificate, f.authority.certificate)) {
            f.clock.set(certificate.notAfter.toInstant().plusMillis(1))
            invalid { f.store().load(f.id) }
            invalid { f.store().save(f.record) }
        }
        assertNull(manager.getPrivateKey(alias))
        assertNull(manager.getCertificateChain(alias))
    }

    @Test fun gatewayAndAuthorityExpiryAreIndependentlyEnforcedWhileLeafIsActive() {
        val f = ApprovedCredentialTestFixture()
        val longAuthority = TestEnrollmentCertificates.authority(notBefore = f.now.minusSeconds(60), notAfter = f.now.plusSeconds(20000))
        val longLeaf = TestEnrollmentCertificates.client(f.keys.public, longAuthority,
            notBefore = f.now.minusSeconds(60), notAfter = f.now.plusSeconds(10000))
        val record = matching(f, f.credential(clientCertificate = longLeaf, authorityCertificate = longAuthority.certificate))
        f.store().save(record)
        f.clock.set(f.gateway.certificate.notAfter.toInstant().plusMillis(1))
        invalid { f.store().load(f.id) }
        f.clock.set(f.now)
        val shortAuthority = TestEnrollmentCertificates.authority(notBefore = f.now.minusSeconds(60), notAfter = f.now.plusSeconds(30))
        val activeLeaf = TestEnrollmentCertificates.client(f.keys.public, shortAuthority,
            notBefore = f.now.minusSeconds(60), notAfter = f.now.plusSeconds(1800))
        val shortRecord = matching(f, f.credential(clientCertificate = activeLeaf, authorityCertificate = shortAuthority.certificate))
        f.store().save(shortRecord)
        f.clock.set(shortAuthority.certificate.notAfter.toInstant().plusMillis(1))
        invalid { f.store().load(f.id) }
    }

    @Test fun failedReplacementRetainsTheEntirePriorGenerationIncludingApproval() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val previous = f.files.entries.values.single().copyOf()
        val newLeaf = f.client()
        val replacement = f.combined(f.credential(clientCertificate = newLeaf),
            f.approval(clientHash = approvedHash(newLeaf.encoded), expires = newLeaf.notAfter.time,
                enrollment = "replacement-grant", caHash = ByteArray(32) { 99 }))
        f.files.publishFailure = IOException("interrupted ${f.id} private path")
        storage { f.store().save(replacement) }
        assertArrayEquals(previous, f.files.entries.values.single())
        f.files.publishFailure = null
        val loaded = checkNotNull(f.store().load(f.id)).record
        assertArrayEquals(f.leaf.encoded, loaded.credential.clientCertificateChain.single().encoded)
        assertEquals("approved-enrollment", loaded.approval.enrollmentId)
        assertArrayEquals(f.approval().interceptionCaCertificateSha256, loaded.approval.interceptionCaCertificateSha256)
        f.store().save(replacement)
        assertArrayEquals(approvedEnvelope(replacement), f.files.entries.values.single())
    }

    @Test fun keyDeletionFailureLeavesCompleteMetadataAndCanBeRetried() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val prior = f.files.entries.values.single().copyOf()
        f.identities.events.clear()
        f.identities.deleteFailure = IllegalStateException("provider ${f.id}")
        val failure = storage { f.store().forget(f.id) }
        approvedRedacted(failure.toString(), f)
        assertEquals(listOf("key-delete"), f.identities.events)
        assertArrayEquals(prior, f.files.entries.values.single())
        assertSame(f.keys, f.identities.currentKeys[f.id])
        assertEquals(f.id, checkNotNull(f.store().load(f.id)).record.credential.desktopId)
        f.identities.deleteFailure = null
        f.store().forget(f.id)
        assertNull(f.store().load(f.id))
    }

    @Test fun metadataFailureOccursAfterKeyDeletionAndRetryWorksWithTheKeyAlreadyAbsent() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val manager = checkNotNull(f.store().load(f.id)).clientKeyManager
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        f.identities.events.clear()
        f.files.deleteFailure = IOException("metadata ${f.id}")
        storage { f.store().forget(f.id) }
        assertEquals(listOf("key-delete", "metadata-delete"), f.identities.events)
        assertTrue(f.identities.currentKeys.isEmpty())
        assertEquals(1, f.files.entries.size)
        invalid { f.store().load(f.id) }
        assertNull(manager.getPrivateKey(alias))
        f.files.deleteFailure = null
        f.store().forget(f.id)
        f.store().forget(f.id)
        assertTrue(f.files.entries.isEmpty())
        assertNull(f.store().load(f.id))
    }

    @Test fun forgetDoesNotNeedUsableEvidenceAndNeverDeletesAnotherComputer() {
        val f = ApprovedCredentialTestFixture()
        f.store().save(f.record)
        val otherKeys = TestEnrollmentCertificates.keyPair()
        f.identities.currentKeys["unrelated"] = otherKeys
        val unrelated = "c".repeat(64) + ".credential"
        f.files.entries[unrelated] = byteArrayOf(12, 34)
        f.identities.loadFailure = IllegalStateException("unreadable provider")
        f.identities.originalFailure = IllegalStateException("unreadable evidence")
        f.store().forget(f.id)
        assertSame(otherKeys, f.identities.currentKeys["unrelated"])
        assertEquals(setOf(unrelated), f.files.entries.keys)
        assertArrayEquals(byteArrayOf(12, 34), f.files.entries[unrelated])
    }

    @Test fun providerAndPublicationExceptionsAreFiniteRedactedWithoutCauses() {
        val f = ApprovedCredentialTestFixture()
        val detail = "private ${f.id} ${f.approval().gatewaySpkiSha256}"
        f.identities.originalFailure = IllegalStateException(detail)
        approvedRedacted(invalid { f.store().save(f.record) }.toString(), f)
        f.identities.originalFailure = null
        f.files.publishFailure = IOException(detail)
        approvedRedacted(storage { f.store().save(f.record) }.toString(), f)
        f.files.publishFailure = null
        f.store().save(f.record)
        f.identities.originalFailure = IllegalStateException(detail)
        approvedRedacted(invalid { f.store().load(f.id) }.toString(), f)
        f.identities.originalFailure = null
        f.files.readFailure = IOException(detail)
        approvedRedacted(invalid { f.store().load(f.id) }.toString(), f)
    }

    @Test fun fatalProviderAndStorageErrorsAreNotFiniteRecoverableFailures() {
        val f = ApprovedCredentialTestFixture()
        val fatal = AssertionError("fatal synthetic error")
        fun escapes(operation: () -> Unit) {
            try { operation(); throw AssertionError("Fatal error was swallowed") }
            catch (caught: AssertionError) { assertSame(fatal, caught) }
        }
        f.identities.originalFailure = fatal
        escapes { f.store().save(f.record) }
        f.identities.originalFailure = null
        f.files.publishFailure = fatal
        escapes { f.store().save(f.record) }
        f.files.publishFailure = null
        f.store().save(f.record)
        f.identities.originalFailure = fatal
        escapes { f.store().load(f.id) }
        f.identities.originalFailure = null
        f.identities.deleteFailure = fatal
        escapes { f.store().forget(f.id) }
    }

    @Test fun saveThenForgetIsSerializedAcrossStoreInstancesUntilPublicationCompletes() {
        serialized(saveFirst = true)
    }

    @Test fun forgetThenSaveCannotPublishAfterTheSharedKeyHasBeenDeleted() {
        serialized(saveFirst = false)
    }

    @Test fun actualBackendUsesConfiguredBoundForBothReadAndPublishWithoutChangingLegacyDefault() {
        val directory = temporary.newFolder("configured-approved")
        val files = AtomicCredentialRecordFiles(directory, 32768)
        val name = "a".repeat(64) + ".credential"
        val maximum = ByteArray(32768) { (it % 251).toByte() }
        files.publish(name, maximum)
        assertArrayEquals(maximum, files.read(name))
        approvedRejected { files.publish(name, ByteArray(32769)) }
        assertArrayEquals(maximum, files.read(name))
        directory.resolve(name).writeBytes(ByteArray(32769))
        approvedRejected { files.read(name) }
        val smallDirectory = temporary.newFolder("small-approved")
        val small = AtomicCredentialRecordFiles(smallDirectory, 8)
        small.publish(name, ByteArray(8))
        assertArrayEquals(ByteArray(8), small.read(name))
        approvedRejected { small.publish(name, ByteArray(9)) }
        smallDirectory.resolve(name).writeBytes(ByteArray(9))
        approvedRejected { small.read(name) }
        val minimum = AtomicCredentialRecordFiles(temporary.newFolder("minimum-approved"), 1)
        minimum.publish(name, byteArrayOf(1))
        assertArrayEquals(byteArrayOf(1), minimum.read(name))
        approvedRejected { minimum.publish(name, byteArrayOf(1, 2)) }
        val legacy = AtomicCredentialRecordFiles(temporary.newFolder("default-legacy"))
        approvedRejected { legacy.publish(name, ByteArray(EnrolledCredentialCodec.MAX_RECORD_BYTES + 1)) }
        for (invalid in listOf(Int.MIN_VALUE, -1, 0, 32769, Int.MAX_VALUE)) {
            approvedRejected { AtomicCredentialRecordFiles(directory, invalid) }
        }
    }

    @Test fun actualBackendPublishesWholeEnvelopeIgnoresPendingAndCleansOnlyOwnedPendingOnForget() {
        val f = ApprovedCredentialTestFixture()
        val directory = temporary.newFolder("atomic-approved")
        val files = AtomicCredentialRecordFiles(directory, 32768)
        val store = AndroidApprovedEnrolledCredentialStore(f.identities, files, f.clock)
        val name = approvedHash(f.id.toByteArray()).joinToString("") { "%02x".format(it) } + ".credential"
        val pending = directory.resolve("$name.interrupted.pending").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val unrelated = directory.resolve("unrelated.pending").apply { writeBytes(byteArrayOf(4)) }
        assertNull(store.load(f.id))
        store.save(f.record)
        assertArrayEquals(approvedEnvelope(f.record), files.read(name))
        val replacementLeaf = f.client()
        val replacement = matching(f, f.credential(clientCertificate = replacementLeaf))
        store.save(replacement)
        assertArrayEquals(approvedEnvelope(replacement), files.read(name))
        assertArrayEquals(replacementLeaf.encoded, checkNotNull(store.load(f.id)).record.credential.clientCertificateChain.single().encoded)
        assertTrue(pending.exists())
        store.forget(f.id)
        assertNull(files.read(name))
        assertFalse(pending.exists())
        assertTrue(unrelated.exists())
    }

    @Test fun actualBackendRejectsUnsafeAndNonregularTargetsAndCleansFailedPublicationTemporaryFile() {
        val directory = temporary.newFolder("safe-approved")
        val files = AtomicCredentialRecordFiles(directory, 32768)
        val name = "b".repeat(64) + ".credential"
        for (unsafe in listOf("../outside", "$name/child", "A".repeat(64) + ".credential", "b".repeat(64))) {
            approvedRejected { files.read(unsafe) }
            approvedRejected { files.publish(unsafe, byteArrayOf(1)) }
            approvedRejected { files.delete(unsafe) }
        }
        approvedRejected { files.publish(name, byteArrayOf()) }
        val target = directory.resolve(name).apply { mkdir() }
        target.resolve("retained").writeText("prior state")
        approvedRejected { files.read(name) }
        approvedRejected { files.publish(name, byteArrayOf(1, 2, 3)) }
        assertEquals("prior state", target.resolve("retained").readText())
        assertTrue(directory.listFiles()!!.none { it.name.endsWith(".pending") })
    }

    private fun matching(f: ApprovedCredentialTestFixture, credential: EnrolledCredentialRecord): ApprovedEnrolledCredentialRecord {
        val leaf = credential.clientCertificateChain.first()
        return f.combined(credential, f.approval(desktop = credential.desktopId, name = credential.logicalServerName,
            pin = credential.gatewaySpkiSha256, spki = leaf.publicKey.encoded, clientHash = approvedHash(leaf.encoded),
            authorityHash = approvedHash(credential.authenticatedEnrollmentAuthority.encoded), expires = leaf.notAfter.time))
    }

    private fun invalid(operation: () -> Unit) = approvedUnavailable(EnrolledCredentialError.INVALID_CREDENTIAL, operation)
    private fun storage(operation: () -> Unit) = approvedUnavailable(EnrolledCredentialError.STORAGE_FAILURE, operation)

    /** Gates observe transaction attempts; no sleeps or scheduler-speed assertion is needed. */
    private fun serialized(saveFirst: Boolean) {
        val f = ApprovedCredentialTestFixture()
        val first = f.store()
        val second = f.store()
        if (!saveFirst) first.save(f.record)
        f.identities.events.clear()
        val inside = CountDownLatch(1)
        val release = CountDownLatch(1)
        val attempted = CountDownLatch(1)
        val gate = { inside.countDown(); await(release) }
        if (saveFirst) f.files.beforePublish = gate else f.files.beforeDelete = gate
        val executor = Executors.newFixedThreadPool(2)
        try {
            val leading = executor.submit { if (saveFirst) first.save(f.record) else first.forget(f.id) }
            await(inside)
            f.identities.beforeTransaction = { attempted.countDown() }
            val trailing = executor.submit(Callable<Exception?> {
                try {
                    if (saveFirst) second.forget(f.id) else second.save(f.record)
                    null
                } catch (failure: Exception) { failure }
            })
            await(attempted)
            release.countDown()
            leading.get(5, TimeUnit.SECONDS)
            val failure = trailing.get(5, TimeUnit.SECONDS)
            if (saveFirst) {
                assertNull(failure)
                assertEquals(listOf("publish", "key-delete", "metadata-delete"), f.identities.events)
            } else {
                assertTrue(failure is EnrolledCredentialUnavailableException)
                assertEquals(EnrolledCredentialError.INVALID_CREDENTIAL, (failure as EnrolledCredentialUnavailableException).code)
                assertEquals(listOf("key-delete", "metadata-delete"), f.identities.events)
            }
            assertTrue(f.identities.currentKeys.isEmpty())
            assertTrue(f.files.entries.isEmpty())
            assertNull(first.load(f.id))
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    private fun await(latch: CountDownLatch) {
        assertTrue("Controlled operation did not reach its gate", latch.await(5, TimeUnit.SECONDS))
    }
}
