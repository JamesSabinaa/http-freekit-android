package com.httpfreekit.security

import java.io.IOException
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class EnrolledCredentialStoreTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun saveAndReopenBindTheOriginalExistingHandleWithoutCreatingAnIdentity() {
        val fixture = Fixture()
        fixture.store().save(fixture.record)
        val reopened = checkNotNull(fixture.store().load(fixture.id))
        assertEquals(fixture.id, reopened.record.desktopId)
        assertEquals(fixture.record.logicalServerName, reopened.record.logicalServerName)
        assertArrayEquals(fixture.leaf.encoded, reopened.record.clientCertificateChain.single().encoded)
        val manager = reopened.clientKeyManager
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        assertSame(fixture.keys.private, manager.getPrivateKey(alias))
        assertArrayEquals(fixture.leaf.encoded, manager.getCertificateChain(alias)!!.single().encoded)
        assertSame(fixture.keys, fixture.state.keys[fixture.id])
        assertEquals(1, fixture.files.entries.size)
        val name = fixture.files.entries.keys.single()
        assertTrue(Regex("[a-f0-9]{64}\\.credential").matches(name))
        assertFalse(name.contains(fixture.id))
    }

    @Test fun absentMetadataDoesNotCreateAnIdentityOrPublishAnything() {
        val fixture = Fixture()
        fixture.state.keys.clear()
        assertNull(fixture.store().load(fixture.id))
        assertTrue(fixture.state.keys.isEmpty())
        assertTrue(fixture.files.entries.isEmpty())
    }

    @Test fun recordAndCodecSnapshotInputAndReturnedMaterial() {
        val fixture = Fixture()
        val chain = mutableListOf(fixture.leaf)
        val record = fixture.record(chain = chain)
        val encoded = EnrolledCredentialCodec.encode(record)
        chain.clear()
        val decoded = EnrolledCredentialCodec.decode(encoded)
        encoded.fill(0)
        assertEquals(fixture.id, decoded.desktopId)
        assertArrayEquals(fixture.leaf.encoded, decoded.clientCertificateChain.single().encoded)
        assertNotSame(decoded.clientCertificateChain, decoded.clientCertificateChain)
        val returned = decoded.clientCertificateChain.single().encoded
        returned.fill(0)
        assertArrayEquals(fixture.leaf.encoded, decoded.clientCertificateChain.single().encoded)
        assertFalse(record.toString().contains(fixture.id))
        assertFalse(record.toString().contains(fixture.record.gatewaySpkiSha256))
    }

    @Test fun decoderRejectsUnknownVersionTrailingBytesAndTruncatedRecords() {
        val encoded = EnrolledCredentialCodec.encode(Fixture().record)
        rejected { EnrolledCredentialCodec.decode(encoded + byteArrayOf(0)) }
        val unknownVersion = encoded.copyOf()
        ByteBuffer.wrap(unknownVersion).putInt(4, 2)
        rejected { EnrolledCredentialCodec.decode(unknownVersion) }
        for (length in listOf(0, 1, 7, 8, 12, encoded.size / 2, encoded.lastIndex)) {
            rejected { EnrolledCredentialCodec.decode(encoded.copyOf(length)) }
        }
    }

    @Test fun decoderBoundsLengthsCountsAndAsciiBeforeAllocatingFields() {
        val encoded = EnrolledCredentialCodec.encode(Fixture().record)
        for (length in listOf(-1, 0, 129, Int.MAX_VALUE)) {
            val invalid = encoded.copyOf()
            ByteBuffer.wrap(invalid).putInt(8, length)
            rejected { EnrolledCredentialCodec.decode(invalid) }
        }
        val nonAscii = encoded.copyOf().apply { this[12] = 0x80.toByte() }
        rejected { EnrolledCredentialCodec.decode(nonAscii) }
        val control = encoded.copyOf().apply { this[12] = '\n'.code.toByte() }
        rejected { EnrolledCredentialCodec.decode(control) }
        rejected { EnrolledCredentialCodec.decode(ByteArray(EnrolledCredentialCodec.MAX_RECORD_BYTES + 1)) }
        val countOffset = afterFields(encoded, 5)
        for (count in listOf(-1, 0, 5, Int.MAX_VALUE)) {
            val invalid = encoded.copyOf()
            ByteBuffer.wrap(invalid).putInt(countOffset, count)
            rejected { EnrolledCredentialCodec.decode(invalid) }
        }
    }

    @Test fun decoderRequiresOneCanonicalDerCertificateInsteadOfPemOrTrailingMaterial() {
        val fixture = Fixture()
        val encoded = EnrolledCredentialCodec.encode(fixture.record)
        val der = fixture.gateway.certificate.encoded
        val pem = ("-----BEGIN CERTIFICATE-----\n" + Base64.getEncoder().encodeToString(der) +
            "\n-----END CERTIFICATE-----\n").toByteArray(Charsets.US_ASCII)
        for (invalid in listOf(pem, der + byteArrayOf(0), der + der, der.copyOf().apply { this[0] = 0 })) {
            rejected { EnrolledCredentialCodec.decode(replaceField(encoded, 3, invalid)) }
        }
        val authority = fixture.authority.certificate.encoded
        rejected { EnrolledCredentialCodec.decode(replaceField(encoded, 4, authority + byteArrayOf(0))) }
    }

    @Test(timeout = 5000) fun recordBoundsCertificatesAggregateAndDishonestCollections() {
        val fixture = Fixture()
        rejected { fixture.record(chain = emptyList()) }
        rejected { fixture.record(chain = List(5) { fixture.leaf }) }
        rejected { fixture.record(chain = listOf(TestEnrollmentCertificates.client(
            fixture.keys.public, fixture.authority, paddingBytes = 5000,
        ))) }
        val dishonest = object : AbstractList<X509Certificate>() {
            override val size: Int get() = 1
            override fun get(index: Int): X509Certificate = fixture.leaf
            override fun iterator(): Iterator<X509Certificate> = generateSequence { fixture.leaf }.iterator()
        }
        rejected { fixture.record(chain = dishonest) }
        val root = TestEnrollmentCertificates.authority(pathLength = 4, paddingBytes = 3000)
        val first = TestEnrollmentCertificates.authority("CN=First", root, pathLength = 3, paddingBytes = 3000)
        val second = TestEnrollmentCertificates.authority("CN=Second", first, pathLength = 2, paddingBytes = 3000)
        val third = TestEnrollmentCertificates.authority("CN=Third", second, pathLength = 1, paddingBytes = 3000)
        val leaf = TestEnrollmentCertificates.client(fixture.keys.public, third, paddingBytes = 3000)
        val all = listOf(leaf, third.certificate, second.certificate, first.certificate, root.certificate)
        assertTrue(all.all { it.encoded.size <= 4096 })
        assertTrue(all.sumOf { it.encoded.size } > 16 * 1024)
        rejected { fixture.record(chain = all.dropLast(1), authority = root.certificate) }
    }

    @Test fun aRecordForAnotherComputerCannotBeLoadedThroughTheRequestedRecordName() {
        val fixture = Fixture()
        fixture.store().save(fixture.record)
        val name = fixture.files.entries.keys.single()
        fixture.files.entries[name] = EnrolledCredentialCodec.encode(fixture.record(id = "another-computer"))
        unavailable { fixture.store().load(fixture.id) }
        assertSame(fixture.keys, fixture.state.keys[fixture.id])
    }

    @Test fun corruptAndOversizedPublishedMetadataFailClosed() {
        val fixture = Fixture()
        fixture.store().save(fixture.record)
        val name = fixture.files.entries.keys.single()
        for (bytes in listOf(byteArrayOf(1, 2, 3), ByteArray(EnrolledCredentialCodec.MAX_RECORD_BYTES + 1))) {
            fixture.files.entries[name] = bytes
            unavailable { fixture.store().load(fixture.id) }
            assertSame(fixture.keys, fixture.state.keys[fixture.id])
        }
    }

    @Test fun missingOrReplacedKeysNeverReviveAnOldRecordOrManager() {
        val fixture = Fixture()
        fixture.store().save(fixture.record)
        val original = checkNotNull(fixture.store().load(fixture.id)).clientKeyManager
        val alias = checkNotNull(original.chooseClientAlias(arrayOf("EC"), null, null))
        fixture.state.keys.remove(fixture.id)
        unavailable { fixture.store().load(fixture.id) }
        unavailable { fixture.store().save(fixture.record) }
        assertNull(original.getPrivateKey(alias))
        val replacement = TestEnrollmentCertificates.keyPair()
        fixture.state.keys[fixture.id] = replacement
        unavailable { fixture.store().load(fixture.id) }
        unavailable { fixture.store().save(fixture.record) }
        assertNull(original.chooseClientAlias(arrayOf("EC"), null, null))
        assertSame(replacement, fixture.state.keys[fixture.id])
    }

    @Test fun legacyIdentityFailureDoesNotPreventKeyFirstForget() {
        val fixture = Fixture()
        fixture.store().save(fixture.record)
        fixture.state.legacy = true
        unavailable { fixture.store().load(fixture.id) }
        unavailable { fixture.store().save(fixture.record) }
        fixture.store().forget(fixture.id)
        assertTrue(fixture.state.keys.isEmpty())
        assertTrue(fixture.files.entries.isEmpty())
    }

    @Test fun gatewayPinNameAndExplicitEnrollmentAuthorityAreRevalidatedBeforePublication() {
        val fixture = Fixture()
        val otherGateway = TestEnrollmentCertificates.server()
        val otherAuthority = TestEnrollmentCertificates.authority("CN=Unauthenticated other authority")
        val invalid = listOf(
            fixture.record(pin = pin(otherGateway.certificate)),
            fixture.record(name = "wrong-gateway.invalid"),
            fixture.record(gateway = fixture.authority.certificate, pin = pin(fixture.authority.certificate)),
            fixture.record(authority = otherAuthority.certificate),
            fixture.record(chain = listOf(TestEnrollmentCertificates.client(TestEnrollmentCertificates.keyPair().public, fixture.authority))),
        )
        invalid.forEach { record -> unavailable { fixture.store().save(record) } }
        assertTrue(fixture.files.entries.isEmpty())
        assertSame(fixture.keys, fixture.state.keys[fixture.id])
    }

    @Test fun clientExpiryIsRecheckedOnReopenAndByAnAlreadyLoadedManager() {
        val fixture = Fixture()
        val shortLeaf = TestEnrollmentCertificates.client(
            fixture.keys.public, fixture.authority, notAfter = fixture.clock.instant().plusSeconds(10),
        )
        fixture.store().save(fixture.record(chain = listOf(shortLeaf)))
        val manager = checkNotNull(fixture.store().load(fixture.id)).clientKeyManager
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        fixture.clock.set(shortLeaf.notAfter.toInstant().plusMillis(1))
        unavailable { fixture.store().load(fixture.id) }
        assertNull(manager.getPrivateKey(alias))
        assertNull(manager.getCertificateChain(alias))
    }

    @Test fun gatewayAndAuthorityExpiryFailClosedOnReopen() {
        val gatewayFixture = Fixture()
        val longLeaf = TestEnrollmentCertificates.client(
            gatewayFixture.keys.public, gatewayFixture.authority, notAfter = Instant.now().plusSeconds(86400),
        )
        gatewayFixture.store().save(gatewayFixture.record(chain = listOf(longLeaf)))
        gatewayFixture.clock.set(gatewayFixture.gateway.certificate.notAfter.toInstant().plusMillis(1))
        unavailable { gatewayFixture.store().load(gatewayFixture.id) }
        val authorityFixture = Fixture()
        val shortAuthority = TestEnrollmentCertificates.authority(notAfter = Instant.now().plusSeconds(10))
        val authorityLeaf = TestEnrollmentCertificates.client(authorityFixture.keys.public, shortAuthority)
        authorityFixture.store().save(authorityFixture.record(chain = listOf(authorityLeaf), authority = shortAuthority.certificate))
        authorityFixture.clock.set(shortAuthority.certificate.notAfter.toInstant().plusMillis(1))
        unavailable { authorityFixture.store().load(authorityFixture.id) }
    }

    @Test fun interruptedPublicationKeepsThePreviouslyValidatedRecord() {
        val fixture = Fixture()
        fixture.store().save(fixture.record)
        val old = fixture.files.entries.values.single().copyOf()
        val renewedLeaf = TestEnrollmentCertificates.client(fixture.keys.public, fixture.authority)
        fixture.files.publishFailure = IOException("Interrupted local write")
        unavailable { fixture.store().save(fixture.record(chain = listOf(renewedLeaf))) }
        assertArrayEquals(old, fixture.files.entries.values.single())
        fixture.files.publishFailure = null
        assertArrayEquals(fixture.leaf.encoded, checkNotNull(fixture.store().load(fixture.id)).record.clientCertificateChain.single().encoded)
    }

    @Test fun forgetDeletesTheKeyBeforeMetadataAndCanRecoverAfterCleanupFailure() {
        val fixture = Fixture()
        fixture.store().save(fixture.record)
        fixture.files.deleteFailure = IOException("Interrupted metadata cleanup")
        unavailable { fixture.store().forget(fixture.id) }
        assertTrue(fixture.state.keys.isEmpty())
        assertEquals(1, fixture.files.entries.size)
        unavailable { fixture.store().load(fixture.id) }
        assertEquals(listOf("key-delete", "metadata-delete"), fixture.state.events.takeLast(2))
        fixture.files.deleteFailure = null
        fixture.store().forget(fixture.id)
        fixture.store().forget(fixture.id)
        assertNull(fixture.store().load(fixture.id))
        assertTrue(fixture.files.entries.isEmpty())
    }

    @Test fun failedKeyDeletionLeavesTheValidMetadataIntactUntilForgetCanBeRetried() {
        val fixture = Fixture()
        fixture.store().save(fixture.record)
        val encoded = fixture.files.entries.values.single().copyOf()
        fixture.state.deleteFailure = IllegalStateException("Keystore deletion failed with identifying details")
        val failure = unavailable { fixture.store().forget(fixture.id) }
        assertEquals(EnrolledCredentialError.STORAGE_FAILURE, failure.code)
        assertSame(fixture.keys, fixture.state.keys[fixture.id])
        assertArrayEquals(encoded, fixture.files.entries.values.single())
        assertEquals(listOf("key-delete"), fixture.state.events)
        val manager = checkNotNull(fixture.store().load(fixture.id)).clientKeyManager
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        assertSame(fixture.keys.private, manager.getPrivateKey(alias))
        fixture.state.deleteFailure = null
        fixture.store().forget(fixture.id)
        assertNull(fixture.store().load(fixture.id))
        assertTrue(fixture.files.entries.isEmpty())
        assertNull(manager.getPrivateKey(alias))
    }

    @Test(timeout = 15000) fun saveHoldsTheSharedIdentityTransactionUntilAtomicPublicationCompletes() {
        val fixture = Fixture()
        val first = fixture.store()
        val second = fixture.store()
        val published = CountDownLatch(1)
        val release = CountDownLatch(1)
        val forgetStarted = CountDownLatch(1)
        fixture.files.beforePublish = { published.countDown(); await(release) }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val saving = executor.submit { first.save(fixture.record) }
            await(published)
            val forgetting = executor.submit { forgetStarted.countDown(); second.forget(fixture.id) }
            await(forgetStarted)
            assertFalse(forgetting.isDone)
            assertSame(fixture.keys, fixture.state.keys[fixture.id])
            release.countDown()
            saving.get(5, TimeUnit.SECONDS)
            forgetting.get(5, TimeUnit.SECONDS)
            assertTrue(fixture.state.keys.isEmpty())
            assertNull(first.load(fixture.id))
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test(timeout = 15000) fun saveCannotPublishAfterForgetDeletesTheKeyAcrossStoreInstances() {
        val fixture = Fixture()
        val first = fixture.store()
        val second = fixture.store()
        first.save(fixture.record)
        val deleting = CountDownLatch(1)
        val release = CountDownLatch(1)
        val saveStarted = CountDownLatch(1)
        fixture.files.beforeDelete = { deleting.countDown(); await(release) }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val forgetting = executor.submit { first.forget(fixture.id) }
            await(deleting)
            assertTrue(fixture.state.keys.isEmpty())
            val saving = executor.submit(Callable<Exception?> {
                saveStarted.countDown()
                try { second.save(fixture.record); null } catch (failure: Exception) { failure }
            })
            await(saveStarted)
            assertFalse(saving.isDone)
            release.countDown()
            forgetting.get(5, TimeUnit.SECONDS)
            assertTrue(saving.get(5, TimeUnit.SECONDS) is EnrolledCredentialUnavailableException)
            assertTrue(fixture.files.entries.isEmpty())
            assertNull(second.load(fixture.id))
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test fun publicStorageFailuresDoNotRetainSensitiveMessagesOrCauses() {
        val fixture = Fixture()
        val detail = "/private/app/path ${fixture.id} ${fixture.record.gatewaySpkiSha256}"
        fixture.files.publishFailure = IOException(detail)
        val failure = unavailable { fixture.store().save(fixture.record) }
        assertEquals(EnrolledCredentialError.STORAGE_FAILURE, failure.code)
        assertFalse(failure.message.orEmpty().contains(detail))
        assertFalse(failure.message.orEmpty().contains(fixture.record.gatewaySpkiSha256))
        assertNull(failure.cause)
    }

    @Test fun actualAtomicFilesIgnoreUnpublishedBytesAndReplaceOnlyTheCompleteRecord() {
        val fixture = Fixture()
        val directory = temporary.newFolder("atomic-records")
        val files = AtomicCredentialRecordFiles(directory)
        val name = "a".repeat(64) + ".credential"
        val pending = directory.resolve("$name.interrupted.pending").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        assertNull(files.read(name))
        val encoded = EnrolledCredentialCodec.encode(fixture.record)
        files.publish(name, encoded)
        assertArrayEquals(encoded, files.read(name))
        val renewed = fixture.record(chain = listOf(TestEnrollmentCertificates.client(fixture.keys.public, fixture.authority)))
        val replacement = EnrolledCredentialCodec.encode(renewed)
        files.publish(name, replacement)
        assertArrayEquals(replacement, files.read(name))
        assertTrue(pending.exists())
        val unrelated = directory.resolve("unrelated.pending").apply { writeText("leave this unrelated file") }
        files.delete(name)
        files.delete(name)
        assertNull(files.read(name))
        assertFalse(pending.exists())
        assertTrue(unrelated.exists())
    }

    @Test fun actualAtomicFilesRejectOversizedNonregularAndUnsafeTargets() {
        val directory = temporary.newFolder("bounded-records")
        val files = AtomicCredentialRecordFiles(directory)
        val name = "b".repeat(64) + ".credential"
        directory.resolve(name).writeBytes(ByteArray(EnrolledCredentialCodec.MAX_RECORD_BYTES + 1))
        rejected { files.read(name) }
        rejected { files.publish(name, ByteArray(EnrolledCredentialCodec.MAX_RECORD_BYTES + 1)) }
        files.delete(name)
        val targetDirectory = directory.resolve(name).apply { mkdir() }
        val original = targetDirectory.resolve("original").apply { writeText("retained") }
        rejected { files.read(name) }
        rejected { files.publish(name, byteArrayOf(1)) }
        assertEquals("retained", original.readText())
        assertTrue(directory.listFiles()!!.none { it.name.endsWith(".pending") })
        for (unsafe in listOf("../outside", "../${name}", "${name}/child", "A".repeat(64) + ".credential")) {
            rejected { files.read(unsafe) }
            rejected { files.publish(unsafe, byteArrayOf(1)) }
            rejected { files.delete(unsafe) }
        }
    }

    private class Fixture {
        val id = "test-computer"
        val keys = TestEnrollmentCertificates.keyPair()
        val authority = TestEnrollmentCertificates.authority(notAfter = Instant.now().plusSeconds(172800))
        val gateway = TestEnrollmentCertificates.server()
        val leaf = TestEnrollmentCertificates.client(keys.public, authority)
        val state = IdentityState().apply { this.keys[id] = this@Fixture.keys }
        val files = MemoryFiles(state)
        val clock = MutableClock(Instant.now())
        val record: EnrolledCredentialRecord get() = record()
        fun store() = AndroidEnrolledCredentialStore(FakeIdentities(state), files, clock)
        fun record(
            id: String = this.id,
            gateway: X509Certificate = this.gateway.certificate,
            pin: String = pin(this.gateway.certificate),
            name: String = "gateway-fixture.invalid",
            chain: List<X509Certificate> = listOf(leaf),
            authority: X509Certificate = this.authority.certificate,
        ) = EnrolledCredentialRecord(id, gateway, pin, name, chain, authority)
    }

    private class IdentityState {
        val monitor = Any()
        val keys = ConcurrentHashMap<String, KeyPair>()
        val events = mutableListOf<String>()
        var legacy = false
        var deleteFailure: Exception? = null
    }

    private class FakeIdentities(private val state: IdentityState) : ExistingCredentialIdentities {
        override fun <T> transaction(desktopId: String, operation: () -> T): T = synchronized(state.monitor) { operation() }
        override fun load(desktopId: String): DeviceIdentity? {
            check(Thread.holdsLock(state.monitor)) { "Identity lookup escaped the shared transaction" }
            check(!state.legacy) { "Legacy identity cannot authenticate TLS" }
            val keys = state.keys[desktopId] ?: return null
            return DeviceIdentity(keys.public, keys.private) {
                synchronized(state.monitor) { state.keys[desktopId] === keys }
            }
        }
        override fun delete(desktopId: String) {
            check(Thread.holdsLock(state.monitor)) { "Identity deletion escaped the shared transaction" }
            state.events += "key-delete"
            state.deleteFailure?.let { throw it }
            state.keys.remove(desktopId)
        }
    }

    private class MemoryFiles(private val state: IdentityState) : CredentialRecordFiles {
        val entries = ConcurrentHashMap<String, ByteArray>()
        var publishFailure: IOException? = null
        var deleteFailure: IOException? = null
        var beforePublish: (() -> Unit)? = null
        var beforeDelete: (() -> Unit)? = null
        override fun read(name: String): ByteArray? {
            check(Thread.holdsLock(state.monitor)) { "Record read escaped the shared transaction" }
            return entries[name]?.copyOf()
        }
        override fun publish(name: String, encoded: ByteArray) {
            check(Thread.holdsLock(state.monitor)) { "Record publication escaped the shared transaction" }
            beforePublish?.invoke()
            publishFailure?.let { throw it }
            entries[name] = encoded.copyOf()
        }
        override fun delete(name: String) {
            check(Thread.holdsLock(state.monitor)) { "Record deletion escaped the shared transaction" }
            check(!entries.containsKey(name) || state.keys.isEmpty()) { "Metadata deletion preceded identity deletion" }
            state.events += "metadata-delete"
            beforeDelete?.invoke()
            deleteFailure?.let { throw it }
            entries.remove(name)
        }
    }

    private class MutableClock(initial: Instant) : Clock() {
        private val current = AtomicReference(initial)
        fun set(value: Instant) { current.set(value) }
        override fun instant(): Instant = current.get()
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
    }

    private companion object {
        fun pin(certificate: X509Certificate): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded),
        )
        fun afterFields(encoded: ByteArray, count: Int): Int {
            val buffer = ByteBuffer.wrap(encoded)
            buffer.position(8)
            repeat(count) { val length = buffer.int; buffer.position(buffer.position() + length) }
            return buffer.position()
        }
        fun replaceField(encoded: ByteArray, index: Int, value: ByteArray): ByteArray {
            val offset = afterFields(encoded, index)
            val originalLength = ByteBuffer.wrap(encoded).getInt(offset)
            return encoded.copyOfRange(0, offset) + ByteBuffer.allocate(4).putInt(value.size).array() +
                value + encoded.copyOfRange(offset + 4 + originalLength, encoded.size)
        }
        fun await(latch: CountDownLatch) {
            assertTrue("Controlled transaction did not reach its gate", latch.await(5, TimeUnit.SECONDS))
        }
        fun unavailable(operation: () -> Unit): EnrolledCredentialUnavailableException {
            try { operation() } catch (failure: EnrolledCredentialUnavailableException) { return failure }
            throw AssertionError("Expected an unusable saved credential")
        }
        fun rejected(operation: () -> Unit) {
            try { operation() } catch (_: Exception) { return }
            throw AssertionError("Expected bounded credential rejection")
        }
    }
}
