package com.httpfreekit.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real Keystore/filesystem cases; compiling them does not establish Android execution. */
@RunWith(AndroidJUnit4::class)
class AndroidEnrolledCredentialStoreTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val directory get() = File(context.noBackupFilesDir, "enrolled-credentials-v1")

    @Test fun reopenedPublicRecordUsesTheOriginalNonexportableKeyWithoutReplacingItsCertificate() {
        val id = "persist-${UUID.randomUUID()}"
        val identities = AndroidDeviceIdentityStore()
        val store = AndroidEnrolledCredentialStore(context)
        try {
            val identity = identities.create(id)
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = Collections.list(keyStore.aliases()).single {
                keyStore.getCertificate(it)?.publicKey?.encoded?.contentEquals(identity.publicKey.encoded) == true
            }
            val before = keyStore.getCertificateChain(alias).map { it.encoded }
            val record = record(id, identity)
            store.save(record)
            val reopened = checkNotNull(AndroidEnrolledCredentialStore(context).load(id))
            assertEquals(context.noBackupFilesDir.canonicalFile, directory.parentFile?.canonicalFile)
            assertArrayEquals(record.gatewayCertificate.encoded, reopened.record.gatewayCertificate.encoded)
            val manager = reopened.clientKeyManager
            val clientAlias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
            val originalHandle = checkNotNull(manager.getPrivateKey(clientAlias))
            assertNull(originalHandle.encoded)
            assertSame(originalHandle, manager.getPrivateKey(clientAlias))
            assertArrayEquals(identity.publicKey.encoded, manager.getCertificateChain(clientAlias)!!.first().publicKey.encoded)
            val challenge = ByteArray(32) { it.toByte() }
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(originalHandle); update(challenge); sign()
            }
            assertTrue(Signature.getInstance("SHA256withECDSA").run {
                initVerify(identity.publicKey); update(challenge); verify(signature)
            })
            val after = keyStore.getCertificateChain(alias).map { it.encoded }
            assertEquals(before.size, after.size)
            before.zip(after).forEach { (first, second) -> assertArrayEquals(first, second) }
            assertArrayEquals(identity.publicKey.encoded, checkNotNull(identities.load(id)).publicKey.encoded)
        } finally { store.forget(id) }
    }

    @Test fun missingReplacedAndLegacyKeysCannotReopenOrPreventForget() {
        val id = "persist-key-${UUID.randomUUID()}"
        val identities = AndroidDeviceIdentityStore()
        val store = AndroidEnrolledCredentialStore(context)
        try {
            val original = identities.create(id)
            val record = record(id, original)
            store.save(record)
            identities.delete(id)
            unavailable { store.load(id) }
            assertNull(identities.load(id))
            val replacement = identities.create(id)
            unavailable { store.load(id) }
            assertArrayEquals(replacement.publicKey.encoded, checkNotNull(identities.load(id)).publicKey.encoded)
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = Collections.list(keyStore.aliases()).single {
                keyStore.getCertificate(it)?.publicKey?.encoded?.contentEquals(replacement.publicKey.encoded) == true
            }
            identities.delete(id)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false).build())
            }.generateKeyPair()
            unavailable { store.load(id) }
            // The transaction must not call load() before deletion of an unusable legacy alias.
            store.forget(id)
            store.forget(id)
            assertNull(identities.load(id))
            assertNull(store.load(id))
        } finally { store.forget(id) }
    }

    @Test fun interruptedAndCorruptRecordsNeverGenerateOrReplaceTheExistingKey() {
        val id = "persist-file-${UUID.randomUUID()}"
        val identities = AndroidDeviceIdentityStore()
        val store = AndroidEnrolledCredentialStore(context)
        try {
            val identity = identities.create(id)
            store.save(record(id, identity))
            val published = File(directory, name(id))
            val original = published.readBytes()
            val pending = File(directory, "${name(id)}.interrupted.pending")
            pending.writeBytes(byteArrayOf(1, 2, 3))
            assertArrayEquals(identity.publicKey.encoded,
                checkNotNull(store.load(id)).record.clientCertificateChain.first().publicKey.encoded)
            published.writeBytes(original.copyOf(original.size / 2))
            unavailable { store.load(id) }
            assertArrayEquals(identity.publicKey.encoded, checkNotNull(identities.load(id)).publicKey.encoded)
            published.writeBytes(original)
            assertTrue(store.load(id) != null)
            store.forget(id)
            assertFalse(pending.exists())
            assertNull(identities.load(id))
            assertNull(store.load(id))
        } finally { store.forget(id) }
    }

    @Test fun failedMetadataCleanupLeavesTheDeletedKeyUnusableAndCanBeRetried() {
        val id = "persist-forget-${UUID.randomUUID()}"
        val identities = AndroidDeviceIdentityStore()
        val store = AndroidEnrolledCredentialStore(context)
        try {
            store.save(record(id, identities.create(id)))
            val files = AtomicCredentialRecordFiles(directory)
            val failedDelete = object : CredentialRecordFiles by files {
                override fun delete(name: String) {
                    assertNull(identities.load(id))
                    throw IOException("Sensitive provider/path detail must not escape")
                }
            }
            val failing = AndroidEnrolledCredentialStore(access(identities), failedDelete)
            val failure = unavailable { failing.forget(id) }
            assertEquals(EnrolledCredentialError.STORAGE_FAILURE, failure.code)
            assertNull(failure.cause)
            assertFalse(failure.toString().contains("Sensitive"))
            assertNull(identities.load(id))
            assertTrue(File(directory, name(id)).isFile)
            unavailable { store.load(id) }
            store.forget(id)
            store.forget(id)
            assertNull(store.load(id))
        } finally { store.forget(id) }
    }

    @Test(timeout = 30000) fun separateStoreInstancesSerializePublicationAndForgetWithTheIdentityMonitor() {
        val id = "persist-race-${UUID.randomUUID()}"
        val identities = AndroidDeviceIdentityStore()
        val store = AndroidEnrolledCredentialStore(context)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val saved = CompletableFuture<Unit>()
        val forgotten = CompletableFuture<Unit>()
        var writer: Thread? = null
        var remover: Thread? = null
        try {
            val record = record(id, identities.create(id))
            val files = AtomicCredentialRecordFiles(directory)
            val blocked = object : CredentialRecordFiles by files {
                override fun publish(name: String, encoded: ByteArray) {
                    entered.countDown()
                    check(release.await(10, TimeUnit.SECONDS)) { "Fixture publication was not released" }
                    files.publish(name, encoded)
                }
            }
            val savingStore = AndroidEnrolledCredentialStore(access(identities), blocked)
            val forgettingStore = AndroidEnrolledCredentialStore(context)
            writer = Thread({
                try { savingStore.save(record); saved.complete(Unit) }
                catch (failure: Throwable) { saved.completeExceptionally(failure) }
            }, "freekit-record-save").apply { isDaemon = true; start() }
            assertTrue(entered.await(10, TimeUnit.SECONDS))
            val started = CountDownLatch(1)
            remover = Thread({
                started.countDown()
                try { forgettingStore.forget(id); forgotten.complete(Unit) }
                catch (failure: Throwable) { forgotten.completeExceptionally(failure) }
            }, "freekit-record-forget").apply { isDaemon = true; start() }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            val contentionDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (remover.state != Thread.State.BLOCKED && !forgotten.isDone && System.nanoTime() < contentionDeadline) {
                Thread.sleep(1)
            }
            assertEquals("Forget did not contend for the live identity monitor", Thread.State.BLOCKED, remover.state)
            assertFalse(forgotten.isDone)
            release.countDown()
            saved.get(10, TimeUnit.SECONDS)
            forgotten.get(10, TimeUnit.SECONDS)
            assertNull(identities.load(id))
            assertNull(store.load(id))
        } finally {
            release.countDown()
            writer?.join(10000)
            remover?.join(10000)
            check(writer?.isAlive != true && remover?.isAlive != true) { "Credential fixture workers did not stop" }
            store.forget(id)
        }
    }

    private fun record(id: String, identity: DeviceIdentity): EnrolledCredentialRecord {
        val gateway = TestEnrollmentCertificates.server()
        val authority = TestEnrollmentCertificates.authority()
        val pin = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(gateway.keys.public.encoded))
        return EnrolledCredentialRecord(id, gateway.certificate, pin, "gateway-fixture.invalid",
            listOf(TestEnrollmentCertificates.client(identity.publicKey, authority)), authority.certificate)
    }

    private fun name(id: String): String = MessageDigest.getInstance("SHA-256")
        .digest(id.toByteArray(Charsets.US_ASCII)).joinToString("") { "%02x".format(it) } + ".credential"

    private fun access(store: AndroidDeviceIdentityStore): ExistingCredentialIdentities = object : ExistingCredentialIdentities {
        override fun <T> transaction(desktopId: String, operation: () -> T): T =
            store.withExistingIdentityTransaction(desktopId, operation)
        override fun load(desktopId: String): DeviceIdentity? = store.load(desktopId)
        override fun delete(desktopId: String) = store.delete(desktopId)
    }

    private fun unavailable(action: () -> Any?): EnrolledCredentialUnavailableException {
        try { action() } catch (expected: EnrolledCredentialUnavailableException) { return expected }
        throw AssertionError("An unusable credential was accepted")
    }
}
