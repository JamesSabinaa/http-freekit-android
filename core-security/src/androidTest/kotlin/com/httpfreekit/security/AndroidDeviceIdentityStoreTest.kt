package com.httpfreekit.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.pkcs.CertificationRequest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Must run on Android; JVM substitutes are not evidence of Keystore behavior. */
@RunWith(AndroidJUnit4::class)
class AndroidDeviceIdentityStoreTest {
    @Test fun nonexportableIdentitySurvivesReopenSignsAndCanBeForgotten() {
        val desktopId = "test-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            assertNull(store.load(desktopId))
            val identity = store.create(desktopId)
            val reopened = checkNotNull(AndroidDeviceIdentityStore().load(desktopId))
            assertArrayEquals(identity.publicKey.encoded, reopened.publicKey.encoded)
            val challenge = ByteArray(32) { it.toByte() }
            val signature = reopened.signChallenge(challenge)
            assertTrue(Signature.getInstance("SHA256withECDSA").run {
                initVerify(identity.publicKey)
                update(challenge)
                verify(signature)
            })
            val request = CertificationRequest.getInstance(reopened.enrollmentRequest())
            assertArrayEquals(identity.publicKey.encoded, request.certificationRequestInfo.subjectPublicKeyInfo.encoded)
            assertTrue(Signature.getInstance("SHA256withECDSA").run {
                initVerify(identity.publicKey)
                update(request.certificationRequestInfo.getEncoded(ASN1Encoding.DER))
                verify(request.signature.octets)
            })
            store.delete(desktopId)
            assertNull(AndroidDeviceIdentityStore().load(desktopId))
        } finally { store.delete(desktopId) }
    }

    @Test fun creationNeverSilentlyReplacesAnExistingComputerKey() {
        val desktopId = "test-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            val first = store.create(desktopId)
            var rejected = false
            try { store.create(desktopId) } catch (_: IllegalStateException) { rejected = true }
            assertTrue(rejected)
            assertArrayEquals(first.publicKey.encoded, checkNotNull(store.load(desktopId)).publicKey.encoded)
            assertFalse(first.toString().contains(desktopId))
        } finally { store.delete(desktopId) }
    }

    @Test fun concurrentStoreInstancesCannotReplaceTheWinningKey() {
        val desktopId = "test-${UUID.randomUUID()}"
        val stores = List(2) { AndroidDeviceIdentityStore() }
        val ready = CountDownLatch(2)
        val start = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(2)
        try {
            val attempts = stores.map { store -> workers.submit<DeviceIdentity?> {
                ready.countDown()
                start.await()
                try { store.create(desktopId) } catch (_: IllegalStateException) { null }
            } }
            assertTrue(ready.await(10, TimeUnit.SECONDS))
            start.countDown()
            val winners = attempts.mapNotNull { it.get(30, TimeUnit.SECONDS) }
            assertTrue(winners.size == 1)
            assertArrayEquals(winners.single().publicKey.encoded, checkNotNull(stores.first().load(desktopId)).publicKey.encoded)
        } finally {
            start.countDown()
            workers.shutdownNow()
            workers.awaitTermination(10, TimeUnit.SECONDS)
            stores.first().delete(desktopId)
        }
    }

    @Test(timeout = 30000) fun freshIdentityAuthorizesPrehashedTlsSigningWithoutExportingItsKey() {
        val desktopId = "tls-digest-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            val identity = store.create(desktopId)
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = aliasForPublicKey(keyStore, identity.publicKey.encoded)
            val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            assertNull(entry.privateKey.encoded)
            val info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(entry.privateKey, KeyInfo::class.java)
            assertEquals(setOf(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256), info.digests.toSet())
            val message = "Controlled TLS prehash signing proof".toByteArray(Charsets.US_ASCII)
            val digest = MessageDigest.getInstance("SHA-256").digest(message)
            val signature = Signature.getInstance("NONEwithECDSA").run {
                initSign(entry.privateKey)
                update(digest)
                sign()
            }
            assertTrue(Signature.getInstance("SHA256withECDSA").run {
                initVerify(identity.publicKey)
                update(message)
                verify(signature)
            })
            assertNull(entry.privateKey.encoded)
            assertArrayEquals(identity.publicKey.encoded, checkNotNull(store.load(desktopId)).publicKey.encoded)
        } finally { store.delete(desktopId) }
    }

    @Test(timeout = 30000) fun legacySha256OnlyIdentityRequiresPairingAgainWithoutReplacement() {
        val desktopId = "legacy-digest-${UUID.randomUUID()}"
        val store = AndroidDeviceIdentityStore()
        try {
            // Discover only this test's alias through its public key, without duplicating alias derivation.
            val initial = store.create(desktopId)
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = aliasForPublicKey(keyStore, initial.publicKey.encoded)
            store.delete(desktopId)
            val legacy = KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
                initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build())
            }.generateKeyPair()
            val certificates = keyStore.getCertificateChain(alias).map { it.encoded }
            listOf(store, AndroidDeviceIdentityStore()).forEach { reader ->
                var failure: IllegalStateException? = null
                try { reader.load(desktopId) } catch (rejected: IllegalStateException) { failure = rejected }
                assertEquals("Device identity cannot authenticate TLS; pair again", failure?.message)
            }
            var replacementRejected = false
            try { store.create(desktopId) } catch (_: IllegalStateException) { replacementRejected = true }
            assertTrue(replacementRejected)
            assertTrue(keyStore.containsAlias(alias))
            assertArrayEquals(legacy.public.encoded, keyStore.getCertificate(alias).publicKey.encoded)
            val after = keyStore.getCertificateChain(alias).map { it.encoded }
            assertEquals(certificates.size, after.size)
            certificates.zip(after).forEach { (before, current) -> assertArrayEquals(before, current) }
            assertNull(keyStore.getKey(alias, null).encoded)
        } finally { store.delete(desktopId) }
    }

    private fun aliasForPublicKey(keyStore: KeyStore, encoded: ByteArray): String =
        Collections.list(keyStore.aliases()).single { keyStore.getCertificate(it)?.publicKey?.encoded?.contentEquals(encoded) == true }
}
