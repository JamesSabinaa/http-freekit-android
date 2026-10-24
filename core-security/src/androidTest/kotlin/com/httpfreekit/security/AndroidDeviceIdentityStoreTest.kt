package com.httpfreekit.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.Signature
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.pkcs.CertificationRequest
import org.junit.Assert.assertArrayEquals
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
}
