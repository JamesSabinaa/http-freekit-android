package com.httpfreekit.interop

import android.content.Context
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.security.AndroidDeviceIdentityStore
import com.httpfreekit.security.AndroidEnrolledCredentialStore
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Instant
import org.junit.Test
import org.junit.runner.RunWith

/** Runs between the original A22 prepare/restart and reopen/Forget invocations. */
@RunWith(AndroidJUnit4::class)
class DraftInterceptionCaInteropTest {
    private var phase = "saved-key-approval-validated"

    @Test(timeout = 60000) fun retrieveSavedApprovedCaAfterRestart() {
        var first: DraftInterceptionCaClient? = null
        var second: DraftInterceptionCaClient? = null
        var failure: Throwable? = null
        var cleanup = true
        try {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val files = DraftEnrollmentResearchFiles(context)
            val recovery = files.readRecovery()
            val recoveryBefore = DraftEnrollmentStateCodec.encodeRecovery(recovery)
            val before = evidence(context, recovery)
            val dial = InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), recovery.credentialPort)
            val getter = DraftInterceptionCaSavedCredential.open(context, recovery, dial).also { first = it }
            requireIdle(getter.snapshot(), closed = false)
            mark("saved-key-approval-validated")

            var attempts = 0
            attempts++ // The only fetch invocation; the second lookup below performs no request.
            val ca = getter.fetch()
            val der = ca.certificateDer
            val approvedHashMatched = MessageDigest.isEqual(DraftInterceptionCaChecks.hash(der), recovery.interceptionCaCertificateSha256) &&
                MessageDigest.isEqual(ca.certificateSha256, recovery.interceptionCaCertificateSha256)
            DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.RESPONSE) {
                check(der.size in 1..4096 && approvedHashMatched)
                check(ca.certificate.encoded.contentEquals(der))
                ca.certificate.checkValidity()
            }
            mark("ca-fetched-and-bound")
            getter.close()
            val firstClosed = getter.snapshot().also { requireIdle(it, closed = true) }
            first = null

            val freshRecovery = files.readRecovery()
            check(recoveryBefore.contentEquals(DraftEnrollmentStateCodec.encodeRecovery(freshRecovery)))
            val fresh = DraftInterceptionCaSavedCredential.open(context, freshRecovery, dial).also { second = it }
            requireIdle(fresh.snapshot(), closed = false)
            val after = evidence(context, freshRecovery)
            fresh.close()
            val secondClosed = fresh.snapshot().also { requireIdle(it, closed = true) }
            second = null
            val recoveryAfter = DraftEnrollmentStateCodec.encodeRecovery(files.readRecovery())
            val recoveryUnchanged = recoveryBefore.contentEquals(recoveryAfter)
            val originalKeyUnchanged = before.spki.contentEquals(after.spki) && equalHashes(before.originalHashes, after.originalHashes)
            val leafUnchanged = before.leaf.contentEquals(after.leaf)
            val nonexportable = before.nonexportable && after.nonexportable
            check(attempts == 1 && recoveryUnchanged && originalKeyUnchanged && leafUnchanged && nonexportable)
            mark("getter-resources-joined")

            // Emitted only after actual fetch, continuity checks and both independent client joins.
            InstrumentationRegistry.getInstrumentation().sendStatus(3, Bundle().apply {
                putString("draftCaVersion", "1")
                putString("draftCaFetchAttempts", attempts.toString())
                putString("draftCaCaBytes", der.size.toString())
                putString("draftCaSavedApprovalValidated", (before.approvalValidated && after.approvalValidated).toString())
                putString("draftCaOriginalKeyUnchanged", originalKeyUnchanged.toString())
                putString("draftCaPrivateKeyNonexportable", nonexportable.toString())
                putString("draftCaRecoveryUnchanged", recoveryUnchanged.toString())
                putString("draftCaApprovedCaHashMatched", approvedHashMatched.toString())
                putString("draftCaCredentialLeafUnchanged", leafUnchanged.toString())
                putString("draftCaFreshLookupAfterFetch", secondClosed.closed.toString())
                putString("draftCaClosed", (firstClosed.closed && secondClosed.closed).toString())
                putString("draftCaActiveCall", (firstClosed.activeCall || secondClosed.activeCall).toString())
                putString("draftCaRawSocketOwned", (firstClosed.rawSocketOwned || secondClosed.rawSocketOwned).toString())
                putString("draftCaTlsSocketOwned", (firstClosed.tlsSocketOwned || secondClosed.tlsSocketOwned).toString())
                putString("draftCaDeadlineAlive", (firstClosed.deadlineAlive || secondClosed.deadlineAlive).toString())
                putString("draftCaTlsCloserAlive", (firstClosed.tlsCloserAlive || secondClosed.tlsCloserAlive).toString())
                putString("draftCaCleanupFailed", (firstClosed.cleanupFailed || secondClosed.cleanupFailed).toString())
            })
        } catch (caught: Exception) { failure = caught }
        catch (caught: AssertionError) { failure = caught }
        finally {
            for (client in listOfNotNull(first, second)) {
                try { client.close(); requireIdle(client.snapshot(), closed = true) }
                catch (caught: Exception) { cleanup = false; if (failure == null) failure = caught }
                catch (caught: AssertionError) { cleanup = false; if (failure == null) failure = caught }
            }
        }
        failure?.let { throw redacted(it, cleanup) }
    }

    private class Evidence(
        val spki: ByteArray, val originalHashes: List<ByteArray>, val leaf: ByteArray,
        val nonexportable: Boolean, val approvalValidated: Boolean,
    ) {
        override fun toString() = "SavedCaEvidence([REDACTED])"
    }

    private fun evidence(context: Context, recovery: DraftEnrollmentRecovery): Evidence =
        DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.BINDING) {
            val identity = checkNotNull(AndroidDeviceIdentityStore().load(recovery.desktopId))
            val loaded = checkNotNull(AndroidEnrolledCredentialStore(context).load(recovery.desktopId))
            val record = loaded.record
            val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val candidates = ArrayList<String>(2); val aliases = keys.aliases(); var scanned = 0
            while (aliases.hasMoreElements()) {
                check(scanned++ < 64)
                val alias = aliases.nextElement()
                if (keys.getCertificate(alias)?.publicKey?.encoded?.contentEquals(identity.publicKey.encoded) == true) {
                    candidates += alias; check(candidates.size == 1)
                }
            }
            val entry = keys.getEntry(candidates.single(), null) as KeyStore.PrivateKeyEntry
            val original = DraftInterceptionCaChecks.chain(entry.certificateChain.also { check(it.size in 1..4) }.map { it as X509Certificate })
            val hashes = original.map { DraftInterceptionCaChecks.hash(it.encoded) }
            val spki = identity.publicKey.encoded.copyOf()
            val leaf = record.clientCertificateChain.single().encoded
            val alias = checkNotNull(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null))
            val nonexportable = entry.privateKey.encoded == null && checkNotNull(loaded.clientKeyManager.getPrivateKey(alias)).encoded == null
            val validated = record.desktopId == recovery.desktopId && record.logicalServerName == recovery.logicalName &&
                record.gatewaySpkiSha256 == recovery.gatewaySpkiSha256 && spki.contentEquals(recovery.originalDeviceSpki) &&
                original.first().publicKey.encoded.contentEquals(spki) && equalHashes(hashes, recovery.originalKeystoreCertificateHashes) &&
                MessageDigest.isEqual(DraftInterceptionCaChecks.hash(leaf), recovery.clientCertificateSha256) &&
                MessageDigest.isEqual(DraftInterceptionCaChecks.hash(record.authenticatedEnrollmentAuthority.encoded), recovery.authorityCertificateSha256) &&
                record.clientCertificateChain.single().notAfter.toInstant() == Instant.parse(recovery.credentialExpiresAt)
            check(validated && nonexportable)
            Evidence(spki, hashes, leaf, nonexportable, validated)
        }

    private fun equalHashes(a: List<ByteArray>, b: List<ByteArray>) =
        a.size == b.size && a.indices.all { MessageDigest.isEqual(a[it], b[it]) }

    private fun requireIdle(snapshot: DraftInterceptionCaClientSnapshot, closed: Boolean) {
        if (snapshot.closed != closed || snapshot.activeCall || snapshot.rawSocketOwned || snapshot.tlsSocketOwned ||
            snapshot.deadlineAlive || snapshot.tlsCloserAlive || snapshot.cleanupFailed)
            throw DraftInterceptionCaException(DraftInterceptionCaFailure.CLEANUP)
    }

    private fun mark(value: String) {
        phase = value
        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
            putString("draftCaVersion", "1"); putString("draftCaPhase", value)
        })
    }

    private fun redacted(failure: Throwable, cleanup: Boolean): AssertionError {
        val type = when (failure) {
            is DraftInterceptionCaException -> failure.code.name
            is AssertionError -> "ASSERTION"
            else -> "OTHER"
        }
        val result = AssertionError("Interception CA research failed at $phase ($type); cleanup=$cleanup.")
        val roots = mapOf(
            "DraftInterceptionCaInteropTest.kt" to setOf("DraftInterceptionCaInteropTest"),
            "DraftInterceptionCaSavedCredential.kt" to setOf("DraftInterceptionCaSavedCredential"),
            "DraftInterceptionCaBinding.kt" to setOf("DraftInterceptionCaBinding", "DraftInterceptionCaChecks", "DraftInterceptionCaException", "DraftInterceptionCa"),
            "DraftInterceptionCaClient.kt" to setOf("DraftInterceptionCaClient", "DraftInterceptionCaClientSnapshot"),
            "DraftInterceptionCaDer.kt" to setOf("DraftInterceptionCaDer"),
            "DraftEnrollmentResearchFiles.kt" to setOf("DraftEnrollmentResearchFiles"),
            "DraftEnrollmentStateCodec.kt" to setOf("DraftEnrollmentStateCodec", "DraftEnrollmentStateChecks", "DraftEnrollmentStateException", "DraftEnrollmentRecovery"),
        )
        val sites = failure.stackTrace.take(128).filter { site ->
            site.className.substringAfterLast('.').substringBefore('$') in roots[site.fileName].orEmpty() &&
                site.lineNumber in 1..100000 && Regex("com\\.httpfreekit\\.interop\\.Draft[A-Za-z0-9_.$]{0,192}").matches(site.className) &&
                Regex("[A-Za-z0-9_$<>-]{1,128}").matches(site.methodName)
        }.take(16)
        result.stackTrace = if (sites.isNotEmpty()) sites.toTypedArray() else arrayOf(StackTraceElement(
            "com.httpfreekit.interop.DraftInterceptionCaInteropTest", "retrieveSavedApprovedCaAfterRestart", "DraftInterceptionCaInteropTest.kt", 1))
        return result
    }
}
