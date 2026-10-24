package com.httpfreekit.interop

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.protocol.*
import com.httpfreekit.security.AndroidDeviceIdentityStore
import com.httpfreekit.security.AndroidEnrolledCredentialStore
import com.httpfreekit.security.DeviceIdentity
import com.httpfreekit.security.EnrolledCredentialRecord
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import java.util.Collections
import org.junit.Test
import org.junit.runner.RunWith

/** A22a only: separate real invocations with a driver-observed package/host-worker stop between. */
@RunWith(AndroidJUnit4::class)
class DraftEnrollmentInteropTest {
    private var phase = "input-consumed"

    @Test(timeout = 180000) fun prepareApprovedCredentialForRestart() = safe {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val files = DraftEnrollmentResearchFiles(context)
        val seed = files.consumeInput()
        mark("input-consumed")
        val identities = AndroidDeviceIdentityStore()
        val credentials = AndroidEnrolledCredentialStore(context)
        var created = false
        var retained = false
        var client: DraftEnrollmentHttpsClient? = null
        try {
            check(identities.load(seed.desktopId) == null && credentials.load(seed.desktopId) == null) { "Research identity already exists" }
            created = true // Cleanup owns a partial generation too, after proving the alias absent.
            val identity = identities.create(seed.desktopId)
            val before = keyEvidence(identity)
            val gateway = DraftEnrollmentHttpsClient.certificate(seed.gatewayCertificateDer)
            client = DraftEnrollmentHttpsClient(gateway, seed.gatewaySpkiSha256, seed.logicalName, seed.setupPort, seed.credentialPort)
            val registration = client.exchange(pair(seed, identity)) as? DraftEnrollmentMessage.Registered
                ?: error("Strict CSR reservation was not registered")
            val deviceHash = hash(identity.publicKey.encoded)
            check(registration.desktopId == seed.desktopId && registration.invitationId == seed.invitationId &&
                registration.deviceSpkiSha256 == b64(deviceHash) && registration.reservationExpiresAt == seed.invitationExpiresAt &&
                Instant.now().isBefore(Instant.parse(registration.resultExpiresAt))) { "Registration context mismatch" }
            val retry = client.exchange(pair(seed, identity)) as? DraftEnrollmentMessage.Registered
                ?: error("Same-key reservation retry failed")
            check(registration.material() == retry.material()) { "Same-key retry replaced the review" }
            seed.clearInvitationSecret()
            mark("strict-csr-reserved")
            val proof = ProofSession(client, identity, seed.desktopId, seed.gatewaySpkiSha256, seed.invitationId,
                registration.enrollmentId, registration.reservationExpiresAt)
            check(proof.status() is DraftEnrollmentMessage.Pending) { "Unapproved enrollment was not pending" }
            mark("pending-proof-observed")
            mark("awaiting-host-approval")
            val until = System.nanoTime() + 60_000_000_000
            var lost = false
            var approved: DraftEnrollmentMessage.Approved? = null
            while (approved == null) {
                check(System.nanoTime() < until) { "Host approval/recovery deadline elapsed" }
                try {
                    when (val reply = proof.status()) {
                        is DraftEnrollmentMessage.Pending -> Thread.sleep(reply.retryAfterMillis.toLong())
                        is DraftEnrollmentMessage.Approved -> {
                            check(lost) { "Approved response was not lost before recovery" }
                            approved = reply
                        }
                        else -> error("Enrollment approval ended unexpectedly")
                    }
                } catch (_: DraftEnrollmentResponseLost) {
                    check(!lost) { "More than one enrollment response was lost" }
                    lost = true
                }
            }
            val exact = checkNotNull(approved)
            val certificates = validateApproved(exact, identity, seed.desktopId, registration.enrollmentId,
                registration.resultExpiresAt)
            val record = EnrolledCredentialRecord(seed.desktopId, gateway, seed.gatewaySpkiSha256, seed.logicalName,
                listOf(certificates.first), certificates.second)
            val recovery = DraftEnrollmentRecovery(seed.setupPort, seed.credentialPort, seed.desktopId,
                unb64(seed.gatewaySpkiSha256), seed.logicalName, seed.invitationId, registration.enrollmentId,
                exact.deviceId, identity.publicKey.encoded, before, hash(certificates.first.encoded), hash(certificates.second.encoded),
                unb64(exact.interceptionCaCertificateSha256), exact.capabilities, registration.reservationExpiresAt,
                registration.resultExpiresAt, exact.credentialExpiresAt)
            sameHashes(before, keyEvidence(identity))
            mark("approved-result-validated")
            credentials.save(record)
            val saved = checkNotNull(AndroidEnrolledCredentialStore(context).load(seed.desktopId))
            check(saved.record.clientCertificateChain.single().encoded.contentEquals(certificates.first.encoded)) { "Saved leaf changed" }
            files.saveRecovery(recovery)
            mark("credential-persisted")
            client.close()
            client = null
            mark("prepare-resources-closed")
            retained = true
        } finally {
            seed.clearInvitationSecret()
            var failed = false
            fun attempt(action: () -> Unit) { try { action() } catch (_: Exception) { failed = true } catch (_: AssertionError) { failed = true } }
            attempt { client?.close() }
            if (!retained && created) {
                attempt { credentials.forget(seed.desktopId) }
                attempt { files.clearRecovery() }
            }
            check(!failed) { "Enrollment prepare cleanup failed" }
        }
    }

    @Test(timeout = 90000) fun reopenApprovedCredentialAfterRestart() = safe {
        phase = "reopen-key-and-record-validated"
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val files = DraftEnrollmentResearchFiles(context)
        val recovery = files.readRecovery()
        val identities = AndroidDeviceIdentityStore()
        val credentials = AndroidEnrolledCredentialStore(context)
        var owned = false
        var client: DraftEnrollmentHttpsClient? = null
        try {
            val identity = checkNotNull(identities.load(recovery.desktopId)) { "Original enrollment key is missing" }
            val loaded = checkNotNull(credentials.load(recovery.desktopId)) { "Saved enrollment credential is missing" }
            val record = loaded.record
            check(record.desktopId == recovery.desktopId && record.gatewaySpkiSha256 == recovery.gatewaySpkiSha256 &&
                record.logicalServerName == recovery.logicalName && identity.publicKey.encoded.contentEquals(recovery.originalDeviceSpki) &&
                hash(record.clientCertificateChain.single().encoded).contentEquals(recovery.clientCertificateSha256) &&
                hash(record.authenticatedEnrollmentAuthority.encoded).contentEquals(recovery.authorityCertificateSha256)) { "Reopened enrollment binding changed" }
            sameHashes(recovery.originalKeystoreCertificateHashes, keyEvidence(identity))
            owned = true
            client = DraftEnrollmentHttpsClient(record.gatewayCertificate, record.gatewaySpkiSha256, record.logicalServerName,
                recovery.setupPort, recovery.credentialPort)
            mark("reopen-key-and-record-validated")
            val proof = ProofSession(client, identity, recovery.desktopId, recovery.gatewaySpkiSha256, recovery.invitationId,
                recovery.enrollmentId, recovery.reservationExpiresAt)
            val approved = proof.status() as? DraftEnrollmentMessage.Approved ?: error("Reopened status did not recover approval")
            val certificates = validateApproved(approved, identity, recovery.desktopId, recovery.enrollmentId, recovery.resultExpiresAt)
            check(approved.deviceId == recovery.deviceId && approved.capabilities.sorted() == recovery.capabilities &&
                approved.credentialExpiresAt == recovery.credentialExpiresAt &&
                unb64(approved.interceptionCaCertificateSha256).contentEquals(recovery.interceptionCaCertificateSha256) &&
                certificates.first.encoded.contentEquals(record.clientCertificateChain.single().encoded) &&
                certificates.second.encoded.contentEquals(record.authenticatedEnrollmentAuthority.encoded)) { "Recovered approval was not the exact stored result" }
            client.authenticateSaved(loaded.clientKeyManager)
            mark("reopen-mtls-authorized")
            client.close(); client = null
            credentials.forget(recovery.desktopId); files.clearRecovery()
            check(identities.load(recovery.desktopId) == null && credentials.load(recovery.desktopId) == null) { "Owned enrollment state survived Forget" }
            owned = false
            mark("reopen-resources-closed")
        } finally {
            var failed = false
            fun attempt(action: () -> Unit) { try { action() } catch (_: Exception) { failed = true } catch (_: AssertionError) { failed = true } }
            attempt { client?.close() }
            if (owned) { attempt { credentials.forget(recovery.desktopId) }; attempt { files.clearRecovery() } }
            check(!failed) { "Enrollment reopen cleanup failed" }
        }
    }

    private fun pair(seed: DraftEnrollmentSeed, identity: DeviceIdentity): DraftEnrollmentMessage {
        val csr = identity.enrollmentRequest().also { check(it.size in 1..4096) }
        return DraftEnrollmentCodec.message(DraftEnrollmentChannel.PAIR_REQUEST, linkedMapOf(
            "protocolVersion" to 1, "type" to "pair", "desktopId" to seed.desktopId, "invitationId" to seed.invitationId,
            "invitationSecret" to seed.secretForEnrollment(), "csrDer" to b64(csr), "deviceName" to "Android enrollment research",
            "capabilities" to REQUESTED))
    }
    private class ProofSession(val client: DraftEnrollmentHttpsClient, val identity: DeviceIdentity,
        val desktop: String, val pin: String, val invitation: String, val enrollment: String, val reservation: String) {
        private var lastReceived = 0L
        fun status(): DraftEnrollmentMessage {
            if (lastReceived != 0L) {
                val remaining = 1_000_000_000 - (System.nanoTime() - lastReceived)
                if (remaining > 0) Thread.sleep((remaining + 999999) / 1_000_000)
            }
            val challenge = client.exchange(DraftEnrollmentCodec.message(DraftEnrollmentChannel.CHALLENGE_REQUEST, linkedMapOf(
                "protocolVersion" to 1, "type" to "pair_challenge", "desktopId" to desktop, "invitationId" to invitation,
                "enrollmentId" to enrollment, "purpose" to "status"))) as? DraftEnrollmentMessage.Challenge
                ?: error("Fresh enrollment challenge was not issued")
            lastReceived = System.nanoTime()
            val payload = DraftEnrollmentProof.payload(DraftEnrollmentProofContext(desktop, pin, invitation,
                enrollment, b64(hash(identity.publicKey.encoded)), DraftEnrollmentPurpose.STATUS), challenge)
            val signature = identity.signChallenge(payload)
            val result = client.exchange(DraftEnrollmentCodec.message(DraftEnrollmentChannel.STATUS_REQUEST, linkedMapOf(
                "protocolVersion" to 1, "type" to "pair_status", "desktopId" to desktop, "invitationId" to invitation,
                "enrollmentId" to enrollment, "challengeId" to challenge.challengeId, "signature" to b64(signature))))
            if (result is DraftEnrollmentMessage.Pending) check(result.desktopId == desktop &&
                result.enrollmentId == enrollment && result.reservationExpiresAt == reservation) { "Pending enrollment context changed" }
            return result
        }
    }
    private fun validateApproved(value: DraftEnrollmentMessage.Approved, identity: DeviceIdentity, desktop: String,
        enrollment: String, resultDeadline: String): Pair<X509Certificate, X509Certificate> {
        check(value.desktopId == desktop && value.enrollmentId == enrollment && value.resultExpiresAt == resultDeadline &&
            Instant.now().isBefore(Instant.parse(value.resultExpiresAt)) && value.capabilities.isNotEmpty() &&
            REQUESTED.containsAll(value.capabilities)) { "Approved enrollment context changed" }
        val leaf = DraftEnrollmentHttpsClient.certificate(unb64(value.clientCertificateDer))
        val authority = DraftEnrollmentHttpsClient.certificate(unb64(value.enrollmentAuthorityDer))
        check(leaf.publicKey.encoded.contentEquals(identity.publicKey.encoded) && leaf.notAfter.toInstant() == Instant.parse(value.credentialExpiresAt) &&
            leaf.notBefore >= authority.notBefore && leaf.notAfter <= authority.notAfter) { "Approved certificate binding changed" }
        val manager = identity.bindEnrolledClientCertificate(listOf(leaf), authority)
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        check(checkNotNull(manager.getPrivateKey(alias)).encoded == null) { "Enrollment key was exportable" }
        return leaf to authority
    }
    private fun keyEvidence(identity: DeviceIdentity): List<ByteArray> {
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = Collections.list(keys.aliases()).single { keys.getCertificate(it)?.publicKey?.encoded?.contentEquals(identity.publicKey.encoded) == true }
        val entry = keys.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Original enrollment key was exportable" }
        val chain = entry.certificateChain.also { check(it.size in 1..4) }
        return chain.map { hash(it.encoded.also { encoded -> check(encoded.size in 1..4096) }) }
    }
    private fun sameHashes(before: List<ByteArray>, after: List<ByteArray>) {
        check(before.size == after.size && before.zip(after).all { (a, b) -> a.contentEquals(b) }) { "Keystore certificate entry was replaced" }
    }
    private fun mark(value: String) {
        phase = value
        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
            putString("draftEnrollmentVersion", "1"); putString("draftEnrollmentPhase", value)
        })
    }
    private fun safe(action: () -> Unit) {
        try { action() }
        catch (failure: Exception) { throw redacted(failure) }
        catch (failure: AssertionError) { throw redacted(failure) }
    }
    private fun redacted(failure: Throwable): AssertionError {
        val result = AssertionError("Draft enrollment failed at $phase")
        val files = mapOf(
            "DraftEnrollmentInteropTest.kt" to setOf("DraftEnrollmentInteropTest"),
            "DraftEnrollmentHttpsClient.kt" to setOf("DraftEnrollmentHttpsClient", "DraftEnrollmentResponseLost", "DraftEnrollmentTransportFailure"),
            "DraftEnrollmentResearchFiles.kt" to setOf("DraftEnrollmentResearchFiles"),
            "DraftEnrollmentStateCodec.kt" to setOf("DraftEnrollmentStateCodec", "DraftEnrollmentStateChecks", "DraftEnrollmentStateException", "DraftEnrollmentSeed", "DraftEnrollmentRecovery"))
        val sites = failure.stackTrace.take(128).filter { site ->
            site.className.substringAfterLast('.').substringBefore('$') in files[site.fileName].orEmpty() && site.lineNumber in 1..100000 &&
            Regex("com\\.httpfreekit\\.interop\\.DraftEnrollment[A-Za-z0-9_.$]{0,192}").matches(site.className) &&
            Regex("[A-Za-z0-9_$<>-]{1,128}").matches(site.methodName) }.take(16)
        result.stackTrace = if (sites.isNotEmpty()) sites.toTypedArray() else arrayOf(StackTraceElement(
            "com.httpfreekit.interop.DraftEnrollmentInteropTest", "safe", "DraftEnrollmentInteropTest.kt", 1))
        return result
    }
    companion object {
        private val REQUESTED = listOf("tcp-http", "tcp-https-connect")
        private fun b64(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
        private fun unb64(value: String) = Base64.getUrlDecoder().decode(value)
        private fun hash(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
    }
}
