package com.httpfreekit.interop

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.b64
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.hash
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.keyEvidence
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.pair
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.sameHashes
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.unb64
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.validateApproved
import com.httpfreekit.protocol.*
import com.httpfreekit.security.AndroidDeviceIdentityStore
import com.httpfreekit.security.AndroidEnrolledCredentialStore
import com.httpfreekit.security.DeviceIdentity
import com.httpfreekit.security.EnrolledCredentialRecord
import java.security.Signature
import java.time.Instant
import java.util.Date
import javax.net.ssl.SSLException
import org.junit.Test
import org.junit.runner.RunWith

/** Actual Keystore proofs and scoped network exchanges; host decisions remain separately observed. */
@RunWith(AndroidJUnit4::class)
class DraftEnrollmentAdversarialInteropTest {
    private var phase = "input-consumed"

    @Test(timeout = 180000) fun purposeContextAndReplayProofsKeepReservationPending() = scenario("proof_misuse") { state ->
        val challenge = state.proof.challenge(DraftEnrollmentPurpose.STATUS)
        val signature = state.proof.signature(challenge)
        val correct = state.proof.request(challenge, signature)
        rejected(state.client.exchange(state.proof.request(challenge, signature, DraftEnrollmentPurpose.CANCEL)))
        mark("purpose-proof-rejected")
        val changedTuple = correct.material().toMutableMap().apply {
            put("invitationId", if (state.seed.invitationId == "different") "another" else "different")
            put("enrollmentId", changedEnrollment(state.registration.enrollmentId))
        }
        rejected(state.client.exchange(DraftEnrollmentCodec.message(DraftEnrollmentChannel.STATUS_REQUEST, changedTuple)))
        mark("wire-context-rejected")

        // Only this negative test signs a deliberately altered, locally coherent typed context.
        val changedPin = b64(unb64(state.seed.gatewaySpkiSha256).also { it[0] = (it[0].toInt() xor 1).toByte() })
        val altered = DraftEnrollmentCodec.message(DraftEnrollmentChannel.CHALLENGE_RESPONSE,
            challenge.material().toMutableMap().apply { put("gatewaySpkiSha256", changedPin) }) as DraftEnrollmentMessage.Challenge
        val alteredContext = DraftEnrollmentProofContext(state.seed.desktopId, changedPin, state.seed.invitationId,
            state.registration.enrollmentId, b64(hash(state.identity.publicKey.encoded)), DraftEnrollmentPurpose.STATUS)
        val wrongSignature = state.identity.signChallenge(DraftEnrollmentProof.payload(alteredContext, altered))
        rejected(state.client.exchange(state.proof.request(challenge, wrongSignature)))
        mark("signed-context-rejected")
        state.pending(state.client.exchange(correct))
        mark("same-challenge-pending")
        rejected(state.client.exchange(correct))
        mark("replay-rejected")
        state.pending(state.proof.status())
        mark("fresh-pending-confirmed")
        linkedMapOf("PurposeHttp" to "403", "PurposeCode" to "authentication_failed", "WireContextHttp" to "403", "WireContextCode" to "authentication_failed",
            "SignedContextHttp" to "403", "SignedContextCode" to "authentication_failed", "SameChallengeHttp" to "200", "SameChallengeType" to "pair_pending",
            "ReplayHttp" to "403", "ReplayCode" to "authentication_failed", "FreshStatusHttp" to "200", "FreshStatusType" to "pair_pending", "BindingUnchanged" to "true")
    }

    @Test(timeout = 180000) fun wrongGatewayPeerFailsTlsWithoutEnrollmentMutation() = scenario("wrong_tls") { state ->
        val port = DraftEnrollmentAdversarialObservation.peerPort(InstrumentationRegistry.getArguments().getString("adversarialPeerPort"),
            state.seed.setupPort, state.seed.credentialPort)
        val certificate = DraftEnrollmentHttpsClient.certificate(state.seed.gatewayCertificateDer)
        val before = hash(certificate.encoded)
        // These expected inputs already passed strict private-input and client trust validation.
        var tlsRejected = false
        try {
            draftStreamingConnect(certificate, state.seed.gatewaySpkiSha256, state.seed.logicalName, port, null, 1024).use {
                error("Alternate gateway unexpectedly completed TLS")
            }
        } catch (_: SSLException) { tlsRejected = true }
        check(tlsRejected) { "Alternate gateway TLS rejection was not observed" }
        mark("alternate-peer-tls-rejected")
        state.pending(state.proof.status())
        mark("fresh-pending-confirmed")
        check(before.contentEquals(hash(certificate.encoded)) && certificate.encoded.contentEquals(state.seed.gatewayCertificateDer)) {
            "Expected gateway trust changed"
        }
        DraftEnrollmentHttpsClient.validateTrust(certificate, state.seed.gatewaySpkiSha256, state.seed.logicalName)
        linkedMapOf("TlsFailureType" to "SSLException", "FreshStatusHttp" to "200", "FreshStatusType" to "pair_pending",
            "BindingUnchanged" to "true", "ExpectedTrustUnchanged" to "true")
    }

    @Test(timeout = 180000) fun pendingCancellationRejectsLateApprovalWithoutSavingCredential() = scenario("pending_cancel") { state ->
        val challenge = state.proof.challenge(DraftEnrollmentPurpose.CANCEL)
        val request = state.proof.request(challenge, state.proof.signature(challenge))
        state.cancelled(state.client.exchange(request))
        mark("signed-cancel-confirmed")
        rejected(state.client.exchange(request))
        mark("cancel-replay-rejected")
        state.cancelled(state.proof.status())
        mark("fresh-cancelled-confirmed")
        // This authorizes a tracked host attempt; it is not an acknowledgement of that attempt.
        mark("awaiting-late-approval")
        linkedMapOf("CancelHttp" to "200", "CancelCode" to "pairing_cancelled", "ReplayHttp" to "403", "ReplayCode" to "authentication_failed",
            "FreshStatusHttp" to "200", "FreshStatusCode" to "pairing_cancelled", "BindingUnchanged" to "true")
    }

    @Test(timeout = 180000) fun publishedCancellationRevokesSavedCredential() = scenario("published_cancel") { state ->
        mark("awaiting-host-approval")
        val deadline = System.nanoTime() + 60_000_000_000
        var approved: DraftEnrollmentMessage.Approved? = null
        while (approved == null) {
            check(System.nanoTime() < deadline) { "Explicit adversarial approval deadline elapsed" }
            when (val reply = state.proof.status()) {
                is DraftEnrollmentMessage.Pending -> Thread.sleep(reply.retryAfterMillis.toLong())
                is DraftEnrollmentMessage.Approved -> approved = reply
                else -> error("Adversarial approval ended unexpectedly")
            }
        }
        val grant = checkNotNull(approved)
        val (leaf, authority) = validateApproved(grant, state.identity, state.seed.desktopId, state.registration.enrollmentId, state.registration.resultExpiresAt)
        val gateway = DraftEnrollmentHttpsClient.certificate(state.seed.gatewayCertificateDer)
        state.credentials.save(EnrolledCredentialRecord(state.seed.desktopId, gateway, state.seed.gatewaySpkiSha256, state.seed.logicalName, listOf(leaf), authority))
        val loaded = checkNotNull(AndroidEnrolledCredentialStore(state.context).load(state.seed.desktopId))
        check(loaded.record.clientCertificateChain.single().encoded.contentEquals(leaf.encoded) &&
            loaded.record.authenticatedEnrollmentAuthority.encoded.contentEquals(authority.encoded)) { "Saved adversarial credential changed" }
        mark("approved-credential-saved-and-reloaded")
        state.client.authenticateSaved(loaded.clientKeyManager)
        mark("saved-credential-mtls-admitted")
        val challenge = state.proof.challenge(DraftEnrollmentPurpose.CANCEL)
        state.cancelled(state.client.exchange(state.proof.request(challenge, state.proof.signature(challenge))))
        mark("signed-cancel-confirmed")
        state.client.requireSavedDenied(loaded.clientKeyManager)
        val refusalUtc = System.currentTimeMillis()
        leaf.checkValidity(Date(refusalUtc))
        checkNotNull(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null)) { "Cancelled credential expired before registry refusal" }
        check(refusalUtc < leaf.notAfter.time) { "Registry denial was not before credential expiry" }
        val unchanged = checkNotNull(state.credentials.load(state.seed.desktopId))
        check(unchanged.record.clientCertificateChain.single().encoded.contentEquals(leaf.encoded) &&
            unchanged.record.authenticatedEnrollmentAuthority.encoded.contentEquals(authority.encoded)) { "Cancellation replaced the saved credential" }
        mark("saved-credential-mtls-denied")
        state.cancelled(state.proof.status())
        mark("fresh-cancelled-confirmed")
        linkedMapOf("ApprovalHttp" to "200", "ApprovalType" to "pair_approved", "SavedCredentialUnchanged" to "true", "BeforeMtlsHttp" to "200",
            "CancelHttp" to "200", "CancelCode" to "pairing_cancelled", "AfterMtlsHttp" to "403", "FreshStatusHttp" to "200", "FreshStatusCode" to "pairing_cancelled",
            "CredentialExpiresUtcMillis" to leaf.notAfter.time.toString(), "RefusalObservedUtcMillis" to refusalUtc.toString(),
            "KeyManagerUsableAtRefusal" to "true", "BindingUnchanged" to "true")
    }

    private class State(val context: android.content.Context, val seed: DraftEnrollmentSeed, val identity: DeviceIdentity,
        val credentials: AndroidEnrolledCredentialStore, val client: DraftEnrollmentHttpsClient,
        val registration: DraftEnrollmentMessage.Registered, val proof: DraftEnrollmentProofSession, val initialPending: DraftEnrollmentMessage.Pending) {
        fun pending(value: DraftEnrollmentMessage) { check(value is DraftEnrollmentMessage.Pending && value.material() == initialPending.material()) { "Pending binding changed" } }
        fun cancelled(value: DraftEnrollmentMessage) { check(value is DraftEnrollmentMessage.Ended && value.code == "pairing_cancelled" &&
            value.desktopId == seed.desktopId && value.enrollmentId == registration.enrollmentId) { "Cancelled binding changed" } }
        override fun toString() = "DraftEnrollmentAdversarialState([REDACTED])"
    }

    private fun scenario(name: String, action: (State) -> Map<String, String>) = safe {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val files = DraftEnrollmentResearchFiles(context)
        val seed = files.consumeInput()
        mark("input-consumed")
        val identities = AndroidDeviceIdentityStore()
        val credentials = AndroidEnrolledCredentialStore(context)
        var client: DraftEnrollmentHttpsClient? = null
        var created = false
        var forgotten = false
        try {
            check(identities.load(seed.desktopId) == null && credentials.load(seed.desktopId) == null) { "Owned adversarial state already exists" }
            created = true
            val identity = identities.create(seed.desktopId)
            val original = keyEvidence(identity)
            val http = DraftEnrollmentHttpsClient(DraftEnrollmentHttpsClient.certificate(seed.gatewayCertificateDer), seed.gatewaySpkiSha256,
                seed.logicalName, seed.setupPort, seed.credentialPort).also { client = it }
            val registered = http.exchange(pair(seed, identity)) as? DraftEnrollmentMessage.Registered ?: error("Adversarial reservation failed")
            check(registered.desktopId == seed.desktopId && registered.invitationId == seed.invitationId &&
                registered.deviceSpkiSha256 == b64(hash(identity.publicKey.encoded)) && registered.reservationExpiresAt == seed.invitationExpiresAt &&
                Instant.now().isBefore(Instant.parse(registered.resultExpiresAt))) { "Adversarial registration context changed" }
            seed.clearInvitationSecret()
            mark("strict-csr-reserved")
            val proof = DraftEnrollmentProofSession(http, identity, seed.desktopId, seed.gatewaySpkiSha256, seed.invitationId,
                registered.enrollmentId, registered.reservationExpiresAt)
            val pending = proof.status() as? DraftEnrollmentMessage.Pending ?: error("Adversarial enrollment was not pending")
            mark("pending-proof-observed")
            val facts = action(State(context, seed, identity, credentials, http, registered, proof, pending))
            val reopened = checkNotNull(identities.load(seed.desktopId))
            check(reopened.publicKey.encoded.contentEquals(identity.publicKey.encoded)) { "Original adversarial key changed" }
            sameHashes(original, keyEvidence(reopened))
            val message = "HTTP FreeKit adversarial identity retention v1\u0000".toByteArray(Charsets.US_ASCII)
            val signed = reopened.signChallenge(message)
            check(Signature.getInstance("SHA256withECDSA").run { initVerify(reopened.publicKey); update(message); verify(signed) }) { "Original key could not sign" }
            val saved = credentials.load(seed.desktopId) != null
            check(saved == (name == "published_cancel")) { "Unexpected adversarial credential persistence" }
            http.close(); client = null
            mark("local-resources-closed")
            credentials.forget(seed.desktopId); files.clearRecovery()
            check(identities.load(seed.desktopId) == null && credentials.load(seed.desktopId) == null) { "Owned adversarial state survived Forget" }
            forgotten = true
            val observation = DraftEnrollmentAdversarialObservation(name, true, saved, true, true, facts)
            InstrumentationRegistry.getInstrumentation().sendStatus(3, Bundle().apply { observation.values().forEach { (key, value) -> putString(key, value) } })
            mark("owned-state-forgotten")
        } finally {
            seed.clearInvitationSecret()
            var failed = false
            fun attempt(block: () -> Unit) { try { block() } catch (_: Exception) { failed = true } catch (_: AssertionError) { failed = true } }
            attempt { client?.close() }
            if (created && !forgotten) { attempt { credentials.forget(seed.desktopId) }; attempt { files.clearRecovery() } }
            check(!failed) { "Adversarial enrollment cleanup failed" }
        }
    }
    private fun changedEnrollment(original: String): String = "enr_" + b64(unb64(original.removePrefix("enr_")).also { it[0] = (it[0].toInt() xor 1).toByte() })
    private fun rejected(value: DraftEnrollmentMessage) { check(value is DraftEnrollmentMessage.Error && value.code == "authentication_failed") { "Proof misuse did not receive exact rejection" } }
    private fun mark(value: String) {
        phase = value
        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
            putString("draftAdversarialVersion", "1"); putString("draftAdversarialPhase", value)
        })
    }
    private fun safe(action: () -> Unit) {
        try { action() } catch (failure: Exception) { throw redacted(failure) } catch (failure: AssertionError) { throw redacted(failure) }
    }
    private fun redacted(failure: Throwable): AssertionError {
        val files = mapOf(
            "DraftEnrollmentAdversarialInteropTest.kt" to setOf("DraftEnrollmentAdversarialInteropTest"),
            "DraftEnrollmentAdversarialObservation.kt" to setOf("DraftEnrollmentAdversarialObservation"),
            "DraftEnrollmentResearchChecks.kt" to setOf("DraftEnrollmentResearchChecks", "DraftEnrollmentProofSession"),
            "DraftEnrollmentResearchFiles.kt" to setOf("DraftEnrollmentResearchFiles"),
            "DraftEnrollmentHttpsClient.kt" to setOf("DraftEnrollmentHttpsClient", "DraftEnrollmentResponseLost", "DraftEnrollmentTransportFailure"),
            "DraftEnrollmentStateCodec.kt" to setOf("DraftEnrollmentStateCodec", "DraftEnrollmentStateChecks", "DraftEnrollmentStateException", "DraftEnrollmentSeed", "DraftEnrollmentRecovery"),
            "DraftStreamingConnector.kt" to setOf("DraftStreamingConnectorKt"),
            "DraftStreamingFixture.kt" to setOf("DraftStreamingTls"))
        val sites = failure.stackTrace.take(128).filter { site ->
            site.className.substringAfterLast('.').substringBefore('$') in files[site.fileName].orEmpty() && site.lineNumber in 1..100000 &&
                Regex("com\\.httpfreekit\\.interop\\.Draft[A-Za-z0-9_.$]{0,192}").matches(site.className) &&
                Regex("[A-Za-z0-9_$<>-]{1,128}").matches(site.methodName) }.take(16)
        return AssertionError("Draft adversarial enrollment failed at $phase").apply {
            stackTrace = if (sites.isNotEmpty()) sites.toTypedArray() else arrayOf(StackTraceElement(
                "com.httpfreekit.interop.DraftEnrollmentAdversarialInteropTest", "safe", "DraftEnrollmentAdversarialInteropTest.kt", 1))
        }
    }
}
