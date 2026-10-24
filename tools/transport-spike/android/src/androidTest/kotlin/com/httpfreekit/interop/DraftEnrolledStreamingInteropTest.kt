package com.httpfreekit.interop

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.b64
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.hash
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.keyEvidence
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.pair
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.sameHashes
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.validateApproved
import com.httpfreekit.protocol.DraftControlPhase
import com.httpfreekit.protocol.DraftEnrollmentMessage
import com.httpfreekit.protocol.DraftStreamPhase
import com.httpfreekit.security.AndroidDeviceIdentityStore
import com.httpfreekit.security.AndroidEnrolledCredentialStore
import com.httpfreekit.security.EnrolledCredentialRecord
import java.security.cert.CertificateException
import java.time.Instant
import javax.net.ssl.SSLException
import org.junit.Test
import org.junit.runner.RunWith

/** Real enrolled credentials and I/O only. Host mutation and proxy proof remain separate evidence. */
@RunWith(AndroidJUnit4::class)
class DraftEnrolledStreamingInteropTest {
    private var phase = "input-consumed"

    @Test(timeout = 180000) fun revocationClosesSavedCredentialBlockedSession() = scenario(1, "revocation", 120000)
    @Test(timeout = 180000) fun credentialExpiryClosesSavedCredentialBlockedSession() = scenario(2, "credential_expiry", 120000)
    @Test(timeout = 180000) fun sessionExpiryClosesSavedCredentialBlockedSession() = scenario(3, "session_expiry", 15000)

    private fun scenario(code: Int, name: String, policyMillis: Long) = safe {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val files = DraftEnrollmentResearchFiles(context)
        val wrapper = files.consumeStreamInput(code)
        val seed = wrapper.enrollment
        mark("input-consumed")
        val identities = AndroidDeviceIdentityStore()
        val credentials = AndroidEnrolledCredentialStore(context)
        val owners = ArrayList<DraftStreamingOwner>()
        var http: DraftEnrollmentHttpsClient? = null
        var created = false
        var forgotten = false
        try {
            check(identities.load(seed.desktopId) == null && credentials.load(seed.desktopId) == null) { "Owned enrollment state already exists" }
            created = true
            val identity = identities.create(seed.desktopId)
            val original = keyEvidence(identity)
            val gateway = DraftEnrollmentHttpsClient.certificate(seed.gatewayCertificateDer)
            val client = DraftEnrollmentHttpsClient(gateway, seed.gatewaySpkiSha256, seed.logicalName, seed.setupPort, seed.credentialPort)
            http = client
            val registration = client.exchange(pair(seed, identity)) as? DraftEnrollmentMessage.Registered
                ?: error("Enrolled stream reservation failed")
            check(registration.desktopId == seed.desktopId && registration.invitationId == seed.invitationId &&
                registration.deviceSpkiSha256 == b64(hash(identity.publicKey.encoded)) && registration.reservationExpiresAt == seed.invitationExpiresAt &&
                Instant.now().isBefore(Instant.parse(registration.resultExpiresAt))) { "Enrolled stream reservation changed" }
            seed.clearInvitationSecret()
            mark("strict-csr-reserved")
            val proof = DraftEnrollmentProofSession(client, identity, seed.desktopId, seed.gatewaySpkiSha256,
                seed.invitationId, registration.enrollmentId, registration.reservationExpiresAt)
            check(proof.status() is DraftEnrollmentMessage.Pending) { "Enrollment did not require approval" }
            mark("pending-proof-observed")
            mark("awaiting-host-approval")
            val approvalDeadline = System.nanoTime() + 60_000_000_000
            var approved: DraftEnrollmentMessage.Approved? = null
            while (approved == null) {
                check(System.nanoTime() < approvalDeadline) { "Explicit stream approval deadline elapsed" }
                when (val result = proof.status()) {
                    is DraftEnrollmentMessage.Pending -> Thread.sleep(result.retryAfterMillis.toLong())
                    is DraftEnrollmentMessage.Approved -> approved = result
                    else -> error("Stream enrollment ended unexpectedly")
                }
            }
            val grant = checkNotNull(approved)
            val (leaf, authority) = validateApproved(grant, identity, seed.desktopId, registration.enrollmentId, registration.resultExpiresAt)
            val record = EnrolledCredentialRecord(seed.desktopId, gateway, seed.gatewaySpkiSha256, seed.logicalName, listOf(leaf), authority)
            credentials.save(record)
            val loaded = checkNotNull(AndroidEnrolledCredentialStore(context).load(seed.desktopId))
            check(loaded.record.clientCertificateChain.single().encoded.contentEquals(leaf.encoded) &&
                loaded.record.authenticatedEnrollmentAuthority.encoded.contentEquals(authority.encoded)) { "Saved stream credential changed" }
            sameHashes(original, keyEvidence(identity))
            client.close(); http = null
            mark("credential-saved-and-reloaded")

            val credential = DraftStreamingFixture.Credential(loaded.clientKeyManager, grant.deviceId) {
                // Enrollment expiry disables its manager, not the original Keystore identity.
                sameHashes(original, keyEvidence(identity))
            }
            val connector = DraftEnrolledStreamingConnector(loaded, credential, wrapper.streamPort)
            val sessionContext = DraftStreamingSessionContext(seed.desktopId, grant.capabilities, loaded, policyMillis)
            val owner = DraftStreamingOwner(connector, credential, "cancel", sessionContext).also(owners::add)
            val oldToken = owner.token()
            val stream = owner.open()
            val credentialExpires = leaf.notAfter.time
            check(owner.expiresAtMillis <= minOf(credentialExpires, gateway.notAfter.time, authority.notAfter.time)) { "Readiness exceeded saved trust" }
            if (code == 2) check(owner.expiresAtMillis == credentialExpires) { "Credential did not limit the session" }
            if (code == 3) check(owner.expiresAtMillis < credentialExpires) { "Policy did not limit the session" }
            mark("bounded-stream-ready")
            stream.produce(DraftStreamingOwner.BURST)
            val blocked = stream.observedBlockedWriter()
            val prefix = minOf(4096L, (blocked.applicationWritten - DraftStreamingOwner.uploadHeader(DraftStreamingOwner.BURST).size).coerceAtLeast(0))
            check(prefix == 4096L && blocked.entered == blocked.inFlight && blocked.completed < blocked.entered &&
                blocked.chargedBytes in 1..8192 && blocked.chargedFrames in 1..4 && blocked.pendingBytes in 1..4096 &&
                blocked.blockedMillis in 250..20000) { "Application writer observation was not bounded" }
            mark("application-writer-blocked")
            mark(when (code) { 1 -> "awaiting-host-revocation"; 2 -> "awaiting-credential-expiry"; else -> "awaiting-session-expiry" })
            draftAwait("first actual enrolled terminal owner", if (code == 2) 70000 else 30000) { owner.terminalObservation() != null }
            val terminal = checkNotNull(owner.terminalObservation())
            val local = owner.snapshot()
            val retained = stream.snapshot()
            val controlInactive = local.phase in setOf(DraftControlPhase.CLOSED, DraftControlPhase.FAILED)
            val streamInactive = retained.phase == DraftStreamPhase.FAILED
            check(controlInactive && streamInactive && retained.chargedBytes > 0 && retained.streamLease && !retained.resourceClosureConfirmed) {
                "Terminal owner released stream resources before actual joins"
            }
            check(terminal.cause in if (code == 1) setOf("device_revoked", "network_unreachable") else setOf("session_expired", "network_unreachable")) {
                "Unexpected first enrolled terminal cause"
            }
            check(owner.deadlineTicks.get() > 0) { "Local deadline worker did not run" }
            mark("terminal-owner-observed")
            owner.close()
            check(stream.writeInFlight.get() == 0L) { "Terminal application writer did not finish" }

            var oldRejected = false
            var newAdmitted = false
            var newControlUtc: Long? = null
            if (code == 3) {
                check(System.currentTimeMillis() < credentialExpires) { "Session policy consumed the credential lifetime" }
                checkNotNull(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null)) { "Session expiry disabled the credential" }
                check(refused(false) { connector.upgrade(credential, "/companion/v1/streams", oldToken, null, 1024) }) { "Old session token survived expiry" }
                oldRejected = true
                val next = DraftStreamingOwner(connector, credential, "cancel", sessionContext).also(owners::add)
                newControlUtc = next.readyAtUtcMillis
                check(newControlUtc < credentialExpires && next.snapshot().phase == DraftControlPhase.ACTIVE) { "Unchanged credential did not establish new control" }
                newAdmitted = true
            } else {
                if (code == 1) {
                    check(System.currentTimeMillis() < credentialExpires) { "Revocation test reached certificate expiry" }
                    checkNotNull(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null)) { "Revocation test credential was unusable" }
                } else {
                    // A peer may expire first within measured skew; retain its original local terminal
                    // observation, then independently observe this device's real saved-leaf boundary.
                    draftAwait("actual saved leaf expiry and manager refusal", 5000) {
                        System.currentTimeMillis() >= credentialExpires &&
                            loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null) == null
                    }
                    sameHashes(original, keyEvidence(identity))
                }
                check(refused(code == 2) { connector.upgrade(credential, "/companion/v1/control", null, "cancel", 1024) }) { "Invalidated credential was admitted again" }
            }
            val sameCredential = loaded.record.clientCertificateChain.single().encoded.contentEquals(leaf.encoded) &&
                checkNotNull(identities.load(seed.desktopId)).publicKey.encoded.contentEquals(identity.publicKey.encoded)
            sameHashes(original, keyEvidence(identity))
            check(sameCredential) { "Admission checks replaced enrollment" }
            mark("admission-policy-verified")
            owners.forEach { it.close() }
            val resources = owners.map { it.closedResources() }
            check(resources.all { it.socketsClosed && it.workersJoined && it.threadsAlive == 0 && it.sessionLeases == 0 &&
                it.streamLeases == 0 && it.chargedBytes == 0L && it.pendingCallbacks == 0 && it.timers == 0 }) { "Enrolled stream cleanup did not join" }
            val observation = DraftEnrolledStreamingObservation(name, credentialExpires, gateway.notAfter.time, authority.notAfter.time,
                policyMillis, owner.readyAtUtcMillis, owner.expiresAtMillis, terminal, blocked, prefix, owner.deadlineTicks.get(),
                controlInactive, streamInactive, sameCredential, if (code == 3) "new_control" else "denied", oldRejected, newAdmitted, newControlUtc, resources)
            InstrumentationRegistry.getInstrumentation().sendStatus(3, Bundle().apply { observation.values().forEach { (key, value) -> putString(key, value) } })
            mark("stream-resources-closed")
            credentials.forget(seed.desktopId); files.clearRecovery()
            check(identities.load(seed.desktopId) == null && credentials.load(seed.desktopId) == null) { "Owned stream enrollment survived Forget" }
            forgotten = true
            mark("owned-state-forgotten")
        } finally {
            seed.clearInvitationSecret()
            var failed = false
            fun attempt(action: () -> Unit) { try { action() } catch (_: Exception) { failed = true } catch (_: AssertionError) { failed = true } }
            attempt { http?.close() }
            owners.forEach { owner -> attempt { owner.close(); owner.closedResources() } }
            if (!failed && created && !forgotten) { attempt { credentials.forget(seed.desktopId) }; attempt { files.clearRecovery() } }
            check(!failed) { "Enrolled stream cleanup failed" }
        }
    }

    private fun refused(allowExpiredTls: Boolean, upgrade: () -> Pair<DraftStreamingTls, Int>): Boolean = try {
        val (tls, status) = upgrade()
        tls.use { check(status == 403) { "Unexpected fresh admission response" } }
        true
    } catch (failure: CertificateException) { if (allowExpiredTls) true else throw failure }
      catch (failure: SSLException) { if (allowExpiredTls) true else throw failure }

    private fun mark(value: String) {
        phase = value
        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
            putString("draftEnrolledVersion", "1"); putString("draftEnrolledPhase", value)
        })
    }
    private fun safe(action: () -> Unit) {
        try { action() } catch (failure: Exception) { throw redacted(failure) } catch (failure: AssertionError) { throw redacted(failure) }
    }
    private fun redacted(failure: Throwable): AssertionError {
        val files = mapOf(
            "DraftEnrolledStreamingInteropTest.kt" to setOf("DraftEnrolledStreamingInteropTest"),
            "DraftEnrolledStreamingConnector.kt" to setOf("DraftEnrolledStreamingConnector"),
            "DraftEnrolledStreamingObservation.kt" to setOf("DraftEnrolledStreamingObservation"),
            "DraftStreamingOwner.kt" to setOf("DraftStreamingOwner"),
            "DraftStreamingFixture.kt" to setOf("DraftStreamingTls", "DraftStreamingWorkers", "DraftStreamingClock", "DraftStreamingFixtureKt", "DraftStreamingFixture"),
            "DraftStreamingConnector.kt" to setOf("DraftStreamingConnectorKt", "DraftStreamingSessionContext"),
            "DraftEnrollmentResearchChecks.kt" to setOf("DraftEnrollmentResearchChecks", "DraftEnrollmentProofSession"),
            "DraftEnrollmentResearchFiles.kt" to setOf("DraftEnrollmentResearchFiles"),
            "DraftEnrollmentHttpsClient.kt" to setOf("DraftEnrollmentHttpsClient", "DraftEnrollmentResponseLost", "DraftEnrollmentTransportFailure"),
            "DraftEnrollmentStreamInputCodec.kt" to setOf("DraftEnrollmentStreamInputCodec", "DraftEnrollmentStreamSeed"),
            "DraftEnrollmentStateCodec.kt" to setOf("DraftEnrollmentStateCodec", "DraftEnrollmentStateChecks", "DraftEnrollmentStateException", "DraftEnrollmentSeed", "DraftEnrollmentRecovery"))
        val sites = failure.stackTrace.take(128).filter { site ->
            site.className.substringAfterLast('.').substringBefore('$') in files[site.fileName].orEmpty() && site.lineNumber in 1..100000 &&
                Regex("com\\.httpfreekit\\.interop\\.Draft[A-Za-z0-9_.$]{0,192}").matches(site.className) &&
                Regex("[A-Za-z0-9_$<>-]{1,128}").matches(site.methodName) }.take(16)
        return AssertionError("Draft enrolled stream failed at $phase").apply {
            stackTrace = if (sites.isNotEmpty()) sites.toTypedArray() else arrayOf(StackTraceElement(
                "com.httpfreekit.interop.DraftEnrolledStreamingInteropTest", "safe", "DraftEnrolledStreamingInteropTest.kt", 1))
        }
    }
}
