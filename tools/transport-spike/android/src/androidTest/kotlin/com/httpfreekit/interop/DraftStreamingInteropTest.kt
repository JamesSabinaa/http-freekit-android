package com.httpfreekit.interop

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.httpfreekit.protocol.DraftControlPhase
import com.httpfreekit.protocol.DraftStreamPhase
import java.util.Base64
import org.junit.Test
import org.junit.runner.RunWith

/** Research-only real sockets/Keystore. No VPN, arbitrary destination, production enrollment or clock substitution. */
@RunWith(AndroidJUnit4::class)
class DraftStreamingInteropTest {
    private var phase = "setup"

    @Test(timeout = 90000) fun authenticatedControlAndGatedStreamPreserveHalfClose() = scenario("gated") { context ->
        val stream = context.owner.open()
        phase = "gated-upload-prefix"
        stream.consume()
        stream.produce(DraftStreamingOwner.UPLOAD, gated = true)
        context.awaitProbe { it.boolean("fixture", "uploadPrefixSeen") }
        check(!stream.producerFinished.get() && stream.applicationWritten.get() ==
            DraftStreamingOwner.uploadHeader(DraftStreamingOwner.UPLOAD).size.toLong() + 4096) { "Upload tail was not gated" }
        context.probe().let {
            check(!it.boolean("fixture", "uploadEof") && !it.boolean("fixture", "responsePrefixWritten")) { "Response preceded actual request EOF" }
        }
        phase = "gated-request-half-close"
        stream.uploadTailReleased.set(true)
        context.awaitProbe { it.boolean("fixture", "uploadEof") && it.boolean("fixture", "uploadVerified") && it.boolean("fixture", "responsePrefixWritten") }
        phase = "gated-response-prefix"
        draftAwait("actual application response prefix") {
            stream.applicationRead.get() >= DraftStreamingOwner.expectedResponseBytes() - DraftStreamingOwner.RESPONSE + 4096 &&
                !stream.consumerFinished.get()
        }
        check(!context.probe().boolean("fixture", "responseTailReleased")) { "Response tail was not gated" }
        context.command("release_response_tail")
        phase = "gated-ordered-completion"
        stream.finishNormally()
        context.assertProxyUpload(DraftStreamingOwner.UPLOAD)
        context.assertResponse()
        context.finish()
    }

    @Test(timeout = 120000) fun boundedBackpressureResumesWithoutDroppingBytes() = scenario("backpressure") { context ->
        val stream = context.owner.open()
        phase = "paused-proxy-actual-write"
        stream.produce(DraftStreamingOwner.BURST)
        context.awaitProxyBackpressure()
        phase = "paused-android-actual-write"
        stream.observedBlockedWriter()
        val before = stream.snapshot()
        check(before.chargedBytes in 1..8192 && before.chargedFrames in 1..4 &&
            stream.pendingClientBytes.get() in 1..4096 && stream.pendingGatewayBytes.get() == 0L && stream.backpressureCount.get() > 0) {
            "Android backpressure ownership was not bounded"
        }
        phase = "resume-actual-proxy-reader"
        stream.consume()
        context.command("resume_proxy_read")
        phase = "resumed-ordered-completion"
        stream.finishNormally(60000)
        check(stream.writeCompleted.get() > 0 && stream.pendingClientBytes.get() == 0L) { "Android writer did not resume" }
        context.assertProxyUpload(DraftStreamingOwner.BURST)
        context.assertResponse()
        check(context.probe().number("io", "resumedPendingCount") > 0) { "Proxy pending message was not resumed" }
        context.finish()
    }

    @Test(timeout = 90000) fun cancelClosesAnObservedBlockedWriterAndJoinsResources() = scenario("cancel") { context ->
        val stream = context.owner.open()
        phase = "cancel-observe-real-writers"
        stream.produce(DraftStreamingOwner.BURST)
        context.awaitProxyBackpressure()
        stream.observedBlockedWriter()
        val outstanding = stream.writeInFlight.get()
        check(outstanding > stream.writeCompleted.get()) { "Cancel writer had already completed" }
        phase = "cancel-independent-control"
        context.owner.cancel()
        val retained = stream.snapshot()
        check(retained.phase == DraftStreamPhase.CANCELLED && retained.chargedBytes > 0 && retained.streamLease &&
            !retained.resourceClosureConfirmed) { "Cancel released resources before real joins" }
        phase = "cancel-real-resource-joins"
        stream.close()
        check(stream.writeInFlight.get() == 0L && stream.snapshot().phase == DraftStreamPhase.CANCELLED) { "Cancelled writer did not terminate" }
        context.assertRetainedAbort()
        context.finish()
    }

    @Test(timeout = 100000) fun expiryClosesAnObservedBlockedWriterAndJoinsResources() = scenario("expiry") { context ->
        val remaining = context.owner.expiresAtMillis - System.currentTimeMillis()
        val profile = context.probe()
        check(profile.number("timing", "expiresUtcMillis") == context.owner.expiresAtMillis &&
            profile.number("timing", "expiresUtcMillis") - profile.number("timing", "readyUtcMillis") in 30000..31000 &&
            remaining > 0) { "Expiry fixture was not the real thirty-second profile" }
        val stream = context.owner.open()
        phase = "expiry-observe-real-writers"
        stream.produce(DraftStreamingOwner.BURST)
        context.awaitProxyBackpressure()
        stream.observedBlockedWriter()
        check(context.owner.expiresAtMillis > System.currentTimeMillis()) { "Writer was not observed before expiry" }
        phase = "real-session-expiry"
        var peerExpired = false
        var localExpired = false
        draftAwait("real deadline invalidation", 35000) {
            val local = context.owner.snapshot()
            val peer = context.probe()
            val peerUtc = peer.optionalNumber("timing", "terminalUtcMillis")
            val peerElapsed = peer.optionalNumber("timing", "terminalElapsedMillis")
            val peerLifetime = peer.number("timing", "expiresUtcMillis") - peer.number("timing", "readyUtcMillis")
            check(peer.number("timing", "expiresUtcMillis") == context.owner.expiresAtMillis) { "Peer changed the canonical expiry" }
            peerExpired = peer.cause("control") == "session_expired" &&
                ((peerUtc != null && peerUtc >= context.owner.expiresAtMillis) || (peerElapsed != null && peerElapsed >= peerLifetime))
            localExpired = local.cause == "session_expired" &&
                (System.currentTimeMillis() >= context.owner.expiresAtMillis ||
                    (System.nanoTime() - context.owner.readyAtNanos) / 1_000_000 >= context.owner.expiresAtMillis - context.owner.readyAtUtcMillis)
            local.phase in setOf(DraftControlPhase.CLOSED, DraftControlPhase.FAILED) &&
                peer.phase("control") in setOf("closed", "failed") && (localExpired || peerExpired)
        }
        val observedUtc = System.currentTimeMillis()
        val elapsed = (System.nanoTime() - context.owner.readyAtNanos) / 1_000_000
        val readyRemaining = context.owner.expiresAtMillis - context.owner.readyAtUtcMillis
        // Either real clock may lead by the driver's measured <=2s; allow only 100ms measurement rounding.
        check(observedUtc >= context.owner.expiresAtMillis - 2100 && elapsed >= readyRemaining - 2100 &&
            context.owner.deadlineTicks.get() > 0) { "Implausibly early or unticked expiry" }
        val peerTiming = context.probe()
        println("draft-expiry readyUtc=${context.owner.readyAtUtcMillis} expiresUtc=${context.owner.expiresAtMillis} " +
            "observedUtc=$observedUtc elapsedMs=$elapsed remainingAtReadyMs=$readyRemaining " +
            "initialDeviceRemainingMs=$remaining " +
            "localTicks=${context.owner.deadlineTicks.get()} localExpiryTicks=${context.owner.expiredDeadlineTicks.get()} " +
            "localExpired=$localExpired peerExpired=$peerExpired peerReadyUtc=${peerTiming.number("timing", "readyUtcMillis")} " +
            "peerTerminalUtc=${peerTiming.optionalNumber("timing", "terminalUtcMillis")} " +
            "peerTerminalElapsedMs=${peerTiming.optionalNumber("timing", "terminalElapsedMillis")}")
        val retained = stream.snapshot()
        check(retained.phase == DraftStreamPhase.FAILED && retained.cause in setOf("session_expired", "network_unreachable") && retained.chargedBytes > 0 &&
            retained.streamLease && !retained.resourceClosureConfirmed) { "Expiry released resources before real joins" }
        phase = "expiry-real-resource-joins"
        stream.close()
        check(stream.writeInFlight.get() == 0L && stream.snapshot().phase == DraftStreamPhase.FAILED) { "Expired writer did not terminate" }
        context.assertRetainedAbort()
        context.finish()
    }

    @Test(timeout = 90000) fun wrongSessionAndDeviceBindingAreRejected() = scenario("binding") { context ->
        val stream = context.owner.open()
        phase = "binding-wrong-token"
        val wrong = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))
        check(wrong != context.token) { "Synthetic wrong token unexpectedly matched" }
        context.reject(context.credential, wrong)
        phase = "binding-other-real-device"
        val other = context.fixture.enroll()
        check(other.deviceId != context.credential.deviceId) { "Second identity was not distinct" }
        context.reject(other, context.token)
        other.verifyKey()
        phase = "binding-negative-upgrade-headers"
        for (header in listOf("Origin" to "https://fixture.invalid", "Cookie" to "synthetic=1",
            "Authorization" to "Bearer synthetic", "X-FreeKit-Session" to context.token,
            "Sec-WebSocket-Extensions" to "permessage-deflate", "Sec-WebSocket-Protocol" to "synthetic")) {
            context.reject(context.credential, context.token, listOf(header), expectedStatus = 400)
        }
        check(context.owner.snapshot().phase == DraftControlPhase.ACTIVE && context.owner.budget().streamLeases == 1 &&
            stream.snapshot().phase == DraftStreamPhase.OPEN) {
            "Refused ingress altered the existing Android owner"
        }
        context.probe().let {
            check(it.phase("control") == "active" && it.phase("stream") == "open" && it.ordinal() == 1 && it.number("pool", "streamLeases") == 1L &&
                it.number("fixture", "uploadBytesRead") == 0L) { "Refused ingress altered the existing gateway owner" }
        }
        phase = "binding-original-owner-still-streams"
        stream.consume(); stream.produce(DraftStreamingOwner.UPLOAD)
        stream.finishNormally()
        context.assertProxyUpload(DraftStreamingOwner.UPLOAD)
        context.finish()
    }

    @Test(timeout = 90000) fun malformedAndOversizedIngressFailBeforeForwarding() = scenario("malformed") { context ->
        for ((index, kind) in listOf("json", "header", "oversized").withIndex()) {
            phase = "malformed-$kind-actual-ingress"
            val stream = context.owner.open()
            stream.adversarial(kind)
            draftAwait("actual malformed transport failure") { stream.snapshot().phase == DraftStreamPhase.FAILED }
            check(stream.snapshot().phase != DraftStreamPhase.COMPLETE && !stream.snapshot().resourceClosureConfirmed && stream.snapshot().streamLease) {
                "Malformed stream completed or released before cleanup"
            }
            stream.close()
            phase = "malformed-$kind-no-forwarding"
            context.awaitProbe {
                it.ordinal() == index + 1 && it.boolean("cleanup", "streamClosed") && it.boolean("cleanup", "proxyClosed") &&
                    it.boolean("cleanup", "fixtureClosed") && it.number("pool", "streamLeases") == 0L
            }.let {
                check(it.phase("stream") == "failed" && it.number("fixture", "uploadBytesRead") == 0L &&
                    it.number("fixture", "responseBytesWritten") == 0L) { "Offending ingress reached the fixed proxy" }
                if (kind == "json") check(it.cause("stream") == "invalid_message") { "Application JSON did not reach the actual codec" }
            }
        }
        context.finish()
    }

    @Test(timeout = 60000) fun prematureCloseCannotCompleteStream() = scenario("premature") { context ->
        val stream = context.owner.open()
        phase = "premature-prefix-before-real-close"
        stream.produce(DraftStreamingOwner.UPLOAD, gated = true)
        draftAwait("actual premature transport failure") { stream.snapshot().phase == DraftStreamPhase.FAILED }
        val state = stream.snapshot()
        check(state.cause == "network_unreachable" && !state.clientSealed && !state.gatewayEof &&
            state.streamLease && !state.resourceClosureConfirmed && !stream.producerFinished.get()) {
            "Premature close satisfied normal EOF/completion"
        }
        phase = "premature-close-real-cleanup"
        stream.close()
        context.awaitProbe { it.boolean("fixture", "uploadPrefixSeen") && it.boolean("cleanup", "streamClosed") }.let {
            check(!it.boolean("fixture", "uploadEof") && it.number("fixture", "responseBytesWritten") == 0L &&
                it.phase("stream") == "failed" && it.cause("stream") == "network_unreachable") { "Premature fixture did not close before EOF" }
        }
        context.finish()
    }

    private class Context(val fixture: DraftStreamingFixture, val credential: DraftStreamingFixture.Credential,
        val owner: DraftStreamingOwner) {
        val token = owner.token()
        fun probe() = DraftStreamingProbe.read(fixture, credential, token)
        fun command(command: String) = DraftStreamingProbe.command(fixture, credential, token, command)
        fun awaitProbe(predicate: (DraftStreamingProbe) -> Boolean): DraftStreamingProbe {
            var last: DraftStreamingProbe? = null
            draftAwait("bounded synthetic peer observation", 15000) { probe().also { last = it }.let(predicate) }
            return checkNotNull(last)
        }
        fun awaitProxyBackpressure(): DraftStreamingProbe {
            var candidate = 0L
            var since = 0L
            return awaitProbe {
                val entry = it.number("io", "proxyWriteEntries")
                val observed = it.boolean("fixture", "proxyReadPaused") && it.boolean("io", "proxyWritePending") &&
                    entry > it.number("io", "proxyWriteCompletions") &&
                    it.number("io", "pendingIngressBytes") in 1..4096 && it.number("io", "backpressureCount") > 0 &&
                    it.number("control", "chargedBytes") in 1..16384
                if (!observed || candidate != entry) { candidate = entry; since = System.nanoTime() }
                observed && System.nanoTime() - since >= 250_000_000
            }
        }
        fun assertProxyUpload(length: Int) {
            awaitProbe { it.boolean("fixture", "uploadVerified") && it.boolean("fixture", "uploadEof") }.let {
                check(it.number("fixture", "uploadBytesRead") == DraftStreamingOwner.uploadHeader(length).size.toLong() + length &&
                    it.digest("uploadSha256") == DraftStreamingOwner.expectedUploadHash(length)) { "Fixed upload count/digest mismatch" }
            }
        }
        fun assertResponse() {
            awaitProbe { it.boolean("fixture", "responseEof") }.let {
                check(it.number("fixture", "responseBytesWritten") == DraftStreamingOwner.expectedResponseBytes() &&
                    it.digest("responseSha256") == DraftStreamingOwner.expectedResponseHash()) { "Fixed response count/digest mismatch" }
            }
        }
        fun assertRetainedAbort() {
            awaitProbe { it.number("io", "retainedStreamLeasesAtAbort") > 0 }.let {
                check(it.number("io", "retainedBytesAtAbort") > 0 && it.number("io", "retainedFramesAtAbort") > 0) {
                    "Peer abort did not retain unfinished writer ownership"
                }
            }
        }
        fun reject(asCredential: DraftStreamingFixture.Credential, token: String, extra: List<Pair<String, String>> = emptyList(), expectedStatus: Int = 403) {
            val reply = fixture.upgrade(asCredential, "/companion/v1/streams", token, extraHeaders = extra)
            reply.first.use { check(reply.second == expectedStatus) { "Unauthorized stream upgrade accepted or misclassified" } }
        }
        fun finish() {
            owner.close()
            awaitProbe { it.boolean("cleanup", "complete") }.let {
                check(it.number("pool", "sessionLeases") == 0L && it.number("pool", "streamLeases") == 0L &&
                    it.number("pool", "chargedBytes") == 0L && it.number("cleanup", "workers") == 0L &&
                    it.number("cleanup", "timers") == 0L && it.number("cleanup", "pendingCallbacks") == 0L &&
                    it.boolean("cleanup", "controlClosed") && it.boolean("cleanup", "streamClosed") &&
                    it.boolean("cleanup", "proxyClosed") && it.boolean("cleanup", "fixtureClosed")) { "Peer cleanup retained real resources" }
            }
            credential.verifyKey()
        }
    }

    private fun scenario(name: String, run: (Context) -> Unit) {
        phase = "real-key-issuance"
        try {
            DraftStreamingFixture().use { fixture ->
                val credential = fixture.enroll()
                phase = "authenticated-control"
                DraftStreamingOwner(fixture, credential, name).use { owner -> run(Context(fixture, credential, owner)) }
            }
        } catch (failure: Exception) {
            // Provider/JSON/framing exceptions can contain peer material; retain only a fixed stage/type.
            throw AssertionError("Draft streaming $name failed at $phase (${failure.javaClass.simpleName})")
        } catch (failure: AssertionError) {
            throw AssertionError("Draft streaming $name failed at $phase (${failure.javaClass.simpleName})")
        }
    }
}
