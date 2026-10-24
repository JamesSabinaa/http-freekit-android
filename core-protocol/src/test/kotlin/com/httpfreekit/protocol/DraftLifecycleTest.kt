package com.httpfreekit.protocol

import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class DraftLifecycleTest {
    private val epoch = Instant.parse("2026-10-24T12:00:00Z").toEpochMilli()
    private val token = "A".repeat(43)
    private val caps = listOf("tcp-http", "tcp-https-connect")
    private fun clock(mono: Long = 0, utc: Long = epoch + mono) = DraftClock(utc, mono)
    private fun controller(pool: DraftBudgetPool = DraftBudgetPool(), device: String = "device", supported: List<String> = caps) =
        DraftSession(device, "desktop", supported, pool, clock())
    private fun send(session: DraftSession, direction: DraftDirection, message: DraftMessage, at: DraftClock = clock()) =
        session.text(direction, DraftWireCodec.encode(message), at)
    private fun active(pool: DraftBudgetPool = DraftBudgetPool(), device: String = "device", limits: DraftLimits = DraftLimits(), duration: Long = 300000): DraftSession {
        val session = controller(pool, device)
        assertEquals("ok", send(session, DraftDirection.CLIENT, DraftMessage.Hello(caps, emptyList())).code)
        assertEquals("ok", send(session, DraftDirection.GATEWAY, DraftMessage.SessionReady(caps, "desktop", Instant.ofEpochMilli(epoch + duration), limits, token)).code)
        return session
    }
    private fun stream(session: DraftSession, id: String = "flow", ready: Boolean = true): DraftStream {
        val allocation = session.allocateStream("device", token, clock())
        assertEquals("ok", allocation.result.code)
        val stream = allocation.stream!!
        text(stream, DraftDirection.CLIENT, "open", id)
        if (ready) text(stream, DraftDirection.GATEWAY, "ready", id)
        return stream
    }
    private fun text(stream: DraftStream, direction: DraftDirection, type: String, id: String = "flow", at: DraftClock = clock(), code: String? = null) =
        stream.text(direction, DraftWireCodec.encode(DraftMessage.Stream(type, id, code)), at)
    private fun finish(stream: DraftStream, id: String = "flow") {
        text(stream, DraftDirection.CLIENT, "end_write", id)
        text(stream, DraftDirection.GATEWAY, "end_write", id)
        assertEquals("ok", stream.webSocketClosed(1000, clock()).code)
        assertEquals(DraftStreamPhase.CLOSING, stream.snapshot().phase)
        assertEquals("ok", stream.confirmClosed(clock()).code)
        assertEquals(DraftStreamPhase.COMPLETE, stream.snapshot().phase)
    }

    @Test fun eachEofWaitsForItsOwnWriterWhileOppositeDirectionContinues() {
        val session = active(); val flow = stream(session)
        assertEquals("ok", flow.binary(DraftDirection.CLIENT, byteArrayOf(1, 2, 3), clock()).code)
        assertTrue(text(flow, DraftDirection.CLIENT, "end_write").eofDirections.isEmpty())
        assertEquals(DraftStreamPhase.HALF_CLOSED, flow.snapshot().phase)
        assertEquals("ok", flow.binary(DraftDirection.GATEWAY, byteArrayOf(4, 5), clock()).code)
        assertTrue(text(flow, DraftDirection.GATEWAY, "end_write").eofDirections.isEmpty())
        assertEquals(DraftStreamPhase.DRAINING, flow.snapshot().phase)
        assertTrue(flow.drain(DraftDirection.CLIENT, 2, clock()).eofDirections.isEmpty())
        assertEquals(listOf(DraftDirection.CLIENT), flow.drain(DraftDirection.CLIENT, 1, clock()).eofDirections)
        assertEquals(DraftStreamPhase.DRAINING, flow.snapshot().phase)
        assertEquals(listOf(DraftDirection.GATEWAY), flow.drain(DraftDirection.GATEWAY, 2, clock()).eofDirections)
        assertEquals(DraftStreamPhase.CLOSING, flow.snapshot().phase)
        flow.webSocketClosed(1000, clock())
        assertEquals(1, session.snapshot().streamLeases)
        flow.confirmClosed(clock())
        assertEquals(DraftStreamPhase.COMPLETE, flow.snapshot().phase)
        assertNull(flow.snapshot().cause)
        assertEquals(0, session.snapshot().streamLeases)
    }
    @Test fun reversedEofAndCompletedCloseCannotBeInferredFromOneDirection() {
        val flow = stream(active())
        assertEquals(listOf(DraftDirection.GATEWAY), text(flow, DraftDirection.GATEWAY, "end_write").eofDirections)
        assertEquals("ok", flow.binary(DraftDirection.CLIENT, byteArrayOf(9), clock()).code)
        assertEquals("network_unreachable", flow.webSocketClosed(1000, clock()).code)
        assertEquals(1, flow.snapshot().chargedBytes)
        assertEquals(DraftStreamPhase.FAILED, flow.snapshot().phase)
        assertEquals("invalid_message", flow.drain(DraftDirection.CLIENT, 1, clock()).code)
        flow.confirmClosed(clock())
        assertEquals(0, flow.snapshot().chargedBytes)
    }
    @Test fun queuesAndPeeksHaveDefensiveCopiesAcrossWritersAndDirections() {
        val flow = stream(active())
        val offered = byteArrayOf(1, 2, 3, 4)
        flow.binary(DraftDirection.CLIENT, offered, clock()); offered.fill(9)
        flow.binary(DraftDirection.GATEWAY, byteArrayOf(7), clock())
        val peek = flow.peek(DraftDirection.CLIENT, 3, clock())
        assertArrayEquals(byteArrayOf(1, 2, 3), peek.bytes())
        peek.bytes().fill(8)
        assertArrayEquals(byteArrayOf(1, 2, 3), peek.bytes())
        assertArrayEquals(byteArrayOf(7), flow.peek(DraftDirection.GATEWAY, 8, clock()).bytes())
        assertEquals(5, flow.snapshot().chargedBytes)
        flow.drain(DraftDirection.CLIENT, 1, clock())
        assertArrayEquals(byteArrayOf(2, 3, 4), flow.peek(DraftDirection.CLIENT, 8, clock()).bytes())
        assertEquals(2, flow.snapshot().chargedFrames)
        assertFalse(peek.toString().contains("1, 2"))
    }
    @Test fun partialDrainsKeepFrameReservationAndBackpressureDoesNotAcceptBytes() {
        val limits = DraftLimits(4, 8, 8, 1, 1, 1)
        val pool = DraftBudgetPool(maxBytes = 8); val session = active(pool, limits = limits); val flow = stream(session)
        flow.binary(DraftDirection.CLIENT, byteArrayOf(1, 2, 3, 4), clock())
        flow.drain(DraftDirection.CLIENT, 3, clock())
        assertEquals("backpressure", flow.binary(DraftDirection.GATEWAY, byteArrayOf(8), clock(1)).code)
        assertEquals(1, flow.snapshot().chargedFrames)
        assertEquals(1, pool.snapshot().chargedBytes)
        assertArrayEquals(byteArrayOf(4), flow.peek(DraftDirection.CLIENT, 4, clock(1)).bytes())
        flow.drain(DraftDirection.CLIENT, 1, clock(1))
        assertEquals("ok", flow.binary(DraftDirection.GATEWAY, byteArrayOf(8), clock(1)).code)
    }
    @Test fun peekAndDrainSpanMessageBoundariesWhilePartialFramesStayCharged() {
        val flow = stream(active())
        flow.binary(DraftDirection.CLIENT, byteArrayOf(1, 2), clock())
        flow.binary(DraftDirection.CLIENT, byteArrayOf(3, 4, 5), clock())
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), flow.peek(DraftDirection.CLIENT, 4, clock()).bytes())
        assertEquals(2, flow.snapshot().chargedFrames)
        flow.drain(DraftDirection.CLIENT, 3, clock())
        assertEquals(1, flow.snapshot().chargedFrames)
        assertArrayEquals(byteArrayOf(4, 5), flow.peek(DraftDirection.CLIENT, 4, clock()).bytes())
    }
    @Test fun crossOwnerGlobalBytesStayChargedAfterAbortUntilConfirmedClosure() {
        val pool = DraftBudgetPool(maxBytes = 4)
        val limits = DraftLimits(4, 8, 8, 2, 8, 2)
        val one = active(pool, limits = limits); val first = stream(one)
        val two = active(pool, "other", limits)
        val second = two.allocateStream("other", token, clock()).stream!!
        text(second, DraftDirection.CLIENT, "open"); text(second, DraftDirection.GATEWAY, "ready")
        first.binary(DraftDirection.CLIENT, byteArrayOf(1, 2, 3, 4), clock())
        first.cancelLocally(clock())
        assertEquals("backpressure", second.binary(DraftDirection.CLIENT, byteArrayOf(5), clock()).code)
        assertEquals(4, pool.snapshot().chargedBytes)
        first.confirmClosed(clock())
        assertEquals("ok", second.binary(DraftDirection.CLIENT, byteArrayOf(5), clock()).code)
        assertEquals(1, pool.snapshot().chargedBytes)
    }
    @Test fun perDeviceCombinedBytesAndConcurrentSlotsIncludePendingAndClosingStreams() {
        val limits = DraftLimits(4, 8, 8, 2, 8, 3)
        val session = active(limits = limits); val first = stream(session)
        val second = stream(session, "second")
        first.binary(DraftDirection.CLIENT, byteArrayOf(1, 2, 3, 4), clock())
        second.binary(DraftDirection.GATEWAY, byteArrayOf(5, 6, 7, 8), clock())
        assertEquals("backpressure", first.binary(DraftDirection.GATEWAY, byteArrayOf(0), clock()).code)
        first.cancelLocally(clock())
        assertEquals("stream_limit", session.allocateStream("device", token, clock()).result.code)
        first.confirmClosed(clock())
        assertEquals("ok", session.allocateStream("device", token, clock()).result.code)
        assertEquals(4, session.snapshot().chargedBytes)
    }
    @Test fun sessionLeaseCannotBeReplacedUntilControlAndAllStreamResourcesClose() {
        val pool = DraftBudgetPool(); val first = active(pool); val flow = stream(first)
        first.cancelLocally(clock())
        first.confirmClosed(clock())
        assertEquals(DraftStreamPhase.CANCELLED, flow.snapshot().phase)
        assertEquals("cancelled", flow.snapshot().cause)
        assertEquals(1, pool.snapshot().sessionLeases)
        val blocked = controller(pool)
        send(blocked, DraftDirection.CLIENT, DraftMessage.Hello(caps, emptyList()))
        assertEquals("session_limit", send(blocked, DraftDirection.GATEWAY, DraftMessage.SessionReady(caps, "desktop", Instant.ofEpochMilli(epoch + 300000), DraftLimits(), token)).code)
        flow.confirmClosed(clock())
        assertEquals(0, pool.snapshot().sessionLeases)
        assertEquals(0, first.snapshot().openedIds)
        assertEquals(DraftControlPhase.ACTIVE, active(pool).snapshot().phase)
    }
    @Test fun wrongUpgradeCredentialsAndCapacityRefusalNeverMutateExistingOwners() {
        val pool = DraftBudgetPool(maxStreams = 1); val session = active(pool)
        assertEquals("authentication_failed", session.allocateStream("stranger", token, clock()).result.code)
        assertEquals("authentication_failed", session.allocateStream("device", "B".repeat(43), clock()).result.code)
        assertEquals(0, pool.snapshot().streamLeases)
        stream(session)
        assertEquals("stream_limit", session.allocateStream("device", token, clock()).result.code)
        assertEquals(DraftControlPhase.ACTIVE, session.snapshot().phase)
        assertEquals(1, pool.snapshot().streamLeases)
    }
    @Test fun streamIdHistorySurvivesCompletionButRemainsBoundedUntilSessionRelease() {
        val session = active(limits = DraftLimits(8, 8, 8, 1, 2, 2))
        finish(stream(session, "first"), "first")
        val duplicate = session.allocateStream("device", token, clock()).stream!!
        assertEquals("invalid_message", text(duplicate, DraftDirection.CLIENT, "open", "first").code)
        duplicate.confirmClosed(clock())
        finish(stream(session, "second"), "second")
        val third = session.allocateStream("device", token, clock()).stream!!
        assertEquals("stream_limit", text(third, DraftDirection.CLIENT, "open", "third").code)
        assertEquals(2, session.snapshot().openedIds)
        assertEquals(1, session.snapshot().streamLeases)
        third.confirmClosed(clock())
    }
    @Test fun invalidBeforeReadyAndAfterSealedBytesFailBeforeBackpressure() {
        val session = active(); val pending = stream(session, ready = false)
        assertEquals("invalid_message", pending.binary(DraftDirection.CLIENT, byteArrayOf(1), clock()).code)
        assertEquals(DraftStreamPhase.FAILED, pending.snapshot().phase)
        val flow = stream(session, "other")
        text(flow, DraftDirection.CLIENT, "end_write", "other")
        assertEquals("invalid_message", flow.binary(DraftDirection.CLIENT, byteArrayOf(1), clock()).code)
        assertEquals(0, flow.snapshot().chargedBytes)
    }
    @Test fun wrongIdDuplicateReadyAndInvalidDrainFailOnlyTheStream() {
        for (operation in listOf<(DraftStream) -> DraftResult>(
            { text(it, DraftDirection.GATEWAY, "ready") },
            { text(it, DraftDirection.CLIENT, "end_write", "wrong") },
            { it.drain(DraftDirection.CLIENT, 0, clock()) },
            { it.drain(DraftDirection.CLIENT, Long.MAX_VALUE, clock()) },
            { it.binary(null, byteArrayOf(1), clock()) },
        )) {
            val session = active(); val flow = stream(session)
            assertEquals("invalid_message", operation(flow).code)
            assertEquals(DraftControlPhase.ACTIVE, session.snapshot().phase)
            assertEquals(DraftStreamPhase.FAILED, flow.snapshot().phase)
        }
    }
    @Test fun timeFailuresWinOverMalformedInputAndNeverPreventClosureRelease() {
        val pool = DraftBudgetPool(); val session = active(pool, duration = 60000); val flow = stream(session)
        flow.binary(DraftDirection.CLIENT, byteArrayOf(1), clock())
        assertEquals("session_expired", flow.text(DraftDirection.CLIENT, byteArrayOf(0xff.toByte()), clock(60000)).code)
        assertEquals("session_expired", flow.snapshot().cause)
        assertEquals(1, pool.snapshot().chargedBytes)
        assertEquals("ok", flow.confirmClosed(clock(60000)).code)
        session.confirmClosed(clock(60000))
        assertEquals(0, pool.snapshot().chargedBytes)
        assertEquals(0, pool.snapshot().streamLeases)
        assertEquals(0, pool.snapshot().sessionLeases)
    }
    @Test fun monotonicLifetimeDoesNotExtendAfterWallClockRollback() {
        val session = active(duration = 60000)
        session.pingPong(DraftDirection.CLIENT, clock(59000, epoch - 60000))
        session.pingPong(DraftDirection.GATEWAY, clock(59000, epoch - 60000))
        assertEquals("session_expired", session.tick(clock(60000, epoch - 60000)).code)
        assertEquals("session_expired", session.snapshot().cause)
        assertEquals("session_expired", session.allocateStream("device", token, clock(60000)).result.code)
    }
    @Test fun backpressureAdvancesClockWatermarkButNeverIdleProgress() {
        val session = active(limits = DraftLimits(1, 1, 1, 1, 1, 1)); val flow = stream(session)
        flow.binary(DraftDirection.CLIENT, byteArrayOf(1), clock())
        session.pingPong(DraftDirection.CLIENT, clock(59000)); session.pingPong(DraftDirection.GATEWAY, clock(59000))
        assertEquals("backpressure", flow.binary(DraftDirection.CLIENT, byteArrayOf(2), clock(59999)).code)
        assertEquals("network_unreachable", flow.tick(clock(60000)).code)
        assertEquals(DraftControlPhase.ACTIVE, session.snapshot().phase)
        val second = active(limits = DraftLimits(1, 1, 1, 1, 1, 1)); val other = stream(second)
        other.binary(DraftDirection.CLIENT, byteArrayOf(1), clock())
        assertEquals("backpressure", other.binary(DraftDirection.CLIENT, byteArrayOf(2), clock(100)).code)
        assertEquals("invalid_message", other.tick(clock(99)).code)
        assertEquals(DraftControlPhase.FAILED, second.snapshot().phase)
    }
    @Test fun streamTrafficCannotKeepADeadControlDirectionAlive() {
        val session = active(); val flow = stream(session)
        session.pingPong(DraftDirection.CLIENT, clock(59000))
        flow.binary(DraftDirection.CLIENT, byteArrayOf(1), clock(59000))
        assertEquals("network_unreachable", flow.tick(clock(60000)).code)
        assertEquals(DraftControlPhase.FAILED, session.snapshot().phase)
        assertEquals("network_unreachable", flow.snapshot().cause)
    }
    @Test fun handshakesUseOriginalCreationTimeAndControlTickChecksPendingStreams() {
        val session = controller()
        send(session, DraftDirection.CLIENT, DraftMessage.Hello(caps, emptyList()), clock(14999))
        assertEquals("network_unreachable", session.tick(clock(15000)).code)
        val active = active(); val pending = active.allocateStream("device", token, clock()).stream!!
        active.tick(clock(15000))
        assertEquals(DraftStreamPhase.FAILED, pending.snapshot().phase)
        assertEquals(DraftControlPhase.ACTIVE, active.snapshot().phase)
    }
    @Test fun successfulCompletionRequiresResourceConfirmationBeforeExpiry() {
        val session = active(duration = 1000); val flow = stream(session)
        text(flow, DraftDirection.CLIENT, "end_write"); text(flow, DraftDirection.GATEWAY, "end_write")
        flow.webSocketClosed(1000, clock())
        assertTrue(flow.snapshot().webSocketClosed)
        assertEquals(1, session.snapshot().streamLeases)
        assertEquals("session_expired", flow.confirmClosed(clock(1000)).code)
        assertEquals(DraftStreamPhase.FAILED, flow.snapshot().phase)
        assertEquals("session_expired", flow.snapshot().cause)
        assertFalse(flow.snapshot().streamLease)
    }
    @Test fun closeObservationsAreIdempotentAndConflictingCodesCannotBecomeSuccess() {
        val flow = stream(active())
        text(flow, DraftDirection.CLIENT, "end_write"); text(flow, DraftDirection.GATEWAY, "end_write")
        assertEquals("ok", flow.webSocketClosed(1000, clock()).code)
        assertEquals("ok", flow.webSocketClosed(1000, clock()).code)
        assertEquals("network_unreachable", flow.webSocketClosed(1006, clock()).code)
        flow.confirmClosed(clock()); flow.confirmClosed(clock())
        assertEquals("network_unreachable", flow.snapshot().cause)
        assertEquals(DraftStreamPhase.FAILED, flow.snapshot().phase)
    }
    @Test fun normalCloseForbidsFurtherQueueOperationsButAllowsTrustedCancellation() {
        val flow = stream(active())
        text(flow, DraftDirection.CLIENT, "end_write"); text(flow, DraftDirection.GATEWAY, "end_write")
        flow.webSocketClosed(1000, clock())
        assertEquals("invalid_message", flow.peek(DraftDirection.CLIENT, 1, clock()).result.code)
        assertEquals(DraftStreamPhase.FAILED, flow.snapshot().phase)
        val other = stream(active())
        text(other, DraftDirection.CLIENT, "end_write"); text(other, DraftDirection.GATEWAY, "end_write")
        other.webSocketClosed(1000, clock()); other.cancelLocally(clock()); other.confirmClosed(clock())
        assertEquals(DraftStreamPhase.CANCELLED, other.snapshot().phase)
    }
    @Test fun resourceConfirmationWithoutWsCloseIsAnAbortAndReleasesExactlyOnce() {
        val pool = DraftBudgetPool(); val session = active(pool); val flow = stream(session)
        flow.binary(DraftDirection.CLIENT, byteArrayOf(1), clock())
        flow.confirmClosed(clock()); flow.confirmClosed(clock())
        assertEquals("network_unreachable", flow.snapshot().cause)
        session.confirmClosed(clock()); session.confirmClosed(clock())
        assertEquals("network_unreachable", session.snapshot().cause)
        assertEquals(0, pool.snapshot().sessionLeases)
        assertEquals(0, pool.snapshot().streamLeases)
        assertEquals(0, pool.snapshot().chargedBytes)
    }
    @Test fun terminalCauseCannotBeReplacedAndSnapshotsDoNotReadTime() {
        val session = active(); val flow = stream(session)
        flow.binary(DraftDirection.CLIENT, byteArrayOf(1), clock())
        text(flow, DraftDirection.GATEWAY, "error", code = "proxy_unavailable")
        assertEquals("invalid_message", text(flow, DraftDirection.CLIENT, "cancel").code)
        session.cancelLocally(clock())
        assertEquals("proxy_unavailable", flow.snapshot().cause)
        assertEquals(1, flow.snapshot().chargedBytes)
        assertEquals("cancelled", session.snapshot().cause)
        assertEquals("invalid_message", session.text(DraftDirection.CLIENT, byteArrayOf(), clock()).code)
        assertEquals("ok", session.tick(clock(Long.MAX_VALUE)).code)
        assertEquals("cancelled", session.snapshot().cause)
    }
    @Test fun invalidSafeIntegerClockFailsSessionButConfirmationStillReleases() {
        val pool = DraftBudgetPool(); val session = active(pool); val flow = stream(session)
        assertEquals("invalid_message", flow.confirmClosed(DraftClock(Long.MAX_VALUE, 0)).code)
        assertEquals(DraftControlPhase.FAILED, session.snapshot().phase)
        assertEquals(0, pool.snapshot().streamLeases)
        session.confirmClosed(clock())
        assertEquals(0, pool.snapshot().sessionLeases)
    }
    @Test fun negotiationChecksOfferSupportIdentityAndExpiryBeforeLeaseAcquisition() {
        val required = controller(supported = listOf("tcp-http"))
        assertEquals("unsupported_capability", send(required, DraftDirection.CLIENT, DraftMessage.Hello(caps, listOf("tcp-https-connect"))).code)
        val wrongDesktop = controller(); send(wrongDesktop, DraftDirection.CLIENT, DraftMessage.Hello(caps, emptyList()))
        assertEquals("authentication_failed", send(wrongDesktop, DraftDirection.GATEWAY, DraftMessage.SessionReady(caps, "other", Instant.ofEpochMilli(epoch + 1000), DraftLimits(), token)).code)
        val far = controller(); send(far, DraftDirection.CLIENT, DraftMessage.Hello(caps, emptyList()))
        assertEquals("invalid_message", send(far, DraftDirection.GATEWAY, DraftMessage.SessionReady(caps, "desktop", Instant.ofEpochMilli(epoch + 1801000), DraftLimits(), token)).code)
        assertFalse(far.snapshot().sessionLease)
    }
    @Test fun combinedReadinessDefectsFollowIdentityTimeCapabilitiesThenCapacity() {
        fun pending(pool: DraftBudgetPool = DraftBudgetPool()): DraftSession = controller(pool, supported = listOf("tcp-http")).also {
            send(it, DraftDirection.CLIENT, DraftMessage.Hello(caps, emptyList()))
        }
        val identity = pending()
        assertEquals("authentication_failed", send(identity, DraftDirection.GATEWAY,
            DraftMessage.SessionReady(listOf("future-feature"), "other", Instant.ofEpochMilli(epoch), DraftLimits(), token)).code)
        val expired = pending()
        assertEquals("session_expired", send(expired, DraftDirection.GATEWAY,
            DraftMessage.SessionReady(listOf("future-feature"), "desktop", Instant.ofEpochMilli(epoch), DraftLimits(), token)).code)
        val constrained = pending(DraftBudgetPool(maxBytes = 1))
        assertEquals("unsupported_capability", send(constrained, DraftDirection.GATEWAY,
            DraftMessage.SessionReady(listOf("tcp-https-connect"), "desktop", Instant.ofEpochMilli(epoch + 1000), DraftLimits(), token)).code)
    }
    @Test fun anAlreadyTerminalStreamKeepsItsOperationCodeWhileItsControllerExpires() {
        val session = active(duration = 1000); val flow = stream(session)
        text(flow, DraftDirection.GATEWAY, "error", code = "proxy_unavailable")
        assertEquals("invalid_message", flow.binary(DraftDirection.CLIENT, byteArrayOf(1), clock(1000)).code)
        assertEquals("proxy_unavailable", flow.snapshot().cause)
        assertEquals("session_expired", session.snapshot().cause)
    }
    @Test fun preOpenPeekIsEmptyAndPollingNeverExtendsTheHandshake() {
        val session = active(); val flow = session.allocateStream("device", token, clock()).stream!!
        assertEquals("ok", flow.peek(DraftDirection.CLIENT, 1, clock(14999)).result.code)
        assertEquals(0, flow.peek(DraftDirection.GATEWAY, 1, clock(14999)).bytes().size)
        assertEquals(DraftStreamPhase.AWAITING_OPEN, flow.snapshot().phase)
        assertEquals("network_unreachable", flow.peek(DraftDirection.CLIENT, 1, clock(15000)).result.code)
        assertEquals(DraftStreamPhase.FAILED, flow.snapshot().phase)
    }
}
