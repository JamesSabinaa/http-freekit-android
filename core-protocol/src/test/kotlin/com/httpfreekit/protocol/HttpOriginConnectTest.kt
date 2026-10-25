package com.httpfreekit.protocol

import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class HttpOriginConnectTest {
    private val epoch = Instant.parse("2026-10-25T12:00:00Z").toEpochMilli()
    private val token = "A".repeat(43)
    private fun clock(millis: Long = 0) = DraftClock(epoch + millis, millis)
    private val mode = HttpOriginConnect.PROXY_MODE
    private val capability = HttpOriginConnect.CAPABILITY

    private fun active(caps: List<String>, duration: Long = 300000): DraftSession {
        val session = DraftSession("device", "desktop", caps, DraftBudgetPool(), clock())
        assertEquals("ok", session.text(DraftDirection.CLIENT, DraftWireCodec.encode(DraftMessage.Hello(caps, caps)), clock()).code)
        assertEquals("ok", session.text(DraftDirection.GATEWAY, DraftWireCodec.encode(DraftMessage.SessionReady(
            caps, "desktop", Instant.ofEpochMilli(epoch + duration), DraftLimits(), token)), clock()).code)
        return session
    }
    private fun allocate(session: DraftSession): DraftStream {
        val allocation = session.allocateStream("device", token, clock())
        assertEquals("ok", allocation.result.code)
        return allocation.stream!!
    }
    private fun open(mode: String? = this.mode) = DraftWireCodec.encode(DraftMessage.Stream("open", "flow", proxyMode = mode))
    private fun reject(action: () -> Unit) {
        try { action(); fail("Expected a fixed protocol failure") }
        catch (failure: DraftProtocolException) { assertEquals("invalid_message", failure.code) }
    }

    @Test fun originalNumericAuthorityHasExactWireBytesAndNoRetainedInput() {
        val address = byteArrayOf(203.toByte(), 0, 113, 10)
        val encoded = HttpOriginConnect.preface(address)
        address.fill(0)
        assertEquals("CONNECT 203.0.113.10:80 HTTP/1.1\r\nHost: 203.0.113.10:80\r\n\r\n", String(encoded, Charsets.US_ASCII))
        val mapped = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff.toByte(), 0xff.toByte(), 192.toByte(), 0, 2, 128.toByte())
        assertEquals("CONNECT [0:0:0:0:0:ffff:c000:280]:80 HTTP/1.1\r\nHost: [0:0:0:0:0:ffff:c000:280]:80\r\n\r\n",
            String(HttpOriginConnect.preface(mapped), Charsets.US_ASCII))
        for (size in listOf(0, 3, 5, 15, 17)) reject { HttpOriginConnect.preface(ByteArray(size)) }
        for (port in listOf(0, 79, 81, 443, 65536)) reject { HttpOriginConnect.preface(ByteArray(4), port) }
    }

    @Test fun acknowledgementHandlesEverySplitAndLeavesCoalescedApplicationBytesUntouched() {
        val expected = "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII)
        assertEquals(39, expected.size)
        assertArrayEquals(expected, HttpOriginConnect.acknowledgementBytes())
        val tail = byteArrayOf(0, 1, 2, 0xff.toByte())
        for (split in 0..expected.size) {
            val reader = HttpOriginConnect.Acknowledgement()
            assertEquals(split, reader.accept(expected.copyOfRange(0, split)))
            val second = expected.copyOfRange(split, expected.size) + tail
            val before = second.copyOf()
            val consumed = reader.accept(second)
            assertEquals(expected.size - split, consumed)
            assertArrayEquals(tail, second.copyOfRange(consumed, second.size))
            assertArrayEquals(before, second)
            assertTrue(reader.complete)
            assertEquals(0, reader.accept(tail))
        }
        HttpOriginConnect.acknowledgementBytes().fill(0)
        assertArrayEquals(expected, HttpOriginConnect.acknowledgementBytes())
    }

    @Test fun incompletePrefixNeverCompletesAndMismatchIsTerminalWithoutRetainingText() {
        val expected = HttpOriginConnect.acknowledgementBytes()
        for (index in expected.indices) {
            val partial = HttpOriginConnect.Acknowledgement()
            partial.accept(expected.copyOfRange(0, index))
            assertFalse(partial.complete)
            val invalid = expected.copyOf(); invalid[index] = (invalid[index].toInt() xor 1).toByte()
            val failed = HttpOriginConnect.Acknowledgement()
            reject { failed.accept(invalid) }
            reject { failed.accept(expected) }
            assertFalse(failed.complete)
            assertFalse(failed.toString().contains("HTTP"))
        }
        val invalidRange = HttpOriginConnect.Acknowledgement()
        reject { invalidRange.accept(byteArrayOf(1), Int.MAX_VALUE, Int.MAX_VALUE) }
    }

    @Test fun optionalModeIsSchemaCheckedWhileLegacyEncodingRemainsExact() {
        assertEquals("{\"protocolVersion\":1,\"streamId\":\"flow\",\"type\":\"open\"}", String(open(null)))
        val encoded = open()
        assertEquals("{\"protocolVersion\":1,\"proxyMode\":\"http-origin-connect\",\"streamId\":\"flow\",\"type\":\"open\"}", String(encoded))
        val decoded = DraftWireCodec.decode(DraftChannel.STREAM, encoded) as DraftDecodeResult.Accepted
        assertEquals(mode, (decoded.message as DraftMessage.Stream).proxyMode)
        for (literal in listOf("null", "true", "1", "\"CANARY\"")) {
            val text = "{\"protocolVersion\":1,\"type\":\"open\",\"streamId\":\"flow\",\"proxyMode\":$literal}"
            assertEquals(DraftDecodeResult.Rejected("invalid_message"), DraftWireCodec.decode(DraftChannel.STREAM, text.toByteArray()))
        }
        reject { DraftWireCodec.encode(DraftMessage.Stream("ready", "flow", proxyMode = mode)) }
        val extensionError = DraftMessage.Stream("error", "flow", "unsupported_capability")
        assertTrue(DraftWireCodec.decode(DraftChannel.STREAM, DraftWireCodec.encode(extensionError)) is DraftDecodeResult.Accepted)
    }

    @Test fun newCapabilityAloneEstablishesTrafficAndExplicitModeClaimsOnlyAfterSupport() {
        val session = active(listOf(capability))
        val flow = allocate(session)
        assertEquals("ok", flow.text(DraftDirection.CLIENT, open(), clock()).code)
        assertEquals(1, session.snapshot().openedIds)
        assertEquals(DraftStreamPhase.AWAITING_READY, flow.snapshot().phase)
        assertEquals("ok", flow.text(DraftDirection.GATEWAY, DraftWireCodec.encode(DraftMessage.Stream("ready", "flow")), clock()).code)
        assertEquals("ok", flow.binary(DraftDirection.CLIENT, HttpOriginConnect.preface(byteArrayOf(127, 0, 0, 2)), clock()).code)
        flow.confirmClosed(clock()); session.confirmClosed(clock())
        assertEquals(0, session.snapshot().streamLeases)
    }

    @Test fun missingNegotiatedModeCannotClaimAnIdOrReleaseAnUnjoinedLease() {
        for ((caps, requestedMode) in listOf(listOf("tcp-https-connect") to mode, listOf(capability) to null)) {
            val session = active(caps)
            val flow = allocate(session)
            assertEquals("unsupported_capability", flow.text(DraftDirection.CLIENT, open(requestedMode), clock()).code)
            assertEquals(0, session.snapshot().openedIds)
            assertEquals(1, session.snapshot().streamLeases)
            flow.confirmClosed(clock())
            assertEquals(0, session.snapshot().streamLeases)
            session.confirmClosed(clock())
        }
    }

    @Test fun supportedLocalCapabilityIsInsufficientWhenOmittedFromNegotiation() {
        val caps = listOf(capability, "tcp-https-connect")
        val session = DraftSession("device", "desktop", caps, DraftBudgetPool(), clock())
        session.text(DraftDirection.CLIENT, DraftWireCodec.encode(DraftMessage.Hello(caps, emptyList())), clock())
        session.text(DraftDirection.GATEWAY, DraftWireCodec.encode(DraftMessage.SessionReady(listOf("tcp-https-connect"),
            "desktop", Instant.ofEpochMilli(epoch + 1000), DraftLimits(), token)), clock())
        val flow = allocate(session)
        assertEquals("unsupported_capability", flow.text(DraftDirection.CLIENT, open(), clock()).code)
        flow.confirmClosed(clock()); session.confirmClosed(clock())
    }

    @Test fun senderAndExpiryStillPrecedeModeSupport() {
        val session = active(listOf("tcp-https-connect"))
        val wrongSender = allocate(session)
        assertEquals("invalid_message", wrongSender.text(DraftDirection.GATEWAY, open(), clock()).code)
        wrongSender.confirmClosed(clock()); session.confirmClosed(clock())
        val expiring = active(listOf("tcp-https-connect"), 1000)
        val late = allocate(expiring)
        assertEquals("session_expired", late.text(DraftDirection.CLIENT, open(), clock(1000)).code)
        late.confirmClosed(clock(1000)); expiring.confirmClosed(clock(1000))
    }
}
