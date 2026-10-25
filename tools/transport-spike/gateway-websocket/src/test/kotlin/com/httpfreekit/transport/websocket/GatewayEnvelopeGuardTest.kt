package com.httpfreekit.transport.websocket

import java.io.ByteArrayOutputStream
import org.java_websocket.WebSocketImpl
import org.java_websocket.WebSocketListener
import org.java_websocket.exceptions.InvalidDataException
import org.junit.Assert.*
import org.junit.Test

class GatewayEnvelopeGuardTest {
    private fun accepted(wire: ByteArray, split: Int = 1): ByteArray {
        val result = ByteArrayOutputStream()
        val guard = GatewayEnvelopeGuard()
        var at = 0
        while (at < wire.size) {
            val size = minOf(split, wire.size - at)
            guard.feed(wire, at, size) { bytes, offset, count -> result.write(bytes, offset, count) }
            at += size
        }
        return result.toByteArray()
    }
    private fun rejected(wire: ByteArray) {
        try { accepted(wire); fail("Accepted invalid server envelope") } catch (_: InvalidDataException) { }
    }
    @Test fun preservesValidatedBytesAcrossEveryHeaderSplitAndInterleavedPing() {
        val wire = byteArrayOf(1, 2, 65, 66, 0x89.toByte(), 0, 0x80.toByte(), 1, 67)
        for (split in 1..wire.size) assertArrayEquals(wire, accepted(wire, split))
    }
    @Test fun rejectsServerMaskRsvReservedOpcodeAndFragmentedControlBeforePassingHeader() {
        for (wire in listOf(byteArrayOf(0x82.toByte(), 0x80.toByte()), byteArrayOf(0xc2.toByte(), 0),
            byteArrayOf(0x83.toByte(), 0), byteArrayOf(9, 0))) rejected(wire)
    }
    @Test fun rejectsNonminimalAndSignedOrOversizedLengthsBeforePayloadAllocation() {
        for (wire in listOf(byteArrayOf(0x82.toByte(), 126, 0, 125),
            byteArrayOf(0x82.toByte(), 127, 0, 0, 0, 0, 0, 0, 0, 126),
            byteArrayOf(0x82.toByte(), 127, 0x80.toByte(), 0, 0, 0, 0, 0, 0, 0),
            byteArrayOf(0x82.toByte(), 127, 0, 0, 0, 0, 0, 1, 0, 1),
            byteArrayOf(0x89.toByte(), 126, 0, 126))) rejected(wire)
    }
    @Test fun boundsWholeMessagesAndAllowsExactBinaryMaximum() {
        val exact = byteArrayOf(0x82.toByte(), 127, 0, 0, 0, 0, 0, 1, 0, 0) + ByteArray(65536)
        assertArrayEquals(exact, accepted(exact, 8192))
        rejected(byteArrayOf(0x81.toByte(), 126, 0x40, 1))
        val fragmented = byteArrayOf(2, 126, 0xff.toByte(), 0xff.toByte()) + ByteArray(65535) + byteArrayOf(0x80.toByte(), 2)
        rejected(fragmented)
    }
    @Test fun boundsEmptyFragmentMetadataAndRejectsContinuationMisuse() {
        val allowed = byteArrayOf(2, 0) + ByteArray(126 * 2) + byteArrayOf(0x80.toByte(), 0)
        assertArrayEquals(allowed, accepted(allowed))
        rejected(byteArrayOf(2, 0) + ByteArray(127 * 2) + byteArrayOf(0x80.toByte(), 0))
        rejected(byteArrayOf(0x80.toByte(), 0))
        rejected(byteArrayOf(2, 0, 0x82.toByte(), 0))
    }
    @Test fun constructorCopyRetainsProjectDraftGuards() {
        val copied = GuardedGatewayDraft().copyInstance()
        assertTrue(copied is GuardedGatewayDraft)
        assertEquals(65536, (copied as GuardedGatewayDraft).maxFrameSize)
        assertFalse(copied.toString().contains("gateway-fixture"))
        val listener = java.lang.reflect.Proxy.newProxyInstance(WebSocketListener::class.java.classLoader,
            arrayOf(WebSocketListener::class.java)) { _, _, _ -> null } as WebSocketListener
        assertTrue(WebSocketImpl(listener, GuardedGatewayDraft()).draft is GuardedGatewayDraft)
    }
    @Test fun invalidAdvertisedAllocationNeverReachesTheMaintainedDecoder() {
        var forwarded = 0
        try {
            GatewayEnvelopeGuard().feed(byteArrayOf(0x82.toByte(), 127, 0x7f, 0xff.toByte(), 0xff.toByte(),
                0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte()), 0, 10) { _, _, count -> forwarded += count }
            fail("Accepted excessive allocation")
        } catch (_: InvalidDataException) { }
        assertEquals(0, forwarded)
    }
}
