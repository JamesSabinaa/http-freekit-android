package com.httpfreekit.research.websocket

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ResearchWebSocketTest {
    @Test fun coalescedMessagesStayUnreadUntilTheLeasedEventIsReleased() {
        val first = frame(2, byteArrayOf(1, 2, 3))
        val input = CountingInput(first + frame(1, "next".toByteArray()))
        val reader = ResearchWebSocketReader(input, EndpointRole.CLIENT)
        val event = reader.read() as ResearchWebSocketEvent.Binary
        assertEquals(first.size, input.position)
        assertArrayEquals(byteArrayOf(1, 2, 3), event.copyBytes())
        event.copyBytes().fill(0)
        assertArrayEquals(byteArrayOf(1, 2, 3), event.copyBytes())
        rejected(FramingFailure.MESSAGE_PENDING) { reader.read() }
        assertEquals(first.size, input.position)
        event.release()
        event.release()
        rejected(FramingFailure.CLOSED) { event.copyBytes() }
        val next = reader.read() as ResearchWebSocketEvent.Text
        assertEquals("next", next.copyBytes().toString(Charsets.UTF_8))
        next.release()
    }

    @Test fun fragmentedUtf8AndInterleavedControlSurviveShortReadsAndLeaseRefusal() {
        val input = CountingInput(
            frame(1, byteArrayOf(65, 0xe2.toByte()), final = false, masked = true) +
                frame(9, byteArrayOf(7), masked = true) +
                frame(0, byteArrayOf(0x82.toByte()), final = false, masked = true) +
                frame(0, byteArrayOf(0xac.toByte(), 90), masked = true),
            chunk = 1,
        )
        val reader = ResearchWebSocketReader(input, EndpointRole.SERVER)
        val ping = reader.read() as ResearchWebSocketEvent.Ping
        assertArrayEquals(byteArrayOf(7), ping.copyBytes())
        rejected(FramingFailure.MESSAGE_PENDING) { reader.read() }
        ping.release()
        val message = reader.read() as ResearchWebSocketEvent.Text
        assertEquals("A€Z", message.copyBytes().toString(Charsets.UTF_8))
        message.release()
    }

    @Test fun acceptsExactLengthBoundariesWithoutChangingPayloads() {
        for (count in listOf(0, 1, 125, 126, 65535, 65536)) {
            val bytes = ByteArray(count) { (it % 251).toByte() }
            val event = ResearchWebSocketReader(ByteArrayInputStream(frame(2, bytes)), EndpointRole.CLIENT).read()
            assertArrayEquals(bytes, event.copyBytes())
            event.release()
        }
        val text = ByteArray(16384) { 65 }
        val event = ResearchWebSocketReader(ByteArrayInputStream(frame(1, text)), EndpointRole.CLIENT).read()
        assertArrayEquals(text, event.copyBytes())
        event.release()
    }

    @Test fun rejectsHugeAndCumulativeLengthsBeforeReadingAnyOffendingPayload() {
        for (header in listOf(
            byteArrayOf(0x82.toByte(), 127, 0x7f, -1, -1, -1, -1, -1, -1, -1),
            byteArrayOf(0x81.toByte(), 126, 0x40, 1),
            byteArrayOf(0x82.toByte(), 126, 1, 1),
        )) {
            val input = CountingInput(header)
            val binaryLimit = if (header.size == 4 && header[0] == 0x82.toByte()) 256 else 65536
            rejected(FramingFailure.TOO_LARGE) { ResearchWebSocketReader(input, EndpointRole.CLIENT, binaryLimit).read() }
            assertEquals(header.size, input.position)
            assertEquals(0, input.bodyReads)
        }
        val prefix = frame(2, byteArrayOf(1, 2, 3), final = false)
        val input = CountingInput(prefix + byteArrayOf(0x80.toByte(), 2))
        rejected(FramingFailure.TOO_LARGE) { ResearchWebSocketReader(input, EndpointRole.CLIENT, 4).read() }
        assertEquals(prefix.size + 2, input.position)
        assertEquals(1, input.bodyReads)
    }

    @Test fun rejectsMaskRoleMismatchReservedBitsAndUnknownOpcodes() {
        for (role in EndpointRole.entries) {
            val wrong = frame(2, byteArrayOf(1), masked = role == EndpointRole.CLIENT)
            rejected(FramingFailure.PROTOCOL) { ResearchWebSocketReader(ByteArrayInputStream(wrong), role).read() }
        }
        for (first in listOf(0xc2, 0xa2, 0x92, 0x83, 0x84, 0x8b, 0x8f)) {
            rejected(FramingFailure.PROTOCOL) {
                ResearchWebSocketReader(ByteArrayInputStream(byteArrayOf(first.toByte(), 0)), EndpointRole.CLIENT).read()
            }
        }
    }

    @Test fun rejectsNonminimalLengthsAndSigned64BitLengths() {
        for (wire in listOf(
            byteArrayOf(0x82.toByte(), 126, 0, 125),
            byteArrayOf(0x82.toByte(), 127, 0, 0, 0, 0, 0, 0, -1, -1),
            byteArrayOf(0x82.toByte(), 127, 0x80.toByte()),
        )) rejected(FramingFailure.PROTOCOL) {
            ResearchWebSocketReader(ByteArrayInputStream(wire), EndpointRole.CLIENT).read()
        }
    }

    @Test fun rejectsIllegalContinuationAndControlFragmentation() {
        for (wire in listOf(
            frame(0, byteArrayOf()),
            frame(2, byteArrayOf(), final = false) + frame(1, byteArrayOf()),
            frame(9, byteArrayOf(), final = false),
            byteArrayOf(0x89.toByte(), 126),
        )) rejected(FramingFailure.PROTOCOL) {
            ResearchWebSocketReader(ByteArrayInputStream(wire), EndpointRole.CLIENT).read()
        }
    }

    @Test fun validatesCloseCodesReasonUtf8AndTerminalReadBehavior() {
        for (code in listOf(1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 4999)) {
            val reader = ResearchWebSocketReader(ByteArrayInputStream(frame(8, close(code, "done\r\n"))), EndpointRole.CLIENT)
            val event = reader.read() as ResearchWebSocketEvent.Close
            assertEquals(code, event.code)
            assertEquals("done\r\n", event.reason)
            assertFalse(event.toString().contains("done"))
            event.release()
            rejected(FramingFailure.CLOSED) { reader.read() }
        }
        val empty = ResearchWebSocketReader(ByteArrayInputStream(frame(8, byteArrayOf())), EndpointRole.CLIENT).read()
        assertNull((empty as ResearchWebSocketEvent.Close).code)
        empty.release()
        for (code in listOf(0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535)) {
            rejected(FramingFailure.PROTOCOL) {
                ResearchWebSocketReader(ByteArrayInputStream(frame(8, close(code))), EndpointRole.CLIENT).read()
            }
        }
        for (bytes in listOf(byteArrayOf(0), byteArrayOf(3, -24, 0xc0.toByte(), 0x80.toByte()))) {
            rejected(FramingFailure.PROTOCOL) {
                ResearchWebSocketReader(ByteArrayInputStream(frame(8, bytes)), EndpointRole.CLIENT).read()
            }
        }
    }

    @Test fun rejectsInvalidUtf8IncludingSequencesSplitAcrossFragments() {
        for (bytes in listOf(
            byteArrayOf(0xc0.toByte(), 0x80.toByte()),
            byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
            byteArrayOf(0xf4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()),
            byteArrayOf(0xe2.toByte(), 0x82.toByte()),
        )) {
            for (wire in listOf(frame(1, bytes), frame(1, bytes.copyOfRange(0, 1), final = false) + frame(0, bytes.copyOfRange(1, bytes.size)))) {
                rejected(FramingFailure.PROTOCOL) {
                    ResearchWebSocketReader(ByteArrayInputStream(wire), EndpointRole.CLIENT).read()
                }
            }
        }
    }

    @Test fun everyTruncatedFramePrefixFailsAndCannotRevive() {
        val whole = frame(2, ByteArray(127) { 11 }, masked = true)
        for (cut in 0 until whole.size) {
            val reader = ResearchWebSocketReader(ByteArrayInputStream(whole.copyOf(cut)), EndpointRole.SERVER)
            rejected(FramingFailure.TRUNCATED) { reader.read() }
            rejected(FramingFailure.TRUNCATED) { reader.read() }
        }
    }

    @Test fun limitsEmptyFragmentsAndInterleavedControlEvents() {
        val accepted = frame(2, byteArrayOf(), final = false) +
            (1..62).fold(byteArrayOf()) { acc, _ -> acc + frame(0, byteArrayOf(), final = false) } +
            frame(0, byteArrayOf(8))
        val event = ResearchWebSocketReader(ByteArrayInputStream(accepted), EndpointRole.CLIENT).read()
        assertArrayEquals(byteArrayOf(8), event.copyBytes())
        event.release()
        val rejected = frame(2, byteArrayOf(), final = false) +
            (1..64).fold(byteArrayOf()) { acc, _ -> acc + frame(0, byteArrayOf(), final = false) }
        rejected(FramingFailure.PROTOCOL) { ResearchWebSocketReader(ByteArrayInputStream(rejected), EndpointRole.CLIENT).read() }
        val controls = frame(2, byteArrayOf(), final = false) +
            (1..65).fold(byteArrayOf()) { acc, _ -> acc + frame(9, byteArrayOf()) }
        val reader = ResearchWebSocketReader(ByteArrayInputStream(controls), EndpointRole.CLIENT)
        repeat(64) { reader.read().release() }
        rejected(FramingFailure.PROTOCOL) { reader.read() }
    }

    @Test fun concurrentReadRefusesWithoutStealingOrFailingTheActiveRead() {
        val entered = CountDownLatch(1)
        val proceed = CountDownLatch(1)
        val input = object : ByteArrayInputStream(frame(2, byteArrayOf(9))) {
            override fun read(): Int {
                entered.countDown()
                check(proceed.await(5, TimeUnit.SECONDS))
                return super.read()
            }
        }
        val executor = Executors.newSingleThreadExecutor()
        try {
            val reader = ResearchWebSocketReader(input, EndpointRole.CLIENT)
            val active = executor.submit<ResearchWebSocketEvent> { reader.read() }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            rejected(FramingFailure.CONCURRENT_READ) { reader.read() }
            proceed.countDown()
            val event = active.get(5, TimeUnit.SECONDS)
            assertArrayEquals(byteArrayOf(9), event.copyBytes())
            event.release()
        } finally {
            proceed.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test fun writerUsesMinimalLengthsAndFreshMasksWithoutMutatingCallerBytes() {
        for (count in listOf(0, 125, 126, 65535, 65536)) {
            val payload = ByteArray(count) { (it % 251).toByte() }
            val expected = payload.copyOf()
            val output = ByteArrayOutputStream()
            ResearchWebSocketWriter(output, EndpointRole.CLIENT).binary(payload)
            val wire = output.toByteArray()
            assertEquals(0x82, wire[0].toInt() and 255)
            assertEquals(if (count < 126) count else if (count < 65536) 126 else 127, wire[1].toInt() and 127)
            assertTrue(wire[1].toInt() and 128 != 0)
            val headerSize = if (count < 126) 2 else if (count < 65536) 4 else 10
            val key = wire.copyOfRange(headerSize, headerSize + 4)
            val decoded = wire.copyOfRange(headerSize + 4, wire.size)
            repeat(decoded.size) { index -> decoded[index] = (decoded[index].toInt() xor key[index % 4].toInt()).toByte() }
            assertArrayEquals(expected, decoded)
            assertArrayEquals(expected, payload)
        }
        val output = ByteArrayOutputStream()
        val writer = ResearchWebSocketWriter(output, EndpointRole.CLIENT)
        repeat(4) { writer.ping(byteArrayOf()) }
        val masks = output.toByteArray().asList().chunked(6).map { it.drop(2) }
        assertEquals(4, masks.toSet().size)
    }

    @Test fun writerSerializesConcurrentFramesAndWaitsForActualFlush() {
        val output = GatedOutput()
        val writer = ResearchWebSocketWriter(output, EndpointRole.SERVER)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val first = executor.submit { writer.binary(byteArrayOf(1, 2)) }
            assertTrue(output.entered.await(5, TimeUnit.SECONDS))
            assertFalse(first.isDone)
            val second = executor.submit { writer.pong(byteArrayOf(3)) }
            assertArrayEquals(byteArrayOf(0x82.toByte(), 2, 1, 2), output.snapshot())
            assertFalse(second.isDone)
            output.proceed.countDown()
            first.get(5, TimeUnit.SECONDS)
            second.get(5, TimeUnit.SECONDS)
            assertArrayEquals(byteArrayOf(0x82.toByte(), 2, 1, 2, 0x8a.toByte(), 1, 3), output.snapshot())
        } finally {
            output.proceed.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test fun writerRejectsInvalidInputsBeforeOutputAndAllowsValidRetry() {
        val output = ByteArrayOutputStream()
        val writer = ResearchWebSocketWriter(output, EndpointRole.SERVER, maxBinaryBytes = 4)
        rejected(FramingFailure.TOO_LARGE) { writer.binary(ByteArray(5)) }
        rejected(FramingFailure.TOO_LARGE) { writer.ping(ByteArray(126)) }
        rejected(FramingFailure.TOO_LARGE) { writer.text(ByteArray(16385)) }
        rejected(FramingFailure.PROTOCOL) { writer.text(byteArrayOf(0xff.toByte())) }
        rejected(FramingFailure.PROTOCOL) { writer.close(byteArrayOf(0)) }
        assertEquals(0, output.size())
        writer.binary(byteArrayOf(1))
        writer.close(close(1000))
        rejected(FramingFailure.CLOSED) { writer.ping(byteArrayOf()) }
    }

    @Test fun ioFailurePoisonsWriterWithoutLeakingProviderDetails() {
        val writer = ResearchWebSocketWriter(object : OutputStream() {
            override fun write(value: Int) { throw IOException("private-payload-detail") }
        }, EndpointRole.SERVER)
        val error = rejected(FramingFailure.IO) { writer.binary(byteArrayOf(1)) }
        assertNull(error.cause)
        assertFalse(error.toString().contains("private-payload-detail"))
        rejected(FramingFailure.CLOSED) { writer.binary(byteArrayOf(2)) }
        val reader = ResearchWebSocketReader(object : InputStream() {
            override fun read(): Int { throw IOException("private-reader-detail") }
        }, EndpointRole.CLIENT)
        rejected(FramingFailure.IO) { reader.read() }
        rejected(FramingFailure.IO) { reader.read() }
    }

    @Test fun invalidConfigurationFailsBeforeAnyIo() {
        for ((binary, text) in listOf(0 to 1, 65537 to 1, 1 to 0, 1 to 16385)) {
            assertThrows(IllegalArgumentException::class.java) {
                ResearchWebSocketReader(ByteArrayInputStream(byteArrayOf()), EndpointRole.CLIENT, binary, text)
            }
            assertThrows(IllegalArgumentException::class.java) {
                ResearchWebSocketWriter(ByteArrayOutputStream(), EndpointRole.SERVER, binary, text)
            }
        }
    }

    private fun rejected(expected: FramingFailure, action: () -> Unit): ResearchWebSocketException =
        assertThrows(ResearchWebSocketException::class.java, action).also { assertEquals(expected, it.failure) }

    private fun close(code: Int, reason: String = "") = byteArrayOf((code ushr 8).toByte(), code.toByte()) + reason.toByteArray()

    /** Independent wire builder, used to exercise the reader without calling its paired writer. */
    private fun frame(opcode: Int, bytes: ByteArray, final: Boolean = true, masked: Boolean = false): ByteArray {
        val result = ByteArrayOutputStream()
        result.write((if (final) 128 else 0) or opcode)
        val maskBit = if (masked) 128 else 0
        when {
            bytes.size <= 125 -> result.write(maskBit or bytes.size)
            bytes.size <= 65535 -> { result.write(maskBit or 126); result.write(bytes.size ushr 8); result.write(bytes.size and 255) }
            else -> {
                result.write(maskBit or 127)
                for (shift in 56 downTo 0 step 8) result.write(((bytes.size.toLong() ushr shift) and 255).toInt())
            }
        }
        val mask = byteArrayOf(0x35, 0x71, 0x19, 0x67)
        if (masked) result.write(mask)
        bytes.forEachIndexed { index, value -> result.write(if (masked) value.toInt() xor mask[index % 4].toInt() else value.toInt()) }
        return result.toByteArray()
    }

    private class CountingInput(bytes: ByteArray, private val chunk: Int = Int.MAX_VALUE) : ByteArrayInputStream(bytes) {
        val position: Int get() = pos
        var bodyReads = 0
        override fun read(target: ByteArray, offset: Int, length: Int): Int {
            bodyReads++
            return super.read(target, offset, minOf(chunk, length))
        }
    }

    private class GatedOutput : OutputStream() {
        private val bytes = ByteArrayOutputStream()
        val entered = CountDownLatch(1)
        val proceed = CountDownLatch(1)
        @Synchronized override fun write(value: Int) { bytes.write(value) }
        override fun flush() { entered.countDown(); check(proceed.await(5, TimeUnit.SECONDS)) }
        @Synchronized fun snapshot(): ByteArray = bytes.toByteArray()
    }
}
