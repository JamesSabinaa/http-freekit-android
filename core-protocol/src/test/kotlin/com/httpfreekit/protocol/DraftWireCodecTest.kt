package com.httpfreekit.protocol

import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class DraftWireCodecTest {
    private val hello = """{"protocolVersion":1,"type":"hello","capabilities":["tcp-http"],"requiredCapabilities":[]}"""
    private fun rejected(text: String, code: String = "invalid_message", channel: DraftChannel = DraftChannel.CONTROL) =
        assertEquals(DraftDecodeResult.Rejected(code), DraftWireCodec.decode(channel, text.toByteArray()))

    @Test fun whitespaceOrderAndEscapesAreAcceptedAndEncodingIsDeterministic() {
        val input = """ { "requiredCapabilities":[], "capabilities":["tcp-https-connect","tcp-http"], "ty\u0070e":"he\u006clo", "protocolVersion":1 } """
        val accepted = DraftWireCodec.decode(DraftChannel.CONTROL, input.toByteArray()) as DraftDecodeResult.Accepted
        assertEquals("""{"capabilities":["tcp-http","tcp-https-connect"],"protocolVersion":1,"requiredCapabilities":[],"type":"hello"}""", String(DraftWireCodec.encode(accepted.message)))
    }
    @Test fun encodedByteBoundsIncludeWhitespaceAndTakePrecedence() {
        assertTrue(DraftWireCodec.decode(DraftChannel.CONTROL, (hello + " ".repeat(16384 - hello.length)).toByteArray()) is DraftDecodeResult.Accepted)
        rejected(hello + " ".repeat(16385 - hello.length), "message_too_large")
        assertEquals(DraftDecodeResult.Rejected("message_too_large"), DraftWireCodec.decode(DraftChannel.CONTROL, ByteArray(16385) { 0xff.toByte() }))
        rejected("")
    }
    @Test fun invalidUtf8BomAndTrailingMaterialAreRejected() {
        for (bytes in listOf(byteArrayOf(0xc0.toByte(), 0xaf.toByte()), byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()), byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + hello.toByteArray())) {
            assertEquals(DraftDecodeResult.Rejected("invalid_message"), DraftWireCodec.decode(DraftChannel.CONTROL, bytes))
        }
        for (suffix in listOf("{}", "// comment", " null")) rejected(hello + suffix)
    }
    @Test fun duplicateEscapeEquivalentKeysAndDeepOrLargeObjectsAreRejectedBeforeVersion() {
        rejected(hello.replace("\"protocolVersion\":1", "\"protocolVersion\":2,\"protocol\\u0056ersion\":1"))
        rejected("{" + (1..17).joinToString(",") { "\"k$it\":0" } + "}")
        rejected("[".repeat(5000) + "]".repeat(5000))
        rejected("{\"" + "a".repeat(257) + "\":0}")
    }
    @Test fun integerSpellingBoundsAndSchemaPrecedeVersion() {
        for (version in listOf("0", "-0", "-1", "1.0", "1e0", "2147483648", "999999999999999999999999999", "true", "null", "\"1\"")) {
            rejected(hello.replace("\"protocolVersion\":1", "\"protocolVersion\":$version"))
        }
        rejected(hello.replace("\"protocolVersion\":1", "\"protocolVersion\":2"), "unsupported_version")
        rejected(hello.replace("\"protocolVersion\":1", "\"protocolVersion\":2").replace("\"hello\"", "\"unknown\""))
        rejected(hello.replace("\"protocolVersion\":1", "\"protocolVersion\":2").dropLast(1) + ",\"unknown\":1}")
    }
    @Test fun capabilitySyntaxUniquenessSubsetAndUnknownNamesAreSchemaOnly() {
        for (caps in listOf("[]", "[\"tcp-http\",\"tcp-http\"]", "[\"UPPER\"]", "[null]", "[1]")) {
            rejected(hello.replace("[\"tcp-http\"]", caps))
        }
        rejected(hello.replace("\"requiredCapabilities\":[]", "\"requiredCapabilities\":[\"unknown\"]"))
        val unknown = DraftMessage.Hello(listOf("future-feature"), listOf("future-feature"))
        assertTrue(DraftWireCodec.decode(DraftChannel.CONTROL, DraftWireCodec.encode(unknown)) is DraftDecodeResult.Accepted)
    }
    @Test fun readinessDateBase64AndDependentLimitsAreStrict() {
        val ready = DraftMessage.SessionReady(listOf("tcp-http"), "desktop", Instant.parse("2028-02-29T12:00:00Z"), DraftLimits(), "A".repeat(43))
        val wire = String(DraftWireCodec.encode(ready))
        for (date in listOf("2027-02-29T12:00:00Z", "2100-01-01T00:00:00Z", "2028-02-29T24:00:00Z", "2028-02-29T12:00:60Z", "2028-02-29T12:00:00.0Z", "2028-02-29T12:00:00+00:00")) rejected(wire.replace("2028-02-29T12:00:00Z", date))
        rejected(wire.replace("A".repeat(43), "A".repeat(42) + "B"))
        rejected(wire.replace("\"maxQueuedBytesPerStream\":1048576", "\"maxQueuedBytesPerStream\":1"))
        rejected(wire.replace("\"maxFrameBytes\":65536", "\"maxFrameBytes\":65537"))
        rejected(wire.replace("\"maxConcurrentStreams\":64", "\"maxConcurrentStreams\":0"))
    }
    @Test fun channelsAndExactErrorEnumsDoNotAcceptDestinationOrSessionFields() {
        val stream = String(DraftWireCodec.encode(DraftMessage.Stream("open", "flow")))
        rejected(stream)
        rejected(hello, channel = DraftChannel.STREAM)
        rejected(stream.dropLast(1) + ",\"sessionId\":\"secret\"}", channel = DraftChannel.STREAM)
        rejected(stream.replace("\"open\"", "\"error\"").dropLast(1) + ",\"code\":\"cancelled\"}", channel = DraftChannel.STREAM)
        rejected("""{"protocolVersion":1,"type":"disconnect","code":"invalid_message"}""")
    }
    @Test fun constructedMessagesSnapshotCapabilitiesAndNeverPrintSecrets() {
        val values = arrayListOf("tcp-http")
        val message = DraftMessage.Hello(values, emptyList())
        values.clear()
        assertEquals(listOf("tcp-http"), message.capabilities)
        assertThrows(UnsupportedOperationException::class.java) { (message.capabilities as MutableList).clear() }
        val secret = "DO_NOT_PRINT_IDENTITY"
        assertFalse(DraftMessage.ControlEnd(secret, secret).toString().contains(secret))
        val failure = assertThrows(DraftProtocolException::class.java) { DraftWireCodec.encode(DraftMessage.ControlEnd(secret, secret)) }
        assertEquals("invalid_message", failure.message)
    }
}
