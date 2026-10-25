package com.httpfreekit.protocol

import java.io.File
import java.security.MessageDigest
import java.io.ByteArrayOutputStream
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

/** Executes the shared producer/codec/response cases; desktop request parsing is a separate binding. */
class HttpOriginWireVectorsTest {
    @Test fun independentlyAuthoredWireBytesMatchAllKotlinClientCases() {
        val bytes = File("protocol/fixtures/c2-draft-0.5/wire.json").inputStream().use { it.readNBytes(131073) }
        require(bytes.size in 1..131072)
        assertEquals("0419f01daa637ddc9433e2ee8f23cac86b841e2cf162a545ed9750e3077f463d",
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) })
        val root = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        assertEquals("http-freekit-http-origin-vectors", root.getValue("format").jsonPrimitive.content)
        assertEquals(1, root.getValue("revision").jsonPrimitive.int)
        val groups = listOf("requests", "opens", "responses", "prefaces")
        val ids = groups.flatMap { name -> root.getValue(name).jsonArray.map { it.jsonObject.getValue("id").jsonPrimitive.content } }
        assertEquals(61, ids.size); assertEquals(ids.size, ids.toSet().size)
        var executed = 0
        for (raw in root.getValue("requests").jsonArray) {
            val item = raw.jsonObject
            val expected = item.getValue("expect").jsonObject
            val output = try {
                HttpOriginConnect.preface(hex(item.getValue("addressHex").jsonPrimitive.content), item.getValue("port").jsonPrimitive.int)
            } catch (_: DraftProtocolException) { null }
            if (expected.getValue("outcome").jsonPrimitive.content == "accepted") {
                assertNotNull(item.getValue("id").jsonPrimitive.content, output)
                assertArrayEquals(hex(expected.getValue("wireHex").jsonPrimitive.content), output)
            } else assertNull(item.getValue("id").jsonPrimitive.content, output)
            executed++
        }
        for (raw in root.getValue("opens").jsonArray) {
            val item = raw.jsonObject
            val expected = item.getValue("expect").jsonObject
            val decoded = DraftWireCodec.decode(DraftChannel.STREAM, hex(item.getValue("wireHex").jsonPrimitive.content))
            if (expected.getValue("outcome").jsonPrimitive.content == "accepted") {
                assertTrue(item.getValue("id").jsonPrimitive.content, decoded is DraftDecodeResult.Accepted)
                assertArrayEquals(hex(expected.getValue("canonicalHex").jsonPrimitive.content),
                    DraftWireCodec.encode((decoded as DraftDecodeResult.Accepted).message))
            } else assertEquals(DraftDecodeResult.Rejected(expected.getValue("code").jsonPrimitive.content), decoded)
            executed++
        }
        for (raw in root.getValue("responses").jsonArray) {
            val item = raw.jsonObject
            val expected = item.getValue("expect").jsonObject
            val consumer = HttpOriginConnect.Acknowledgement()
            val remaining = ByteArrayOutputStream()
            var rejected = false
            for (chunk in item.getValue("chunksHex").jsonArray) {
                val input = hex(chunk.jsonPrimitive.content)
                if (rejected) continue
                try {
                    val count = consumer.accept(input)
                    remaining.write(input, count, input.size - count)
                } catch (_: DraftProtocolException) { rejected = true }
            }
            val accepted = !rejected && consumer.complete
            if (expected.getValue("outcome").jsonPrimitive.content == "accepted") {
                assertTrue(item.getValue("id").jsonPrimitive.content, accepted)
                assertArrayEquals(hex(expected.getValue("remainingHex").jsonPrimitive.content), remaining.toByteArray())
            } else assertFalse(item.getValue("id").jsonPrimitive.content, accepted)
            executed++
        }
        assertEquals(38, executed)
    }

    private fun hex(value: String): ByteArray {
        require(value.matches(Regex("(?:[0-9a-f]{2})*")) && value.length <= 131072)
        return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
