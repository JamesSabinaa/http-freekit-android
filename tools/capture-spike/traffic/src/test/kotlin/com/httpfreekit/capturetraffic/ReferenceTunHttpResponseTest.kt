package com.httpfreekit.capturetraffic

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.SocketException
import java.net.SocketTimeoutException
import org.junit.Assert.*
import org.junit.Test

class ReferenceTunHttpResponseTest {
    private val body = ReferenceTunHttpResponse.expectedBody()
    private val header = "HTTP/1.1 200 OK\r\nContent-Length: 81\r\nConnection: close\r\n\r\n"

    @Test fun fixedRequestAndFragmentedResponse() {
        val request = ReferenceTunHttpResponse.request()
        val prefix = "POST /reference/proof HTTP/1.1\r\nHost: reference-target.invalid\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n".toByteArray()
        assertArrayEquals(prefix + ByteArray(4096) { ((it * 31 + 7) and 255).toByte() }, request)
        assertEquals(81, body.size)
        assertEquals("reference-origin:d41d438c379110c7f7b2c561b1f04f26c1b4549110791f8e022f48974280c13e", String(body, Charsets.US_ASCII))
        for (chunk in listOf(1, 7, 81)) {
            val input = object : ByteArrayInputStream(header.toByteArray() + body) {
                override fun read(b: ByteArray, off: Int, len: Int) = super.read(b, off, minOf(len, chunk))
            }
            assertArrayEquals(body, ReferenceTunHttpResponse.readBody(input))
            ReferenceTunHttpResponse.requireEof(input)
        }
    }

    @Test fun hostileStatusFramingAndHeaderSyntax() {
        val invalid = listOf(
            "HTTP/1.0 200 OK\r\nContent-Length: 81", "HTTP/1.1 201 OK\r\nContent-Length: 81",
            "HTTP/1.1 200 Other\r\nContent-Length: 81", "HTTP/1.1 200 OK\r\nConnection: close",
            "HTTP/1.1 200 OK\r\nContent-Length: 081", "HTTP/1.1 200 OK\r\nContent-Length: +81",
            "HTTP/1.1 200 OK\r\nContent-Length: 81,81", "HTTP/1.1 200 OK\r\nContent-Length: 80",
            "HTTP/1.1 200 OK\r\nContent-Length: 82", "HTTP/1.1 200 OK\r\n Content-Length: 81",
            "HTTP/1.1 200 OK\r\nContent-Length : 81", "HTTP/1.1 200 OK\nContent-Length: 81",
            "HTTP/1.1 200 OK\r\nContent-Length: 81\r\ncontent-length: 81",
        ) + listOf("Transfer-Encoding: chunked", "tRaNsFeR-EnCoDiNg: identity", "Trailer: x",
            "Upgrade: h2c", "Connection: keep-alive", "Connection: close, upgrade", "X: canary\u0000", "X: canary\u0080", "X: a\ncanary").map {
            "HTTP/1.1 200 OK\r\nContent-Length: 81\r\n$it"
        }
        for (value in invalid) assertThrows(IllegalStateException::class.java) {
            ReferenceTunHttpResponse.readBody(ByteArrayInputStream((value + "\r\n\r\n").toByteArray(Charsets.UTF_8) + body))
        }
    }

    @Test fun boundIncludesDelimiterAndStopsAt4096() {
        val prefix = "HTTP/1.1 200 OK\r\nContent-Length: 81\r\nX: "
        val exact = prefix + "x".repeat(4096 - prefix.length - 4) + "\r\n\r\n"
        assertArrayEquals(body, ReferenceTunHttpResponse.readBody(ByteArrayInputStream(exact.toByteArray() + body)))
        var reads = 0
        val oversized = object : ByteArrayInputStream((prefix + "x".repeat(4096) + "\r\n\r\n").toByteArray()) {
            override fun read(): Int = super.read().also { reads++ }
        }
        assertThrows(IllegalStateException::class.java) { ReferenceTunHttpResponse.readBody(oversized) }
        assertEquals(4096, reads)
    }

    @Test fun truncationCorruptionAndZeroProgressAreNotSuccess() {
        for (size in listOf(0, 80)) assertThrows(IllegalStateException::class.java) {
            ReferenceTunHttpResponse.readBody(ByteArrayInputStream(header.toByteArray() + body.copyOf(size)))
        }
        val corrupt = body.copyOf().also { it[80] = (it[80].toInt() xor 1).toByte() }
        assertThrows(IllegalStateException::class.java) { ReferenceTunHttpResponse.readBody(ByteArrayInputStream(header.toByteArray() + corrupt)) }
        assertThrows(IllegalStateException::class.java) { ReferenceTunHttpResponse.readBody(ByteArrayInputStream("HTTP/1.1".toByteArray())) }
        val stuck = object : ByteArrayInputStream(header.toByteArray()) {
            override fun read(b: ByteArray, off: Int, len: Int) = 0
        }
        assertThrows(IllegalStateException::class.java) { ReferenceTunHttpResponse.readBody(stuck) }
    }

    @Test fun bodyValidationNeverWaivesActualEofAndNeverAcceptsReset() {
        for (suffix in listOf(byteArrayOf(42), "HTTP/1.1 200 OK\r\n\r\n".toByteArray())) {
            val input = ByteArrayInputStream(header.toByteArray() + body + suffix)
            ReferenceTunHttpResponse.readBody(input)
            assertThrows(IllegalStateException::class.java) { ReferenceTunHttpResponse.requireEof(input) }
        }
        for (failure in listOf(SocketException("canary-reset"), SocketTimeoutException("canary-timeout"))) {
            val source = ByteArrayInputStream(header.toByteArray() + body)
            val input = object : InputStream() {
                override fun read(): Int = source.read().also { if (it == -1) throw failure }
                override fun read(b: ByteArray, off: Int, len: Int) = source.read(b, off, len)
            }
            ReferenceTunHttpResponse.readBody(input)
            assertSame(failure, assertThrows(failure.javaClass) { ReferenceTunHttpResponse.requireEof(input) })
        }
    }
}
