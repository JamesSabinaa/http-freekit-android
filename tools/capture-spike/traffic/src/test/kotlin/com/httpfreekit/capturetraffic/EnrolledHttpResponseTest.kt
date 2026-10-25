package com.httpfreekit.capturetraffic

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test

class EnrolledHttpResponseTest {
    private val body = ByteArray(32787) { ((it * 7) % 253).toByte() }
    private val head = "HTTP/1.1 200 OK\r\nContent-Length: 32787\r\nConnection: close\r\n\r\n"

    @Test fun completeFragmentedResponsePreservesExactBodyAndRequiresSeparateEof() {
        for (chunk in listOf(1, 7, 4096)) {
            val input = fragmented(head.toByteArray() + body, chunk)
            val result = EnrolledHttpResponse.readBody(input)
            assertArrayEquals(body, result)
            assertEquals("62a22a63bb850ba7b263fccff99e868133570394d36d6ee16fd32e9d7c1a4601", hash(result))
            EnrolledHttpResponse.requireEof(input)
        }
    }

    @Test fun headerLimitIncludesTerminatorAndRefusesBeforeReadingMoreThan4096Bytes() {
        val prefix = "HTTP/1.1 200 OK\r\nContent-Length: 32787\r\nX-Pad: "
        val header = prefix + "x".repeat(4096 - prefix.length - 4) + "\r\n\r\n"
        val exact = ByteArrayInputStream(header.toByteArray() + body)
        assertArrayEquals(body, EnrolledHttpResponse.readBody(exact))
        EnrolledHttpResponse.requireEof(exact)
        var bytesRead = 0
        val oversized = object : ByteArrayInputStream((prefix + "x".repeat(4096) + "\r\n\r\n").toByteArray()) {
            override fun read(): Int = super.read().also { if (it >= 0) bytesRead++ }
        }
        assertThrows(IllegalStateException::class.java) { EnrolledHttpResponse.readBody(oversized) }
        assertEquals(4096, bytesRead)
    }

    @Test fun statusAndLengthMustBeExactAndDuplicateOrTransferFramingCannotPass() {
        val invalid = listOf(
            "HTTP/1.0 200 OK\r\nContent-Length: 32787",
            "HTTP/1.1 201 OK\r\nContent-Length: 32787",
            "HTTP/1.1 200 Other\r\nContent-Length: 32787",
            "HTTP/1.1 200 OK\r\nConnection: close",
            "HTTP/1.1 200 OK\r\nContent-Length: 32787\r\ncontent-length: 32787",
            "HTTP/1.1 200 OK\r\nContent-Length: 32787, 32787",
            "HTTP/1.1 200 OK\r\nContent-Length: +32787",
            "HTTP/1.1 200 OK\r\nContent-Length: 032787",
            "HTTP/1.1 200 OK\r\nContent-Length: 32786",
            "HTTP/1.1 200 OK\r\nContent-Length: 32788",
            "HTTP/1.1 200 OK\r\nContent-Length: 32787\r\nTransfer-Encoding: chunked",
            "HTTP/1.1 200 OK\r\nContent-Length: 32787\r\ntRaNsFeR-EnCoDiNg: identity",
        )
        for (header in invalid) {
            val failure = assertThrows(IllegalStateException::class.java) {
                EnrolledHttpResponse.readBody(ByteArrayInputStream((header + "\r\n\r\n").toByteArray() + body))
            }
            assertEquals("Invalid research HTTP response", failure.message)
        }
    }

    @Test fun malformedHeaderSyntaxAndNonAsciiFailWithoutRetainingSuppliedText() {
        val invalid = listOf(
            "HTTP/1.1 200 OK\r\n Content-Length: 32787",
            "HTTP/1.1 200 OK\r\nContent-Length : 32787",
            "HTTP/1.1 200 OK\r\nContent-Length: 32787\nX-Canary: SECRET",
            "HTTP/1.1 200 OK\r\nContent-Length: 32787\r\nX-Canary: SECRET\u0000",
            "HTTP/1.1 200 OK\r\nContent-Length: 32787\r\nX-Canary: SECRET\u0080",
        )
        for (header in invalid) {
            val failure = assertThrows(IllegalStateException::class.java) {
                EnrolledHttpResponse.readBody(ByteArrayInputStream((header + "\r\n\r\n").toByteArray(Charsets.UTF_8) + body))
            }
            assertFalse(failure.toString().contains("SECRET"))
        }
        val mixedCase = ByteArrayInputStream("HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh:\t32787 \t\r\n\r\n".toByteArray() + body)
        assertArrayEquals(body, EnrolledHttpResponse.readBody(mixedCase))
        EnrolledHttpResponse.requireEof(mixedCase)
    }

    @Test fun truncatedHeadersShortBodiesAndCorruptedBodiesCannotPass() {
        for (header in listOf("", "HTTP/1.1 200 OK\r\nContent-Length: 32787\r\n"))
            assertThrows(IllegalStateException::class.java) { EnrolledHttpResponse.readBody(ByteArrayInputStream(header.toByteArray())) }
        for (size in listOf(0, body.size - 1))
            assertThrows(IllegalStateException::class.java) { EnrolledHttpResponse.readBody(ByteArrayInputStream(head.toByteArray() + body.copyOf(size))) }
        for (index in listOf(0, body.lastIndex)) {
            val corrupt = body.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertThrows(IllegalStateException::class.java) { EnrolledHttpResponse.readBody(ByteArrayInputStream(head.toByteArray() + corrupt)) }
        }
    }

    @Test fun completeBodyDoesNotAuthorizeTrailingBytesOrWaiveMissingEofResetOrTimeout() {
        val trailing = ByteArrayInputStream(head.toByteArray() + body + byteArrayOf(42))
        assertArrayEquals(body, EnrolledHttpResponse.readBody(trailing))
        assertThrows(IllegalStateException::class.java) { EnrolledHttpResponse.requireEof(trailing) }
        for (failure in listOf(SocketException("Connection reset"), SocketTimeoutException("SECRET"))) {
            val bytes = ByteArrayInputStream(head.toByteArray() + body)
            val input = object : InputStream() {
                override fun read(): Int = bytes.read().also { if (it < 0) throw failure }
                override fun read(buffer: ByteArray, offset: Int, length: Int): Int = bytes.read(buffer, offset, length)
            }
            assertArrayEquals(body, EnrolledHttpResponse.readBody(input))
            assertSame(failure, assertThrows(failure.javaClass) { EnrolledHttpResponse.requireEof(input) })
        }
    }

    private fun fragmented(bytes: ByteArray, chunk: Int): InputStream = object : ByteArrayInputStream(bytes) {
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int = super.read(buffer, offset, minOf(length, chunk))
    }
    private fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
