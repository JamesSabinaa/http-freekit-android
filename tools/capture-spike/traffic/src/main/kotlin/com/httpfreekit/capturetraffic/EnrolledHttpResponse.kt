package com.httpfreekit.capturetraffic

import java.io.InputStream

/** Fixed C5 response only: bounded H1 framing, exact synthetic body, and a separate mandatory EOF. */
internal object EnrolledHttpResponse {
    private const val HEADER_LIMIT = 4096
    private const val BODY_BYTES = 32787
    private val name = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")

    fun readBody(input: InputStream): ByteArray {
        val header = ByteArray(HEADER_LIMIT)
        var count = 0
        while (count < header.size) {
            val next = input.read()
            check(next >= 0) { "Invalid research HTTP response" }
            header[count++] = next.toByte()
            if (count >= 4 && header[count - 4] == 13.toByte() && header[count - 3] == 10.toByte() &&
                header[count - 2] == 13.toByte() && header[count - 1] == 10.toByte()) break
        }
        check(count >= 4 && header[count - 4] == 13.toByte() && header[count - 3] == 10.toByte() &&
            header[count - 2] == 13.toByte() && header[count - 1] == 10.toByte()) { "Invalid research HTTP response" }
        check((0 until count).all { header[it].toInt() in 0..127 }) { "Invalid research HTTP response" }
        val lines = String(header, 0, count - 4, Charsets.US_ASCII).split("\r\n")
        check(lines.first() == "HTTP/1.1 200 OK") { "Invalid research HTTP response" }
        var lengthSeen = false
        for (line in lines.drop(1)) {
            val colon = line.indexOf(':')
            check(colon > 0 && name.matches(line.substring(0, colon))) { "Invalid research HTTP response" }
            val value = line.substring(colon + 1)
            check(value.all { it == '\t' || it.code in 32..126 }) { "Invalid research HTTP response" }
            val field = line.substring(0, colon)
            check(!field.equals("Transfer-Encoding", ignoreCase = true)) { "Invalid research HTTP response" }
            if (field.equals("Content-Length", ignoreCase = true)) {
                check(!lengthSeen && value.trim(' ', '\t') == BODY_BYTES.toString()) { "Invalid research HTTP response" }
                lengthSeen = true
            }
        }
        check(lengthSeen) { "Invalid research HTTP response" }
        val body = ByteArray(BODY_BYTES)
        var offset = 0
        while (offset < body.size) {
            val size = input.read(body, offset, body.size - offset)
            check(size > 0) { "Invalid research HTTP response" }
            offset += size
        }
        check(body.indices.all { body[it] == ((it * 7) % 253).toByte() }) { "Invalid research HTTP response" }
        return body
    }

    /** IOException, reset and timeout remain failures; no exception is promoted to EOF. */
    fun requireEof(input: InputStream) {
        check(input.read() == -1) { "Invalid research HTTP response" }
    }
}
