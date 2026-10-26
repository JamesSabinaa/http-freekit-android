package com.httpfreekit.capturetraffic

import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale

/** Fixed research transaction only; neither request bytes nor digests are diagnostics. */
internal object ReferenceTunHttpResponse {
    const val HOST = "reference-target.invalid"
    fun requestBody() = ByteArray(4096) { ((it * 31 + 7) and 255).toByte() }
    fun request(): ByteArray = ("POST /reference/proof HTTP/1.1\r\nHost: $HOST\r\n" +
        "Content-Length: 4096\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII) + requestBody()
    fun expectedBody(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256").digest(requestBody())
        val hex = digest.joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 255) }
        return ("reference-origin:" + hex).toByteArray(Charsets.US_ASCII)
    }

    fun readBody(input: InputStream): ByteArray {
        val header = ByteArray(4096)
        var count = 0
        while (true) {
            check(count < header.size)
            val value = input.read()
            check(value in 0..127)
            header[count++] = value.toByte()
            if (count >= 4 && header[count - 4] == 13.toByte() && header[count - 3] == 10.toByte() &&
                header[count - 2] == 13.toByte() && header[count - 1] == 10.toByte()) break
        }
        val lines = String(header, 0, count - 4, Charsets.US_ASCII).split("\r\n")
        check(lines.first() == "HTTP/1.1 200 OK")
        val fields = HashMap<String, String>()
        for (line in lines.drop(1)) {
            val colon = line.indexOf(':')
            check(colon > 0)
            val name = line.substring(0, colon)
            check(name.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in "!#$%&'*+-.^_`|~" })
            val value = line.substring(colon + 1)
            check(value.all { it == '\t' || it in ' '..'~' })
            val key = name.lowercase(Locale.ROOT)
            check(fields.put(key, value.trim(' ', '\t')) == null)
        }
        check(fields["content-length"] == "81")
        check(listOf("transfer-encoding", "trailer", "upgrade").none(fields::containsKey))
        check(fields["connection"] == null || fields["connection"].equals("close", ignoreCase = true))
        val body = ByteArray(81)
        var offset = 0
        while (offset < body.size) {
            val size = input.read(body, offset, body.size - offset)
            check(size > 0)
            offset += size
        }
        check(MessageDigest.isEqual(body, expectedBody()))
        return body
    }

    /** A reset/timeout is an exception, never EOF. Call separately for TLS and raw transport. */
    fun requireEof(input: InputStream) { check(input.read() == -1) }
}
