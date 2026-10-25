package com.httpfreekit.protocol

/** Draft 0.5 numeric destination preface. No DNS, sockets or application HTTP rewriting. */
object HttpOriginConnect {
    const val CAPABILITY = "tcp-http-origin-connect"
    const val PROXY_MODE = "http-origin-connect"
    private val acknowledgement = "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII)

    fun preface(address: ByteArray, port: Int = 80): ByteArray {
        if (port != 80 || address.size !in setOf(4, 16)) throw DraftProtocolException("invalid_message")
        val copy = address.copyOf()
        val host = if (copy.size == 4) copy.joinToString(".") { (it.toInt() and 255).toString() }
        else "[" + (0 until 8).joinToString(":") { index ->
            (((copy[index * 2].toInt() and 255) shl 8) or (copy[index * 2 + 1].toInt() and 255)).toString(16)
        } + "]"
        val authority = "$host:80"
        return "CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n".toByteArray(Charsets.US_ASCII)
    }

    fun acknowledgementBytes(): ByteArray = acknowledgement.copyOf()

    /** Consumes only the fixed prefix. Following bytes remain with the caller, even when coalesced. */
    class Acknowledgement {
        private var offset = 0
        private var failed = false
        val complete: Boolean get() = !failed && offset == acknowledgement.size

        fun accept(bytes: ByteArray, start: Int = 0, length: Int = bytes.size - start): Int {
            if (failed) throw DraftProtocolException("invalid_message")
            if (start < 0 || length < 0 || start > bytes.size || length > bytes.size - start) reject()
            val count = minOf(length, acknowledgement.size - offset)
            for (index in 0 until count) {
                if (bytes[start + index] != acknowledgement[offset]) reject()
                offset++
            }
            return count
        }

        private fun reject(): Nothing { failed = true; throw DraftProtocolException("invalid_message") }
        override fun toString() = "HttpOriginAcknowledgement(complete=$complete, failed=$failed)"
    }
}
