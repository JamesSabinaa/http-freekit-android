package com.httpfreekit.interop

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Bounded DER envelope/primitive guard. The platform still parses X.509 and verifies signatures. */
internal object DraftInterceptionCaDer {
    fun requireCanonical(bytes: ByteArray) {
        check(bytes.size in 1..4096 && bytes[0].toInt() == 0x30)
        var nodes = 0
        fun octet(index: Int) = bytes[index].toInt() and 255
        fun compare(a: Int, aEnd: Int, b: Int, bEnd: Int): Int {
            for (index in 0 until minOf(aEnd - a, bEnd - b)) {
                val delta = octet(a + index) - octet(b + index)
                if (delta != 0) return delta
            }
            return (aEnd - a) - (bEnd - b)
        }
        fun item(start: Int, limit: Int, depth: Int): Int {
            check(++nodes <= 512 && depth <= 16 && start + 2 <= limit)
            var at = start
            val tag = octet(at++)
            check(tag != 0 && tag and 31 != 31)
            var length = octet(at++)
            if (length and 128 != 0) {
                val count = length and 127
                check(count in 1..2 && at + count <= limit && octet(at) != 0)
                length = 0
                repeat(count) { length = length * 256 + octet(at++) }
                check(length >= 128 && (count == 1 || length >= 256))
            }
            val end = at + length
            check(end <= limit)
            if (tag and 32 != 0) {
                if (tag and 192 == 0) check(tag == 0x30 || tag == 0x31)
                var previousStart = -1; var previousEnd = -1
                while (at < end) {
                    val next = item(at, end, depth + 1)
                    if (tag == 0x31 && previousStart >= 0) check(compare(previousStart, previousEnd, at, next) <= 0)
                    previousStart = at; previousEnd = next; at = next
                }
            } else {
                check(tag != 0x10 && tag != 0x11)
                when (tag) {
                    1 -> check(length == 1 && octet(at) in setOf(0, 255))
                    2 -> {
                        check(length > 0)
                        if (length > 1) check(!(octet(at) == 0 && octet(at + 1) and 128 == 0) &&
                            !(octet(at) == 255 && octet(at + 1) and 128 != 0))
                    }
                    3 -> {
                        check(length > 0)
                        val unused = octet(at)
                        check(unused <= 7 && (length != 1 || unused == 0) && octet(end - 1) and ((1 shl unused) - 1) == 0)
                    }
                    5 -> check(length == 0)
                    6 -> {
                        check(length > 0 && octet(end - 1) and 128 == 0)
                        for (index in at until end) check(octet(index) != 128 || index != at && octet(index - 1) and 128 != 0)
                    }
                    12 -> Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes, at, length))
                    19 -> check(Regex("[A-Za-z0-9 '()+,\\-./:=?]*").matches(String(bytes, at, length, Charsets.ISO_8859_1)))
                    22 -> check((at until end).all { octet(it) <= 127 })
                    23 -> check(Regex("[0-9]{12}Z").matches(String(bytes, at, length, Charsets.US_ASCII)))
                    24 -> check(Regex("[0-9]{14}Z").matches(String(bytes, at, length, Charsets.US_ASCII)))
                }
            }
            return end
        }
        check(item(0, bytes.size, 0) == bytes.size)
    }
}
