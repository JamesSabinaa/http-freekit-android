package com.httpfreekit.capturetraffic

import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException
import org.junit.Assert.*
import org.junit.Test

class TrafficTcpFailureTest {
    @Test fun exactJavaSocketConstantsAreNegativeCategoriesAndDoNotRecoverErrno() {
        assertEquals("reset", TrafficTcpFailure.category(SocketException("Connection reset")))
        assertEquals("reset", TrafficTcpFailure.category(SocketException("Connection reset by peer")))
        assertEquals("closed", TrafficTcpFailure.category(SocketException("Socket closed")))
        assertEquals("closed", TrafficTcpFailure.category(SocketException("Socket is closed")))
        assertEquals("not_connected", TrafficTcpFailure.category(SocketException("Socket is not connected")))
        for (message in listOf("connection reset", "Connection reset: CANARY", "Socket input is shutdown", "CANARY"))
            assertEquals("io", TrafficTcpFailure.category(SocketException(message)))
        assertEquals("io", TrafficTcpFailure.category(IOException("Connection reset")))
        assertEquals("timeout", TrafficTcpFailure.category(SocketTimeoutException("Connection reset")))
        assertEquals("protocol", TrafficTcpFailure.category(IllegalStateException("Connection reset")))
        assertEquals("other", TrafficTcpFailure.category(Exception("Connection reset")))
    }

    @Test fun typedErrnoAdapterHasPrecedenceAndUnknownOrSuppressedMaterialIsNotPromoted() {
        val marker = Exception("CANARY_ERRNO")
        val wrapped = SocketException("Socket closed").apply { initCause(IOException("CANARY_WRAPPER", marker)) }
        for (known in TrafficTcpFailure.Errno.entries)
            assertEquals(known.category, TrafficTcpFailure.category(wrapped) { if (it === marker) known else null })
        assertEquals("closed", TrafficTcpFailure.category(wrapped) { null })
        val hidden = IOException("CANARY").apply { addSuppressed(SocketException("Connection reset")) }
        assertEquals("io", TrafficTcpFailure.category(hidden))
        assertEquals("io", TrafficTcpFailure.category(IOException("CANARY", SocketTimeoutException("CANARY"))))
        assertEquals("io", TrafficTcpFailure.category(IOException("CANARY")) { error("CANARY_PROVIDER") })
    }

    @Test fun causeTraversalIsIdentityBoundedCycleSafeAndNeverStringifiesProviderObjects() {
        class Link : IOException() {
            var next: Throwable? = null
            override val cause: Throwable? get() = next
            override fun equals(other: Any?): Boolean = error("CANARY_EQUALS")
            override fun hashCode(): Int = error("CANARY_HASH")
            override fun toString(): String = error("CANARY_STRING")
        }
        val first = Link(); val second = Link(); first.next = second; second.next = first
        var visited = 0
        assertEquals("io", TrafficTcpFailure.category(first) { visited++; null }); assertEquals(2, visited)
        val chain = List(9) { Link() }; chain.zipWithNext().forEach { (a, b) -> a.next = b }
        visited = 0
        assertEquals("io", TrafficTcpFailure.category(chain.first()) { visited++; if (it === chain.last()) TrafficTcpFailure.Errno.RESET else null })
        assertEquals(8, visited)
        assertEquals("aborted", TrafficTcpFailure.category(chain.first()) { if (it === chain[7]) TrafficTcpFailure.Errno.ABORTED else null })
    }
}
