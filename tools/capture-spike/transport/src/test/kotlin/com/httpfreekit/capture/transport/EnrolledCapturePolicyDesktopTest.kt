package com.httpfreekit.capture.transport

import com.httpfreekit.capture.CaptureSocketGuard
import com.httpfreekit.capture.transport.CaptureOriginNodePeer.Companion.bool
import com.httpfreekit.capture.transport.CaptureOriginNodePeer.Companion.number
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.*
import org.junit.Test

/** The six unchanged C3 exchanges now enter the actual authenticated production SOCKS boundary. */
class EnrolledCapturePolicyDesktopTest : EnrolledCaptureHttpsDesktopTest() {
    override fun application(factory: EnrolledCaptureTcpFactory, address: InetAddress, port: Int): ApplicationConnection {
        val policy = CapturePolicyPeer(factory, address, port)
        return object : ApplicationConnection {
            override val app: Socket get() = policy.app
            override fun finish() {
                policy.finish()
                val state = factory.snapshot()
                assertFalse(state.closed); assertFalse(state.admissionClosed); assertNull(state.failureCode)
                assertEquals(0, state.pendingOpens); assertEquals(0, state.pendingCalls)
                assertTrue(state.sessionLease); assertEquals(0, state.streamLeases); assertEquals(0L, state.chargedBytes)
                assertEquals(0L, state.pendingIngressBytes); assertEquals(0L, state.backendOutputBytes); assertEquals(0L, state.backendIncomingBytes)
            }
            override fun close() = policy.close()
        }
    }

    @Test(timeout = 45_000) fun httpOriginUsesActualPolicyHalfClosesAndNormalStreamCompletion() {
        CaptureOriginNodePeer("http-h1").use { peer ->
            val guard = object : CaptureSocketGuard {
                val protects = AtomicInteger()
                val binds = AtomicInteger()
                override fun protect(socket: Socket): Boolean { assertFalse(socket.isConnected); protects.incrementAndGet(); return true }
                override fun bind(socket: Socket) { assertFalse(socket.isConnected); binds.incrementAndGet() }
                override fun protect(socket: DatagramSocket) = false
                override fun bind(socket: DatagramSocket): Unit = error("Unexpected UDP")
            }
            // Preserve the actual factory default requirement for both HTTP-origin and HTTPS capabilities.
            val factory = EnrolledCaptureTcpFactory(peer.configuration, peer.endpoint, guard)
            try {
                application(factory, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 2)), 80).use { bridge ->
                    val request = ByteArray(16421) { (it % 251).toByte() }
                    bridge.app.outputStream.write(("POST /factory-research HTTP/1.1\r\nHost: capture-origin.invalid\r\n" +
                        "Content-Length: ${request.size}\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
                    bridge.app.outputStream.write(request); bridge.app.outputStream.flush(); bridge.app.shutdownOutput()
                    val header = java.io.ByteArrayOutputStream(); var tail = 0
                    while (tail != 0x0d0a0d0a) {
                        val value = bridge.app.inputStream.read(); check(value >= 0 && header.size() < 4096)
                        header.write(value); tail = (tail shl 8) or value
                    }
                    val lines = header.toString(Charsets.US_ASCII).split("\r\n")
                    assertEquals("HTTP/1.1 200 OK", lines.first())
                    assertEquals(1, lines.count { it.startsWith("content-length:", ignoreCase = true) })
                    assertTrue(lines.any { it.equals("content-length: 32787", ignoreCase = true) })
                    assertFalse(lines.any { it.startsWith("transfer-encoding:", ignoreCase = true) })
                    val response = ByteArray(32787)
                    val input = java.io.DataInputStream(bridge.app.inputStream)
                    input.readFully(response, 0, 4096)
                    // The existing fixture releases its response tail only after actual client END_WRITE.
                    peer.release()
                    input.readFully(response, 4096, response.size - 4096)
                    assertArrayEquals(ByteArray(32787) { ((it * 7) % 253).toByte() }, response)
                    assertEquals(-1, bridge.app.inputStream.read())
                    bridge.finish()
                    val snapshot = peer.completedSnapshot()
                    assertTrue(snapshot.bool("gatewayStreamComplete"))
                    val origin = snapshot.getValue("origin").jsonObject
                    assertEquals(1L, origin.number("requests")); assertTrue(origin.bool("requestVerified"))
                    assertTrue(origin.bool("captureMatched")); assertTrue(origin.bool("originalDestinationMatched"))
                    assertFalse(origin.bool("failed")); assertEquals(16421L, origin.number("requestBodyBytes"))
                    assertEquals(32787L, origin.number("responseBodyBytesWritten"))
                    assertTrue(origin.bool("clientEndWriteApplied"))
                    assertEquals(2, guard.protects.get()); assertEquals(2, guard.binds.get())
                }
            } finally { factory.close() }
            val state = factory.snapshot()
            assertTrue(state.closed); assertTrue(state.admissionClosed); assertNull(state.failureCode)
            assertEquals(0, state.pendingOpens); assertEquals(0, state.pendingCalls)
            assertEquals(0, state.retainedTransports); assertEquals(0, state.liveWorkers)
            assertFalse(state.sessionLease); assertEquals(0, state.streamLeases); assertEquals(0L, state.chargedBytes)
            assertEquals(0L, state.pendingIngressBytes); assertEquals(0L, state.backendOutputBytes); assertEquals(0L, state.backendIncomingBytes)
        }
    }
}
