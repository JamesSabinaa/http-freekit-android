package com.httpfreekit.capture.transport

import com.httpfreekit.capture.CaptureException
import com.httpfreekit.capture.CaptureSocketGuard
import com.httpfreekit.capture.transport.CaptureOriginNodePeer.Companion.bool
import com.httpfreekit.capture.transport.CaptureOriginNodePeer.Companion.number
import com.httpfreekit.capture.transport.CaptureOriginNodePeer.Companion.text
import com.httpfreekit.protocol.HttpOriginConnect
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Run only by the explicit desktop integration task. A missing checkout is a failure, never a skip. */
class EnrolledCaptureDesktopTest {
    @Test fun realEnrolledTlsDesktopOriginPreservesGatesCaptureBodyAndBothEofs() {
        CaptureOriginNodePeer().use { peer ->
            val guard = Guard(); val factory = factory(peer, guard)
            try {
                val flow = factory.open(original(), 80)
                flow.output.write(HEADER); flow.output.write(requestBody(), 0, 4096)
                var originObserved = false
                repeat(3) {
                    if (!originObserved) {
                        Thread.sleep(200)
                        val origin = peer.snapshot().getValue("origin").jsonObject
                        originObserved = origin.number("requests") == 1L
                        assertFalse(origin.bool("requestVerified"))
                    }
                }
                assertTrue(originObserved) // Actual origin parser ran before the producer released its tail.
                flow.output.write(requestBody(), 4096, REQUEST - 4096); flow.shutdownOutput()
                responseHeader(flow.input); assertTrue(exactly(flow.input, 4096).contentEquals(responseBody().copyOf(4096)))
                peer.release()
                val tail = exactly(flow.input, RESPONSE - 4096)
                assertTrue(tail.contentEquals(responseBody().copyOfRange(4096, RESPONSE)))
                assertEquals(-1, flow.input.read()); flow.close()
                val observed = peer.snapshot(); val origin = observed.getValue("origin").jsonObject
                assertTrue(origin.bool("clientEndWriteApplied")); assertTrue(origin.bool("requestVerified"))
                assertTrue(origin.bool("captureMatched")); assertTrue(origin.bool("originalDestinationMatched"))
                assertEquals(REQUEST.toLong(), origin.number("requestBodyBytes")); assertEquals(RESPONSE.toLong(), origin.number("responseBodyBytesWritten"))
                assertEquals(hex(MessageDigest.getInstance("SHA-256").digest(requestBody())), origin.text("requestBodySha256"))
                assertEquals(hex(MessageDigest.getInstance("SHA-256").digest(responseBody())), origin.text("responseBodySha256"))
                assertTrue(guard.protects.get() >= 2); assertEquals(guard.protects.get(), guard.binds.get())
            } finally { factory.close() }
            joined(factory)
        }
    }

    @Test fun serverNormalCloseRemainsOwnedWhileTheLocalReaderDeliberatelyHoldsTailBytes() {
        CaptureOriginNodePeer().use { peer ->
            val factory = factory(peer, Guard())
            val releases = Executors.newSingleThreadExecutor()
            try {
                val flow = factory.open(original(), 80)
                flow.output.write(HEADER); flow.output.write(requestBody())
                responseHeader(flow.input); assertTrue(exactly(flow.input, 4096).contentEquals(responseBody().copyOf(4096)))
                val release = releases.submit { peer.release() }
                Thread.sleep(275) // The actual peer release remains gated on the client's typed END_WRITE.
                assertFalse(release.isDone)
                flow.shutdownOutput(); release.get(6, TimeUnit.SECONDS)
                // Leave a bounded tail queued locally while allowing the backend
                // to decode the actual peer Close beyond all preceding data.
                val middle = exactly(flow.input, RESPONSE - 8192)
                assertTrue(middle.contentEquals(responseBody().copyOfRange(4096, RESPONSE - 4096)))
                var remoteComplete = false
                repeat(4) {
                    if (!remoteComplete) { Thread.sleep(200); remoteComplete = peer.snapshot().bool("gatewayStreamComplete") }
                }
                assertTrue(remoteComplete)
                val retained = factory.snapshot(); assertTrue(retained.chargedBytes > 0); assertEquals(1, retained.streamLeases)
                val tail = exactly(flow.input, 4096)
                assertTrue(tail.contentEquals(responseBody().copyOfRange(RESPONSE - 4096, RESPONSE))); assertEquals(-1, flow.input.read())
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
                while (factory.snapshot().streamLeases != 0 && System.nanoTime() - deadline < 0) Thread.sleep(20)
                assertEquals(0, factory.snapshot().streamLeases)
                assertEquals(-1, flow.input.read()); flow.close() // A confirmed COMPLETE stream retains legitimate EOF.
            } finally {
                factory.close(); releases.shutdownNow(); assertTrue(releases.awaitTermination(5, TimeUnit.SECONDS))
            }
            joined(factory)
        }
    }

    @Test fun anUnnegotiated443HasNoFallbackAndInterruptNeverBecomesCleanInputEof() {
        CaptureOriginNodePeer().use { peer ->
            val factory = factory(peer, Guard()); val executor = Executors.newSingleThreadExecutor()
            try {
                val flow = factory.open(original(), 80)
                try { factory.open(original(), 443); fail("Unnegotiated HTTPS must refuse") }
                catch (failure: CaptureException) { assertEquals("invalid_request", failure.code) }
                val reading = executor.submit<String> { try { if (flow.input.read() == -1) "eof" else "bytes" } catch (_: IOException) { "failed" } }
                Thread.sleep(150); assertFalse(reading.isDone)
                factory.interrupt(); assertEquals("failed", reading.get(3, TimeUnit.SECONDS))
                assertEquals(0L, peer.snapshot().getValue("origin").jsonObject.number("connections"))
            } finally { factory.close(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
            joined(factory, "closed")
        }
    }

    @Test fun deniedOriginalNumericDestinationFailsBeforeAcknowledgementOrOriginEgress() {
        CaptureOriginNodePeer().use { peer ->
            val guard = Guard(); val factory = factory(peer, guard)
            var cause: String? = null
            try {
                try {
                    factory.open(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 3)), 80)
                    fail("A denied original destination must not return an acknowledged connection")
                } catch (failure: CaptureException) { assertEquals("connect_failed", failure.code) }
                val snapshot = peer.snapshot(); val origin = snapshot.getValue("origin").jsonObject
                assertEquals(0L, origin.number("connections")); assertEquals(0L, origin.number("requests"))
                assertEquals(0L, snapshot.getValue("backend").jsonObject.number("captures"))
                assertEquals(2, guard.protects.get()); assertEquals(2, guard.binds.get())
                cause = factory.snapshot().failureCode; assertTrue(cause != null)
            } finally { factory.close() }
            joined(factory, cause)
        }
    }

    @Test fun defaultBothCapabilitiesRefusesANewOnlyGatewayWithoutDowngradeOrProxyAllocation() {
        CaptureOriginNodePeer().use { peer ->
            val guard = Guard()
            val factory = EnrolledCaptureTcpFactory(peer.configuration, peer.endpoint, guard)
            var cause: String? = null
            try {
                try { factory.open(original(), 80); fail("The default required set must not downgrade") }
                catch (failure: CaptureException) { assertEquals("connect_failed", failure.code) }
                val snapshot = peer.snapshot()
                assertEquals(0L, snapshot.getValue("origin").jsonObject.number("connections"))
                assertEquals(0L, snapshot.getValue("backend").jsonObject.number("admitted"))
                assertEquals(1, guard.protects.get()); assertEquals(1, guard.binds.get())
                cause = factory.snapshot().failureCode; assertTrue(cause != null)
            } finally { factory.close() }
            joined(factory, cause)
        }
    }

    @Test fun realClippedCredentialDeadlineInterruptsAnIdleOpenStreamAndJoins() {
        CaptureOriginNodePeer().use { peer ->
            val factory = factory(peer, Guard()); val executor = Executors.newSingleThreadExecutor()
            try {
                val flow = factory.open(original(), 80)
                val remaining = peer.credentialExpiresAt - System.currentTimeMillis()
                assertTrue(remaining in 30000..60000)
                val reading = executor.submit<String> { try { if (flow.input.read() == -1) "eof" else "bytes" } catch (_: IOException) { "failed" } }
                assertEquals("failed", reading.get(70, TimeUnit.SECONDS))
                assertTrue(System.currentTimeMillis() >= peer.credentialExpiresAt)
                assertTrue(factory.snapshot().admissionClosed); assertEquals("session_expired", factory.snapshot().failureCode)
                assertEquals(0L, peer.snapshot().getValue("origin").jsonObject.number("connections"))
            } finally { factory.close(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
            joined(factory, "session_expired")
        }
    }

    private class Guard : CaptureSocketGuard {
        val protects = AtomicInteger(); val binds = AtomicInteger()
        override fun protect(socket: Socket): Boolean { assertFalse(socket.isConnected); assertFalse(socket.isBound); protects.incrementAndGet(); return true }
        override fun bind(socket: Socket) { assertFalse(socket.isConnected); binds.incrementAndGet() }
        override fun protect(socket: DatagramSocket) = false
        override fun bind(socket: DatagramSocket): Unit = throw AssertionError("Unexpected UDP")
    }

    companion object {
        private const val REQUEST = 16421
        private const val RESPONSE = 32787
        private val HEADER = "POST /factory-research HTTP/1.1\r\nHost: factory-origin.invalid\r\nContent-Length: $REQUEST\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
        private fun requestBody() = ByteArray(REQUEST) { (it % 251).toByte() }
        private fun responseBody() = ByteArray(RESPONSE) { ((it * 7) % 253).toByte() }
        private fun original() = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 2))
        private fun factory(peer: CaptureOriginNodePeer, guard: CaptureSocketGuard) = EnrolledCaptureTcpFactory(peer.configuration, peer.endpoint, guard, setOf(HttpOriginConnect.CAPABILITY))
        private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
        private fun exactly(input: InputStream, count: Int): ByteArray {
            val bytes = ByteArray(count); var offset = 0
            while (offset < count) { val size = input.read(bytes, offset, count - offset); check(size > 0); offset += size }
            return bytes
        }
        private fun responseHeader(input: InputStream) {
            val buffer = ByteArrayOutputStream(); var tail = 0
            while (tail != 0x0d0a0d0a) { val byte = input.read(); check(byte >= 0 && buffer.size() < 4096); buffer.write(byte); tail = (tail shl 8) or byte }
            val head = buffer.toString(Charsets.US_ASCII)
            assertTrue(head.startsWith("HTTP/1.1 200 OK\r\n")); assertTrue(Regex("(?im)^content-length: $RESPONSE\\r?$").containsMatchIn(head))
        }
        private fun joined(factory: EnrolledCaptureTcpFactory, failure: String? = null) {
            val snapshot = factory.snapshot(); assertTrue(snapshot.closed); assertTrue(snapshot.admissionClosed)
            assertEquals(failure, snapshot.failureCode)
            assertEquals(0, snapshot.pendingOpens); assertEquals(0, snapshot.pendingCalls); assertEquals(0, snapshot.retainedTransports); assertEquals(0, snapshot.liveWorkers)
            assertFalse(snapshot.sessionLease); assertEquals(0, snapshot.streamLeases); assertEquals(0L, snapshot.chargedBytes)
            assertEquals(0L, snapshot.pendingIngressBytes); assertEquals(0L, snapshot.backendOutputBytes); assertEquals(0L, snapshot.backendIncomingBytes)
        }
    }
}
