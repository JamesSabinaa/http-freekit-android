package com.httpfreekit.capture.transport

import com.httpfreekit.capture.CaptureException
import com.httpfreekit.capture.CaptureSocketGuard
import com.httpfreekit.protocol.HttpOriginConnect
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class EnrolledCaptureTcpFactoryTest {
    @Test fun constructorAndInspectionAreInertAndRedacted() {
        val identity = CaptureTransportTestIdentity(); val guard = Guard()
        val factory = EnrolledCaptureTcpFactory(identity.configuration(), endpoint(), guard)
        val snapshot = factory.snapshot()
        assertFalse(snapshot.started); assertFalse(snapshot.closed); assertFalse(snapshot.admissionClosed)
        assertEquals(0, snapshot.liveWorkers); assertEquals(0, snapshot.retainedTransports); assertEquals(0, guard.protects.get())
        assertEquals(snapshot.toString(), factory.snapshot().toString())
        val diagnostic = listOf(factory, snapshot, identity.configuration()).joinToString()
        for (material in listOf(identity.record.desktopId, identity.record.gatewaySpkiSha256, identity.record.logicalServerName)) assertFalse(diagnostic.contains(material))
        factory.close(); factory.close(); assertTrue(factory.snapshot().closed); assertEquals(0, factory.snapshot().liveWorkers)
        failure("closed") { factory.open(loopback(), 80) }
        assertEquals(null, factory.snapshot().failureCode)
    }

    @Test fun invalidTargetsAndConfigurationNeverAllocateTransportOrCallGuard() {
        val identity = CaptureTransportTestIdentity(); val guard = Guard()
        for (required in listOf(emptySet(), setOf("tcp-http"), setOf("other"))) failure("invalid_request") {
            EnrolledCaptureTcpFactory(identity.configuration(), endpoint(), guard, required)
        }
        failure("invalid_request") { EnrolledCaptureTcpFactory(identity.configuration(), InetSocketAddress.createUnresolved("unresolved.invalid", 443), guard) }
        val required = linkedSetOf(HttpOriginConnect.CAPABILITY)
        val factory = EnrolledCaptureTcpFactory(identity.configuration(), endpoint(), guard, required); required.clear()
        for (port in listOf(0, 53, 8080, 65536)) failure("invalid_request") { factory.open(loopback(), port) }
        assertEquals(0, guard.protects.get()); assertEquals(0, factory.snapshot().retainedTransports); factory.close()
    }

    @Test fun protectAndBindRefusalsFailBeforeConnectAndLeaveActuallyJoinedResources() {
        val identity = CaptureTransportTestIdentity()
        for (protect in listOf(false, true)) {
            val guard = Guard(protect = protect, failBind = true)
            val factory = EnrolledCaptureTcpFactory(identity.configuration(), endpoint(), guard)
            try {
                failure(if (protect) "bind_failed" else "protect_failed") { factory.open(loopback(), 80) }
                assertEquals(1, guard.protects.get()); assertEquals(if (protect) 1 else 0, guard.binds.get())
                val raw = guard.raw.get()!!; assertTrue(raw.isClosed); assertFalse(raw.isConnected)
            } finally { factory.close() }
            val snapshot = factory.snapshot(); assertTrue(snapshot.closed); assertEquals(0, snapshot.retainedTransports)
            assertEquals(0, snapshot.liveWorkers); assertFalse(snapshot.sessionLease); assertEquals(0, snapshot.chargedBytes)
        }
    }

    @Test fun openDeadlineReturnsWhileBlockedProtectRemainsOwnedAndStopRetainsItUntilActualExit() {
        val identity = CaptureTransportTestIdentity(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val guard = Guard(onProtect = { entered.countDown(); release.await() })
        val factory = EnrolledCaptureTcpFactory(identity.configuration(), endpoint(), guard)
        val executor = Executors.newSingleThreadExecutor()
        val started = System.nanoTime()
        val result = executor.submit<String> { try { factory.open(loopback(), 80); "unexpected" } catch (failure: CaptureException) { failure.code } }
        try {
            assertTrue(entered.await(3, TimeUnit.SECONDS)); assertEquals("connect_failed", result.get(7, TimeUnit.SECONDS))
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(elapsed in 4500..6500)
            assertTrue(guard.raw.get()!!.isClosed)
            assertEquals(1, factory.snapshot().retainedTransports); assertTrue(factory.snapshot().liveWorkers >= 1)
            failure("cleanup_failed") { factory.close() }
            assertFalse(factory.snapshot().closed); assertEquals(1, factory.snapshot().retainedTransports)
        } finally {
            release.countDown(); result.get(5, TimeUnit.SECONDS)
            factory.close(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
        assertTrue(factory.snapshot().closed); assertEquals(0, factory.snapshot().liveWorkers); assertEquals(0, factory.snapshot().retainedTransports)
    }

    @Test fun interruptSealsAndClosesRawWithoutJoiningABlockedStartupCall() {
        val identity = CaptureTransportTestIdentity(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val guard = Guard(onProtect = { entered.countDown(); release.await() })
        val factory = EnrolledCaptureTcpFactory(identity.configuration(), endpoint(), guard)
        val executor = Executors.newSingleThreadExecutor()
        val result = executor.submit<String> { try { factory.open(loopback(), 80); "unexpected" } catch (failure: CaptureException) { failure.code } }
        try {
            assertTrue(entered.await(3, TimeUnit.SECONDS)); val started = System.nanoTime(); factory.interrupt()
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 1000)
            assertEquals("connect_failed", result.get(2, TimeUnit.SECONDS)); assertTrue(guard.raw.get()!!.isClosed)
            assertTrue(factory.snapshot().admissionClosed); assertFalse(factory.snapshot().closed)
            assertEquals("closed", factory.snapshot().failureCode); assertEquals(1, factory.snapshot().retainedTransports)
        } finally {
            release.countDown(); factory.close(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
        assertEquals(0, factory.snapshot().retainedTransports); assertEquals(0, factory.snapshot().liveWorkers)
    }

    private class Guard(private val protect: Boolean = true, private val failBind: Boolean = false, private val onProtect: () -> Unit = {}) : CaptureSocketGuard {
        val protects = AtomicInteger(); val binds = AtomicInteger(); val raw = AtomicReference<Socket>()
        override fun protect(socket: Socket): Boolean {
            assertFalse(socket.isConnected); assertFalse(socket.isBound); assertTrue(socket.tcpNoDelay)
            raw.set(socket); protects.incrementAndGet(); onProtect(); return protect
        }
        override fun bind(socket: Socket) { binds.incrementAndGet(); if (failBind) throw IllegalStateException("Provider material must not escape") }
        override fun protect(socket: DatagramSocket) = false
        override fun bind(socket: DatagramSocket): Unit = throw AssertionError("Unexpected UDP")
    }

    companion object {
        private fun loopback() = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        private fun endpoint() = InetSocketAddress(loopback(), 9)
        private fun failure(code: String, operation: () -> Unit) {
            try { operation(); fail("Expected a finite capture failure") }
            catch (failure: CaptureException) { assertEquals(code, failure.code); assertFalse(failure.toString().contains("Provider")) }
        }
    }
}
