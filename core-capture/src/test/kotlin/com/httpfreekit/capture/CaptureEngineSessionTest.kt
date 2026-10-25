package com.httpfreekit.capture

import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class CaptureEngineSessionTest {
    private class Tun : CaptureTun {
        var closed = false
        var beforeClose: () -> Unit = {}
        override fun descriptor() = 7
        override fun close() { beforeClose(); closed = true }
    }
    private class Configuration : CaptureConfiguration {
        var contents: String? = null
        override fun write(contents: String) { check(this.contents == null); this.contents = contents }
        override fun path() = "fixed-private-config.yaml"
        override fun present() = contents != null
        override fun remove() { contents = null }
    }
    private class Native : CaptureNative {
        @Volatile var running = false
        var accept = true
        val stops = AtomicInteger()
        var beforeStop: () -> Unit = {}
        override fun start(path: String, descriptor: Int): Boolean { check(descriptor == 7); running = accept; return accept }
        override fun stop(): Boolean { stops.incrementAndGet(); beforeStop(); running = false; return true }
        override fun running() = running
    }
    private class Intercept : InterceptedTcpFactory {
        @Volatile var closed = false
        override fun open(originalAddress: InetAddress, originalPort: Int): CaptureTcpConnection = error("No test interception expected")
        override fun close() { closed = true }
    }
    private class Owned {
        val tun = Tun(); val config = Configuration(); val native = Native(); val intercept = Intercept()
        val egress = ProtectedEgressFactory(object : CaptureSocketGuard {
            override fun protect(socket: Socket) = true
            override fun protect(socket: DatagramSocket) = true
            override fun bind(socket: Socket) { }
            override fun bind(socket: DatagramSocket) { }
        })
        val session = CaptureEngineSession(tun, setOf("com.fixture.traffic"), intercept, egress, config) { native }
    }
    @Test fun failClosedJoinsActualJavaWorkersButRetainsTunUntilExplicitStop() {
        val owned = Owned()
        try {
            owned.session.start()
            assertTrue(owned.session.snapshot().nativeRunning)
            assertTrue(owned.session.localSocksPort() in 1..65535)
            val yaml = checkNotNull(owned.config.contents)
            assertTrue(yaml.contains("udp: 'tcp'")); assertTrue(yaml.contains("ipv4: 198.18.0.1")); assertTrue(yaml.contains("ipv6: 'fd00:6672:6565::1'"))
            owned.session.failClosed()
            val stopped = owned.session.snapshot()
            assertTrue(stopped.nativeStopJoined); assertTrue(stopped.admissionClosed)
            assertFalse(stopped.tunClosed); assertFalse(owned.tun.closed); assertFalse(stopped.configurationPresent)
            assertEquals(0, stopped.liveWorkers); assertEquals(0, stopped.ownedSockets); assertEquals(0, stopped.activeFlows)
            assertTrue(owned.intercept.closed); assertEquals(1, owned.native.stops.get())
            val other = Owned()
            try { rejected("capacity") { other.session.start() } } finally { other.session.close() }
            owned.tun.beforeClose = { assertEquals(1, owned.native.stops.get()); assertFalse(owned.native.running); assertTrue(owned.session.snapshot().nativeStopJoined) }
            owned.session.close(); assertTrue(owned.tun.closed)
            owned.session.close(); assertEquals(1, owned.native.stops.get())
        } finally { owned.session.close() }
        val next = Owned()
        try { next.session.start(); assertTrue(next.session.snapshot().nativeRunning) } finally { next.session.close() }
    }

    @Test(timeout = 18000) fun timeoutCannotFabricateNativeJoinOrReleaseTunAndLease() {
        val owned = Owned(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        owned.native.beforeStop = { entered.countDown(); check(release.await(15, TimeUnit.SECONDS)) }
        try {
            owned.session.start()
            rejected("cleanup_failed") { owned.session.failClosed() }
            assertEquals(0, entered.count); assertFalse(owned.session.snapshot().nativeStopJoined)
            assertFalse(owned.tun.closed); assertTrue(owned.config.present()); assertTrue(owned.session.snapshot().liveWorkers > 0)
            val other = Owned()
            try { rejected("capacity") { other.session.start() } } finally { other.session.close() }
            release.countDown(); owned.session.close()
            assertTrue(owned.session.snapshot().nativeStopJoined); assertTrue(owned.tun.closed); assertEquals(1, owned.native.stops.get())
        } finally { release.countDown(); owned.session.close() }
    }

    @Test fun rejectedNativeStartupIsStillOwnedAndSafelyJoinedBeforeTunClose() {
        val owned = Owned(); owned.native.accept = false
        try {
            rejected("native_failed") { owned.session.start() }
            val snapshot = owned.session.snapshot()
            assertTrue(snapshot.failed); assertTrue(snapshot.nativeStopJoined); assertFalse(snapshot.tunClosed)
            assertEquals(0, snapshot.liveWorkers); assertEquals(0, snapshot.ownedSockets)
            assertFalse(owned.config.present()); assertEquals(1, owned.native.stops.get())
        } finally { owned.session.close() }
    }

    @Test fun unexpectedNativeExitAutomaticallySealsAndJoinsWhileRouteRemainsOwned() {
        val owned = Owned()
        try {
            owned.session.start(); owned.native.running = false
            val until = System.nanoTime() + 3_000_000_000
            while (!owned.session.snapshot().nativeStopJoined || owned.session.snapshot().liveWorkers != 0) {
                check(System.nanoTime() < until) { "Failure cleanup did not complete" }; Thread.sleep(1)
            }
            val snapshot = owned.session.snapshot()
            assertTrue(snapshot.failed); assertTrue(snapshot.admissionClosed); assertFalse(snapshot.tunClosed)
            assertFalse(snapshot.nativeRunning); assertEquals(0, snapshot.ownedSockets)
        } finally { owned.session.close() }
    }

    @Test fun actualAcceptFailureStaysLatchedButJoinedExplicitStopCanReleaseTheRoute() {
        val owned = Owned()
        try {
            owned.session.start()
            val policyField = CaptureEngineSession::class.java.getDeclaredField("policy").apply { isAccessible = true }
            val policy = policyField.get(owned.session) as CapturePolicyServer
            val listenerField = CapturePolicyServer::class.java.getDeclaredField("listener").apply { isAccessible = true }
            (listenerField.get(policy) as java.net.ServerSocket).close()
            val until = System.nanoTime() + 3_000_000_000
            while (!owned.session.snapshot().nativeStopJoined || owned.session.snapshot().liveWorkers != 0) {
                check(System.nanoTime() < until) { "Actual listener failure did not join" }; Thread.sleep(1)
            }
            assertTrue(owned.session.snapshot().failed); assertFalse(owned.tun.closed)
            owned.session.close()
            assertTrue(owned.tun.closed); assertTrue(owned.session.snapshot().failed)
            assertEquals(0, owned.session.snapshot().ownedSockets)
        } finally { owned.session.close() }
    }

    @Test fun emptySelectionCannotAcquireNativeOwnershipOrBecomeAnAllAppCapture() {
        val tun = Tun(); val config = Configuration(); val native = Native(); val intercept = Intercept()
        val resources = Owned()
        try { rejected("invalid_request") { CaptureEngineSession(tun, emptySet(), intercept, resources.egress, config) { native } } }
        finally { resources.session.close(); tun.close() }
        assertEquals(0, native.stops.get()); assertFalse(config.present())
    }
    private fun rejected(code: String, action: () -> Unit) {
        try { action(); fail("Expected owned capture refusal") } catch (failure: CaptureException) { assertEquals(code, failure.code) }
    }
}
