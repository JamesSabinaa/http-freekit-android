package com.httpfreekit.capture

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ProtectedEgressFactoryTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private class Guard(private val fail: String? = null) : CaptureSocketGuard {
        val calls = ArrayList<String>()
        override fun protect(socket: Socket): Boolean { check(!socket.isConnected); calls.add("protect-tcp"); return fail != "protect" }
        override fun protect(socket: DatagramSocket): Boolean { check(!socket.isConnected); calls.add("protect-udp"); return fail != "protect" }
        override fun bind(socket: Socket) { check(!socket.isConnected); calls.add("bind-tcp"); if (fail == "bind") error("PRIVATE_CANARY") }
        override fun bind(socket: DatagramSocket) { check(!socket.isConnected); calls.add("bind-udp"); if (fail == "bind") error("PRIVATE_CANARY") }
    }
    @Test fun actualTcpBytesAndHalfCloseFollowProtectThenBindBeforeConnect() {
        ServerSocket(0, 1, loopback).use { receiver ->
            receiver.soTimeout = 2000
            val guard = Guard()
            ProtectedEgressFactory(guard).use { factory ->
                factory.openTcp(loopback, receiver.localPort).use { connection ->
                    receiver.accept().use { peer ->
                        connection.output.write(byteArrayOf(7, 8)); connection.shutdownOutput()
                        assertEquals(7, peer.inputStream.read()); assertEquals(8, peer.inputStream.read()); assertEquals(-1, peer.inputStream.read())
                        peer.outputStream.write(9); peer.shutdownOutput()
                        assertEquals(9, connection.input.read()); assertEquals(-1, connection.input.read())
                    }
                }
                assertEquals(listOf("protect-tcp", "bind-tcp"), guard.calls)
                assertEquals(0, factory.budget.count())
            }
        }
    }
    @Test fun directAndRawTcpAreOwnedAndConfiguredBeforeProtectWithoutPriorBindOrConnect() {
        lateinit var factory: ProtectedEgressFactory
        var protections = 0
        var bindings = 0
        val guard = object : CaptureSocketGuard {
            override fun protect(socket: Socket): Boolean {
                // This checks public option/order behavior; Android descriptor protection still needs runtime proof.
                assertTrue(socket.tcpNoDelay)
                assertFalse(socket.isBound); assertFalse(socket.isConnected)
                assertEquals(1, factory.ownedCount()); assertEquals(1, factory.budget.count())
                assertEquals(1, factory.pendingOpens())
                protections++
                return true
            }
            override fun bind(socket: Socket) {
                assertEquals(bindings + 1, protections)
                assertFalse(socket.isBound); assertFalse(socket.isConnected)
                bindings++
            }
            override fun protect(socket: DatagramSocket): Boolean = error("Unexpected UDP socket")
            override fun bind(socket: DatagramSocket): Unit = error("Unexpected UDP socket")
        }
        factory = ProtectedEgressFactory(guard)
        factory.use {
            ServerSocket(0, 1, loopback).use { receiver ->
                receiver.soTimeout = 2000
                factory.openTcp(loopback, receiver.localPort).use { connection ->
                    receiver.accept().use { peer -> connection.output.write(7); assertEquals(7, peer.inputStream.read()) }
                }
                factory.rawSocketFactory().createSocket().use { socket ->
                    assertFalse(socket.isBound); assertFalse(socket.isConnected)
                    socket.connect(InetSocketAddress(loopback, receiver.localPort), 1000)
                    receiver.accept().use { peer -> socket.outputStream.write(9); assertEquals(9, peer.inputStream.read()) }
                }
            }
            assertEquals(2, protections); assertEquals(2, bindings)
            assertEquals(0, factory.ownedCount()); assertEquals(0, factory.budget.count())
        }
    }
    @Test fun udpIsConnectedOnlyAfterGuardAndPreservesDatagrams() {
        DatagramSocket(InetSocketAddress(loopback, 0)).use { receiver ->
            receiver.soTimeout = 2000
            val guard = Guard()
            ProtectedEgressFactory(guard).use { factory ->
                factory.openUdp(loopback, receiver.localPort).use { socket ->
                    socket.send(DatagramPacket(byteArrayOf(1, 2, 3), 3))
                    val packet = DatagramPacket(ByteArray(8), 8); receiver.receive(packet)
                    assertArrayEquals(byteArrayOf(1, 2, 3), packet.data.copyOf(packet.length))
                    receiver.send(DatagramPacket(byteArrayOf(4), 1, packet.socketAddress))
                    val reply = DatagramPacket(ByteArray(8), 8); socket.receive(reply); assertEquals(4, reply.data[0].toInt())
                }
                assertEquals(listOf("protect-udp", "bind-udp"), guard.calls)
                assertEquals(0, factory.budget.count())
            }
        }
    }
    @Test fun protectOrBindRefusalClosesOwnedSocketAndNeverConnectsOrFallsBack() {
        for (failure in listOf("protect", "bind")) ServerSocket(0, 1, loopback).use { receiver ->
            receiver.soTimeout = 100
            val guard = Guard(failure)
            ProtectedEgressFactory(guard).use { factory ->
                rejected(if (failure == "protect") "protect_failed" else "bind_failed") { factory.openTcp(loopback, receiver.localPort) }
                assertEquals(if (failure == "protect") listOf("protect-tcp") else listOf("protect-tcp", "bind-tcp"), guard.calls)
                assertEquals(0, factory.budget.count()); assertEquals(0, factory.ownedCount())
                try { receiver.accept().close(); fail("Refused socket connected") } catch (_: SocketTimeoutException) { }
            }
        }
    }
    @Test fun rawTlsFactoryRemainsScopedBoundedAndRefusesImplicitDnsOverloads() {
        val guard = Guard()
        val factory = ProtectedEgressFactory(guard)
        val raw = factory.rawSocketFactory()
        val sockets = (1..32).map { raw.createSocket() }
        assertEquals(32, factory.budget.count())
        rejected("capacity") { raw.createSocket() }
        rejected("invalid_request") { raw.createSocket("PRIVATE_CANARY.invalid", 443) }
        sockets.first().close()
        raw.createSocket().use { socket ->
            rejected("invalid_request") { socket.connect(InetSocketAddress.createUnresolved("PRIVATE_CANARY.invalid", 443), 0) }
        }
        factory.close(); assertTrue(sockets.all { it.isClosed }); assertEquals(0, factory.budget.count())
        rejected("closed") { raw.createSocket() }
        assertFalse(factory.toString().contains("PRIVATE_CANARY"))
    }
    @Test fun closeInterruptsAnOwnedSocketWhileProtectIsStillPending() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        var owned: Socket? = null
        val factory = ProtectedEgressFactory(object : CaptureSocketGuard {
            override fun protect(socket: Socket): Boolean { owned = socket; entered.countDown(); check(release.await(2, TimeUnit.SECONDS)); return true }
            override fun protect(socket: DatagramSocket) = false
            override fun bind(socket: Socket) { }
            override fun bind(socket: DatagramSocket) { }
        })
        val finished = CountDownLatch(1)
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val worker = Thread {
            try { factory.rawSocketFactory().createSocket(); fail("Closed open succeeded") }
            catch (_: CaptureException) { }
            catch (error: Throwable) { failure.set(error) }
            finally { finished.countDown() }
        }
        worker.start(); assertTrue(entered.await(2, TimeUnit.SECONDS))
        factory.close(); assertTrue(checkNotNull(owned).isClosed)
        release.countDown(); assertTrue(finished.await(2, TimeUnit.SECONDS)); worker.join(2000)
        assertFalse(worker.isAlive); assertNull(failure.get()); assertEquals(0, factory.pendingOpens()); assertEquals(0, factory.budget.count())
    }
    @Test fun udp443IsRejectedBeforeSocketOrGuardAllocation() {
        val guard = Guard()
        ProtectedEgressFactory(guard).use { factory ->
            rejected("invalid_request") { factory.openUdp(loopback, 443) }
            assertTrue(guard.calls.isEmpty()); assertEquals(0, factory.budget.count())
        }
    }
    private fun rejected(code: String, action: () -> Unit) {
        try { action(); fail("Expected capture refusal") } catch (failure: CaptureException) {
            assertEquals(code, failure.code); assertEquals("Capture unavailable", failure.message)
            assertNull(failure.cause); assertEquals(0, failure.suppressed.size)
        }
    }
}
