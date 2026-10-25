package com.httpfreekit.capture

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class CapturePolicyServerTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private class Guard : CaptureSocketGuard {
        val calls = java.util.Collections.synchronizedList(ArrayList<String>())
        override fun protect(socket: Socket): Boolean { check(!socket.isConnected); calls.add("protect-tcp"); return true }
        override fun protect(socket: DatagramSocket): Boolean { check(!socket.isConnected); calls.add("protect-udp"); return true }
        override fun bind(socket: Socket) { check(!socket.isConnected); calls.add("bind-tcp") }
        override fun bind(socket: DatagramSocket) { check(!socket.isConnected); calls.add("bind-udp") }
    }
    private class Intercept(private val receiver: Int) : InterceptedTcpFactory {
        val requested = java.util.Collections.synchronizedList(ArrayList<InetSocketAddress>())
        private val sockets = java.util.Collections.synchronizedList(ArrayList<Socket>())
        override fun open(originalAddress: InetAddress, originalPort: Int): CaptureTcpConnection {
            requested.add(InetSocketAddress(originalAddress, originalPort))
            val socket = Socket().also { sockets.add(it); it.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), receiver), 2000) }
            return object : CaptureTcpConnection {
                override val input get() = socket.getInputStream()
                override val output get() = socket.getOutputStream()
                override fun shutdownOutput() = socket.shutdownOutput()
                override fun interrupt() = socket.close()
                override fun close() = socket.close()
            }
        }
        override fun close() { synchronized(sockets) { sockets.forEach(Socket::close) } }
    }
    @Test fun missingOrWrongAuthenticationCannotAllocateAnyEgress() = fixture { policy, egress, intercept, _ ->
        Socket(loopback, policy.port).use { socket ->
            socket.soTimeout = 2000
            socket.outputStream.write(byteArrayOf(5, 1, 0))
            assertEquals(5, socket.inputStream.read()); assertEquals(255, socket.inputStream.read()); assertEquals(-1, socket.inputStream.read())
        }
        Socket(loopback, policy.port).use { socket ->
            socket.soTimeout = 2000
            val input = DataInputStream(socket.getInputStream()); val output = DataOutputStream(socket.getOutputStream())
            output.write(byteArrayOf(5, 1, 2)); output.flush(); assertEquals(5, input.readUnsignedByte()); assertEquals(2, input.readUnsignedByte())
            output.write(byteArrayOf(1, 1, 65, 1, 66)); output.flush()
            assertEquals(1, input.readUnsignedByte()); assertEquals(1, input.readUnsignedByte()); assertEquals(-1, input.read())
        }
        await { policy.facts().flows == 0 }
        assertEquals(0, egress.ownedCount()); assertEquals(0, egress.budget.count()); assertTrue(intercept.requested.isEmpty())
    }

    @Test fun bothIpFamiliesAndInterceptedPortsStreamBytesAndRetainDirectionalEof() {
        val mapped = java.net.Inet6Address.getByAddress(null, ByteArray(16).also { it[10] = -1; it[11] = -1; it[12] = 127; it[15] = 1 }, -1)
        for (destination in listOf(loopback, InetAddress.getByAddress(ByteArray(16).also { it[0] = 0x20; it[1] = 1; it[15] = 7 }), mapped)) for (port in listOf(80, 443)) {
            ServerSocket(0, 1, loopback).use { receiver ->
                receiver.soTimeout = 2000
                val failure = AtomicReference<Throwable?>()
                val body = ByteArray(32791) { (it % 251).toByte() }
                val reply = ByteArray(24589) { ((it * 7) % 253).toByte() }
                val peer = Thread {
                    try { receiver.accept().use { socket ->
                        socket.soTimeout = 2000
                        val received = socket.inputStream.readBytes()
                        assertArrayEquals(body, received)
                        socket.outputStream.write(reply); socket.shutdownOutput()
                    } } catch (error: Throwable) { failure.set(error) }
                }.apply { start() }
                fixture(receiver.localPort) { policy, _, intercept, guard ->
                    client(policy).use { socket ->
                        request(socket, 1, InetSocketAddress(destination, port))
                        socket.outputStream.write(body); socket.shutdownOutput()
                        assertArrayEquals(reply, socket.inputStream.readBytes())
                    }
                    peer.join(3000); assertFalse(peer.isAlive); failure.get()?.let { throw it }
                    assertEquals(listOf(InetSocketAddress(destination, port)), intercept.requested)
                    assertArrayEquals(destination.address, intercept.requested.single().address.address)
                    assertTrue(guard.calls.isEmpty()) // Intercepted traffic never falls back to protected direct egress.
                    await { policy.facts().flows == 0 }
                }
            }
        }
    }

    @Test fun otherTcpUsesActualProtectedDirectConnection() {
        ServerSocket(0, 1, loopback).use { receiver ->
            receiver.soTimeout = 2000
            fixture { policy, _, intercept, guard ->
                client(policy).use { socket ->
                    request(socket, 1, InetSocketAddress(loopback, receiver.localPort))
                    receiver.accept().use { peer ->
                        socket.outputStream.write(42); assertEquals(42, peer.inputStream.read())
                        peer.outputStream.write(43); assertEquals(43, socket.inputStream.read())
                    }
                }
                assertTrue(intercept.requested.isEmpty()); assertEquals(listOf("protect-tcp", "bind-tcp"), guard.calls)
            }
        }
    }

    @Test fun sealingWhileTheRealSocketReaderIsBlockedDoesNotForwardLaterBytes() {
        ServerSocket(0, 1, loopback).use { receiver ->
            receiver.soTimeout = 2000
            fixture { policy, _, _, _ ->
                client(policy).use { socket ->
                    request(socket, 1, InetSocketAddress(loopback, receiver.localPort))
                    receiver.accept().use { peer ->
                        peer.soTimeout = 2000
                        await {
                            Thread.getAllStackTraces().any { (thread, sites) ->
                                thread.name == "capture-flow" && sites.any { it.className.contains("CapturePolicyServer") && it.methodName == "copy" } &&
                                    sites.any { it.methodName == "read" && (it.className.startsWith("java.net.") || it.className.startsWith("sun.nio.")) }
                            }
                        }
                        policy.sealAdmission()
                        socket.outputStream.write(42)
                        assertEquals(-1, peer.inputStream.read())
                    }
                }
            }
        }
    }

    @Test fun authenticatedUdpInTcpPreservesFramingAndBlocks443BeforeAllocation() {
        DatagramSocket(InetSocketAddress(loopback, 0)).use { receiver ->
            receiver.soTimeout = 2000
            fixture { policy, egress, intercept, guard ->
                client(policy).use { socket ->
                    request(socket, 5, InetSocketAddress(loopback, 0))
                    val output = DataOutputStream(socket.getOutputStream()); val input = DataInputStream(socket.getInputStream())
                    udpFrame(output, InetSocketAddress(loopback, 443), byteArrayOf(9))
                    await { policy.facts().drops == 1 }
                    assertEquals(0, egress.ownedCount()); assertTrue(guard.calls.isEmpty())
                    val bytes = byteArrayOf(1, 2, 3, 4)
                    udpFrame(output, InetSocketAddress(loopback, receiver.localPort), bytes)
                    val packet = DatagramPacket(ByteArray(32), 32); receiver.receive(packet)
                    assertArrayEquals(bytes, packet.data.copyOf(packet.length))
                    receiver.send(DatagramPacket(byteArrayOf(7, 8), 2, packet.socketAddress))
                    assertEquals(2, input.readUnsignedShort()); assertEquals(10, input.readUnsignedByte()); assertEquals(1, input.readUnsignedByte())
                    assertArrayEquals(loopback.address, ByteArray(4).also(input::readFully)); assertEquals(receiver.localPort, input.readUnsignedShort())
                    assertArrayEquals(byteArrayOf(7, 8), ByteArray(2).also(input::readFully))
                    assertEquals(listOf("protect-udp", "bind-udp"), guard.calls); assertTrue(intercept.requested.isEmpty())
                }
                await { policy.facts().flows == 0 }; assertEquals(0, egress.budget.count())
            }
        }
    }

    @Test fun domainTargetsAndMalformedUdpLengthsAreRejectedWithoutResolutionOrEgress() = fixture { policy, egress, intercept, guard ->
        client(policy).use { socket ->
            socket.outputStream.write(byteArrayOf(5, 1, 0, 3, 1, 65, 0, 80))
            assertEquals(-1, socket.inputStream.read())
        }
        for (size in listOf(65508, 65535)) client(policy).use { socket ->
            request(socket, 5, InetSocketAddress(loopback, 0))
            DataOutputStream(socket.getOutputStream()).apply { writeShort(size); writeByte(10); flush() }
            assertEquals(-1, socket.inputStream.read())
        }
        client(policy).use { socket ->
            request(socket, 5, InetSocketAddress(loopback, 0))
            val output = DataOutputStream(socket.getOutputStream())
            output.writeShort(1); output.writeByte(11); output.writeByte(1); output.write(loopback.address); output.writeShort(53); output.flush()
            assertEquals(-1, socket.inputStream.read())
        }
        await { policy.facts().flows == 0 }; assertEquals(0, egress.budget.count())
        assertTrue(guard.calls.isEmpty()); assertTrue(intercept.requested.isEmpty())
    }

    @Test fun listenerAndRawEgressShareTheSame32OwnershipLimit() = fixture { policy, egress, _, _ ->
        val raw = (1..32).map { egress.rawSocketFactory().createSocket() }
        Socket(loopback, policy.port).use { socket -> socket.soTimeout = 2000; assertEquals(-1, socket.inputStream.read()) }
        assertEquals(32, egress.budget.count()); assertEquals(0, policy.facts().flows)
        raw.forEach(Socket::close)
        client(policy).close()
        await { policy.facts().flows == 0 }
    }

    private fun fixture(receiver: Int = 1, action: (CapturePolicyServer, ProtectedEgressFactory, Intercept, Guard) -> Unit) {
        val guard = Guard(); val egress = ProtectedEgressFactory(guard); val intercept = Intercept(receiver)
        val policy = CapturePolicyServer(intercept, egress)
        policy.start()
        try { action(policy, egress, intercept, guard) }
        finally {
            policy.interrupt(); egress.close(); intercept.close(); policy.factoryClosed(); policy.join(System.nanoTime() + 3_000_000_000); policy.destroySecrets()
            assertEquals(0, egress.budget.count()); assertEquals(0, policy.facts().workers)
        }
    }
    private fun client(policy: CapturePolicyServer): Socket = Socket(loopback, policy.port).also { socket ->
        socket.soTimeout = 2000
        val config = policy.configuration()
        val username = Regex("username: '([^']+)'").find(config)!!.groupValues[1].toByteArray()
        val password = Regex("password: '([^']+)'").find(config)!!.groupValues[1].toByteArray()
        val output = DataOutputStream(socket.getOutputStream()); val input = DataInputStream(socket.getInputStream())
        output.write(byteArrayOf(5, 1, 2)); output.flush(); assertEquals(5, input.readUnsignedByte()); assertEquals(2, input.readUnsignedByte())
        output.writeByte(1); output.writeByte(username.size); output.write(username); output.writeByte(password.size); output.write(password); output.flush()
        username.fill(0); password.fill(0); assertEquals(1, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
    }
    private fun request(socket: Socket, command: Int, destination: InetSocketAddress) {
        val output = DataOutputStream(socket.getOutputStream()); output.write(byteArrayOf(5, command.toByte(), 0)); address(output, destination); output.flush()
        val input = DataInputStream(socket.getInputStream()); assertEquals(5, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
        val size = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> throw AssertionError("Invalid reply") }
        input.readFully(ByteArray(size)); input.readUnsignedShort()
    }
    private fun udpFrame(output: DataOutputStream, destination: InetSocketAddress, payload: ByteArray) {
        output.writeShort(payload.size); output.writeByte(if (destination.address.address.size == 4) 10 else 22); address(output, destination); output.write(payload); output.flush()
    }
    private fun address(output: DataOutputStream, destination: InetSocketAddress) {
        output.writeByte(if (destination.address.address.size == 4) 1 else 4); output.write(destination.address.address); output.writeShort(destination.port)
    }
    private fun await(condition: () -> Boolean) {
        val until = System.nanoTime() + 3_000_000_000
        while (!condition()) { check(System.nanoTime() < until) { "Owned flow did not terminate" }; Thread.sleep(1) }
    }
}
