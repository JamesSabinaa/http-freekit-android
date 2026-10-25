package com.httpfreekit.capture

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class CapturePolicyCompletionTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    @Test(timeout = 20_000) fun realDirectionalEofClosesGracefullyBeforeInterruptAndRetainsChargesUntilJoin() {
        val body = ByteArray(32791) { (it % 251).toByte() }
        val reply = ByteArray(24589) { ((it * 7) % 253).toByte() }
        val uploadEnded = CountDownLatch(1)
        val releaseReply = CountDownLatch(1)
        peer({ socket ->
            assertArrayEquals(body, socket.getInputStream().readBytes())
            uploadEnded.countDown()
            assertTrue(releaseReply.await(5, TimeUnit.SECONDS))
            socket.getOutputStream().write(reply)
            socket.shutdownOutput()
        }) { receiver ->
            val factory = StrictFactory(receiver)
            policy(factory) { server, egress ->
                try {
                    client(server).use { socket ->
                        socket.getOutputStream().write(body)
                        socket.shutdownOutput()
                        assertTrue(uploadEnded.await(3, TimeUnit.SECONDS))
                        val connection = factory.connection()
                        assertTrue(connection.outputEnded.get())
                        assertFalse(connection.closeEntered.await(100, TimeUnit.MILLISECONDS))
                        releaseReply.countDown()
                        assertArrayEquals(reply, socket.getInputStream().readBytes())
                        assertTrue(connection.closeEntered.await(3, TimeUnit.SECONDS))
                        assertTrue(connection.inputEnded.get())
                        assertTrue(connection.outputEnded.get())
                        assertFalse(connection.reverseAliveAtClose.get())
                        assertEquals(listOf("close"), connection.events.toList())
                        assertFalse(connection.socket.isClosed)
                        assertEquals(1, server.facts().flows)
                        assertEquals(2, egress.budget.count())
                        assertThrows(CaptureException::class.java) { server.join(System.nanoTime() + 20_000_000) }
                        assertEquals(1, server.facts().flows)
                        assertEquals(2, egress.budget.count())
                        connection.releaseClose.countDown()
                        await { server.facts().flows == 0 && egress.budget.count() == 0 }
                        assertEquals(listOf("close"), connection.events.toList())
                        assertTrue(connection.socket.isClosed)
                    }
                } finally { releaseReply.countDown(); factory.release() }
            }
        }
    }

    @Test(timeout = 20_000) fun sealingAfterARealReadDoesNotInventEofOrHalfClose() {
        peer({ socket ->
            socket.getOutputStream().write(42); socket.getOutputStream().flush()
            assertEquals(-1, socket.getInputStream().read())
        }) { receiver ->
            val factory = StrictFactory(receiver, gatePositiveRead = true)
            policy(factory) { server, egress ->
                client(server).use {
                    val connection = factory.connection()
                    assertTrue(connection.positiveReadEntered.await(3, TimeUnit.SECONDS))
                    server.sealAdmission()
                    connection.releasePositiveRead.countDown()
                    assertTrue(connection.interruptEntered.await(3, TimeUnit.SECONDS))
                    assertTrue(connection.closeEntered.await(3, TimeUnit.SECONDS))
                    assertFalse(connection.inputEnded.get())
                    assertFalse(connection.outputEnded.get())
                    connection.releaseClose.countDown()
                    server.interrupt()
                    server.join(System.nanoTime() + 3_000_000_000)
                    assertEquals(0, server.facts().flows)
                    assertEquals(0, egress.budget.count())
                }
            }
        }
    }

    @Test(timeout = 20_000) fun stopAttemptsCloseAfterInterruptFailureAndRetainsBothChargesUntilFactoryAndRelayJoin() {
        peer({ socket -> assertEquals(-1, socket.getInputStream().read()) }) { receiver ->
            val factory = StrictFactory(receiver, failClose = true, throwInterrupt = true, holdInterruptedRead = true)
            policy(factory) { server, egress ->
                client(server).use {
                    val connection = factory.connection()
                    assertTrue(connection.readEntered.await(3, TimeUnit.SECONDS))
                    server.interrupt()
                    assertTrue(connection.interruptEntered.await(3, TimeUnit.SECONDS))
                    assertTrue(connection.interruptedReadEntered.await(3, TimeUnit.SECONDS))
                    assertTrue(connection.closeEntered.await(3, TimeUnit.SECONDS))
                    assertTrue(connection.events.indexOf("interrupt") < connection.events.indexOf("close"))
                    assertFalse(connection.inputEnded.get())
                    assertFalse(connection.outputEnded.get())
                    connection.releaseClose.countDown()
                    assertTrue(connection.closeFailed.await(3, TimeUnit.SECONDS))
                    assertThrows(CaptureException::class.java) { server.join(System.nanoTime() + 20_000_000) }
                    assertEquals(1, server.facts().flows)
                    assertEquals(2, egress.budget.count())
                    // Factory closure proves its resources, but cannot join the core's gated reader.
                    factory.close()
                    server.factoryClosed()
                    assertThrows(CaptureException::class.java) { server.join(System.nanoTime() + 20_000_000) }
                    assertEquals(1, server.facts().flows)
                    assertEquals(2, egress.budget.count())
                    connection.releaseInterruptedRead.countDown()
                    server.join(System.nanoTime() + 3_000_000_000)
                    assertEquals(0, server.facts().flows)
                    assertEquals(0, egress.budget.count())
                    assertTrue(connection.socket.isClosed)
                }
            }
        }
    }

    private class StrictFactory(private val receiver: Int, private val gatePositiveRead: Boolean = false,
        private val failClose: Boolean = false, private val throwInterrupt: Boolean = false,
        private val holdInterruptedRead: Boolean = false) : InterceptedTcpFactory {
        private val opened = AtomicReference<StrictConnection>()
        override fun open(originalAddress: InetAddress, originalPort: Int): CaptureTcpConnection {
            check(originalAddress.address.contentEquals(byteArrayOf(127, 0, 0, 1)) && originalPort == 80)
            val socket = Socket()
            val connection = StrictConnection(socket, gatePositiveRead, failClose, throwInterrupt, holdInterruptedRead)
            check(opened.compareAndSet(null, connection))
            socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), receiver), 2000)
            return connection
        }
        fun connection(): StrictConnection = checkNotNull(opened.get())
        fun release() {
            opened.get()?.let { it.releaseClose.countDown(); it.releasePositiveRead.countDown(); it.releaseInterruptedRead.countDown() }
        }
        override fun close() {
            opened.get()?.let { it.releaseClose.countDown(); it.releasePositiveRead.countDown(); it.socket.close() }
        }
    }

    private class StrictConnection(val socket: Socket, private val gatePositiveRead: Boolean,
        private val failClose: Boolean, private val throwInterrupt: Boolean,
        private val holdInterruptedRead: Boolean) : CaptureTcpConnection {
        val inputEnded = AtomicBoolean()
        val outputEnded = AtomicBoolean()
        val reverseAliveAtClose = AtomicBoolean()
        val closeEntered = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val closeFailed = CountDownLatch(1)
        val interruptEntered = CountDownLatch(1)
        val readEntered = CountDownLatch(1)
        val positiveReadEntered = CountDownLatch(1)
        val releasePositiveRead = CountDownLatch(1)
        val interruptedReadEntered = CountDownLatch(1)
        val releaseInterruptedRead = CountDownLatch(1)
        val events: MutableList<String> = Collections.synchronizedList(ArrayList())
        private val reader = AtomicReference<Thread>()
        override val input: InputStream by lazy {
            object : FilterInputStream(socket.getInputStream()) {
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                    reader.compareAndSet(null, Thread.currentThread())
                    readEntered.countDown()
                    try {
                        return super.read(bytes, offset, length).also {
                            if (it < 0) inputEnded.set(true)
                            if (it > 0 && gatePositiveRead) {
                                positiveReadEntered.countDown()
                                check(releasePositiveRead.await(5, TimeUnit.SECONDS))
                            }
                        }
                    } catch (failure: IOException) {
                        if (holdInterruptedRead) {
                            interruptedReadEntered.countDown()
                            check(releaseInterruptedRead.await(5, TimeUnit.SECONDS))
                        }
                        throw failure
                    }
                }
            }
        }
        override val output get() = socket.getOutputStream()
        override fun shutdownOutput() { socket.shutdownOutput(); outputEnded.set(true) }
        override fun interrupt() {
            events.add("interrupt"); socket.close(); interruptEntered.countDown()
            if (throwInterrupt) throw CaptureException("cleanup_failed")
        }
        override fun close() {
            events.add("close")
            reverseAliveAtClose.set(reader.get()?.isAlive == true)
            closeEntered.countDown()
            check(releaseClose.await(5, TimeUnit.SECONDS))
            if (failClose) { closeFailed.countDown(); throw CaptureException("cleanup_failed") }
            socket.close()
        }
    }

    private fun policy(factory: StrictFactory, action: (CapturePolicyServer, ProtectedEgressFactory) -> Unit) {
        val guard = object : CaptureSocketGuard {
            override fun protect(socket: Socket): Boolean = error("Unexpected direct egress")
            override fun protect(socket: DatagramSocket): Boolean = error("Unexpected direct egress")
            override fun bind(socket: Socket) = error("Unexpected direct egress")
            override fun bind(socket: DatagramSocket) = error("Unexpected direct egress")
        }
        val egress = ProtectedEgressFactory(guard)
        val server = CapturePolicyServer(factory, egress)
        server.start()
        try { action(server, egress) }
        finally {
            factory.release()
            server.interrupt()
            factory.close()
            server.factoryClosed()
            egress.close()
            server.join(System.nanoTime() + 5_000_000_000)
            server.destroySecrets()
        }
    }

    private fun client(server: CapturePolicyServer): Socket {
        val config = server.configuration()
        val user = Regex("username: '([^']+)'").find(config)!!.groupValues[1].toByteArray(Charsets.US_ASCII)
        val password = Regex("password: '([^']+)'").find(config)!!.groupValues[1].toByteArray(Charsets.US_ASCII)
        val socket = Socket(loopback, server.port).apply { soTimeout = 3000 }
        try {
            val input = DataInputStream(socket.getInputStream()); val output = DataOutputStream(socket.getOutputStream())
            output.write(byteArrayOf(5, 1, 2)); output.flush()
            assertEquals(5, input.readUnsignedByte()); assertEquals(2, input.readUnsignedByte())
            output.writeByte(1); output.writeByte(user.size); output.write(user); output.writeByte(password.size); output.write(password); output.flush()
            assertEquals(1, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
            output.write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1)); output.writeShort(80); output.flush()
            val response = ByteArray(10); input.readFully(response)
            assertArrayEquals(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0), response)
            return socket
        } catch (failure: Throwable) { socket.close(); throw failure }
        finally { user.fill(0); password.fill(0) }
    }

    private fun peer(exchange: (Socket) -> Unit, action: (Int) -> Unit) {
        ServerSocket(0, 1, loopback).use { listener ->
            listener.soTimeout = 3000
            val accepted = AtomicReference<Socket>()
            val failure = AtomicReference<Throwable>()
            val thread = Thread({
                try { listener.accept().also(accepted::set).use { socket -> socket.soTimeout = 5000; exchange(socket) } }
                catch (caught: Throwable) { failure.set(caught) }
            }, "capture-completion-peer").apply { start() }
            try { action(listener.localPort) }
            finally {
                listener.close(); accepted.get()?.close(); thread.join(6000)
                assertFalse(thread.isAlive)
                failure.get()?.let { throw it }
            }
        }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + 3_000_000_000
        while (!condition() && System.nanoTime() - deadline < 0) Thread.sleep(5)
        assertTrue(condition())
    }
}
