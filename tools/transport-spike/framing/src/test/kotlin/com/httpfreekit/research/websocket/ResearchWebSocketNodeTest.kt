package com.httpfreekit.research.websocket

import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

/** Actual framing compatibility only. This is deliberately not an authenticated transport proof. */
class ResearchWebSocketNodeTest {
    @Test(timeout = 45000) fun independentNodeAndKotlinFramesInteroperateAndBothPeersStop() {
        val worker = Executors.newSingleThreadExecutor()
        val process = ProcessBuilder("node", "tools/transport-spike/research-websocket-peer.mjs")
            .redirectError(ProcessBuilder.Redirect.INHERIT).start()
        try {
            val ready = worker.submit<String> { line(process.inputStream) }.get(10, TimeUnit.SECONDS)
            assertTrue("Missing fixed peer readiness", ready.matches(Regex("READY [1-9][0-9]{0,4}")))
            val port = ready.removePrefix("READY ").toInt()
            check(port in 1..65535) { "Invalid fixture port" }
            Socket().use { socket ->
                socket.soTimeout = 5000
                socket.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 5000)
                val reader = ResearchWebSocketReader(socket.getInputStream(), EndpointRole.CLIENT)
                val writer = ResearchWebSocketWriter(socket.getOutputStream(), EndpointRole.CLIENT)
                writer.text("framing-probe".toByteArray())
                val readyEvent = reader.read()
                assertTrue(readyEvent is ResearchWebSocketEvent.Text)
                assertArrayEquals("framing-ready".toByteArray(), readyEvent.copyBytes())
                readyEvent.release()

                val payload = ByteArray(65536) { (it % 251).toByte() }
                writer.binary(payload)
                val echoed = reader.read()
                assertTrue(echoed is ResearchWebSocketEvent.Binary)
                assertArrayEquals(payload, echoed.copyBytes())
                echoed.release()

                writer.ping(byteArrayOf(7, 8))
                val pong = reader.read()
                assertTrue(pong is ResearchWebSocketEvent.Pong)
                assertArrayEquals(byteArrayOf(7, 8), pong.copyBytes())
                pong.release()
                writer.close(byteArrayOf(3, 0xe8.toByte()))
                val close = reader.read() as ResearchWebSocketEvent.Close
                assertEquals(1000, close.code)
                close.release()
            }
            val complete = worker.submit<String> { line(process.inputStream) }.get(10, TimeUnit.SECONDS)
            assertEquals("COMPLETE", complete)
            assertTrue("Node framing peer did not exit", process.waitFor(5, TimeUnit.SECONDS))
            assertEquals("Node framing peer failed", 0, process.exitValue())
        } finally {
            if (process.isAlive) process.destroy()
            if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly()
            check(process.waitFor(5, TimeUnit.SECONDS) && !process.isAlive) { "Node framing fixture cleanup incomplete" }
            process.inputStream.close()
            worker.shutdownNow()
            check(worker.awaitTermination(5, TimeUnit.SECONDS)) { "Node fixture reader did not join" }
        }
    }

    private fun line(input: InputStream): String {
        val result = StringBuilder()
        while (result.length < 64) {
            val next = input.read()
            check(next in 0..127) { "Missing fixture status" }
            if (next == 10) return result.toString()
            result.append(next.toChar())
        }
        error("Invalid fixture status")
    }
}
