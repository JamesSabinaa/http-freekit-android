package com.httpfreekit.capture.transport

import java.io.ByteArrayOutputStream
import java.net.Socket
import java.nio.ByteBuffer
import org.java_websocket.WebSocket
import org.java_websocket.WebSocketAdapter
import org.java_websocket.WebSocketImpl
import org.java_websocket.drafts.Draft_6455
import org.java_websocket.enums.Opcode
import org.java_websocket.framing.CloseFrame
import org.java_websocket.framing.Framedata
import org.java_websocket.framing.PingFrame
import org.java_websocket.handshake.HandshakeImpl1Client
import org.java_websocket.handshake.Handshakedata

/** Synchronous, bounded test driver around the pinned maintained RFC6455 implementation. */
internal class InnerUpgradePeer(private val socket: Socket) {
    private var opened = false
    private var closed = false
    private var peerClose = false
    private var failed = false
    private val messages = mutableListOf<String>()
    private var binaryEcho = false
    private var pings = 0
    private var pongs = 0
    private val listener = object : WebSocketAdapter() {
        override fun onWebsocketOpen(conn: WebSocket, handshake: Handshakedata) { opened = true }
        override fun onWebsocketMessage(conn: WebSocket, message: String) {
            check(messages.size < 2 && message == if (messages.isEmpty()) "origin-ready" else "capture-upgrade-€")
            messages.add(message)
        }
        override fun onWebsocketMessage(conn: WebSocket, bytes: ByteBuffer) {
            check(!binaryEcho && bytes.remaining() == 4097)
            for (index in 0 until 4097) check(bytes.get() == ((index * 29 + 3) and 255).toByte())
            binaryEcho = true
        }
        override fun onWebsocketPing(conn: WebSocket, frame: Framedata) {
            check(++pings <= 2); super.onWebsocketPing(conn, frame)
        }
        override fun onWebsocketPong(conn: WebSocket, frame: Framedata) { check(++pongs <= 2) }
        override fun onWebsocketClose(conn: WebSocket, code: Int, reason: String?, remote: Boolean) {
            closed = true; if (code != 1000 || !peerClose) failed = true
        }
        override fun onWebsocketClosing(conn: WebSocket, code: Int, reason: String?, remote: Boolean) = Unit
        override fun onWebsocketCloseInitiated(conn: WebSocket, code: Int, reason: String?) = Unit
        override fun onWebsocketError(conn: WebSocket, error: Exception) { failed = true }
        override fun onWriteDemand(conn: WebSocket) = Unit
        override fun getLocalSocketAddress(conn: WebSocket) = null
        override fun getRemoteSocketAddress(conn: WebSocket) = null
    }
    private val engine = WebSocketImpl(listener, Draft_6455())

    fun exchange() {
        val request = HandshakeImpl1Client().apply {
            resourceDescriptor = "/factory-upgrade"
            put("Host", "capture-origin.invalid")
        }
        engine.startHandshake(request); flush()
        val header = ByteArrayOutputStream(); var tail = 0
        while (tail != 0x0d0a0d0a) {
            val value = socket.inputStream.read(); check(value >= 0 && header.size() < 4096)
            header.write(value); tail = (tail shl 8) or value
        }
        engine.decode(ByteBuffer.wrap(header.toByteArray())); check(opened && !failed)
        receiveUntil { messages == listOf("origin-ready") }
        engine.send("capture-upgrade-€")
        engine.send(ByteArray(4097) { ((it * 29 + 3) and 255).toByte() })
        engine.sendFrame(PingFrame()); flush()
        receiveUntil { messages.size == 2 && binaryEcho && pings == 1 && pongs == 1 }
        engine.close(1000); flush()
        receiveUntil { peerClose && closed }
        check(!failed)
        // The strict TLS task rejects a missing close_notify; plain WS needs actual TCP EOF.
        check(socket.inputStream.read() == -1)
    }

    private fun receiveUntil(done: () -> Boolean) {
        val buffer = ByteArray(8192); var total = 0
        while (!done()) {
            val count = socket.inputStream.read(buffer)
            check(count > 0); total += count; check(total <= 65536)
            // v1.6.0 WebSocketImpl.decode ignores frames in CLOSING. Its public
            // maintained draft still validates/processes peer Close correctly.
            val draft = engine.draft
            for (frame in draft.translateFrame(ByteBuffer.wrap(buffer, 0, count))) {
                check(!peerClose)
                if (frame.opcode == Opcode.CLOSING) {
                    check(frame is CloseFrame && frame.closeCode == 1000); peerClose = true
                }
                draft.processFrame(engine, frame)
            }
            flush(); check(!failed)
        }
    }

    private fun flush() {
        var total = 0
        while (true) {
            val pending = engine.outQueue.poll() ?: break
            val count = pending.remaining(); total += count; check(total <= 65536)
            val bytes = ByteArray(count); pending.get(bytes)
            socket.outputStream.write(bytes)
        }
        socket.outputStream.flush()
    }
}
