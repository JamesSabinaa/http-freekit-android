package com.httpfreekit.transport.websocket

import org.java_websocket.WebSocketImpl
import org.java_websocket.drafts.Draft
import org.java_websocket.drafts.Draft_6455
import org.java_websocket.extensions.DefaultExtension
import org.java_websocket.framing.Framedata
import org.java_websocket.protocols.Protocol

internal class GuardedGatewayDraft : Draft_6455(listOf(DefaultExtension()), listOf(Protocol("")), 65536) {
    private var bounds = GatewayMessageBounds()
    override fun copyInstance(): Draft = GuardedGatewayDraft()
    override fun processFrame(webSocket: WebSocketImpl, frame: Framedata) {
        bounds.accept(frame.opcode, frame.isFin, frame.payloadData.remaining().toLong())
        super.processFrame(webSocket, frame)
    }
    override fun reset() { super.reset(); bounds = GatewayMessageBounds() }
    override fun toString() = "GuardedGatewayDraft([REDACTED])"
}
