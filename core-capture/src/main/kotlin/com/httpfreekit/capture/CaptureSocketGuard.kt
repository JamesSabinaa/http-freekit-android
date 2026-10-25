package com.httpfreekit.capture

import java.net.DatagramSocket
import java.net.Socket

/** The service supplies actual VpnService.protect and its captured underlying Network.bindSocket. */
interface CaptureSocketGuard {
    fun protect(socket: Socket): Boolean
    fun protect(socket: DatagramSocket): Boolean
    fun bind(socket: Socket)
    fun bind(socket: DatagramSocket)
}
