package com.httpfreekit.capturetest

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

internal class HostReceiver(private val port: Int) {
    init { require(port in 1024..65535) { "receiver_port" } }
    fun snapshot(): Map<String, Int> = request("/snapshot")
    fun armHeld(): Map<String, Int> = request("/hold-next")
    private fun request(path: String): Map<String, Int> = Socket().use { socket ->
        socket.soTimeout = 5000
        socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(10, 0, 2, 2)), port), 5000)
        socket.getOutputStream().write("GET $path HTTP/1.1\r\nHost: capture-fixture.invalid\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
        socket.getOutputStream().flush()
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (true) {
            val size = socket.getInputStream().read(buffer)
            if (size == -1) break
            check(output.size() + size <= 8192) { "receiver_response_bound" }; output.write(buffer, 0, size)
        }
        val bytes = output.toByteArray()
        val text = bytes.toString(Charsets.US_ASCII)
        val split = text.indexOf("\r\n\r\n")
        check(split in 16..4096 && text.startsWith("HTTP/1.1 200 ")) { "receiver_http" }
        val header = text.substring(0, split).split("\r\n").drop(1)
        val lengths = header.filter { it.startsWith("Content-Length:", ignoreCase = true) }
        check(lengths.size == 1 && lengths.single().substringAfter(':').trim().toIntOrNull() == bytes.size - split - 4) { "receiver_length" }
        val value = JSONObject(text.substring(split + 4))
        val names = value.keys().asSequence().toSet()
        check(names == COUNTERS + "closed" && value.get("closed") is Boolean && !value.getBoolean("closed")) { "receiver_schema" }
        COUNTERS.associateWith { name ->
            val number = value.get(name)
            check(number is Int && number in 0..10_000_000) { "receiver_counter" }
            number
        }
    }
    companion object {
        private val COUNTERS = setOf("directHttp", "directOpaque", "directTcp", "udp", "dns", "udp443", "interceptedHttp", "interceptedOpaque", "interceptedIpv6", "uploadBytes", "downloadBytes", "invalidRequests", "heldRequestsClosed", "tcpConnections", "udpDatagrams", "activeSockets", "pendingCallbacks", "timers", "listeners", "heldConnections")
    }
}
