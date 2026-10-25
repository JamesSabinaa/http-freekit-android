package com.httpfreekit.transport.websocket

import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocket
import okhttp3.tls.HandshakeCertificates

/** Owned private test IPC. No child output, certificate or provider text is printed on failure. */
internal class GatewayNodePeer(scenario: String) : AutoCloseable {
    private val executor = Executors.newFixedThreadPool(2)
    private val events = ArrayBlockingQueue<Map<String, String>>(4)
    private val failed = AtomicBoolean()
    private val process: Process
    private val output: java.util.concurrent.Future<*>
    private val errors: java.util.concurrent.Future<*>
    private val sockets = ArrayList<Socket>()
    private val ready: Map<String, String>
    var closedFacts: Map<String, String>? = null
        private set

    init {
        check(Files.isRegularFile(Path.of("tools/transport-spike/gateway-websocket-peer.mjs"))) { "Independent peer missing" }
        process = ProcessBuilder(System.getenv("FREEKIT_NODE") ?: "node", "tools/transport-spike/gateway-websocket-peer.mjs", "--scenario", scenario).start()
        output = executor.submit {
            try {
                var total = 0
                while (true) {
                    val line = readLine(process.inputStream) ?: break
                    total += line.length
                    check(total <= 32768 && events.offer(parse(line)))
                }
            } catch (_: Exception) { failed.set(true) }
        }
        errors = executor.submit {
            try {
                val bytes = ByteArray(1024); var total = 0
                while (true) {
                    val count = process.errorStream.read(bytes)
                    if (count < 0) break
                    total += count
                    if (total > 4096) { failed.set(true); process.errorStream.close(); break }
                }
                if (total != 0) failed.set(true)
            } catch (_: Exception) { failed.set(true) }
        }
        try {
            ready = next("ready")
            check(ready.keys == setOf("format", "revision", "event", "port", "logicalName", "gatewayCertificateDer"))
            check(ready.getValue("port").toInt() in 1..65535)
            check(Regex("[A-Za-z0-9.-]{1,253}").matches(ready.getValue("logicalName")))
        } catch (_: Exception) {
            process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS)
            executor.shutdownNow(); executor.awaitTermination(5, TimeUnit.SECONDS)
            throw AssertionError("Independent peer startup failed")
        }
    }

    val authority: String get() = ready.getValue("logicalName") + ":" + ready.getValue("port")
    fun connect(): Pair<Socket, SSLSocket> {
        val encoded = ready.getValue("gatewayCertificateDer")
        check(Regex("[A-Za-z0-9_-]{1,5462}").matches(encoded))
        val der = Base64.getUrlDecoder().decode(encoded)
        check(der.size <= 4096 && Base64.getUrlEncoder().withoutPadding().encodeToString(der) == encoded)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
        check(certificate.encoded.contentEquals(der)); certificate.checkValidity()
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(certificate).build()
        val raw = Socket(); sockets.add(raw)
        raw.sendBufferSize = 65536; raw.receiveBufferSize = 8192; raw.tcpNoDelay = true
        raw.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), ready.getValue("port").toInt()), 5000)
        val tls = trust.sslSocketFactory().createSocket(raw, ready.getValue("logicalName"), ready.getValue("port").toInt(), true) as SSLSocket
        sockets.add(tls)
        tls.soTimeout = 5000
        tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
        tls.startHandshake()
        tls.soTimeout = 0
        return raw to tls
    }

    fun release() { command("release"); next("released") }
    private fun command(op: String) {
        process.outputStream.write("{\"op\":\"$op\"}\n".toByteArray(Charsets.US_ASCII)); process.outputStream.flush()
    }
    private fun next(event: String): Map<String, String> {
        val value = events.poll(15, TimeUnit.SECONDS)
        check(value != null && !failed.get() && value["format"] == "http-freekit-gateway-ws-peer" && value["revision"] == "1" && value["event"] == event) { "Invalid independent peer event" }
        return value
    }
    override fun close() {
        if (closedFacts != null) return
        var valid = true
        try {
            sockets.forEach { try { it.close() } catch (_: Exception) { valid = false } }
            command("stop")
            val closed = next("closed")
            check(closed.keys == setOf("format", "revision", "event", "admissionClosed", "listenerClosed", "activeSockets", "pendingCallbacks", "pendingTimers", "workers", "ownedChildrenJoined", "privateDirectoryRemoved", "upgrades", "clientTextMessages", "clientBinaryMessages", "clientPongs", "clientCloseObserved"))
            check(listOf("admissionClosed", "listenerClosed", "ownedChildrenJoined", "privateDirectoryRemoved").all { closed[it] == "true" })
            check(listOf("activeSockets", "pendingCallbacks", "pendingTimers", "workers").all { closed[it] == "0" })
            check(process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0)
            output.get(5, TimeUnit.SECONDS); errors.get(5, TimeUnit.SECONDS)
            check(!failed.get())
            closedFacts = closed.toMap()
        } catch (_: Exception) { valid = false }
        finally {
            if (process.isAlive) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS); valid = false }
            process.outputStream.close(); process.inputStream.close(); process.errorStream.close()
            executor.shutdownNow(); if (!executor.awaitTermination(5, TimeUnit.SECONDS)) valid = false
        }
        check(valid) { "Independent peer cleanup failed" }
    }
    override fun toString() = "GatewayNodePeer([REDACTED])"

    companion object {
        private fun readLine(input: InputStream): String? {
            val output = java.io.ByteArrayOutputStream()
            while (true) {
                val byte = input.read()
                if (byte < 0) { check(output.size() == 0); return null }
                if (byte == 10) return output.toString(Charsets.UTF_8)
                check(byte in 32..126 && output.size() < 8192)
                output.write(byte)
            }
        }
        private fun parse(line: String): Map<String, String> {
            check(line.startsWith('{') && line.endsWith('}'))
            val fields = Regex("\"([A-Za-z]+)\":(?:\"([^\"\\\\]*)\"|(true|false|0|[1-9][0-9]*))").findAll(line.substring(1, line.length - 1)).toList()
            check(fields.joinToString(",") { it.value } == line.substring(1, line.length - 1))
            check(fields.map { it.groupValues[1] }.distinct().size == fields.size)
            return fields.associate { it.groupValues[1] to (if (it.groupValues[3].isNotEmpty()) it.groupValues[3] else it.groupValues[2]) }
        }
    }
}
