package com.httpfreekit.interop

import com.httpfreekit.security.EnrolledSessionReadyBound
import com.httpfreekit.security.LoadedEnrolledCredential
import java.util.Collections
import com.httpfreekit.security.GatewayTlsConnectionFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import javax.net.SocketFactory
import javax.net.ssl.X509ExtendedKeyManager

/** Upgrade ownership transfers to the existing stream/control owner on success. */
internal fun interface DraftStreamingConnector {
    fun upgrade(credential: DraftStreamingFixture.Credential, route: String, session: String?,
        scenario: String?, rawSendBufferBytes: Int): Pair<DraftStreamingTls, Int>
}

/** Only trusted enrolled context is supplied here; legacy fixture defaults use no saved bound. */
internal class DraftStreamingSessionContext(
    val desktopId: String, capabilities: Collection<String>,
    private val loaded: LoadedEnrolledCredential? = null, private val policyLifetimeMillis: Long? = null,
) {
    val capabilities: List<String>
    init {
        require(Regex("[A-Za-z0-9_-]{1,128}").matches(desktopId)) { "Invalid research desktop context" }
        require((loaded == null) == (policyLifetimeMillis == null)) { "Invalid enrolled policy context" }
        if (loaded != null) require(loaded.record.desktopId == desktopId && checkNotNull(policyLifetimeMillis) in 1L..1800000L) { "Invalid enrolled policy context" }
        val expectedSize = capabilities.size
        require(expectedSize in 1..16) { "Invalid research capabilities" }
        val copied = ArrayList<String>()
        for (capability in capabilities) {
            require(copied.size < 16 && capability !in copied && Regex("[a-z][a-z0-9-]{0,31}").matches(capability)) { "Invalid research capabilities" }
            copied.add(capability)
        }
        require(copied.size == expectedSize && copied.any { it == "tcp-http" || it == "tcp-https-connect" }) { "Invalid research capabilities" }
        this.capabilities = Collections.unmodifiableList(copied)
    }
    fun requireReady(expiresAtMillis: Long, observedUtcMillis: Long) {
        if (loaded != null) {
            // Only the policy observation admits the measured research skew. Certificates stay exact.
            val deadline = Math.addExact(observedUtcMillis, Math.addExact(checkNotNull(policyLifetimeMillis), 2000))
            EnrolledSessionReadyBound(loaded, deadline).requireReady(expiresAtMillis, observedUtcMillis)
        }
    }
    override fun toString() = "DraftStreamingSessionContext([REDACTED])"
}

/** Shared fresh scoped TLS; raw ownership is registered before any fallible socket configuration. */
internal fun draftStreamingConnect(gateway: X509Certificate, pin: String, logicalName: String, port: Int,
    manager: X509ExtendedKeyManager?, rawSendBufferBytes: Int): DraftStreamingTls {
    require(rawSendBufferBytes == 1024 || rawSendBufferBytes == 65536) { "Invalid research send buffer" }
    val raw = AtomicReference<Socket?>()
    val rawFactory = object : SocketFactory() {
        override fun createSocket(): Socket = Socket().also {
            raw.set(it)
            // Compare only the accepted stream's send hint; effective kernel values remain observable.
            it.sendBufferSize = rawSendBufferBytes
            it.receiveBufferSize = 1024
            it.tcpNoDelay = true
        }
        override fun createSocket(host: String?, port: Int): Socket = error("Unowned socket overload")
        override fun createSocket(host: String?, port: Int, local: InetAddress?, localPort: Int): Socket = error("Unowned socket overload")
        override fun createSocket(host: InetAddress?, port: Int): Socket = error("Unowned socket overload")
        override fun createSocket(host: InetAddress?, port: Int, local: InetAddress?, localPort: Int): Socket = error("Unowned socket overload")
    }
    try {
        val tls = GatewayTlsConnectionFactory(gateway, pin, logicalName, 5000, 5000,
            rawSocketFactory = rawFactory, clientKeyManager = manager)
            .connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
        check(tls.session.protocol in setOf("TLSv1.2", "TLSv1.3")) { "Unsupported research TLS" }
        return DraftStreamingTls(checkNotNull(raw.get()), tls)
    } catch (failure: Exception) {
        raw.get()?.close()
        throw failure
    }
}

/** The original bounded research upgrade, with an explicit already-trusted Host value. */
internal fun draftStreamingUpgrade(tls: DraftStreamingTls, host: String, route: String, session: String?, scenario: String?,
    extraHeaders: List<Pair<String, String>> = emptyList()): Pair<DraftStreamingTls, Int> {
    try {
        check(route in setOf("/companion/v1/control", "/companion/v1/streams") &&
            host.length in 1..259 && host.all { it.code in 33..126 }) { "Invalid trusted research upgrade target" }
        tls.socket.soTimeout = 5000
        val key = Base64.getEncoder().encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val head = buildString {
            append("GET $route HTTP/1.1\r\nHost: $host\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
            append("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: $key\r\n")
            session?.let { append("X-FreeKit-Session: $it\r\n") }
            scenario?.let { append("X-FreeKit-Research-Scenario: $it\r\n") }
            extraHeaders.forEach { (name, value) ->
                check(name.length <= 64 && value.length <= 256 && (name + value).all { it.code in 32..126 })
                append("$name: $value\r\n")
            }
            append("\r\n")
        }
        tls.socket.outputStream.write(head.toByteArray(Charsets.US_ASCII))
        tls.socket.outputStream.flush()
        val response = DraftStreamingFixture.readHeaders(tls.socket)
        if (response.first == 101) {
            check(response.second["upgrade"]?.lowercase() == "websocket" &&
                response.second["connection"]?.lowercase()?.split(',')?.any { it.trim() == "upgrade" } == true)
            val expected = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1")
                .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.US_ASCII)))
            check(response.second["sec-websocket-accept"] == expected &&
                "sec-websocket-extensions" !in response.second && "sec-websocket-protocol" !in response.second)
        }
        tls.socket.soTimeout = 0
        return tls to response.first
    } catch (failure: Exception) { tls.close(); throw failure }
}
