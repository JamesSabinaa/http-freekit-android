package com.httpfreekit.transport.websocket

import java.io.OutputStream
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket

/** Instrumented real TLS output, never a fake write/flush completion. */
internal class GatewayTestSocket(
    private val delegate: SSLSocket,
    private val beforeWrite: () -> Unit = {}, private val afterWrite: () -> Unit = {},
    private val beforeFlush: () -> Unit = {},
    private val beforeClose: () -> Unit = {},
) : SSLSocket() {
    private val output = object : OutputStream() {
        override fun write(value: Int) { beforeWrite(); delegate.outputStream.write(value); afterWrite() }
        override fun write(bytes: ByteArray, offset: Int, count: Int) {
            beforeWrite(); delegate.outputStream.write(bytes, offset, count); afterWrite()
        }
        override fun flush() { beforeFlush(); delegate.outputStream.flush() }
    }
    override fun getOutputStream() = output
    override fun getInputStream() = delegate.inputStream
    override fun close() { beforeClose(); delegate.close() }
    override fun isClosed() = delegate.isClosed
    override fun getSupportedCipherSuites() = delegate.supportedCipherSuites
    override fun getEnabledCipherSuites() = delegate.enabledCipherSuites
    override fun setEnabledCipherSuites(suites: Array<out String>) { delegate.enabledCipherSuites = suites }
    override fun getSupportedProtocols() = delegate.supportedProtocols
    override fun getEnabledProtocols() = delegate.enabledProtocols
    override fun setEnabledProtocols(protocols: Array<out String>) { delegate.enabledProtocols = protocols }
    override fun getSession(): SSLSession = delegate.session
    override fun addHandshakeCompletedListener(listener: HandshakeCompletedListener) = delegate.addHandshakeCompletedListener(listener)
    override fun removeHandshakeCompletedListener(listener: HandshakeCompletedListener) = delegate.removeHandshakeCompletedListener(listener)
    override fun startHandshake() = delegate.startHandshake()
    override fun setUseClientMode(mode: Boolean) { delegate.useClientMode = mode }
    override fun getUseClientMode() = delegate.useClientMode
    override fun setNeedClientAuth(need: Boolean) { delegate.needClientAuth = need }
    override fun getNeedClientAuth() = delegate.needClientAuth
    override fun setWantClientAuth(want: Boolean) { delegate.wantClientAuth = want }
    override fun getWantClientAuth() = delegate.wantClientAuth
    override fun setEnableSessionCreation(enabled: Boolean) { delegate.enableSessionCreation = enabled }
    override fun getEnableSessionCreation() = delegate.enableSessionCreation
    override fun getSSLParameters(): SSLParameters = delegate.sslParameters
    override fun setSSLParameters(parameters: SSLParameters) { delegate.sslParameters = parameters }
    override fun toString() = "GatewayTestSocket([REDACTED])"
}
