package com.httpfreekit.capture

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress

/** An owned duplex stream. EOF in one direction does not close the other direction. */
interface CaptureTcpConnection : AutoCloseable {
    val input: InputStream
    val output: OutputStream
    fun shutdownOutput()
    fun interrupt()
    /** Idempotently close/join this connection's own transport workers, independently of relay callers. */
    override fun close()
}

/** Per-session ownership includes pending opens. Close is idempotent and interrupts them before joining. */
interface InterceptedTcpFactory : AutoCloseable {
    fun open(originalAddress: InetAddress, originalPort: Int): CaptureTcpConnection
    override fun close()
}

/** Fixed safe categories only; underlying socket/provider failures are never retained. */
class CaptureException(val code: String) : IllegalStateException("Capture unavailable") {
    init { require(code in setOf("invalid_request", "capacity", "closed", "protect_failed", "bind_failed", "connect_failed", "cleanup_failed", "native_failed")) }
}
