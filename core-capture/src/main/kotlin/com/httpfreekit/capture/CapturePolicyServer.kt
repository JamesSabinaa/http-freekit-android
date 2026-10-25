package com.httpfreekit.capture

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Numeric-only authenticated local boundary for the pinned engine, with no direct interception fallback. */
internal class CapturePolicyServer(
    private val intercepted: InterceptedTcpFactory, private val egress: ProtectedEgressFactory,
    private val idleMillis: Long = 60000, private val lifetimeMillis: Long = 1800000,
) {
    private val lock = Any()
    private val user = credential()
    private val password = credential()
    private val listener = ServerSocket()
    private val flows = LinkedHashSet<Flow>()
    private val workers = LinkedHashSet<Thread>()
    private val retainedIntercepts = ArrayList<CaptureSocketBudget.Lease>()
    private var sealed = false
    private var failed = false
    private var factoryJoined = false
    private val openedIntercepts = AtomicInteger()
    private val openedDirect = AtomicInteger()
    private val openedUdp = AtomicInteger()
    val udp443Drops = AtomicInteger()
    private val pending = AtomicInteger()
    init {
        require(idleMillis in 100..60000 && lifetimeMillis in idleMillis..1800000)
        listener.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 16)
    }
    val port get() = listener.localPort
    fun configuration(): String = "tunnel:\n  mtu: 1500\n  ipv4: 198.18.0.1\n  ipv6: 'fd00:6672:6565::1'\n" +
        "socks5:\n  address: 127.0.0.1\n  port: $port\n  udp: 'tcp'\n  pipeline: false\n" +
        "  username: '${user.toString(Charsets.US_ASCII)}'\n  password: '${password.toString(Charsets.US_ASCII)}'\n" +
        "misc:\n  log-file: null\n  log-level: error\n  max-session-count: 32\n  tcp-buffer-size: 8192\n" +
        "  udp-copy-buffer-nums: 1\n  connect-timeout: 5000\n  tcp-read-write-timeout: 60000\n  udp-read-write-timeout: 60000\n"

    fun start() {
        launch(null, "capture-accept") {
            while (!isSealed()) {
                val socket = try { listener.accept() } catch (_: Exception) { if (!isSealed()) markFailed(); break }
                synchronized(lock) {
                    if (sealed) { socket.close(); return@synchronized }
                    val lease = try { egress.budget.acquire() } catch (_: CaptureException) { socket.close(); return@synchronized }
                    val flow = Flow(socket, lease); flows.add(flow)
                    try { launch(flow, "capture-flow") { flow.run() } }
                    catch (_: Exception) { flow.interrupt(); flow.done = true }
                }
            }
        }
        launch(null, "capture-watch") {
            while (!isSealed()) {
                val now = System.nanoTime()
                val current = synchronized(lock) { flows.toList() }
                current.forEach { flow ->
                    val handshake = !flow.ready && now - flow.created >= 5_000_000_000L
                    if (handshake || now - flow.progress.get() >= idleMillis * 1_000_000 || now - flow.created >= lifetimeMillis * 1_000_000) flow.interrupt()
                }
                reap()
                Thread.sleep(25)
            }
        }
    }
    private fun launch(flow: Flow?, name: String, action: () -> Unit): Thread = synchronized(lock) {
        if (sealed) throw CaptureException("closed")
        val thread = Thread({
            try { action() } catch (_: Exception) { if (flow == null) { if (!isSealed()) markFailed() } else flow.interrupt() }
        }, name).apply { isDaemon = true }
        workers.add(thread); flow?.threads?.add(thread)
        try { thread.start() } catch (_: Exception) { workers.remove(thread); flow?.threads?.remove(thread); throw CaptureException("connect_failed") }
        thread
    }
    private fun markFailed() { synchronized(lock) { failed = true } }
    private fun isSealed() = synchronized(lock) { sealed }
    private fun reap() {
        val complete = synchronized(lock) { flows.filter { it.done && it.threads.none(Thread::isAlive) } }
        complete.forEach { flow ->
            flow.threads.forEach { it.join() }
            if (flow.clean) synchronized(lock) {
                workers.removeAll(flow.threads.toSet()); flows.remove(flow); flow.lease.release()
            }
        }
    }
    /** No join is claimed here: this step only closes admission and interrupts owned I/O. */
    fun sealAdmission() { synchronized(lock) { sealed = true } }
    fun interrupt() {
        val current = synchronized(lock) { sealed = true; flows.toList() }
        try { listener.close() } catch (_: Exception) { markFailed() }
        current.forEach { it.interrupt() }
        synchronized(lock) { workers.filter { it.name == "capture-watch" }.forEach(Thread::interrupt) }
    }
    fun join(deadlineNanos: Long) {
        val current = synchronized(lock) { workers.toList() }
        current.forEach { thread ->
            val remaining = deadlineNanos - System.nanoTime()
            if (remaining > 0) thread.join(maxOf(1, remaining / 1_000_000))
        }
        if (current.any(Thread::isAlive)) throw CaptureException("cleanup_failed")
        reap()
        // Operational failure stays visible, but only unresolved resource closure blocks Stop.
        if (synchronized(lock) { flows.isNotEmpty() }) throw CaptureException("cleanup_failed")
    }
    /** Called only after the per-session interception factory's actual close/join has returned. */
    fun factoryClosed() {
        synchronized(lock) { factoryJoined = true; retainedIntercepts.forEach { it.release() }; retainedIntercepts.clear() }
    }
    fun destroySecrets() {
        check(isSealed() && synchronized(lock) { workers.none(Thread::isAlive) && flows.isEmpty() && factoryJoined })
        user.fill(0); password.fill(0)
    }
    fun facts(): Facts = synchronized(lock) { Facts(sealed, failed, flows.size, workers.count(Thread::isAlive), pending.get(), openedIntercepts.get(), openedDirect.get(), openedUdp.get(), udp443Drops.get()) }
    data class Facts(val sealed: Boolean, val failed: Boolean, val flows: Int, val workers: Int, val pending: Int,
        val intercepted: Int, val direct: Int, val udp: Int, val drops: Int)

    private inner class Flow(val socket: Socket, val lease: CaptureSocketBudget.Lease) {
        val threads = ArrayList<Thread>()
        val created = System.nanoTime()
        val progress = AtomicLong(created)
        @Volatile var ready = false
        @Volatile var done = false
        @Volatile var clean = true
        private val closing = Any()
        private var connection: CaptureTcpConnection? = null
        private var transportLease: CaptureSocketBudget.Lease? = null
        private val targets = LinkedHashMap<InetSocketAddress, UdpTarget>()
        private var inputEnded = false
        private var outputEnded = false

        fun run() {
            try {
                socket.soTimeout = 5000; socket.tcpNoDelay = true
                val input = DataInputStream(socket.getInputStream()); val output = DataOutputStream(socket.getOutputStream())
                if (!authenticate(input, output)) return
                if (input.readUnsignedByte() != 5) return
                val command = input.readUnsignedByte()
                if (input.readUnsignedByte() != 0) return
                val destination = address(input)
                when (command) {
                    1 -> tcp(input, output, destination)
                    5 -> {
                        reply(output, 0); socket.soTimeout = 0; ready = true
                        udp(input, output)
                    }
                    else -> reply(output, 7)
                }
            } catch (_: Exception) { /* A refused/malformed/closed flow never falls back. */ }
            finally {
                interrupt()
                val current = synchronized(closing) { connection }
                try { current?.close(); synchronized(closing) { transportLease?.release(); transportLease = null } }
                catch (_: Exception) { clean = false }
                done = true
            }
        }
        private fun authenticate(input: DataInputStream, output: DataOutputStream): Boolean {
            if (input.readUnsignedByte() != 5) return false
            val count = input.readUnsignedByte()
            if (count !in 1..16) return false
            val methods = ByteArray(count).also(input::readFully)
            if (methods.none { it.toInt() == 2 }) { output.write(byteArrayOf(5, -1)); output.flush(); return false }
            output.write(byteArrayOf(5, 2)); output.flush()
            if (input.readUnsignedByte() != 1) return false
            val u = ByteArray(input.readUnsignedByte()).also(input::readFully)
            val p = ByteArray(input.readUnsignedByte()).also(input::readFully)
            val accepted = MessageDigest.isEqual(u, user) and MessageDigest.isEqual(p, password)
            u.fill(0); p.fill(0)
            output.write(byteArrayOf(1, if (accepted) 0 else 1)); output.flush()
            return accepted
        }
        private fun tcp(input: DataInputStream, output: DataOutputStream, destination: InetSocketAddress) {
            if (destination.port !in 1..65535) { reply(output, 8); return }
            if (isSealed()) throw CaptureException("closed")
            pending.incrementAndGet()
            val opened: CaptureTcpConnection
            try {
                opened = if (destination.port == 80 || destination.port == 443) {
                    val charge = egress.budget.acquire(); synchronized(closing) { transportLease = charge }
                    try { intercepted.open(destination.address, destination.port).also { openedIntercepts.incrementAndGet() } }
                    catch (failure: Exception) {
                        // Without a returned connection, the factory retains the failed open until its close/join.
                        synchronized(lock) { if (factoryJoined) charge.release() else retainedIntercepts.add(charge) }
                        synchronized(closing) { transportLease = null }
                        throw failure
                    }
                } else egress.openTcp(destination.address, destination.port).also { openedDirect.incrementAndGet() }
            } finally { pending.decrementAndGet() }
            synchronized(closing) { connection = opened }
            if (done || socket.isClosed || isSealed()) { opened.interrupt(); return }
            reply(output, 0); socket.soTimeout = 0; ready = true
            val reverse = launch(this, "capture-tcp-read") {
                try { copy(opened.input, output); socket.shutdownOutput(); synchronized(closing) { outputEnded = true } }
                finally { if (!synchronized(closing) { outputEnded }) interrupt() }
            }
            try { copy(input, opened.output); opened.shutdownOutput(); synchronized(closing) { inputEnded = true } }
            finally { if (!synchronized(closing) { inputEnded }) interrupt() }
            // Preserve directional EOF: the opposite reader runs until real EOF, failure or bounded idle/Stop.
            while (reverse.isAlive && !socket.isClosed) reverse.join(100)
        }
        private fun copy(input: java.io.InputStream, output: java.io.OutputStream) {
            val bytes = ByteArray(8192)
            while (!socket.isClosed && !isSealed()) {
                val size = input.read(bytes)
                if (size < 0) return
                if (size == 0) continue
                if (socket.isClosed || isSealed()) return
                output.write(bytes, 0, size); output.flush(); progress.set(System.nanoTime())
            }
        }
        private fun udp(input: DataInputStream, output: DataOutputStream) {
            val bytes = ByteArray(65507)
            while (!socket.isClosed && !isSealed()) {
                val size = try { input.readUnsignedShort() } catch (_: EOFException) { return }
                val header = input.readUnsignedByte()
                if (size > bytes.size) return
                val destination = address(input)
                if (header != (if (destination.address.address.size == 4) 10 else 22) || destination.port == 0) return
                input.readFully(bytes, 0, size)
                if (socket.isClosed || isSealed()) return
                if (destination.port == 443) { udp443Drops.incrementAndGet(); continue }
                var target = synchronized(closing) { targets[destination] }
                if (target == null) {
                    if (synchronized(closing) { targets.size >= 8 }) continue
                    pending.incrementAndGet()
                    val raw = try { egress.openUdp(destination.address, destination.port) } finally { pending.decrementAndGet() }
                    val createdTarget = UdpTarget(raw, destination)
                    target = createdTarget
                    synchronized(closing) {
                        if (done || socket.isClosed || isSealed()) { raw.close(); return }
                        targets[destination] = createdTarget
                    }
                    openedUdp.incrementAndGet()
                    launch(this, "capture-udp-read") {
                        val response = ByteArray(65507)
                        while (!socket.isClosed && !raw.isClosed && !isSealed()) {
                            val packet = DatagramPacket(response, response.size)
                            try { raw.receive(packet) } catch (_: SocketTimeoutException) { continue }
                            synchronized(output) {
                                output.writeShort(packet.length); output.writeByte(if (destination.address.address.size == 4) 10 else 22)
                                writeAddress(output, destination); output.write(response, 0, packet.length); output.flush()
                            }
                            progress.set(System.nanoTime())
                        }
                        raw.close()
                    }
                }
                if (socket.isClosed || isSealed()) return
                checkNotNull(target).socket.send(DatagramPacket(bytes, size)); progress.set(System.nanoTime())
            }
        }
        fun interrupt() {
            try { socket.close() } catch (_: Exception) { clean = false }
            val current = synchronized(closing) { connection to targets.values.toList() }
            try { current.first?.interrupt() } catch (_: Exception) { clean = false }
            current.second.forEach { try { it.socket.close() } catch (_: Exception) { clean = false } }
        }
    }
    private class UdpTarget(val socket: DatagramSocket, val destination: InetSocketAddress)
    private fun address(input: DataInputStream): InetSocketAddress {
        val length = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> throw CaptureException("invalid_request") }
        val bytes = ByteArray(length).also(input::readFully)
        // InetAddress.getByAddress collapses IPv4-mapped IPv6. Preserve the actual SOCKS family/bytes.
        val address = if (length == 16) Inet6Address.getByAddress(null, bytes, -1) else InetAddress.getByAddress(bytes)
        return InetSocketAddress(address, input.readUnsignedShort())
    }
    private fun writeAddress(output: DataOutputStream, address: InetSocketAddress) {
        output.writeByte(if (address.address.address.size == 4) 1 else 4)
        output.write(address.address.address); output.writeShort(address.port)
    }
    private fun reply(output: DataOutputStream, result: Int) { output.write(byteArrayOf(5, result.toByte(), 0, 1, 0, 0, 0, 0, 0, 0)); output.flush() }
    private fun credential(): ByteArray = Base64.getUrlEncoder().withoutPadding().encode(ByteArray(32).also(SecureRandom()::nextBytes))
    override fun toString() = "CapturePolicyServer([REDACTED])"
}
