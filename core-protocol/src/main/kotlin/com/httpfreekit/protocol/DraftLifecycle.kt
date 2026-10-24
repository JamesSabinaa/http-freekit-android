package com.httpfreekit.protocol

import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.Collections

data class DraftClock(val utcMillis: Long, val monotonicMillis: Long) {
    internal fun valid() = utcMillis in -9007199254740991L..9007199254740991L && monotonicMillis in 0..9007199254740991L
}
enum class DraftControlPhase { AWAITING_HELLO, AWAITING_READY, ACTIVE, CLOSED, FAILED }
enum class DraftStreamPhase { AWAITING_OPEN, AWAITING_READY, OPEN, HALF_CLOSED, DRAINING, CLOSING, COMPLETE, CANCELLED, FAILED }

class DraftResult internal constructor(val code: String = "ok", eofDirections: List<DraftDirection> = emptyList()) {
    val eofDirections: List<DraftDirection> = Collections.unmodifiableList(ArrayList(eofDirections))
    override fun toString() = "DraftResult(code=$code, eofDirections=$eofDirections)"
}
class DraftPeek internal constructor(val result: DraftResult, bytes: ByteArray = ByteArray(0)) {
    private val value = bytes.copyOf()
    fun bytes(): ByteArray = value.copyOf()
    override fun toString() = "DraftPeek(code=${result.code}, bytes=[REDACTED])"
}
class DraftAllocation internal constructor(val result: DraftResult, val stream: DraftStream? = null)
class DraftPoolSnapshot internal constructor(val sessionLeases: Int, val streamLeases: Int, val chargedBytes: Long)
class DraftSessionSnapshot internal constructor(val phase: DraftControlPhase, val cause: String?, val sessionLease: Boolean,
    val controlClosureConfirmed: Boolean, val webSocketClosed: Boolean, val streamLeases: Int, val chargedBytes: Long, val openedIds: Int)
class DraftStreamSnapshot internal constructor(val phase: DraftStreamPhase, val cause: String?, val streamId: String?,
    val resourceClosureConfirmed: Boolean, val webSocketClosed: Boolean, val streamLease: Boolean, val chargedBytes: Long, val chargedFrames: Int,
    val clientBytes: Long, val gatewayBytes: Long, val clientSealed: Boolean, val gatewaySealed: Boolean,
    val clientEof: Boolean, val gatewayEof: Boolean)

/** Shared across owners. Only accounting is synchronized; adapters serialize each owner's events. */
class DraftBudgetPool(val maxSessions: Int = 16, val maxStreams: Int = 256, val maxBytes: Long = 16777216) {
    init { require(maxSessions in 1..16 && maxStreams in 1..256 && maxBytes in 1..16777216) { "invalid_message" } }
    private val devices = HashMap<String, DraftSession>()
    private var streams = 0
    private var bytes = 0L
    @Synchronized fun snapshot() = DraftPoolSnapshot(devices.size, streams, bytes)
    @Synchronized internal fun acquireSession(owner: DraftSession, device: String): Boolean {
        if (devices.size >= maxSessions || devices.containsKey(device)) return false
        devices[device] = owner
        return true
    }
    @Synchronized internal fun releaseSession(owner: DraftSession, device: String) {
        if (devices[device] === owner) devices.remove(device)
    }
    @Synchronized internal fun acquireStream(): Boolean {
        if (streams >= maxStreams) return false
        streams++
        return true
    }
    @Synchronized internal fun releaseStream() { check(streams > 0); streams-- }
    @Synchronized internal fun reserveBytes(count: Long): Boolean {
        if (count > maxBytes - bytes) return false
        bytes += count
        return true
    }
    @Synchronized internal fun releaseBytes(count: Long) { check(count >= 0 && count <= bytes); bytes -= count }
}

/** Pure draft control owner. No socket, timer, registry authorization or writer lives here. */
class DraftSession(
    private val trustedDeviceId: String,
    private val expectedDesktopId: String,
    supportedCapabilities: Collection<String>,
    internal val pool: DraftBudgetPool,
    created: DraftClock,
) {
    private val supported = supportedCapabilities.toSet()
    private val createdMono = created.monotonicMillis
    private var observedMono = created.monotonicMillis
    private var readyMono = 0L
    private var lifetime = 0L
    private var expires = 0L
    private var activity = longArrayOf(0, 0)
    private var offered = emptySet<String>()
    private var required = emptySet<String>()
    private var token: String? = null
    internal var limits = DraftLimits()
        private set
    private var phase = DraftControlPhase.AWAITING_HELLO
    private var cause: String? = null
    private var lease = false
    private var closure = false
    private var wsClosedCode: Int? = null
    private val streams = ArrayList<DraftStream>()
    private val history = HashSet<String>()
    internal var chargedBytes = 0L
        private set
    private var streamLeases = 0

    init {
        require(Regex("[A-Za-z0-9_-]{1,128}").matches(trustedDeviceId) && Regex("[A-Za-z0-9_-]{1,128}").matches(expectedDesktopId) &&
            supported.size <= 16 &&
            supported.all { Regex("[a-z][a-z0-9-]{0,31}").matches(it) }) { "invalid_message" }
        if (!created.valid()) { phase = DraftControlPhase.FAILED; cause = "invalid_message" }
    }
    override fun toString() = "DraftSession(state=$phase, credentials=[REDACTED])"
    fun snapshot() = DraftSessionSnapshot(phase, cause, lease, closure, wsClosedCode != null, streamLeases, chargedBytes, history.size)
    /** Explicit credential access for the authenticated upgrade header only. */
    fun sessionHeader(): String? = token

    fun text(direction: DraftDirection?, bytes: ByteArray, now: DraftClock): DraftResult {
        observe(now)?.let { return DraftResult(it) }
        if (terminal()) return DraftResult("invalid_message")
        val decoded = DraftWireCodec.decode(DraftChannel.CONTROL, bytes)
        if (decoded is DraftDecodeResult.Rejected) return fail(decoded.code)
        val message = (decoded as DraftDecodeResult.Accepted).message
        when (message) {
            is DraftMessage.Hello -> {
                if (direction != DraftDirection.CLIENT || phase != DraftControlPhase.AWAITING_HELLO) return fail("invalid_message")
                if (!supported.containsAll(message.requiredCapabilities)) return fail("unsupported_capability")
                offered = message.capabilities.toSet(); required = message.requiredCapabilities.toSet()
                phase = DraftControlPhase.AWAITING_READY
            }
            is DraftMessage.SessionReady -> {
                if (direction != DraftDirection.GATEWAY || phase != DraftControlPhase.AWAITING_READY) return fail("invalid_message")
                if (message.desktopId != expectedDesktopId) return fail("authentication_failed")
                val end = message.expiresAt.toEpochMilli()
                if (end <= now.utcMillis) return fail("session_expired")
                if (now.utcMillis < end - 1800000) return fail("invalid_message")
                if (!offered.containsAll(message.capabilities)) return fail("invalid_message")
                if (!supported.containsAll(message.capabilities) || !message.capabilities.containsAll(required) ||
                    message.capabilities.none { it == "tcp-http" || it == "tcp-https-connect" }) return fail("unsupported_capability")
                if (message.limits.maxFrameBytes > pool.maxBytes) return fail("invalid_message")
                if (!pool.acquireSession(this, trustedDeviceId)) return fail("session_limit")
                lease = true; token = message.sessionId; limits = message.limits
                readyMono = now.monotonicMillis; lifetime = end - now.utcMillis; expires = end
                activity = longArrayOf(now.monotonicMillis, now.monotonicMillis)
                phase = DraftControlPhase.ACTIVE
            }
            is DraftMessage.ControlCancel -> {
                if (direction != DraftDirection.CLIENT || phase !in setOf(DraftControlPhase.AWAITING_READY, DraftControlPhase.ACTIVE)) return fail("invalid_message")
                terminate(DraftControlPhase.CLOSED, "cancelled", true)
            }
            is DraftMessage.ControlEnd -> {
                if (direction != DraftDirection.GATEWAY || (message.type == "disconnect" && phase != DraftControlPhase.ACTIVE) ||
                    (message.type == "error" && phase !in setOf(DraftControlPhase.AWAITING_READY, DraftControlPhase.ACTIVE))) return fail("invalid_message")
                val cancel = message.type == "disconnect" && message.code == "desktop_stopped"
                terminate(if (message.type == "disconnect") DraftControlPhase.CLOSED else DraftControlPhase.FAILED, message.code, cancel)
            }
            else -> return fail("invalid_message")
        }
        if (!terminal() && phase == DraftControlPhase.ACTIVE) activity[direction.ordinal] = now.monotonicMillis
        return DraftResult()
    }

    fun pingPong(direction: DraftDirection?, now: DraftClock): DraftResult {
        observe(now)?.let { return DraftResult(it) }
        if (terminal()) return DraftResult("invalid_message")
        if (phase != DraftControlPhase.ACTIVE || direction == null) return fail("invalid_message")
        activity[direction.ordinal] = now.monotonicMillis
        return DraftResult()
    }

    fun allocateStream(presentedDeviceId: String, presentedSessionId: String, now: DraftClock): DraftAllocation {
        val time = observe(now)
        if (time != null) return DraftAllocation(DraftResult(time))
        if (phase != DraftControlPhase.ACTIVE) return DraftAllocation(DraftResult(if (cause == "session_expired") "session_expired" else "authentication_failed"))
        val acceptedToken = token!!
        if (presentedDeviceId != trustedDeviceId || presentedSessionId.length != acceptedToken.length) {
            return DraftAllocation(DraftResult("authentication_failed"))
        }
        val presentedBytes = presentedSessionId.toByteArray(Charsets.UTF_8)
        val acceptedBytes = acceptedToken.toByteArray(Charsets.UTF_8)
        if (presentedBytes.size != acceptedBytes.size || !MessageDigest.isEqual(presentedBytes, acceptedBytes)) return DraftAllocation(DraftResult("authentication_failed"))
        if (streamLeases >= limits.maxConcurrentStreams || !pool.acquireStream()) return DraftAllocation(DraftResult("stream_limit"))
        val stream = DraftStream(this, now.monotonicMillis)
        streams.add(stream); streamLeases++
        return DraftAllocation(DraftResult(), stream)
    }

    fun cancelLocally(now: DraftClock): DraftResult {
        observe(now)?.let { return DraftResult(it) }
        if (terminal()) return DraftResult("invalid_message")
        terminate(DraftControlPhase.CLOSED, "cancelled", true)
        return DraftResult()
    }
    fun webSocketClosed(code: Int, now: DraftClock): DraftResult {
        val time = observe(now)
        if (code !in 1000..4999) return DraftResult(time ?: if (terminal()) "invalid_message" else fail("invalid_message").code)
        if (wsClosedCode != null) return DraftResult(time ?: if (wsClosedCode == code) "ok" else "invalid_message")
        wsClosedCode = code
        if (time != null) return DraftResult(time)
        if (!terminal()) return fail("network_unreachable")
        return DraftResult()
    }
    fun confirmClosed(now: DraftClock): DraftResult {
        val time = observe(now)
        if (!terminal()) terminate(DraftControlPhase.FAILED, "network_unreachable", false)
        if (wsClosedCode == null) wsClosedCode = 1006
        closure = true
        releaseIfClosed()
        return DraftResult(time ?: "ok")
    }
    fun tick(now: DraftClock): DraftResult {
        val time = observe(now)
        if (!terminal()) streams.forEach { it.checkDeadline(now.monotonicMillis) }
        return DraftResult(time ?: "ok")
    }

    internal fun terminal() = phase == DraftControlPhase.CLOSED || phase == DraftControlPhase.FAILED
    internal fun observe(now: DraftClock): String? {
        if (terminal()) return null
        if (!now.valid() || now.monotonicMillis < observedMono) { fail("invalid_message"); return "invalid_message" }
        observedMono = now.monotonicMillis
        val code = if (phase == DraftControlPhase.ACTIVE) {
            when {
                now.utcMillis >= expires || now.monotonicMillis - readyMono >= lifetime -> "session_expired"
                activity.any { now.monotonicMillis - it >= 60000 } -> "network_unreachable"
                else -> null
            }
        } else if (now.monotonicMillis - createdMono >= 15000) "network_unreachable" else null
        if (code != null) fail(code)
        return code
    }
    internal fun inactiveCause() = cause ?: "authentication_failed"
    internal fun claim(id: String): String? {
        if (id in history) return "invalid_message"
        if (history.size >= limits.maxOpenedStreamsPerSession) return "stream_limit"
        history.add(id)
        return null
    }
    internal fun reserve(count: Long): Boolean {
        if (count > limits.maxQueuedBytesPerDevice - chargedBytes || !pool.reserveBytes(count)) return false
        chargedBytes += count
        return true
    }
    internal fun release(count: Long) { check(count >= 0 && count <= chargedBytes); chargedBytes -= count; pool.releaseBytes(count) }
    internal fun release(stream: DraftStream) {
        check(stream in streams && streamLeases > 0)
        streams.remove(stream)
        streamLeases--; pool.releaseStream()
        releaseIfClosed()
    }
    private fun releaseIfClosed() {
        if (closure && streamLeases == 0 && lease) {
            pool.releaseSession(this, trustedDeviceId); lease = false; history.clear(); token = null
        }
    }
    private fun terminate(next: DraftControlPhase, reason: String, cancelled: Boolean) {
        if (terminal()) return
        phase = next; cause = reason
        streams.forEach { it.invalidate(reason, cancelled) }
    }
    private fun fail(code: String): DraftResult { terminate(DraftControlPhase.FAILED, code, false); return DraftResult(code) }
}

/** Two independent ordered queues. Reservations cover both queued and writer-in-flight bytes. */
class DraftStream internal constructor(private val owner: DraftSession, private val createdMono: Long) {
    private class Chunk(val bytes: ByteArray, var offset: Int = 0)
    private val queues = arrayOf(ArrayDeque<Chunk>(), ArrayDeque<Chunk>())
    private val directionBytes = longArrayOf(0, 0)
    private val sealed = booleanArrayOf(false, false)
    private val eof = booleanArrayOf(false, false)
    private var frames = 0
    private var charged = 0L
    private var phase = DraftStreamPhase.AWAITING_OPEN
    private var cause: String? = null
    private var id: String? = null
    private var closure = false
    private var lease = true
    private var lastProgress = createdMono
    private var ready = false
    private var wsClosedCode: Int? = null
    override fun toString() = "DraftStream(state=$phase, payload=[REDACTED])"
    fun snapshot() = DraftStreamSnapshot(phase, cause, id, closure, wsClosedCode != null, lease, charged, frames,
        directionBytes[0], directionBytes[1], sealed[0], sealed[1], eof[0], eof[1])

    fun text(direction: DraftDirection?, bytes: ByteArray, now: DraftClock): DraftResult {
        preflight(now)?.let { return DraftResult(it) }
        val decoded = DraftWireCodec.decode(DraftChannel.STREAM, bytes)
        if (decoded is DraftDecodeResult.Rejected) return fail(decoded.code)
        val message = (decoded as DraftDecodeResult.Accepted).message as DraftMessage.Stream
        if (direction == null) return fail("invalid_message")
        if (phase == DraftStreamPhase.AWAITING_OPEN) {
            if (message.type != "open" || direction != DraftDirection.CLIENT) return fail("invalid_message")
            owner.claim(message.streamId)?.let { return fail(it) }
            id = message.streamId; phase = DraftStreamPhase.AWAITING_READY
        } else {
            if (message.streamId != id) return fail("invalid_message")
            when (message.type) {
                "ready" -> {
                    if (direction != DraftDirection.GATEWAY || phase != DraftStreamPhase.AWAITING_READY) return fail("invalid_message")
                    ready = true; phase = DraftStreamPhase.OPEN
                }
                "end_write" -> {
                    if (!ready || sealed[direction.ordinal]) return fail("invalid_message")
                    sealed[direction.ordinal] = true
                }
                "cancel" -> { phase = DraftStreamPhase.CANCELLED; cause = "cancelled" }
                "error" -> { phase = DraftStreamPhase.FAILED; cause = message.code!! }
                else -> return fail("invalid_message")
            }
        }
        lastProgress = now.monotonicMillis
        return if (!terminal()) propagate() else DraftResult()
    }

    fun binary(direction: DraftDirection?, bytes: ByteArray, now: DraftClock): DraftResult {
        preflight(now)?.let { return DraftResult(it) }
        if (direction == null || !ready || bytes.isEmpty() || bytes.size > owner.limits.maxFrameBytes || sealed[direction.ordinal]) return fail("invalid_message")
        val count = bytes.size.toLong()
        if (frames >= owner.limits.maxQueuedFramesPerStream || count > owner.limits.maxQueuedBytesPerStream - charged || !owner.reserve(count)) return DraftResult("backpressure")
        queues[direction.ordinal].add(Chunk(bytes.copyOf()))
        charged += count; directionBytes[direction.ordinal] += count; frames++
        lastProgress = now.monotonicMillis
        return DraftResult()
    }

    fun peek(direction: DraftDirection?, count: Int, now: DraftClock): DraftPeek {
        preflight(now)?.let { return DraftPeek(DraftResult(it)) }
        if (direction == null || count < 1 || count > owner.limits.maxFrameBytes) return DraftPeek(fail("invalid_message"))
        val size = minOf(count.toLong(), directionBytes[direction.ordinal]).toInt()
        val result = ByteArray(size)
        var offset = 0
        for (chunk in queues[direction.ordinal]) {
            val copied = minOf(size - offset, chunk.bytes.size - chunk.offset)
            chunk.bytes.copyInto(result, offset, chunk.offset, chunk.offset + copied)
            offset += copied
            if (offset == size) break
        }
        return DraftPeek(DraftResult(), result)
    }

    fun drain(direction: DraftDirection?, count: Long, now: DraftClock): DraftResult {
        preflight(now)?.let { return DraftResult(it) }
        if (direction == null || count < 1 || count > directionBytes[direction.ordinal] || !ready) return fail("invalid_message")
        var remaining = count
        val queue = queues[direction.ordinal]
        while (remaining > 0) {
            val chunk = queue.first
            val consumed = minOf(remaining, (chunk.bytes.size - chunk.offset).toLong()).toInt()
            chunk.offset += consumed; remaining -= consumed
            if (chunk.offset == chunk.bytes.size) { queue.removeFirst(); frames-- }
        }
        charged -= count; directionBytes[direction.ordinal] -= count; owner.release(count)
        lastProgress = now.monotonicMillis
        return propagate()
    }

    fun cancelLocally(now: DraftClock): DraftResult {
        preflight(now, allowClosedSocket = true)?.let { return DraftResult(it) }
        phase = DraftStreamPhase.CANCELLED; cause = "cancelled"
        return DraftResult()
    }
    fun webSocketClosed(code: Int, now: DraftClock): DraftResult {
        val time = owner.observe(now)
        if (code !in 1000..4999) return DraftResult(time ?: if (terminal()) "invalid_message" else fail("invalid_message").code)
        if (wsClosedCode != null) {
            if (time != null) return DraftResult(time)
            if (wsClosedCode == code) return DraftResult()
            return if (terminal()) DraftResult("invalid_message") else fail("network_unreachable")
        }
        wsClosedCode = code
        if (time != null) return DraftResult(time)
        if (terminal()) return DraftResult()
        checkDeadline(now.monotonicMillis)?.let { return DraftResult(it) }
        if (code != 1000 || phase != DraftStreamPhase.CLOSING) return fail("network_unreachable")
        return DraftResult()
    }
    fun confirmClosed(now: DraftClock): DraftResult {
        val time = owner.observe(now) ?: checkDeadline(now.monotonicMillis)
        if (!terminal()) {
            if (wsClosedCode == 1000 && phase == DraftStreamPhase.CLOSING) phase = DraftStreamPhase.COMPLETE
            else invalidate("network_unreachable", false)
        }
        if (wsClosedCode == null) wsClosedCode = 1006
        if (!closure) {
            closure = true
            owner.release(charged); charged = 0; directionBytes.fill(0); frames = 0
            queues.forEach { it.clear() }
            if (lease) { lease = false; owner.release(this) }
        }
        return DraftResult(time ?: "ok")
    }
    fun tick(now: DraftClock): DraftResult {
        val time = owner.observe(now) ?: checkDeadline(now.monotonicMillis)
        return DraftResult(time ?: "ok")
    }

    internal fun invalidate(code: String, cancelled: Boolean) {
        if (!terminal()) { phase = if (cancelled) DraftStreamPhase.CANCELLED else DraftStreamPhase.FAILED; cause = code }
    }
    internal fun checkDeadline(monotonic: Long): String? {
        if (terminal()) return null
        if ((!ready && monotonic - createdMono >= 15000) || (ready && monotonic - lastProgress >= 60000)) {
            invalidate("network_unreachable", false)
            return "network_unreachable"
        }
        return null
    }
    private fun terminal() = phase in setOf(DraftStreamPhase.COMPLETE, DraftStreamPhase.CANCELLED, DraftStreamPhase.FAILED)
    private fun preflight(now: DraftClock, allowClosedSocket: Boolean = false): String? {
        val wasTerminal = terminal()
        val time = owner.observe(now)
        if (wasTerminal) return "invalid_message"
        if (time != null) return time
        if (owner.terminal()) { invalidate(owner.inactiveCause(), false); return owner.inactiveCause() }
        checkDeadline(now.monotonicMillis)?.let { return it }
        if (!allowClosedSocket && wsClosedCode != null) { invalidate("invalid_message", false); return "invalid_message" }
        return null
    }
    private fun fail(code: String): DraftResult { invalidate(code, false); return DraftResult(code) }
    private fun propagate(): DraftResult {
        val effects = ArrayList<DraftDirection>(2)
        for (direction in DraftDirection.entries) {
            val index = direction.ordinal
            if (sealed[index] && !eof[index] && directionBytes[index] == 0L) { eof[index] = true; effects.add(direction) }
        }
        phase = when {
            sealed.all { it } && charged > 0 -> DraftStreamPhase.DRAINING
            eof.all { it } -> DraftStreamPhase.CLOSING
            sealed.any { it } -> DraftStreamPhase.HALF_CLOSED
            ready -> DraftStreamPhase.OPEN
            else -> phase
        }
        return DraftResult(eofDirections = effects)
    }
}
