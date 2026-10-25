package com.httpfreekit.capture

/** Caller serializes events. Keys stay private and are never rendered in diagnostics. */
internal class CaptureVpnFrameworkTracker<K : Any> {
    private class Entry {
        var available = false
        var lost = false
        var capabilities = false
        var links = false
        var connected = false
        var matched = false
        fun ready() = available && !lost && capabilities && links && connected
    }
    private val entries = LinkedHashMap<K, Entry>()
    private val prior = HashSet<K>()
    private var begun = false
    private var prepared = false
    private var closed = false
    private var failure: String? = null
    private var accepted: K? = null

    fun begin(priorKeys: Collection<K>) {
        checkOpen()
        if (begun) throw CaptureException("invalid_request")
        begun = true
        addPrior(priorKeys)
        checkOpen()
    }
    fun prepared(priorKeys: Collection<K>) {
        checkOpen()
        if (!begun || prepared) throw CaptureException("invalid_request")
        // Anything observed before establish is ineligible, including callbacks racing registration.
        addPrior(priorKeys + entries.keys)
        checkOpen(); prepared = true
    }
    private fun addPrior(keys: Collection<K>) { keys.forEach { if (entry(it) != null) prior.add(it) } }
    private fun entry(key: K): Entry? {
        if (closed) return null
        entries[key]?.let { return it }
        if (entries.size == 16) { failure = "capacity"; return null }
        return Entry().also { entries[key] = it }
    }
    fun available(key: K) {
        entry(key)?.let {
            if (it.lost) failure = "invalid_request" else it.available = true
        }
        validate()
    }
    fun capabilities(key: K, matches: Boolean) { entry(key)?.capabilities = matches; validate() }
    fun links(key: K, matches: Boolean) { entry(key)?.links = matches; validate() }
    fun connected(key: K, connected: Boolean) { if (!closed) entries[key]?.connected = connected; validate() }
    fun queryMatching(key: K) { entry(key)?.matched = true }
    fun lost(key: K) { entry(key)?.let { it.lost = true; it.available = false; it.connected = false } }
    fun failed() { if (!closed && failure == null) failure = "connect_failed" }
    private fun validate() {
        entries.values.forEach { if (it.capabilities && it.links) it.matched = true }
        if (!prepared || closed) return
        val matches = entries.filter { (key, value) -> key !in prior && value.ready() }
        if (matches.size > 1) failure = "invalid_request"
    }
    fun availableKeys(): List<K> = entries.filter { (key, value) -> key !in prior && value.available && !value.lost }.keys.toList()
    fun records(key: K): Boolean = !closed && entries.containsKey(key)
    fun acceptReady(): Boolean {
        checkOpen()
        if (!prepared) throw CaptureException("invalid_request")
        validate(); checkOpen()
        if (accepted == null) accepted = entries.entries.singleOrNull { it.value.ready() && it.key !in prior }?.key
        return isReady()
    }
    fun isReady(): Boolean = !closed && failure == null && accepted?.let { entries[it]?.ready() } == true
    fun isPrior(key: K): Boolean = key in prior
    fun hasAccepted(): Boolean = accepted != null
    fun removed(current: Set<K>, newMatchingPresent: Boolean = false): Boolean {
        checkUnsealed()
        if (accepted == null && newMatchingPresent) return false
        // Failed readiness must not prevent actual cleanup observation.
        val targets = accepted?.let(::listOf) ?: entries.filter { (key, value) -> key !in prior && value.matched }.keys
        // onLost invalidates readiness, but can precede removal from the framework's network map.
        return targets.all { it !in current }
    }
    fun seal() { closed = true }
    fun checkUnsealed() { if (closed) throw CaptureException("closed") }
    fun checkOpen() { if (closed) throw CaptureException("closed"); failure?.let { throw CaptureException(it) } }
    override fun toString() = "CaptureVpnFrameworkTracker([REDACTED])"
}

/** Ownership starts before registration, and survives a failed call until unregister succeeds. */
internal class CaptureVpnRegistration(private val register: () -> Unit, private val unregister: () -> Unit) {
    private var attempted = false
    private var sealed = false
    private var owned = false
    @Synchronized fun prepare() {
        if (sealed) throw CaptureException("closed")
        if (attempted) throw CaptureException("invalid_request")
        attempted = true; owned = true
        register()
    }
    @Synchronized fun close() {
        sealed = true
        if (owned) { unregister(); owned = false }
    }
}

internal fun awaitCaptureVpnFramework(timeoutMillis: Long, cancelled: () -> Boolean, ready: () -> Boolean,
    pause: (Long) -> Unit, now: () -> Long = System::nanoTime) {
    if (timeoutMillis !in 1..30000) throw CaptureException("invalid_request")
    val start = now()
    while (true) {
        if (cancelled()) throw CaptureException("closed")
        val elapsed = now() - start
        if (elapsed < 0 || elapsed >= timeoutMillis * 1_000_000) throw CaptureException("connect_failed")
        val complete = ready()
        if (cancelled()) throw CaptureException("closed")
        val after = now() - start
        if (after < 0 || after >= timeoutMillis * 1_000_000) throw CaptureException("connect_failed")
        if (complete) return
        pause(minOf(25, maxOf(1, timeoutMillis - after / 1_000_000)))
    }
}

/** Only immutable booleans are retained after extracting these public LinkProperties values. */
internal fun captureVpnLinksMatch(mtu: Int, addresses: List<Pair<ByteArray, Int>>, default4: Boolean, default6: Boolean): Boolean =
    mtu == 1500 && captureVpnAddressesAndRoutesMatch(addresses, default4, default6)

internal fun captureVpnAddressesAndRoutesMatch(addresses: List<Pair<ByteArray, Int>>, default4: Boolean, default6: Boolean): Boolean =
    default4 && default6 && addresses.size == 2 &&
        addresses.any { it.second == 32 && it.first.contentEquals(byteArrayOf(198.toByte(), 18, 0, 1)) } &&
        addresses.any { it.second == 128 && it.first.contentEquals(byteArrayOf(0xfd.toByte(), 0, 0x66, 0x72, 0x65, 0x65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)) }

/** Immutable, caller-confined to one Network generation; the interface name is only an MTU query key. */
internal class CaptureVpnLinkObservation private constructor(val shape: Boolean, private val reportedMtu: Int?,
    private val interfaceName: String?, private val verifiedMtu: Boolean) {
    constructor(shape: Boolean, reportedMtu: Int?, interfaceName: String?) :
        this(shape, reportedMtu, interfaceName, reportedMtu == 1500)
    fun matches(): Boolean = shape && verifiedMtu
    fun refreshed(previous: CaptureVpnLinkObservation?): CaptureVpnLinkObservation =
        if (reportedMtu == null && shape && interfaceName != null && previous?.matches() == true &&
            previous.interfaceName == interfaceName) CaptureVpnLinkObservation(shape, null, interfaceName, true) else this
    fun observed(readMtu: (String) -> Int?): CaptureVpnLinkObservation {
        if (!shape || verifiedMtu || reportedMtu != null || interfaceName == null) return this
        val actual = try { readMtu(interfaceName) } catch (_: Exception) { null }
        return CaptureVpnLinkObservation(shape, null, interfaceName, actual == 1500)
    }
    override fun toString() = "CaptureVpnLinkObservation([REDACTED])"
}
