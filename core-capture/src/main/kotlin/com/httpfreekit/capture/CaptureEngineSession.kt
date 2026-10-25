package com.httpfreekit.capture

import android.os.ParcelFileDescriptor
import android.system.Os
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicBoolean

data class CaptureSnapshot(
    val started: Boolean, val admissionClosed: Boolean, val nativeRunning: Boolean, val nativeStopJoined: Boolean,
    val tunClosed: Boolean, val configurationPresent: Boolean, val activeFlows: Int, val ownedSockets: Int,
    val liveWorkers: Int, val pendingOpens: Int, val interceptedTcpFlows: Int, val directTcpFlows: Int,
    val udpTargets: Int, val udp443Drops: Int, val protectFailures: Int, val bindFailures: Int, val failed: Boolean,
)

/** Construct and retain this owner before start. An unresolved Stop never closes or forgets its TUN. */
class CaptureEngineSession internal constructor(
    private val tun: CaptureTun, selectedPackages: Set<String>, private val intercepted: InterceptedTcpFactory,
    private val egress: ProtectedEgressFactory, private val config: CaptureConfiguration,
    private val nativeFactory: () -> CaptureNative,
) : AutoCloseable {
    constructor(tun: ParcelFileDescriptor, selectedPackages: Set<String>, intercepted: InterceptedTcpFactory,
        egress: ProtectedEgressFactory, privateConfigDirectory: File) : this(AndroidCaptureTun(tun), selectedPackages,
        intercepted, egress, PrivateCaptureConfiguration(privateConfigDirectory), { AndroidCaptureNative() })

    private val state = Any()
    private val teardown = Any()
    private val selection = selectedPackages.toSet()
    private var policy: CapturePolicyServer? = null
    private var native: CaptureNative? = null
    private var nativeMayOwn = false
    private var started = false
    private var stopping = false
    private var tunClosed = false
    @Volatile private var nativeJoined = false
    private var closed = false
    private val failure = AtomicBoolean()
    private var watch: Thread? = null
    private var safetyStop: Thread? = null
    private val stops = ArrayList<StopWork>()
    init {
        if (selection.isEmpty() || selection.size > 64 || selection.any { !Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+").matches(it) }) throw CaptureException("invalid_request")
    }

    fun start() {
        synchronized(state) {
            if (started || stopping || closed) throw CaptureException("closed")
            synchronized(nativeLease) {
                if (active != null && active !== this) throw CaptureException("capacity")
                active = this
            }
            try {
                val server = CapturePolicyServer(intercepted, egress).also { policy = it }
                config.write(server.configuration())
                val engine = nativeFactory().also { native = it }
                server.start()
                nativeMayOwn = true
                if (!engine.start(config.path(), tun.descriptor())) throw CaptureException("native_failed")
                started = true
                watch = Thread({
                    try {
                        while (!synchronized(state) { stopping }) {
                            if (!engine.running() || server.facts().failed) {
                                requestSafetyStop()
                                break
                            }
                            Thread.sleep(25)
                        }
                    } catch (_: InterruptedException) { /* Stop owns and joins this watcher. */ }
                    catch (_: Exception) { requestSafetyStop() }
                }, "capture-engine-watch").apply { isDaemon = true; start() }
            } catch (_: Exception) { failure.set(true) }
            catch (_: LinkageError) { failure.set(true) }
        }
        if (failure.get()) { failClosed(); throw CaptureException("native_failed") }
    }

    /** Preserve the established route while denying traffic after failure or network loss. */
    fun failClosed() {
        stopOwnedIo()
        val safety = synchronized(state) { safetyStop }
        if (safety != null && safety !== Thread.currentThread()) join(safety, System.nanoTime() + 10_000_000_000)
    }
    private fun requestSafetyStop() = synchronized(state) {
        if (!stopping && safetyStop == null) {
            failure.set(true)
            safetyStop = Thread({
                try { stopOwnedIo() } catch (_: Exception) { /* Retain every unjoined resource and route. */ }
            }, "capture-failure-stop").apply { isDaemon = true; start() }
        }
    }
    private fun stopOwnedIo() = synchronized(teardown) {
        synchronized(state) {
            stopping = true
            policy?.sealAdmission()
            if (stops.isEmpty()) {
                fun work(name: String, action: () -> Unit) {
                    val item = StopWork(name, action); stops.add(item)
                    try { item.thread.start() } catch (_: Exception) { failure.set(true) }
                }
                work("capture-stop-local") { policy?.interrupt() }
                work("capture-stop-egress") { egress.close() }
                work("capture-stop-intercept") { intercepted.close(); policy?.factoryClosed() }
                work("capture-stop-native") {
                    if (nativeMayOwn && native?.stop() != true) throw CaptureException("native_failed")
                }
            }
            if (watch !== Thread.currentThread()) watch?.interrupt()
        }
        val deadline = System.nanoTime() + 10_000_000_000
        for (item in stops) join(item.thread, deadline)
        val nativeStop = stops.single { it.thread.name == "capture-stop-native" }
        nativeJoined = nativeStop.succeeded.get() && !nativeStop.thread.isAlive
        if (stops.any { !it.succeeded.get() || it.thread.isAlive }) throw CaptureException("cleanup_failed")
        policy?.join(deadline)
        val currentWatch = synchronized(state) { watch }
        if (currentWatch != null && currentWatch !== Thread.currentThread()) join(currentWatch, deadline)
        if (egress.pendingOpens() != 0 || egress.budget.count() != 0) throw CaptureException("cleanup_failed")
        config.remove()
        policy?.destroySecrets()
    }

    override fun close() {
        failClosed()
        synchronized(state) {
            if (!closed) {
                try { tun.close() } catch (_: Exception) { failure.set(true); throw CaptureException("cleanup_failed") }
                tunClosed = true; closed = true
                synchronized(nativeLease) { if (active === this) active = null }
            }
        }
    }
    fun localSocksPort(): Int = synchronized(state) { policy?.port ?: 0 }
    fun snapshot(): CaptureSnapshot = synchronized(state) {
        val facts = policy?.facts()
        val running = if (nativeMayOwn) try { native?.running() == true } catch (_: Exception) { false } else false
        CaptureSnapshot(started, stopping || closed, running, nativeJoined, tunClosed, config.present(), facts?.flows ?: 0,
            egress.budget.count(), (facts?.workers ?: 0) + stops.count { it.thread.isAlive } + (if (watch?.isAlive == true) 1 else 0) + (if (safetyStop?.isAlive == true) 1 else 0),
            (facts?.pending ?: 0) + egress.pendingOpens(), facts?.intercepted ?: 0, facts?.direct ?: 0, facts?.udp ?: 0,
            facts?.drops ?: 0, egress.protectFailures, egress.bindFailures, failure.get() || facts?.failed == true)
    }
    override fun toString() = "CaptureEngineSession([REDACTED])"

    private fun join(thread: Thread, deadline: Long) {
        val remaining = deadline - System.nanoTime()
        if (remaining > 0) thread.join(maxOf(1, remaining / 1_000_000))
        if (thread.isAlive) throw CaptureException("cleanup_failed")
    }
    private class StopWork(name: String, action: () -> Unit) {
        val succeeded = AtomicBoolean()
        val thread = Thread({ try { action(); succeeded.set(true) } catch (_: Exception) { /* A failed operation never attests closure. */ } }, name).apply { isDaemon = true }
    }
    companion object {
        private val nativeLease = Any()
        private var active: CaptureEngineSession? = null
    }
}

internal interface CaptureTun : AutoCloseable { fun descriptor(): Int }
internal interface CaptureNative { fun start(path: String, descriptor: Int): Boolean; fun stop(): Boolean; fun running(): Boolean }
internal interface CaptureConfiguration { fun write(contents: String); fun path(): String; fun present(): Boolean; fun remove() }
private class AndroidCaptureTun(private val descriptor: ParcelFileDescriptor) : CaptureTun {
    override fun descriptor() = descriptor.fd
    override fun close() = descriptor.close()
}
private class AndroidCaptureNative : CaptureNative {
    private val engine = NativeEngine()
    override fun start(path: String, descriptor: Int) = engine.TProxyStartService(path, descriptor)
    override fun stop() = engine.TProxyStopService()
    override fun running() = engine.TProxyIsRunning()
}
private class PrivateCaptureConfiguration(private val directory: File) : CaptureConfiguration {
    private var file: File? = null
    override fun write(contents: String) {
        if (file != null || directory.canonicalFile != directory.absoluteFile || !directory.isDirectory) throw CaptureException("invalid_request")
        val stat = Os.lstat(directory.path)
        if (stat.st_uid != android.os.Process.myUid() || stat.st_mode and 63 != 0) throw CaptureException("invalid_request")
        val created = Files.createTempFile(directory.toPath(), "capture-", ".yaml").toFile().also { file = it }
        Os.chmod(created.path, 384)
        FileOutputStream(created).use { output -> output.write(contents.toByteArray(Charsets.US_ASCII)); output.fd.sync() }
    }
    override fun path(): String = file?.path ?: throw CaptureException("invalid_request")
    override fun present() = file?.exists() == true
    override fun remove() { file?.let { if (it.exists() && !it.delete()) throw CaptureException("cleanup_failed") } }
}
