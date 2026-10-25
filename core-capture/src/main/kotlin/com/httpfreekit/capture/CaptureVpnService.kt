package com.httpfreekit.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import java.net.DatagramSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Ownership transfers to the service after captureRequest returns successfully. */
class CaptureStartRequest(selectedPackages: Set<String>, val intercepted: InterceptedTcpFactory) {
    val selectedPackages: Set<String> = Collections.unmodifiableSet(LinkedHashSet(selectedPackages))
    override fun toString(): String = "CaptureStartRequest([REDACTED])"
}

class CaptureServiceSnapshot(
    val state: String,
    val tunEstablished: Boolean,
    val selectedPackageCount: Int,
    val underlyingNetworkPresent: Boolean,
    val lifecycleThreadAlive: Boolean,
    val capture: CaptureSnapshot?,
    val failureCode: String?,
) {
    override fun toString(): String = "CaptureServiceSnapshot([REDACTED])"
}

/** Shared platform lifecycle. Concrete apps supply consent UI and a trusted transport factory. */
abstract class CaptureVpnService : VpnService() {
    private enum class Command { START, FAIL_CLOSED, STOP }
    private val commands = ArrayBlockingQueue<Command>(4)
    private val startQueued = AtomicBoolean()
    private val failureQueued = AtomicBoolean()
    private val stopQueued = AtomicBoolean()
    private val workerStarted = AtomicBoolean()
    private val worker = Thread(::runLifecycle, "freekit-capture-lifecycle")
    @Volatile private var state = "idle"
    @Volatile private var failureCode: String? = null
    @Volatile private var established = false
    @Volatile private var selectedCount = 0
    @Volatile private var networkPresent = false
    @Volatile private var owner: CaptureEngineSession? = null
    @Volatile private var lastCapture: CaptureSnapshot? = null
    @Volatile private var underlying: Network? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var startupRequest: CaptureStartRequest? = null
    private var startupEgress: ProtectedEgressFactory? = null
    private var startupTun: ParcelFileDescriptor? = null

    protected abstract fun captureRequest(network: Network, guard: CaptureSocketGuard): CaptureStartRequest
    protected open fun onCaptureStateChanged(snapshot: CaptureServiceSnapshot) = Unit

    protected open fun socketGuard(network: Network): CaptureSocketGuard = object : CaptureSocketGuard {
        override fun protect(socket: Socket): Boolean = this@CaptureVpnService.protect(socket)
        override fun protect(socket: DatagramSocket): Boolean = this@CaptureVpnService.protect(socket)
        override fun bind(socket: Socket) = network.bindSocket(socket)
        override fun bind(socket: DatagramSocket) = network.bindSocket(socket)
    }

    fun captureSnapshot(): CaptureServiceSnapshot = CaptureServiceSnapshot(
        state, established, selectedCount, networkPresent, worker.isAlive, owner?.snapshot() ?: lastCapture, failureCode,
    )
    fun localSocksPort(): Int = owner?.localSocksPort() ?: 0

    /** Invoke away from the main thread. The return value observes an actual lifecycle thread join. */
    fun awaitStopped(timeoutMillis: Long): Boolean {
        require(timeoutMillis in 1..30_000 && Thread.currentThread() !== worker) { "Invalid capture join" }
        if (workerStarted.get()) worker.join(timeoutMillis)
        return !worker.isAlive && state == "stopped" && !established
    }

    final override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                if (startQueued.compareAndSet(false, true)) {
                    try { foreground("Starting selected-app capture") }
                    catch (_: RuntimeException) { failureCode = "foreground_unavailable"; state = "failed"; enqueueStop(); return START_NOT_STICKY }
                    enqueue(Command.START)
                }
            }
            ACTION_STOP -> enqueueStop()
            else -> enqueueStop()
        }
        return START_NOT_STICKY
    }

    final override fun onRevoke() { enqueueStop() }

    final override fun onDestroy() {
        enqueueStop()
        super.onDestroy()
    }

    private fun enqueueStop() {
        if (stopQueued.compareAndSet(false, true)) enqueue(Command.STOP)
    }

    private fun enqueue(command: Command) {
        // At most one command of each kind is queued. STOP therefore has reserved capacity.
        check(commands.offer(command)) { "Capture lifecycle admission failed" }
        if (workerStarted.compareAndSet(false, true)) worker.start()
    }

    private fun publish(next: String) {
        state = next
        lastCapture = owner?.snapshot() ?: lastCapture
        try { onCaptureStateChanged(captureSnapshot()) } catch (_: RuntimeException) { /* Observer owns no I/O. */ }
    }

    private fun runLifecycle() {
        while (true) {
            when (commands.poll(100, TimeUnit.MILLISECONDS)) {
                Command.START -> if (!stopQueued.get()) startCapture()
                Command.FAIL_CLOSED -> {
                    try { owner?.failClosed(); publish("disconnected") }
                    catch (_: Exception) { publish("failed") }
                    try { foreground("Capture disconnected; Stop restores networking") } catch (_: RuntimeException) { }
                }
                Command.STOP -> {
                    if (stopCapture()) return
                    // The unresolved owner/descriptor remain retained. A later Stop may observe its join.
                    stopQueued.set(false)
                }
                null -> if (state == "active") {
                    val current = owner?.snapshot()
                    if (current == null || current.failed || !current.nativeRunning || current.admissionClosed) {
                        failureCode = "capture_runtime_failed"
                        try { owner?.failClosed(); publish("disconnected") }
                        catch (_: Exception) { publish("failed") }
                        try { foreground("Capture disconnected; Stop restores networking") } catch (_: RuntimeException) { }
                    }
                }
            }
        }
    }

    private fun startCapture() {
        publish("starting")
        try {
            if (prepare(this) != null) { failureCode = "consent_required"; error("VPN consent is required") }
            if (Build.VERSION.SDK_INT >= 37) {
                if (checkSelfPermission(android.Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) {
                    failureCode = "local_network_permission"; error("Local network permission is required")
                }
            }
            val manager = getSystemService(ConnectivityManager::class.java)
            fun suitable(network: Network): Boolean = manager.getNetworkCapabilities(network)?.let {
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            } == true
            val network = manager.activeNetwork?.takeIf(::suitable) ?: manager.allNetworks.firstOrNull(::suitable)
                ?: error("Underlying network unavailable")
            underlying = network; networkPresent = true
            val guard = socketGuard(network)
            val request = captureRequest(network, guard).also { startupRequest = it }
            val selected = request.selectedPackages
            check(selected.isNotEmpty() && selected.size <= 64 && packageName !in selected) { "Invalid capture app selection" }
            val builder = Builder().setSession("HTTP FreeKit").setMtu(1500).setBlocking(false)
                .addAddress("198.18.0.1", 32).addAddress("fd00:6672:6565::1", 128)
                .addRoute("0.0.0.0", 0).addRoute("::", 0).setUnderlyingNetworks(arrayOf(network))
            selected.sorted().forEach { name ->
                check(Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+").matches(name)) { "Invalid capture package" }
                // addAllowedApplication checks installed identity; a missing app fails the whole request.
                builder.addAllowedApplication(name)
            }
            selectedCount = selected.size
            val dns = manager.getLinkProperties(network)?.dnsServers.orEmpty()
            check(dns.isNotEmpty()) { "Underlying DNS unavailable" }
            dns.forEach(builder::addDnsServer)
            val configDirectory = noBackupFilesDir.canonicalFile.resolve("capture-engine")
            if (!configDirectory.exists()) {
                check(configDirectory.mkdir()) { "Capture configuration directory unavailable" }
                Os.chmod(configDirectory.path, 448)
            }
            check(configDirectory.isDirectory && configDirectory.canonicalFile == configDirectory.absoluteFile) { "Invalid capture configuration directory" }
            val directoryStat = Os.lstat(configDirectory.path)
            check(directoryStat.st_uid == android.os.Process.myUid() && directoryStat.st_mode and 63 == 0) { "Capture configuration directory is not private" }
            val egress = ProtectedEgressFactory(guard).also { startupEgress = it }
            check(!stopQueued.get()) { "Capture start cancelled" }
            val tun = checkNotNull(builder.establish()) { "VPN interface unavailable" }.also { startupTun = it }
            established = true
            val retained = CaptureEngineSession(tun, selected, request.intercepted, egress,
                configDirectory)
            owner = retained
            startupTun = null; startupRequest = null; startupEgress = null
            retained.start()
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onLost(network: Network) {
                    if (network == underlying && !stopQueued.get()) {
                        networkPresent = false
                        failureCode = "network_lost"
                        if (failureQueued.compareAndSet(false, true)) enqueue(Command.FAIL_CLOSED)
                    }
                }
            }
            networkCallback = callback
            manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
            // Registration does not retrospectively deliver a loss before it was registered.
            check(suitable(network)) { "Underlying network lost during start" }
            if (!stopQueued.get()) { publish("active"); foreground("Capturing selected apps") }
        } catch (_: Exception) { failedStart() }
        catch (_: LinkageError) { failedStart() }
    }

    private fun failedStart() {
        if (failureCode == null) failureCode = "capture_start_failed"
        // A retained owner or newly established TUN keeps the route while capture remains requested.
        if (owner != null) {
            try { owner?.failClosed() } catch (_: Exception) { } catch (_: LinkageError) { }
        } else {
            try { closeStartup(releaseTun = false) } catch (_: Exception) { }
        }
        publish("failed")
        try { foreground("Capture unavailable; use Stop") } catch (_: RuntimeException) { }
    }

    private fun stopCapture(): Boolean {
        publish("stopping")
        var failed = false
        try {
            networkCallback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
            networkCallback = null
        } catch (_: IllegalArgumentException) {
            // Android reports this owned callback was never registered or is already removed.
            networkCallback = null
        } catch (_: Exception) { failed = true }
        try {
            owner?.close()
            lastCapture = owner?.snapshot() ?: lastCapture
            owner = null
        } catch (_: Exception) { failed = true }
        try { closeStartup() } catch (_: Exception) { failed = true }
        if (failed) {
            failureCode = "capture_cleanup_failed"
            publish("failed")
            try { foreground("Capture cleanup pending; use Stop") } catch (_: RuntimeException) { }
            return false
        }
        try {
            established = false; networkPresent = false; underlying = null
            publish("stopped")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return true
        } catch (_: Exception) {
            failureCode = "capture_cleanup_failed"
            publish("failed")
            try { foreground("Capture cleanup pending; use Stop") } catch (_: RuntimeException) { }
            return false
        }
    }

    private fun closeStartup(releaseTun: Boolean = true) {
        var failed = false
        try { startupRequest?.intercepted?.close(); startupRequest = null } catch (_: Exception) { failed = true }
        try { startupEgress?.close(); startupEgress = null } catch (_: Exception) { failed = true }
        // No native call can have started while startupTun is retained here.
        try {
            if (releaseTun) { startupTun?.close(); startupTun = null }
            if (owner == null && startupTun == null) established = false
        } catch (_: Exception) { failed = true }
        check(!failed) { "Capture startup cleanup pending" }
    }

    private fun foreground(text: String) {
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(NotificationChannel(CHANNEL, "Selected-app capture", NotificationManager.IMPORTANCE_LOW))
        val stop = PendingIntent.getService(this, 0, Intent(this, javaClass).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("HTTP FreeKit").setContentText(text).setOngoing(true)
            .addAction(Notification.Action.Builder(android.graphics.drawable.Icon.createWithResource(this,
                android.R.drawable.ic_menu_close_clear_cancel), "Stop", stop).build()).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(NOTIFICATION, notification)
    }

    companion object {
        const val ACTION_START = "com.httpfreekit.capture.START"
        const val ACTION_STOP = "com.httpfreekit.capture.STOP"
        private const val CHANNEL = "freekit-capture"
        private const val NOTIFICATION = 6201
    }
}
