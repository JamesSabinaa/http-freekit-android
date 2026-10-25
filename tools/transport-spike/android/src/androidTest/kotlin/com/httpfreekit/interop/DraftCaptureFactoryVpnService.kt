package com.httpfreekit.interop

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Binder
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import com.httpfreekit.capture.CaptureSocketGuard
import java.net.DatagramSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Bound prepared service only. No Builder, TUN, native owner or foreground capture is created. */
class DraftCaptureFactoryVpnService : VpnService() {
    class GuardObservation internal constructor(
        val protectAttempts: Int, val protectSuccesses: Int, val bindAttempts: Int, val bindSuccesses: Int,
        val networkPresent: Boolean, val observerRegistered: Boolean, val observerJoined: Boolean,
        val destroyed: Boolean, val failureCode: String?,
    ) {
        override fun toString() = "FactoryGuardObservation([REDACTED])"
    }
    class LocalBinder internal constructor(private val owner: DraftCaptureFactoryVpnService) : Binder() {
        fun service(): DraftCaptureFactoryVpnService = owner
        override fun toString() = "FactoryGuardBinder([REDACTED])"
    }
    private val lock = Any()
    private val available = LinkedHashMap<Network, Boolean>()
    private var manager: ConnectivityManager? = null
    private var callbackThread: HandlerThread? = null
    private var registered = false
    private var sealed = false
    private var joined = false
    private var selected: Network? = null
    private var lost = false
    private var lossAction: (() -> Unit)? = null
    private var protectAttempts = 0
    private var protectSuccesses = 0
    private var bindAttempts = 0
    private var bindSuccesses = 0
    private var failureCode: String? = null
    private val destroyed = CountDownLatch(1)
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val action = synchronized(lock) {
                if (sealed) return
                if (!available.containsKey(network) && available.size == 16) failLocked("network_capacity")
                else { available.putIfAbsent(network, false); null }
            }
            invokeLoss(action)
        }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            val eligible = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            val action = synchronized(lock) {
                if (sealed) return
                if (!available.containsKey(network) && available.size == 16) failLocked("network_capacity")
                else {
                    available[network] = eligible
                    if (selected == network && !eligible) failLocked("network_lost") else null
                }
            }
            invokeLoss(action)
        }
        override fun onLost(network: Network) {
            val action = synchronized(lock) {
                if (sealed) return
                available.remove(network)
                if (selected == network) failLocked("network_lost") else null
            }
            invokeLoss(action)
        }
    }

    override fun onCreate() {
        super.onCreate()
        try {
            manager = checkNotNull(getSystemService(ConnectivityManager::class.java))
            val thread = HandlerThread("factory-research-network")
            callbackThread = thread // Retain before either start or registration can fail.
            thread.start()
            synchronized(lock) { registered = true }
            manager!!.registerNetworkCallback(NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback, Handler(thread.looper))
        } catch (_: Exception) { synchronized(lock) { failLocked("network_observer") } }
    }

    override fun onBind(intent: Intent): IBinder? = when (intent.action) {
        SERVICE_INTERFACE -> super.onBind(intent)
        ACTION_GUARD -> LocalBinder(this)
        else -> null
    }

    /** Callback reads stay cached; these public framework queries run only on the test caller. */
    fun awaitUnderlyingNetwork(timeoutMillis: Long = 5000): Network {
        require(timeoutMillis in 1..5000)
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            synchronized(lock) { check(!sealed && failureCode == null) { "Factory network unavailable" }; selected?.let { return it } }
            val connectivity = checkNotNull(manager) { "Factory network unavailable" }
            val active = connectivity.activeNetwork
            val capabilities = active?.let(connectivity::getNetworkCapabilities)
            if (active != null && capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                synchronized(lock) {
                    check(!sealed && failureCode == null) { "Factory network unavailable" }
                    if (available[active] == true) { selected = active; return active }
                }
            }
            Thread.sleep(25)
        }
        throw IllegalStateException("Factory network deadline")
    }

    /** Trusted nonblocking seal/interrupt only. Actual factory joins remain the caller's duty. */
    fun onNetworkLost(action: () -> Unit) {
        val invoke = synchronized(lock) {
            check(!sealed && lossAction == null) { "Factory network observer closed" }
            lossAction = action
            if (lost || failureCode != null) action else null
        }
        invokeLoss(invoke)
    }

    fun guard(): CaptureSocketGuard = object : CaptureSocketGuard {
        override fun protect(socket: Socket): Boolean = protectReal { this@DraftCaptureFactoryVpnService.protect(socket) }
        override fun protect(socket: DatagramSocket): Boolean = protectReal { this@DraftCaptureFactoryVpnService.protect(socket) }
        override fun bind(socket: Socket) = bindReal { it.bindSocket(socket) }
        override fun bind(socket: DatagramSocket) = bindReal { it.bindSocket(socket) }
        override fun toString() = "FactorySocketGuard([REDACTED])"
    }

    private fun protectReal(protect: () -> Boolean): Boolean {
        synchronized(lock) { checkLiveLocked(); protectAttempts++ }
        val success = try { protect() } catch (_: Exception) { false }
        synchronized(lock) {
            if (success) protectSuccesses++
            else if (failureCode == null) failureCode = "protect_failed"
        }
        return success
    }

    private fun bindReal(bind: (Network) -> Unit) {
        val network = synchronized(lock) { checkLiveLocked(); bindAttempts++; checkNotNull(selected) }
        try {
            bind(network)
            synchronized(lock) { checkLiveLocked(); bindSuccesses++ }
        } catch (_: Exception) {
            synchronized(lock) { if (failureCode == null) failureCode = "bind_failed" }
            throw IllegalStateException("Factory network binding failed")
        }
    }

    private fun checkLiveLocked() {
        check(!sealed && !lost && selected != null && failureCode == null) { "Factory socket guard unavailable" }
    }
    private fun failLocked(code: String): (() -> Unit)? {
        if (failureCode == null) failureCode = code
        lost = true
        return lossAction
    }
    private fun invokeLoss(action: (() -> Unit)?) {
        try { action?.invoke() } catch (_: Exception) { synchronized(lock) { if (failureCode == null) failureCode = "interrupt_failed" } }
    }

    /** Call off the main/callback thread before unbinding; a failed unregister remains owned. */
    fun closeObserver(timeoutMillis: Long = 5000): Boolean {
        require(timeoutMillis in 1..5000 && Looper.myLooper() != Looper.getMainLooper() && Thread.currentThread() !== callbackThread)
        sealObserver()
        val thread = callbackThread
        thread?.quitSafely()
        thread?.join(timeoutMillis)
        return synchronized(lock) { joined = !registered && thread?.isAlive != true; joined }
    }
    private fun sealObserver() {
        val unregister = synchronized(lock) { sealed = true; lossAction = null; available.clear(); registered }
        if (unregister) {
            try { manager?.unregisterNetworkCallback(callback); synchronized(lock) { registered = false } }
            catch (_: IllegalArgumentException) { synchronized(lock) { registered = false } }
            catch (_: Exception) { synchronized(lock) { if (failureCode == null) failureCode = "network_cleanup" } }
        }
    }
    fun snapshot(): GuardObservation = synchronized(lock) { GuardObservation(protectAttempts, protectSuccesses, bindAttempts, bindSuccesses,
        selected != null && !lost && !sealed, registered, joined, destroyed.count == 0L, failureCode) }
    fun awaitDestroyed(timeoutMillis: Long = 5000): Boolean = destroyed.await(timeoutMillis, TimeUnit.MILLISECONDS)

    override fun onRevoke() {
        val action = synchronized(lock) { if (sealed) null else failLocked("permission_revoked") }
        invokeLoss(action)
        super.onRevoke()
    }
    override fun onDestroy() {
        try { sealObserver(); callbackThread?.quitSafely(); super.onDestroy() }
        finally { destroyed.countDown() }
    }
    override fun toString() = "DraftCaptureFactoryVpnService([REDACTED])"

    companion object { const val ACTION_GUARD = "com.httpfreekit.interop.action.CAPTURE_FACTORY_GUARD" }
}
