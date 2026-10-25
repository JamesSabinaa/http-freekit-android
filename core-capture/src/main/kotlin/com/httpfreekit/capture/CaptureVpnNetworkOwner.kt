package com.httpfreekit.capture

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Process
import java.net.NetworkInterface

/** Owns framework observations only; availability/loss never attests a netd routing transaction join. */
class CaptureVpnNetworkOwner(private val manager: ConnectivityManager) : AutoCloseable {
    private val events = Object()
    private val tracker = CaptureVpnFrameworkTracker<Network>()
    private val links = LinkedHashMap<Network, CaptureVpnLinkObservation>()
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = event { tracker.available(network) }
        override fun onLost(network: Network) = event { tracker.lost(network) }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            try { val matches = capabilitiesMatch(capabilities); event { tracker.capabilities(network, matches) } }
            catch (_: Exception) { event { tracker.failed() } }
        }
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            try {
                val received = copyLinks(linkProperties)
                event {
                    val copy = received.refreshed(links[network])
                    tracker.links(network, copy.matches())
                    if (tracker.records(network)) links[network] = copy
                }
            }
            catch (_: Exception) { event { tracker.failed() } }
        }
    }
    private val registration = CaptureVpnRegistration(
        register = {
            val request = NetworkRequest.Builder().removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            if (Build.VERSION.SDK_INT >= 31) request.setIncludeOtherUidNetworks(true)
            manager.registerNetworkCallback(request.build(), callback)
        },
        unregister = {
            try { manager.unregisterNetworkCallback(callback) }
            catch (_: IllegalArgumentException) { /* Android reports this callback is already absent. */ }
        },
    )

    /** Retain this owner before invoking this fallible operation, and invoke before Builder.establish. */
    fun prepare() {
        try {
            synchronized(events) { tracker.checkOpen() }
            val prior = manager.allNetworks.toList()
            synchronized(events) { tracker.begin(prior) }
            registration.prepare()
            val afterRegistration = manager.allNetworks.toList()
            synchronized(events) { tracker.prepared(afterRegistration) }
        } catch (failure: CaptureException) { event { tracker.failed() }; throw failure }
        catch (_: Exception) { event { tracker.failed() }; throw CaptureException("connect_failed") }
    }

    fun awaitReady(timeoutMillis: Long, cancelled: () -> Boolean) {
        try {
            awaitCaptureVpnFramework(timeoutMillis, cancelled, ready = {
                val candidates = synchronized(events) {
                    tracker.checkOpen(); tracker.availableKeys().associateWith { links[it] }
                }
                // Public API26 connection status is queried outside callbacks and the event lock.
                val observations = candidates.map { (network, copy) ->
                    Triple(network, manager.getNetworkInfo(network)?.isConnected == true,
                        copy?.observed { NetworkInterface.getByName(it)?.mtu })
                }
                synchronized(events) {
                    observations.forEach { (network, connected, observed) ->
                        if (links[network] === candidates[network] && tracker.records(network)) {
                            if (observed != null) links[network] = observed
                            tracker.links(network, observed?.matches() == true)
                        }
                        tracker.connected(network, connected)
                    }
                    tracker.acceptReady()
                }
            }, pause = ::pause)
        } catch (failure: CaptureException) { event { tracker.failed() }; throw failure }
        catch (_: InterruptedException) { event { tracker.failed() }; Thread.currentThread().interrupt(); throw CaptureException("closed") }
        catch (_: Exception) { event { tracker.failed() }; throw CaptureException("connect_failed") }
    }

    /** Inert: no clock read, framework query, registration, or admission change. */
    fun isReady(): Boolean = synchronized(events) { tracker.isReady() }

    /** Invoke only after actual TUN closure. A never-observed future agent is not an attested loss. */
    fun awaitRemoved(timeoutMillis: Long) {
        try {
            awaitCaptureVpnFramework(timeoutMillis, { false }, ready = {
                synchronized(events) { tracker.checkUnsealed() }
                val current = manager.allNetworks.toSet()
                // Failed startup may have no accepted handle. Retain any new matching observed generation.
                var newMatchingPresent = false
                for (network in if (synchronized(events) { tracker.hasAccepted() }) emptySet() else current) {
                    if (synchronized(events) { tracker.isPrior(network) }) continue
                    val capabilities = manager.getNetworkCapabilities(network)
                    val properties = manager.getLinkProperties(network)
                    // After TUN closure its MTU query may be unavailable. Conservatively retain a new
                    // matching address/route candidate; this never grants readiness without actual MTU.
                    if (capabilities != null && properties != null && capabilitiesMatch(capabilities) && copyLinks(properties).shape) {
                        newMatchingPresent = true
                        synchronized(events) { tracker.queryMatching(network) }
                    }
                }
                synchronized(events) { tracker.removed(current, newMatchingPresent) }
            }, pause = ::pause)
        } catch (failure: CaptureException) { throw failure }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); throw CaptureException("closed") }
        catch (_: Exception) { throw CaptureException("connect_failed") }
    }

    override fun close() {
        event { tracker.seal(); links.clear() }
        try { registration.close() } catch (_: Exception) { throw CaptureException("cleanup_failed") }
    }
    private fun event(action: () -> Unit) = synchronized(events) { action(); events.notifyAll() }
    private fun pause(millis: Long) = synchronized(events) { events.wait(millis) }
    private fun capabilitiesMatch(capabilities: NetworkCapabilities): Boolean =
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            (Build.VERSION.SDK_INT < 30 || capabilities.ownerUid == Process.myUid())
    private fun copyLinks(properties: LinkProperties): CaptureVpnLinkObservation {
        val addresses = properties.linkAddresses
        val defaults = properties.routes.filter { it.isDefaultRoute }
        val shape = addresses.size == 2 && captureVpnAddressesAndRoutesMatch(
            addresses.map { it.address.address.copyOf() to it.prefixLength },
            defaults.any { it.destination.address.address.size == 4 }, defaults.any { it.destination.address.address.size == 16 })
        return CaptureVpnLinkObservation(shape, if (Build.VERSION.SDK_INT >= 29) properties.mtu else null, properties.interfaceName)
    }
    override fun toString() = "CaptureVpnNetworkOwner([REDACTED])"
}
