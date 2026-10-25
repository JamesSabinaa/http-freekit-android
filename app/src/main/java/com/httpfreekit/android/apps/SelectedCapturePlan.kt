package com.httpfreekit.android.apps

import java.util.Collections

/**
 * Inert local selection snapshot, not a running capture or a readiness assertion.
 * Packages may subsequently disappear: platform package revalidation, VPN consent,
 * trusted transport and target-app certificate trust are still required before capture.
 * Retains no inventory, labels, resources or credentials and makes no freshness claim.
 */
class SelectedCapturePlan internal constructor(selectedPackages: Set<String>) {
    val selectedPackages: Set<String> = Collections.unmodifiableSet(LinkedHashSet(selectedPackages))
    val policy: SelectedCapturePolicy = SelectedCapturePolicy.TCP_80_443_REFUSE_UDP_443

    override fun toString() = "SelectedCapturePlan([REDACTED])"
}

/** Fixed description of the existing capture policy; not a routing engine or wire capability. */
enum class SelectedCapturePolicy {
    TCP_80_443_REFUSE_UDP_443;

    val interceptedTcpPorts: Set<Int> = Collections.unmodifiableSet(linkedSetOf(80, 443))
    val refusedUdpPorts: Set<Int> = Collections.unmodifiableSet(linkedSetOf(443))
    val interceptedDirectFallbackAllowed: Boolean get() = false
}
