package com.httpfreekit.capturetest

import com.httpfreekit.capture.CaptureException
import com.httpfreekit.capture.CaptureServiceSnapshot
import java.util.Collections

internal data class CaptureTrafficOutcome(val command: Int, val status: Int, val bytes: Int)

/** Failure-only inert observations; no exception text, identities, destinations or configuration. */
internal object CaptureFailure {
    val phases = setOf("setup", "platform-consent", "route-readiness", "tun-start", "local-auth-baseline", "local-auth-refusal", "selected-traffic", "nonselected-traffic",
        "udp443-positive-control", "direct-protocols", "blocked-udp443", "selected-ipv6", "held-intercepted-request", "held-fixture-cleanup", "fresh-restart-traffic",
        "protect-refusal", "bind-refusal", "final-cleanup", "actual-stop-join", "local-network-denial")
    private val checks = setOf("route_transition_count", "separate_uid", "auth_egress", "auth_guard_admission", "uid_changed", "udp_positive_control", "udp_bytes", "dns_bytes",
        "udp443_not_blocked", "policy_drop_not_observed", "ipv6_policy_admission", "stop_did_not_interrupt_before_request_deadline", "held_request_completed",
        "fixture_request_not_joined", "refused_flow_connected", "refused_socket_not_closed", "guard_order", "failure_route_not_retained", "local_network_permission",
        "start_stop_count", "previous_owner_live", "tun_not_active", "lifecycle_not_joined", "capture_snapshot_missing", "capture_resources_not_closed",
        "foreground_notification_missing", "platform_consent_missing", "consent_touch", "consent_bounds", "local_listener_missing", "missing_auth_accepted",
        "auth_negotiation", "wrong_auth_accepted", "tcp_bytes", "service_missing", "research_port", "receiver_path_count", "research_condition_timeout",
        "traffic_bind", "traffic_configure", "traffic_closed", "traffic_disconnected", "traffic_reply_timeout", "traffic_invalid_reply", "traffic_worker_not_joined",
        "traffic_reply_worker_not_joined", "receiver_port", "receiver_response_bound", "receiver_http", "receiver_length", "receiver_schema", "receiver_counter",
        "research_configuration", "research_original_tuple", "research_factory_closed", "research_factory_cleanup", "local_permission_not_denied", "denied_permission_created_capture", "denied_stop_not_joined")
    private val captureCodes = setOf("invalid_request", "capacity", "closed", "protect_failed", "bind_failed", "connect_failed", "cleanup_failed", "native_failed")
    private val failureCodes = setOf("foreground_unavailable", "capture_runtime_failed", "consent_required", "local_network_permission", "network_lost", "capture_start_failed", "capture_cleanup_failed", "vpn_framework_unavailable", "vpn_framework_cleanup_failed")
    private val roots = mapOf(
        "CapturePolicyInteropTest.kt" to "com.httpfreekit.capturetest.CapturePolicyInteropTest",
        "TrafficClient.kt" to "com.httpfreekit.capturetest.TrafficClient", "HostReceiver.kt" to "com.httpfreekit.capturetest.HostReceiver",
        "ResearchCaptureService.kt" to "com.httpfreekit.capturetest.ResearchCaptureService", "ConsentActivity.kt" to "com.httpfreekit.capturetest.ConsentActivity",
        "CaptureFailure.kt" to "com.httpfreekit.capturetest.CaptureFailure", "CaptureEngineSession.kt" to "com.httpfreekit.capture.CaptureEngineSession",
        "CapturePolicyServer.kt" to "com.httpfreekit.capture.CapturePolicyServer", "ProtectedEgressFactory.kt" to "com.httpfreekit.capture.ProtectedEgressFactory",
    )
    fun type(error: Throwable): String = when (error) {
        is AssertionError -> "AssertionError"; is IllegalArgumentException -> "IllegalArgumentException"; is java.io.IOException -> "IOException"; else -> "IllegalStateException"
    }
    fun checkCode(error: Throwable): String = when {
        error is CaptureException && error.code in captureCodes -> "capture_" + error.code
        error.message in checks || error.message in CaptureTrafficReply.failureCodes -> error.message!!
        else -> "other"
    }
    fun frames(error: Throwable): Array<StackTraceElement> = error.stackTrace.take(128).filter { frame ->
        val root = roots[frame.fileName]
        root != null && (frame.className == root || frame.className.startsWith(root + "$")) && frame.lineNumber in 1..1_000_000 &&
            frame.methodName.matches(Regex("(?:[A-Za-z_$][A-Za-z0-9_$]*|<init>|<clinit>)"))
    }.take(16).toTypedArray()

    fun values(scenario: String, phase: String, error: Throwable, service: CaptureServiceSnapshot?,
               guard: ResearchCaptureService.GuardObservation?, requestCalls: Int?, factoryClosed: Boolean?, traffic: CaptureTrafficOutcome): Map<String, String> {
        require(scenario in setOf("uid", "direct", "ipv6", "stop", "guards", "permission") && phase in phases) { "failure_observation" }
        require(service == null || service.state in setOf("idle", "starting", "active", "disconnected", "stopping", "stopped", "failed")) { "failure_observation" }
        require(service?.failureCode == null || service.failureCode in failureCodes) { "failure_observation" }
        require(traffic.command in setOf(0, 10, 11, 12, 13, 14, 15, 16, 17, 18) && traffic.status in -1..3 && traffic.bytes in 0..65507 &&
            (traffic.command !in 17..18 || traffic.bytes == 0)) { "failure_observation" }
        val result = linkedMapOf<String, String>()
        fun put(name: String, value: Any?) {
            require(value == null || value is String || value is Boolean || value is Int && value in -1..1_000_000_000) { "failure_observation" }
            result["captureFailure$name"] = value?.toString() ?: "null"
        }
        put("Version", "1"); put("Scenario", scenario); put("Phase", phase); put("Type", type(error)); put("Check", checkCode(error))
        put("TrafficCommand", traffic.command); put("TrafficStatus", traffic.status); put("TrafficBytes", traffic.bytes)
        put("ServicePresent", service != null); put("ServiceState", service?.state ?: "absent"); put("ServiceFailureCode", service?.failureCode)
        put("TunEstablished", service?.tunEstablished); put("SelectedPackageCount", service?.selectedPackageCount)
        put("UnderlyingNetworkPresent", service?.underlyingNetworkPresent); put("LifecycleThreadAlive", service?.lifecycleThreadAlive)
        val capture = service?.capture
        put("CapturePresent", capture != null); put("Started", capture?.started); put("AdmissionClosed", capture?.admissionClosed)
        put("NativeRunning", capture?.nativeRunning); put("NativeStopJoined", capture?.nativeStopJoined); put("TunClosed", capture?.tunClosed)
        put("ConfigurationPresent", capture?.configurationPresent); put("ActiveFlows", capture?.activeFlows); put("OwnedSockets", capture?.ownedSockets)
        put("LiveWorkers", capture?.liveWorkers); put("PendingOpens", capture?.pendingOpens); put("InterceptedTcpFlows", capture?.interceptedTcpFlows)
        put("DirectTcpFlows", capture?.directTcpFlows); put("UdpTargets", capture?.udpTargets); put("Udp443Drops", capture?.udp443Drops)
        put("ProtectFailures", capture?.protectFailures); put("BindFailures", capture?.bindFailures); put("Failed", capture?.failed)
        put("GuardProtects", guard?.protects); put("GuardBinds", guard?.binds); put("GuardRejected", guard?.rejected)
        put("GuardRejectedSocketsClosed", guard?.rejectedSocketsClosed); put("CaptureRequestCalls", requestCalls); put("InterceptedFactoryClosed", factoryClosed)
        check(result.size == 39)
        return Collections.unmodifiableMap(result)
    }
}
