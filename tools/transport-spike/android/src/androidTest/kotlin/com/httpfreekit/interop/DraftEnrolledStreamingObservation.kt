package com.httpfreekit.interop

import java.util.Collections

/** Only bounded primitive observations enter instrumentation. No identity, token or DER is accepted. */
internal class DraftEnrolledStreamingObservation(
    private val scenario: String, private val credentialExpires: Long, private val gatewayExpires: Long, private val anchorExpires: Long,
    private val policyMillis: Long, private val readyUtc: Long, private val sessionExpires: Long,
    private val terminal: DraftStreamingOwner.TerminalObservation, private val blocked: DraftStreamingOwner.BlockedWrite,
    private val prefixBytes: Long, private val ticks: Long, private val controlInactive: Boolean, private val streamInactive: Boolean,
    private val sameCredential: Boolean, private val freshAdmission: String, private val oldSessionRejected: Boolean,
    private val newControlAdmitted: Boolean, private val newControlUtc: Long?, resources: List<DraftStreamingOwner.ClosedResources>,
) {
    private val resources = resources.toList().also { require(it.size in 1..2) }
    fun values(): Map<String, String> {
        require(scenario in setOf("revocation", "credential_expiry", "session_expiry") &&
            freshAdmission in setOf("denied", "new_control") && terminal.cause in setOf("device_revoked", "session_expired", "network_unreachable"))
        val fields = linkedMapOf(
            "Version" to "1", "Scenario" to scenario, "CredentialExpiresUtcMillis" to credentialExpires.toString(),
            "GatewayExpiresUtcMillis" to gatewayExpires.toString(), "AnchorExpiresUtcMillis" to anchorExpires.toString(),
            "PolicyMillis" to policyMillis.toString(), "ReadinessObservedUtcMillis" to readyUtc.toString(), "SessionExpiresUtcMillis" to sessionExpires.toString(),
            "TerminalObservedUtcMillis" to terminal.utcMillis.toString(), "TerminalObservedElapsedMillis" to terminal.elapsedMillis.toString(), "LocalCause" to terminal.cause,
            "ApplicationWriteEntered" to blocked.entered.toString(), "ApplicationWriteCompleted" to blocked.completed.toString(), "ApplicationWriteInFlight" to blocked.inFlight.toString(),
            "ApplicationPendingBytes" to blocked.pendingBytes.toString(), "ApplicationChargedBytes" to blocked.chargedBytes.toString(), "ApplicationChargedFrames" to blocked.chargedFrames.toString(),
            "ApplicationBlockedMillis" to blocked.blockedMillis.toString(), "PrefixBytes" to prefixBytes.toString(), "LocalTicks" to ticks.toString(),
            "ControlInactive" to controlInactive.toString(), "StreamInactive" to streamInactive.toString(), "SameCredential" to sameCredential.toString(), "FreshAdmission" to freshAdmission,
            "OldSessionRejected" to oldSessionRejected.toString(), "NewControlAdmitted" to newControlAdmitted.toString(), "NewControlObservedUtcMillis" to (newControlUtc?.toString() ?: "null"),
            "SocketsClosed" to resources.all { it.socketsClosed }.toString(), "WorkersJoined" to resources.all { it.workersJoined }.toString(),
            "OwnedThreadsAlive" to resources.sumOf { it.threadsAlive }.toString(), "SessionLeases" to resources.sumOf { it.sessionLeases }.toString(),
            "StreamLeases" to resources.sumOf { it.streamLeases }.toString(), "ChargedBytes" to resources.sumOf { it.chargedBytes }.toString(),
            "PendingCallbacks" to resources.sumOf { it.pendingCallbacks }.toString(), "Timers" to resources.sumOf { it.timers }.toString())
        return Collections.unmodifiableMap(fields.mapKeys { "draftEnrolled${it.key}" })
    }
    override fun toString() = "DraftEnrolledStreamingObservation([REDACTED])"
}
