package com.httpfreekit.android.preview

import com.httpfreekit.protocol.PairingError
import com.httpfreekit.protocol.PairingInvitationParser
import com.httpfreekit.protocol.PairingParseResult
import java.time.Instant

/** Local preview state only. This coordinator never opens a socket or establishes a VPN. */
data class PreviewComputer(
    val id: String,
    val name: String,
    val serverName: String,
    val pin: String,
    val transport: String,
    val address: String,
    val credentials: PreviewCredentials = PreviewCredentials.MISSING,
)

enum class PreviewCredentials { PENDING, AVAILABLE, MISSING, REVOKED }
enum class PreviewPhase {
    IDLE, AWAITING_APPROVAL, AWAITING_NOTIFICATIONS, AWAITING_VPN_CONSENT,
    CONNECTING, CONNECTED, RECONNECTING, DISCONNECTED, NEEDS_PAIRING,
}

enum class PreviewProblem {
    INVALID_INVITATION, INVITATION_TOO_LARGE, UNSUPPORTED_VERSION, INVITATION_EXPIRED,
    PAIRING_REJECTED, PAIRING_CANCELLED, SELECT_COMPUTER, SELECT_APPS, MISSING_CREDENTIALS,
    DEVICE_REVOKED, NOTIFICATIONS_DENIED, CONSENT_CANCELLED, VPN_REVOKED,
    GATEWAY_UNAVAILABLE, CAMERA_UNAVAILABLE,
}

enum class DiagnosticCode {
    INVITATION_REVIEWED, INVITATION_REJECTED, APPROVAL_REQUESTED, PAIRING_APPROVED,
    PAIRING_REJECTED, PAIRING_CANCELLED, COMPUTER_SELECTED, COMPUTER_FORGOTTEN,
    CONNECTION_REQUESTED, NOTIFICATIONS_ALLOWED, NOTIFICATIONS_DENIED,
    VPN_CONSENT_ALLOWED, VPN_CONSENT_CANCELLED, PREVIEW_CONNECTED, PREVIEW_STOPPED,
    NETWORK_CHANGED, RECONNECTING, RETRY_EXHAUSTED, VPN_REVOKED, CREDENTIALS_MISSING,
    DEVICE_REVOKED, PROCESS_RESTORED, CAMERA_UNAVAILABLE,
}

data class InvitationReview(val computer: PreviewComputer, val expiresAt: Instant)

data class PreviewState(
    val computers: List<PreviewComputer> = emptyList(),
    val selectedComputerId: String? = null,
    val selectedAppIds: Set<String> = emptySet(),
    val phase: PreviewPhase = PreviewPhase.IDLE,
    val review: InvitationReview? = null,
    val problem: PreviewProblem? = null,
    val notificationsAllowed: Boolean = false,
    val vpnConsent: Boolean = false,
    val existingVpn: Boolean = false,
    val gatewayAvailable: Boolean = true,
    val attempt: Int = 0,
    val reconnectAttempts: Int = 0,
    val diagnostics: List<DiagnosticCode> = emptyList(),
) {
    val selectedComputer: PreviewComputer? get() = computers.find { it.id == selectedComputerId }
    val canStop: Boolean get() = phase in setOf(
        PreviewPhase.AWAITING_APPROVAL, PreviewPhase.AWAITING_NOTIFICATIONS,
        PreviewPhase.AWAITING_VPN_CONSENT, PreviewPhase.CONNECTING,
        PreviewPhase.CONNECTED, PreviewPhase.RECONNECTING,
    )
}

sealed interface PreviewAction {
    data object LoadSampleComputer : PreviewAction
    data class SelectComputer(val id: String) : PreviewAction
    data class ForgetComputer(val id: String) : PreviewAction
    data class SelectApp(val id: String, val selected: Boolean) : PreviewAction
    data class ConfirmInvitation(val now: Instant) : PreviewAction
    data object DismissReview : PreviewAction
    data object ApprovePairing : PreviewAction
    data object RejectPairing : PreviewAction
    data object CancelPairing : PreviewAction
    data object Connect : PreviewAction
    data class NotificationPermission(val allowed: Boolean) : PreviewAction
    data class VpnConsent(val allowed: Boolean) : PreviewAction
    data class GatewayResult(val attempt: Int, val available: Boolean) : PreviewAction
    data class GatewayAvailability(val available: Boolean) : PreviewAction
    data class ExistingVpn(val active: Boolean) : PreviewAction
    data object NetworkChanged : PreviewAction
    data object Stop : PreviewAction
    data object RevokeVpn : PreviewAction
    data object RemoveCredentials : PreviewAction
    data object RevokeDevice : PreviewAction
    data object Restart : PreviewAction
    data object CameraUnavailable : PreviewAction
}

object PreviewCoordinator {
    const val MAX_RECONNECT_ATTEMPTS = 3
    private const val MAX_DIAGNOSTICS = 20

    /** Converts the draft payload into public review metadata; never retains its invitation secret. */
    fun review(state: PreviewState, payload: String, now: Instant): PreviewState =
        when (val parsed = PairingInvitationParser.parse(payload, now)) {
            is PairingParseResult.Rejected -> state.copy(
                review = null,
                problem = when (parsed.error) {
                    PairingError.INVALID_MESSAGE -> PreviewProblem.INVALID_INVITATION
                    PairingError.MESSAGE_TOO_LARGE -> PreviewProblem.INVITATION_TOO_LARGE
                    PairingError.UNSUPPORTED_VERSION -> PreviewProblem.UNSUPPORTED_VERSION
                    PairingError.INVITATION_EXPIRED -> PreviewProblem.INVITATION_EXPIRED
                },
            ).record(DiagnosticCode.INVITATION_REJECTED)
            is PairingParseResult.Accepted -> {
                val invitation = parsed.invitation
                val endpoint = invitation.endpoints.first()
                val host = if (':' in endpoint.host) "[${endpoint.host}]" else endpoint.host
                state.copy(
                    review = InvitationReview(
                        PreviewComputer(
                            invitation.desktopId, invitation.displayName, invitation.serverName,
                            invitation.gatewaySpkiSha256, endpoint.mode.name, "$host:${endpoint.port}",
                        ),
                        invitation.expiresAt,
                    ),
                    problem = null,
                ).record(DiagnosticCode.INVITATION_REVIEWED)
            }
        }

    fun reduce(state: PreviewState, action: PreviewAction): PreviewState = when (action) {
        PreviewAction.LoadSampleComputer -> {
            val sample = PreviewComputer(
                "sample-desktop", "Studio computer", "gateway-preview.invalid",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", "USB", "127.0.0.1:8766",
                PreviewCredentials.AVAILABLE,
            )
            state.copy(
                computers = state.computers.filterNot { it.id == sample.id } + sample,
                selectedComputerId = sample.id, phase = PreviewPhase.IDLE,
                problem = null, attempt = state.attempt + 1, reconnectAttempts = 0,
            ).record(DiagnosticCode.COMPUTER_SELECTED)
        }
        is PreviewAction.SelectComputer -> if (state.computers.none { it.id == action.id }) state else state.copy(
            selectedComputerId = action.id, phase = PreviewPhase.IDLE,
            problem = null, attempt = state.attempt + 1, reconnectAttempts = 0,
        ).record(DiagnosticCode.COMPUTER_SELECTED)
        is PreviewAction.ForgetComputer -> state.copy(
            computers = state.computers.filterNot { it.id == action.id },
            selectedComputerId = state.selectedComputerId.takeUnless { it == action.id },
            phase = if (state.selectedComputerId == action.id) PreviewPhase.IDLE else state.phase,
            problem = null, attempt = if (state.selectedComputerId == action.id) state.attempt + 1 else state.attempt,
        ).record(DiagnosticCode.COMPUTER_FORGOTTEN)
        is PreviewAction.SelectApp -> if (state.canStop) state else state.copy(
            selectedAppIds = if (action.selected) state.selectedAppIds + action.id else state.selectedAppIds - action.id,
            problem = null,
        )
        is PreviewAction.ConfirmInvitation -> {
            val review = state.review
            if (review == null) state else if (!review.expiresAt.isAfter(action.now)) state.copy(
                review = null, problem = PreviewProblem.INVITATION_EXPIRED,
            ).record(DiagnosticCode.INVITATION_REJECTED) else {
                val computer = review.computer.copy(credentials = PreviewCredentials.PENDING)
                state.copy(
                    computers = state.computers.filterNot { it.id == computer.id } + computer,
                    selectedComputerId = computer.id, review = null,
                    phase = PreviewPhase.AWAITING_APPROVAL, problem = null,
                    attempt = state.attempt + 1, reconnectAttempts = 0,
                ).record(DiagnosticCode.APPROVAL_REQUESTED)
            }
        }
        PreviewAction.DismissReview -> state.copy(review = null)
        PreviewAction.ApprovePairing -> if (state.phase != PreviewPhase.AWAITING_APPROVAL) state else state
            .credentials(PreviewCredentials.AVAILABLE).copy(phase = PreviewPhase.IDLE, problem = null)
            .record(DiagnosticCode.PAIRING_APPROVED)
        PreviewAction.RejectPairing -> if (state.phase != PreviewPhase.AWAITING_APPROVAL) state else state
            .credentials(PreviewCredentials.MISSING).copy(phase = PreviewPhase.NEEDS_PAIRING, problem = PreviewProblem.PAIRING_REJECTED)
            .record(DiagnosticCode.PAIRING_REJECTED)
        PreviewAction.CancelPairing -> if (state.phase != PreviewPhase.AWAITING_APPROVAL) state else state
            .credentials(PreviewCredentials.MISSING).copy(phase = PreviewPhase.NEEDS_PAIRING, problem = PreviewProblem.PAIRING_CANCELLED)
            .record(DiagnosticCode.PAIRING_CANCELLED)
        PreviewAction.Connect -> connect(state)
        is PreviewAction.NotificationPermission -> if (state.phase != PreviewPhase.AWAITING_NOTIFICATIONS) state else if (action.allowed) {
            advance(state.copy(notificationsAllowed = true).record(DiagnosticCode.NOTIFICATIONS_ALLOWED))
        } else state.copy(
            notificationsAllowed = false, phase = PreviewPhase.DISCONNECTED,
            problem = PreviewProblem.NOTIFICATIONS_DENIED, attempt = state.attempt + 1,
        ).record(DiagnosticCode.NOTIFICATIONS_DENIED)
        is PreviewAction.VpnConsent -> if (state.phase != PreviewPhase.AWAITING_VPN_CONSENT) state else if (action.allowed) {
            advance(state.copy(vpnConsent = true, existingVpn = false).record(DiagnosticCode.VPN_CONSENT_ALLOWED))
        } else state.copy(
            vpnConsent = false, phase = PreviewPhase.DISCONNECTED,
            problem = PreviewProblem.CONSENT_CANCELLED, attempt = state.attempt + 1,
        ).record(DiagnosticCode.VPN_CONSENT_CANCELLED)
        is PreviewAction.GatewayResult -> gatewayResult(state, action)
        is PreviewAction.GatewayAvailability -> {
            val next = state.copy(gatewayAvailable = action.available)
            if (!action.available && state.phase == PreviewPhase.CONNECTED) reconnect(next) else next
        }
        is PreviewAction.ExistingVpn -> if (action.active && state.vpnConsent) state.copy(
            existingVpn = true, vpnConsent = false, phase = PreviewPhase.DISCONNECTED,
            problem = PreviewProblem.VPN_REVOKED, attempt = state.attempt + 1, reconnectAttempts = 0,
        ).record(DiagnosticCode.VPN_REVOKED) else state.copy(existingVpn = action.active)
        PreviewAction.NetworkChanged -> if (state.phase in setOf(PreviewPhase.CONNECTED, PreviewPhase.CONNECTING, PreviewPhase.RECONNECTING)) {
            reconnect(state.record(DiagnosticCode.NETWORK_CHANGED))
        } else state.record(DiagnosticCode.NETWORK_CHANGED)
        PreviewAction.Stop -> if (state.phase == PreviewPhase.AWAITING_APPROVAL) {
            reduce(state, PreviewAction.CancelPairing)
        } else state.copy(
            phase = PreviewPhase.IDLE, problem = null, attempt = state.attempt + 1, reconnectAttempts = 0,
        ).record(DiagnosticCode.PREVIEW_STOPPED)
        PreviewAction.RevokeVpn -> state.copy(
            vpnConsent = false, phase = PreviewPhase.DISCONNECTED, problem = PreviewProblem.VPN_REVOKED,
            attempt = state.attempt + 1, reconnectAttempts = 0,
        ).record(DiagnosticCode.VPN_REVOKED)
        PreviewAction.RemoveCredentials -> state.credentials(PreviewCredentials.MISSING).copy(
            phase = PreviewPhase.NEEDS_PAIRING, problem = PreviewProblem.MISSING_CREDENTIALS,
            attempt = state.attempt + 1, reconnectAttempts = 0,
        ).record(DiagnosticCode.CREDENTIALS_MISSING)
        PreviewAction.RevokeDevice -> state.credentials(PreviewCredentials.REVOKED).copy(
            phase = PreviewPhase.NEEDS_PAIRING, problem = PreviewProblem.DEVICE_REVOKED,
            attempt = state.attempt + 1, reconnectAttempts = 0,
        ).record(DiagnosticCode.DEVICE_REVOKED)
        PreviewAction.Restart -> restore(state.computers, state.selectedComputerId, state.selectedAppIds)
        PreviewAction.CameraUnavailable -> state.copy(problem = PreviewProblem.CAMERA_UNAVAILABLE).record(DiagnosticCode.CAMERA_UNAVAILABLE)
    }

    /** Restore only public preferences. A saved computer without its original key requires pairing again. */
    fun restore(computers: List<PreviewComputer>, selectedComputerId: String?, appIds: Set<String>): PreviewState = PreviewState(
        computers = computers.map { it.copy(credentials = PreviewCredentials.MISSING) },
        selectedComputerId = selectedComputerId?.takeIf { id -> computers.any { it.id == id } },
        selectedAppIds = appIds,
        phase = if (computers.isEmpty()) PreviewPhase.IDLE else PreviewPhase.NEEDS_PAIRING,
        problem = if (computers.isEmpty()) null else PreviewProblem.MISSING_CREDENTIALS,
        diagnostics = listOf(DiagnosticCode.PROCESS_RESTORED),
    )

    private fun connect(state: PreviewState): PreviewState {
        if (state.canStop) return state
        val computer = state.selectedComputer ?: return state.copy(problem = PreviewProblem.SELECT_COMPUTER)
        if (computer.credentials != PreviewCredentials.AVAILABLE) return state.copy(
            phase = PreviewPhase.NEEDS_PAIRING,
            problem = if (computer.credentials == PreviewCredentials.REVOKED) PreviewProblem.DEVICE_REVOKED else PreviewProblem.MISSING_CREDENTIALS,
        )
        if (state.selectedAppIds.isEmpty()) return state.copy(problem = PreviewProblem.SELECT_APPS)
        return advance(state.copy(problem = null, reconnectAttempts = 0).record(DiagnosticCode.CONNECTION_REQUESTED))
    }

    private fun advance(state: PreviewState): PreviewState = state.copy(
        phase = when {
            !state.notificationsAllowed -> PreviewPhase.AWAITING_NOTIFICATIONS
            !state.vpnConsent -> PreviewPhase.AWAITING_VPN_CONSENT
            else -> PreviewPhase.CONNECTING
        },
        attempt = state.attempt + 1,
    )

    private fun reconnect(state: PreviewState): PreviewState = state.copy(
        phase = PreviewPhase.RECONNECTING, reconnectAttempts = 1,
        attempt = state.attempt + 1, problem = null,
    ).record(DiagnosticCode.RECONNECTING)

    private fun gatewayResult(state: PreviewState, result: PreviewAction.GatewayResult): PreviewState {
        if (result.attempt != state.attempt || state.phase !in setOf(PreviewPhase.CONNECTING, PreviewPhase.RECONNECTING)) return state
        if (result.available) return state.copy(phase = PreviewPhase.CONNECTED, reconnectAttempts = 0, problem = null)
            .record(DiagnosticCode.PREVIEW_CONNECTED)
        if (state.phase == PreviewPhase.CONNECTING) return reconnect(state)
        if (state.reconnectAttempts < MAX_RECONNECT_ATTEMPTS) return state.copy(
            reconnectAttempts = state.reconnectAttempts + 1, attempt = state.attempt + 1,
        ).record(DiagnosticCode.RECONNECTING)
        return state.copy(
            phase = PreviewPhase.DISCONNECTED, problem = PreviewProblem.GATEWAY_UNAVAILABLE,
            attempt = state.attempt + 1,
        ).record(DiagnosticCode.RETRY_EXHAUSTED)
    }

    private fun PreviewState.credentials(credentials: PreviewCredentials): PreviewState = copy(
        computers = computers.map { if (it.id == selectedComputerId) it.copy(credentials = credentials) else it },
    )

    private fun PreviewState.record(code: DiagnosticCode): PreviewState = copy(
        diagnostics = (diagnostics + code).takeLast(MAX_DIAGNOSTICS),
    )
}
