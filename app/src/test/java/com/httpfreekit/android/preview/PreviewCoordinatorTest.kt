package com.httpfreekit.android.preview

import java.io.File
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PreviewCoordinatorTest {
    private val now = Instant.parse("2026-10-24T12:00:00Z")
    private val invitation = generateSequence(File(checkNotNull(System.getProperty("user.dir"))).absoluteFile) { it.parentFile }
        .map { File(it, "protocol/fixtures/pairing-valid.json") }.first { it.isFile }.readText()
    private val secret = Regex("\"invitationSecret\"\\s*:\\s*\"([^\"]+)\"").find(invitation)!!.groupValues[1]

    private fun PreviewState.act(action: PreviewAction): PreviewState = PreviewCoordinator.reduce(this, action)
    private fun ready(): PreviewState = PreviewState().act(PreviewAction.LoadSampleComputer)
        .act(PreviewAction.SelectApp("example.browser", true))
    private fun connecting(): PreviewState = ready().act(PreviewAction.Connect)
        .act(PreviewAction.NotificationPermission(true)).act(PreviewAction.VpnConsent(true))
    private fun connected(): PreviewState = connecting().let { it.act(PreviewAction.GatewayResult(it.attempt, true)) }
    private fun pending(): PreviewState = PreviewCoordinator.review(PreviewState(), invitation, now)
        .act(PreviewAction.ConfirmInvitation(now))

    @Test fun invitationReviewDoesNotPairOrRetainSecret() {
        val state = PreviewCoordinator.review(PreviewState(), invitation, now)
        assertEquals(PreviewPhase.IDLE, state.phase)
        assertTrue(state.computers.isEmpty())
        assertEquals("Development computer", state.review!!.computer.name)
        assertFalse(state.toString().contains(secret))
        assertFalse(state.diagnostics.toString().contains("fixture-invitation"))
    }

    @Test fun explicitReviewAndApprovalAreBothRequired() {
        val pending = pending()
        assertEquals(PreviewPhase.AWAITING_APPROVAL, pending.phase)
        assertEquals(PreviewCredentials.PENDING, pending.selectedComputer!!.credentials)
        assertEquals(pending, pending.act(PreviewAction.Connect))
        val approved = pending.act(PreviewAction.ApprovePairing)
        assertEquals(PreviewCredentials.AVAILABLE, approved.selectedComputer!!.credentials)
        assertEquals(PreviewPhase.IDLE, approved.phase)
        assertFalse(approved.vpnConsent)
    }

    @Test fun approvalAndCancellationCannotBeAppliedOutsidePendingEnrollment() {
        val state = ready()
        assertEquals(state, state.act(PreviewAction.ApprovePairing))
        assertEquals(state, state.act(PreviewAction.RejectPairing))
        assertEquals(state, state.act(PreviewAction.CancelPairing))
    }

    @Test fun rejectedAndCancelledApprovalRequirePairingAgain() {
        val rejected = pending().act(PreviewAction.RejectPairing)
        assertEquals(PreviewProblem.PAIRING_REJECTED, rejected.problem)
        assertEquals(PreviewCredentials.MISSING, rejected.selectedComputer!!.credentials)
        assertEquals(PreviewPhase.NEEDS_PAIRING, rejected.act(PreviewAction.Connect).phase)
        assertEquals(PreviewProblem.PAIRING_CANCELLED, pending().act(PreviewAction.Stop).problem)
    }

    @Test fun invitationMustStillBeUnexpiredWhenReviewIsConfirmed() {
        val review = PreviewCoordinator.review(PreviewState(), invitation, now)
        val expired = review.act(PreviewAction.ConfirmInvitation(now.plusSeconds(300)))
        assertNull(expired.review)
        assertTrue(expired.computers.isEmpty())
        assertEquals(PreviewProblem.INVITATION_EXPIRED, expired.problem)
    }

    @Test fun invalidInvitationProducesOnlySafeDiagnosticCodes() {
        val invalid = PreviewCoordinator.review(PreviewState(), "secret=$secret", now)
        assertEquals(PreviewProblem.INVALID_INVITATION, invalid.problem)
        assertEquals(listOf(DiagnosticCode.INVITATION_REJECTED), invalid.diagnostics)
        assertFalse(invalid.toString().contains(secret))
    }

    @Test fun connectionRequiresComputerAppsAndCredentials() {
        assertEquals(PreviewProblem.SELECT_COMPUTER, PreviewState().act(PreviewAction.Connect).problem)
        assertEquals(PreviewProblem.SELECT_APPS, ready().copy(selectedAppIds = emptySet()).act(PreviewAction.Connect).problem)
        assertEquals(PreviewPhase.NEEDS_PAIRING, ready().act(PreviewAction.RemoveCredentials).act(PreviewAction.Connect).phase)
    }

    @Test fun permissionsAreSeparateFromConnectionAndTraffic() {
        var state = ready().act(PreviewAction.Connect)
        assertEquals(PreviewPhase.AWAITING_NOTIFICATIONS, state.phase)
        state = state.act(PreviewAction.NotificationPermission(true))
        assertEquals(PreviewPhase.AWAITING_VPN_CONSENT, state.phase)
        state = state.act(PreviewAction.VpnConsent(true))
        assertEquals(PreviewPhase.CONNECTING, state.phase)
        state = state.act(PreviewAction.GatewayResult(state.attempt, true))
        assertEquals(PreviewPhase.CONNECTED, state.phase)
        // The model has no captured payloads/counters and never constructs a real VPN or transport.
        assertTrue(state.notificationsAllowed && state.vpnConsent)
    }

    @Test fun deniedNotificationAndCancelledVpnConsentDoNotStartSession() {
        val denied = ready().act(PreviewAction.Connect).act(PreviewAction.NotificationPermission(false))
        assertEquals(PreviewPhase.DISCONNECTED, denied.phase)
        assertEquals(PreviewProblem.NOTIFICATIONS_DENIED, denied.problem)
        val cancelled = ready().act(PreviewAction.Connect).act(PreviewAction.NotificationPermission(true))
            .act(PreviewAction.VpnConsent(false))
        assertEquals(PreviewProblem.CONSENT_CANCELLED, cancelled.problem)
        assertFalse(cancelled.vpnConsent)
    }

    @Test fun anExistingVpnRemainsVisibleBeforeConsent() {
        val state = ready().act(PreviewAction.ExistingVpn(true)).act(PreviewAction.Connect)
            .act(PreviewAction.NotificationPermission(true))
        assertEquals(PreviewPhase.AWAITING_VPN_CONSENT, state.phase)
        assertTrue(state.existingVpn)
        assertEquals(PreviewPhase.DISCONNECTED, state.act(PreviewAction.VpnConsent(false)).phase)
    }

    @Test fun anotherVpnRevokesExistingConsentAndRequiresANewChoice() {
        val connected = connected()
        val replaced = connected.act(PreviewAction.ExistingVpn(true))
        assertEquals(PreviewPhase.DISCONNECTED, replaced.phase)
        assertFalse(replaced.vpnConsent)
        assertTrue(replaced.existingVpn)
        assertEquals(replaced, replaced.act(PreviewAction.GatewayResult(connected.attempt, true)))
        val awaitingConsent = replaced.act(PreviewAction.Connect)
        assertEquals(PreviewPhase.AWAITING_VPN_CONSENT, awaitingConsent.phase)
        assertTrue(awaitingConsent.existingVpn)
        val allowed = awaitingConsent.act(PreviewAction.VpnConsent(true))
        assertFalse(allowed.existingVpn)
        assertEquals(PreviewPhase.CONNECTING, allowed.phase)
    }

    @Test fun stopDiscardsLateConnectionCompletions() {
        val connecting = connecting()
        val stopped = connecting.act(PreviewAction.Stop)
        assertEquals(PreviewPhase.IDLE, stopped.phase)
        assertEquals(stopped, stopped.act(PreviewAction.GatewayResult(connecting.attempt, true)))
    }

    @Test fun changingAppsWhileActiveDoesNotChangeRoutedSelection() {
        val state = connected()
        assertEquals(state, state.act(PreviewAction.SelectApp("example.other", true)))
        val stopped = state.act(PreviewAction.Stop).act(PreviewAction.SelectApp("example.other", true))
        assertTrue("example.other" in stopped.selectedAppIds)
    }

    @Test fun revocationInvalidatesPendingAndActiveSessions() {
        val state = connected()
        val revoked = state.act(PreviewAction.RevokeDevice)
        assertEquals(PreviewPhase.NEEDS_PAIRING, revoked.phase)
        assertEquals(PreviewCredentials.REVOKED, revoked.selectedComputer!!.credentials)
        assertEquals(PreviewProblem.DEVICE_REVOKED, revoked.act(PreviewAction.Connect).problem)
        val vpnRevoked = state.act(PreviewAction.RevokeVpn)
        assertFalse(vpnRevoked.vpnConsent)
        assertEquals(PreviewPhase.DISCONNECTED, vpnRevoked.phase)
    }

    @Test fun networkChangeUsesNewAttemptAndOldCompletionCannotReconnect() {
        val state = connected()
        val changed = state.act(PreviewAction.NetworkChanged)
        assertEquals(PreviewPhase.RECONNECTING, changed.phase)
        assertTrue(changed.attempt > state.attempt)
        assertEquals(changed, changed.act(PreviewAction.GatewayResult(state.attempt, true)))
        assertEquals(PreviewPhase.CONNECTED, changed.act(PreviewAction.GatewayResult(changed.attempt, true)).phase)
    }

    @Test fun failedReconnectHasABoundedBudgetAndNeverFallsBack() {
        var state = connecting()
        repeat(PreviewCoordinator.MAX_RECONNECT_ATTEMPTS + 1) {
            state = state.act(PreviewAction.GatewayResult(state.attempt, false))
        }
        assertEquals(PreviewPhase.DISCONNECTED, state.phase)
        assertEquals(PreviewProblem.GATEWAY_UNAVAILABLE, state.problem)
        val oldAttempt = state.attempt - 1
        assertEquals(state, state.act(PreviewAction.GatewayResult(oldAttempt, true)))
    }

    @Test fun restoredPreferencesDoNotRestoreCredentialsOrActiveSession() {
        val state = connected()
        val restored = state.act(PreviewAction.Restart)
        assertEquals(state.selectedAppIds, restored.selectedAppIds)
        assertEquals(PreviewPhase.NEEDS_PAIRING, restored.phase)
        assertFalse(restored.vpnConsent)
        assertFalse(restored.notificationsAllowed)
        assertEquals(PreviewCredentials.MISSING, restored.selectedComputer!!.credentials)
        assertEquals(PreviewPhase.NEEDS_PAIRING, restored.act(PreviewAction.Connect).phase)
        assertNull(restored.review)
    }

    @Test fun forgettingSelectedComputerStopsSessionButOtherComputerDoesNotInvalidateIt() {
        val state = connected()
        val other = state.selectedComputer!!.copy(id = "other")
        val withOther = state.copy(computers = state.computers + other)
        assertEquals(state.attempt, withOther.act(PreviewAction.ForgetComputer("other")).attempt)
        val forgotten = withOther.act(PreviewAction.ForgetComputer(state.selectedComputerId!!))
        assertEquals(PreviewPhase.IDLE, forgotten.phase)
        assertNull(forgotten.selectedComputer)
    }

    @Test fun cameraFailureKeepsPasteAvailableAndDiagnosticsRemainBounded() {
        var state = PreviewState().act(PreviewAction.CameraUnavailable)
        assertEquals(PreviewProblem.CAMERA_UNAVAILABLE, state.problem)
        state = PreviewCoordinator.review(state, invitation, now)
        assertNull(state.problem)
        assertTrue(state.review != null)
        repeat(50) { state = state.act(PreviewAction.NetworkChanged) }
        assertEquals(20, state.diagnostics.size)
    }
}
