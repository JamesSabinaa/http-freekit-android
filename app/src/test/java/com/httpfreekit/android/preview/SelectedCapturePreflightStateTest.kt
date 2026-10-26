package com.httpfreekit.android.preview

import com.httpfreekit.android.apps.AppCatalogMode
import com.httpfreekit.android.apps.AppFilter
import com.httpfreekit.android.apps.AppSelectionState
import com.httpfreekit.android.apps.InstalledAppEntry
import com.httpfreekit.android.apps.SelectedPackageAvailability
import com.httpfreekit.android.apps.SelectedPackageProbe
import org.junit.Assert.*
import org.junit.Test

class SelectedCapturePreflightStateTest {
    private val selection = AppSelectionState(mode = AppCatalogMode.INSTALLED, loaded = true,
        installed = listOf(InstalledAppEntry("test.fixture.first", "Fixture", false),
            InstalledAppEntry("test.fixture.second", "Second", true)),
        installedSelected = setOf("test.fixture.first", "test.fixture.second"))
    private fun ready() = SelectedCapturePreflightState().started()
    private fun checking() = ready().begin(selection, false)
    private fun finish(state: SelectedCapturePreflightState, outcome: SelectedCapturePreflightPhase = SelectedCapturePreflightPhase.CHECKED) =
        state.complete(checkNotNull(state.activeRequest), outcome, selection, false)

    @Test fun inertDefaultCannotCheck() {
        val state = SelectedCapturePreflightState()
        assertFalse(state.canCheck(selection, false))
        assertEquals(state, state.begin(selection, false))
    }

    @Test fun onlyReadyInstalledUnlockedInventoryCanCheck() {
        for (apps in listOf(selection.copy(mode = AppCatalogMode.SAMPLE), selection.copy(loaded = false),
            selection.copy(loading = true), selection.copy(failed = true))) {
            assertEquals(ready(), ready().begin(apps, false))
        }
        assertEquals(ready(), ready().begin(selection, true))
        assertTrue(ready().canCheck(selection, false))
    }

    @Test fun duplicateClickCannotCreateAnotherRequest() {
        val state = checking()
        assertEquals(SelectedCapturePreflightPhase.CHECKING, state.phase)
        assertEquals(state, state.begin(selection, false))
    }

    @Test fun successfulAndRejectedOutcomesAreFiniteAndReleaseOwnership() {
        for (outcome in listOf(SelectedCapturePreflightPhase.CHECKED, SelectedCapturePreflightPhase.REJECTED)) {
            val result = finish(checking(), outcome)
            assertEquals(outcome, result.phase)
            assertNull(result.activeRequest)
            assertTrue(result.canCheck(selection, false))
        }
    }

    @Test fun cancellationKeepsSingleFlightUntilActualCompletion() {
        val original = checking()
        val cancelled = original.invalidate()
        assertEquals(SelectedCapturePreflightPhase.IDLE, cancelled.phase)
        assertEquals(cancelled, cancelled.begin(selection, false))
        val drained = finish(cancelled)
        assertEquals(SelectedCapturePreflightPhase.IDLE, drained.phase)
        assertTrue(drained.canCheck(selection, false))
    }

    @Test fun repeatedInvalidationsNeverReviveOldSuccessOrFailure() {
        for (outcome in listOf(SelectedCapturePreflightPhase.CHECKED, SelectedCapturePreflightPhase.REJECTED)) {
            val state = checking().invalidate().invalidate().invalidate()
            assertEquals(SelectedCapturePreflightPhase.IDLE, finish(state, outcome).phase)
        }
    }

    @Test fun completionBeforeInvalidationAlsoLosesObservation() {
        assertEquals(SelectedCapturePreflightPhase.IDLE, finish(checking()).invalidate().phase)
    }

    @Test fun lockAtPublicationSuppressesBothOutcomes() {
        val state = checking()
        for (outcome in listOf(SelectedCapturePreflightPhase.CHECKED, SelectedCapturePreflightPhase.REJECTED)) {
            val result = state.complete(checkNotNull(state.activeRequest), outcome, selection, true)
            assertEquals(SelectedCapturePreflightPhase.IDLE, result.phase)
            assertNull(result.activeRequest)
        }
    }

    @Test fun failedLoadingAndSampleAtPublicationCannotPublish() {
        val state = checking()
        for (apps in listOf(selection.copy(mode = AppCatalogMode.SAMPLE), selection.copy(loaded = false),
            selection.copy(loading = true), selection.copy(failed = true))) {
            assertEquals(SelectedCapturePreflightPhase.IDLE,
                state.complete(checkNotNull(state.activeRequest), SelectedCapturePreflightPhase.CHECKED, apps, false).phase)
        }
    }

    @Test fun actualBackgroundReturnCannotPublishOldCompletion() {
        val state = checking().stopped().started()
        assertEquals(SelectedCapturePreflightPhase.IDLE, finish(state).phase)
        assertEquals(state, state.begin(selection, false))
        assertTrue(finish(state).canCheck(selection, false))
    }

    @Test fun backgroundCompletionDrainsButDoesNotPublishOrEnableCheck() {
        val result = finish(checking().stopped())
        assertEquals(SelectedCapturePreflightPhase.IDLE, result.phase)
        assertFalse(result.canCheck(selection, false))
        assertTrue(result.started().canCheck(selection, false))
    }

    @Test fun clearIsTerminalAcrossReturnAndLateCompletion() {
        val result = finish(checking().clear()).started()
        assertTrue(result.cleared)
        assertEquals(SelectedCapturePreflightPhase.IDLE, result.phase)
        assertFalse(result.canCheck(selection, false))
        assertEquals(result, result.begin(selection, false))
    }

    @Test fun oldCompletionCannotReleaseNewRequestOrOverwriteCheckedResult() {
        val first = checking()
        val second = finish(first.invalidate()).begin(selection, false)
        val stale = second.complete(checkNotNull(first.activeRequest), SelectedCapturePreflightPhase.CHECKED, selection, false)
        assertEquals(second, stale)
        val checked = finish(second)
        assertEquals(checked, checked.complete(checkNotNull(second.activeRequest), SelectedCapturePreflightPhase.REJECTED, selection, false))
    }

    @Test fun nonterminalWorkerOutcomeCannotLeaveCheckingStuck() {
        assertEquals(SelectedCapturePreflightPhase.IDLE, finish(checking(), SelectedCapturePreflightPhase.CHECKING).phase)
    }

    @Test fun searchAndFiltersDoNotPruneWholeSelection() {
        val calls = mutableListOf<String>()
        val result = checkSelectedCapture(selection.copy(search = "no match", filter = AppFilter.DEVELOPMENT),
            "test.companion.debug", SelectedPackageProbe { calls.add(it); SelectedPackageAvailability.AVAILABLE })
        assertEquals(SelectedCapturePreflightPhase.CHECKED, result)
        assertEquals(selection.installedSelected, calls.toSet())
        assertEquals(2, calls.size)
    }

    @Test fun companionIdentityIsInjectedIncludingDebugSuffix() {
        var calls = 0
        val debugPackage = "test.companion.debug"
        val own = selection.copy(installed = listOf(InstalledAppEntry(debugPackage, "Own debug", true)),
            installedSelected = setOf(debugPackage))
        val result = checkSelectedCapture(own, debugPackage, SelectedPackageProbe {
            calls++; SelectedPackageAvailability.AVAILABLE
        })
        assertEquals(SelectedCapturePreflightPhase.REJECTED, result)
        assertEquals(0, calls)
    }

    @Test fun absentDisabledAndErrorsAreRejectedWithoutProviderText() {
        for (availability in listOf(SelectedPackageAvailability.NOT_INSTALLED, SelectedPackageAvailability.DISABLED,
            SelectedPackageAvailability.UNAVAILABLE)) {
            assertEquals(SelectedCapturePreflightPhase.REJECTED,
                checkSelectedCapture(selection, "test.companion", SelectedPackageProbe { availability }))
        }
        for (error in listOf(SecurityException("secret provider test.fixture.first"),
            IllegalStateException("secret"), InterruptedException("private interruption"))) {
            val outcome = checkSelectedCapture(selection, "test.companion", SelectedPackageProbe { throw error })
            assertEquals(SelectedCapturePreflightPhase.REJECTED, outcome)
            assertFalse(outcome.toString().contains("secret"))
            assertFalse(finish(checking(), outcome).toString().contains("test.fixture"))
        }
    }

    @Test fun newStateRetainsNeitherPlanSelectionNorRawFailure() {
        val state = finish(checking())
        assertEquals(setOf("phase", "generation", "activeRequest", "foreground", "cleared"),
            SelectedCapturePreflightState::class.java.declaredFields.filterNot { it.isSynthetic || it.name == "Companion" }.map { it.name }.toSet())
        assertFalse(state.toString().contains("test.fixture"))
        assertEquals(SelectedCapturePreflightPhase.CHECKED, state.phase)
    }
}
