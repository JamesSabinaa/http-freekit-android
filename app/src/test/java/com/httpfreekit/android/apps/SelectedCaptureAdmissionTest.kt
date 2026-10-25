package com.httpfreekit.android.apps

import org.junit.Assert.*
import org.junit.Test

class SelectedCaptureAdmissionTest {
    private val companion = "com.httpfreekit.android.debug"
    private val browser = InstalledAppEntry("local.browser", "Browser", false)
    private val headless = InstalledAppEntry("local.headless", "Development worker", true)

    private fun loaded(entries: List<InstalledAppEntry> = listOf(browser, headless)): AppSelectionState {
        val request = AppSelection.beginRefresh(AppSelection.mode(AppSelectionState(), AppCatalogMode.INSTALLED, false), false)
        return AppSelection.succeeded(request, request.requestId, entries, false)
    }
    private fun selected() = AppSelection.select(loaded(), browser.packageName, true, false)
    private fun accepted(state: AppSelectionState): SelectedCapturePlan {
        val result = SelectedCaptureAdmission.prepare(state, companion)
        assertTrue(result is SelectedCaptureResult.Accepted)
        return (result as SelectedCaptureResult.Accepted).plan
    }
    private fun rejected(state: AppSelectionState, reason: SelectedCaptureRejection, identity: String = companion) {
        val result = SelectedCaptureAdmission.prepare(state, identity)
        assertTrue(result is SelectedCaptureResult.Rejected)
        assertEquals(reason, (result as SelectedCaptureResult.Rejected).reason)
    }

    @Test fun reducerSuccessfulInstalledSelectionIsAcceptedExactly() {
        assertEquals(setOf(browser.packageName), accepted(selected()).selectedPackages)
    }
    @Test fun headlessDevelopmentAppNeedsNoLauncherOrSpecialAdmission() {
        val state = AppSelection.select(loaded(), headless.packageName, true, false)
        assertEquals(setOf(headless.packageName), accepted(state).selectedPackages)
    }
    @Test fun searchAndDevelopmentFilterNeverDropHiddenSelectedPackages() {
        val state = AppSelection.select(selected(), headless.packageName, true, false)
            .copy(search = "not present", filter = AppFilter.DEVELOPMENT)
        assertTrue(state.visibleInstalled.isEmpty())
        assertEquals(setOf(browser.packageName, headless.packageName), accepted(state).selectedPackages)
    }
    @Test fun sampleModeRejectedEvenWhenInventoryAndInstalledChoiceCollide() {
        val collision = "example.browser"
        val installed = loaded(listOf(browser.copy(packageName = collision))).copy(
            installedSelected = setOf(collision), sampleSelected = setOf(collision),
        )
        rejected(AppSelection.mode(installed, AppCatalogMode.SAMPLE, false), SelectedCaptureRejection.INSTALLED_MODE_REQUIRED)
        assertEquals(setOf(collision), accepted(installed).selectedPackages)
    }
    @Test fun installedModeIgnoresUnrelatedSampleChoices() {
        assertEquals(setOf(browser.packageName), accepted(selected().copy(sampleSelected = setOf("unknown.sample"))).selectedPackages)
    }
    @Test fun unloadedForgedChoicesAreRejected() {
        rejected(selected().copy(loaded = false), SelectedCaptureRejection.INVENTORY_NOT_READY)
    }
    @Test fun firstLoadFailureIsRejected() {
        val request = AppSelection.beginRefresh(AppSelectionState(mode = AppCatalogMode.INSTALLED), false)
        rejected(AppSelection.failed(request, request.requestId), SelectedCaptureRejection.INVENTORY_NOT_READY)
    }
    @Test fun loadingRetainedSuccessfulChoicesAreRejected() {
        val request = AppSelection.beginRefresh(selected(), false)
        assertTrue(request.loaded)
        assertFalse(request.installedSelected.isEmpty())
        rejected(request, SelectedCaptureRejection.INVENTORY_NOT_READY)
    }
    @Test fun failedRefreshRetainedSuccessfulChoicesAreRejected() {
        val request = AppSelection.beginRefresh(selected(), false)
        val failed = AppSelection.failed(request, request.requestId)
        assertTrue(failed.loaded)
        assertFalse(failed.installedSelected.isEmpty())
        rejected(failed, SelectedCaptureRejection.INVENTORY_NOT_READY)
    }
    @Test fun forgedUnknownChoiceRejectsWholeRequestNotJustUnknownPackage() {
        rejected(selected().copy(installedSelected = setOf(browser.packageName, "unknown.package")), SelectedCaptureRejection.PACKAGE_NOT_INSTALLED)
    }
    @Test fun emptySelectionRejected() {
        rejected(loaded(), SelectedCaptureRejection.INVALID_SELECTION_SIZE)
    }
    @Test fun sixtyFourAcceptedAndSixtyFiveRejected() {
        val entries = (1..65).map { InstalledAppEntry("local.app$it", "App $it", false) }
        val state = loaded(entries)
        val sixtyFour = entries.take(64).map { it.packageName }.toSet()
        assertEquals(sixtyFour, accepted(state.copy(installedSelected = sixtyFour)).selectedPackages)
        rejected(state.copy(installedSelected = entries.map { it.packageName }.toSet()), SelectedCaptureRejection.INVALID_SELECTION_SIZE)
    }
    @Test fun malformedSelectedPackagesRejectedEvenIfPresentInInventory() {
        listOf("", "single", "local.1app", "1local.app", "local._app", "local..app", ".local.app", "local.app.", "local.app-name", " local.app", "local.app\n", "local.äpp").forEach { name ->
            val state = loaded(listOf(browser, browser.copy(packageName = name))).copy(installedSelected = setOf(browser.packageName, name))
            rejected(state, SelectedCaptureRejection.INVALID_SELECTED_PACKAGE)
        }
    }
    @Test fun serviceCompatibleUppercaseUnderscoresAndDigitsAccepted() {
        val name = "Local_A.app2"
        assertEquals(setOf(name), accepted(loaded(listOf(browser.copy(packageName = name))).copy(installedSelected = setOf(name))).selectedPackages)
    }
    @Test fun companionChoiceRejectsWholeRequest() {
        val state = loaded(listOf(browser, browser.copy(packageName = companion))).copy(installedSelected = setOf(browser.packageName, companion))
        rejected(state, SelectedCaptureRejection.COMPANION_SELECTED)
    }
    @Test fun invalidConfiguredCompanionCannotBypassExclusion() {
        listOf("", "single", "com.1app", " com.httpfreekit.android.debug", "$companion\n", "com.httpfreekit.android.debug.").forEach { identity ->
            rejected(selected(), SelectedCaptureRejection.INVALID_COMPANION_PACKAGE, identity)
        }
    }
    @Test fun actualConfiguredIdentityIsExcludedWithoutHardcodedApplicationId() {
        rejected(selected(), SelectedCaptureRejection.COMPANION_SELECTED, browser.packageName)
    }
}
