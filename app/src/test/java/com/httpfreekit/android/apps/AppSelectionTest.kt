package com.httpfreekit.android.apps

import org.junit.Assert.*
import org.junit.Test

class AppSelectionTest {
    private val browser = InstalledAppEntry("local.browser", "Browser", false)
    private val headless = InstalledAppEntry("local.headless", "Development worker", true)
    private fun loading(state: AppSelectionState = AppSelectionState()): AppSelectionState =
        AppSelection.beginRefresh(AppSelection.mode(state, AppCatalogMode.INSTALLED, false), false)
    private fun loaded(entries: List<InstalledAppEntry> = listOf(browser, headless)): AppSelectionState = loading().let {
        AppSelection.succeeded(it, it.requestId, entries, false)
    }

    @Test fun initialSampleModeDoesNotRequestInstalledInventory() {
        val state = AppSelectionState()
        assertEquals(AppCatalogMode.SAMPLE, state.mode)
        assertFalse(state.loading)
        assertFalse(state.loaded)
        assertEquals(state, AppSelection.beginRefresh(state, false))
        assertTrue(state.installed.isEmpty())
    }
    @Test fun successfulCatalogIsSortedDeduplicatedAndDefensivelySnapshotted() {
        val entries = arrayListOf(headless, browser, browser)
        val state = loaded(entries)
        entries.clear()
        assertEquals(listOf(browser, headless), state.installed)
        assertTrue(state.loaded)
        assertFalse(state.loading)
        assertThrows(UnsupportedOperationException::class.java) { (state.installed as MutableList).clear() }
        val sameLabel = loaded(listOf(browser.copy(packageName = "z.package"), browser.copy(packageName = "a.package")))
        assertEquals(listOf("a.package", "z.package"), sameLabel.installed.map { it.packageName })
    }
    @Test fun allAndDevelopmentFiltersKeepHeadlessPackagesAndDoNotChangeSelection() {
        val state = AppSelection.select(loaded(), browser.packageName, true, false)
        assertEquals(2, state.visibleInstalled.size)
        val filtered = state.copy(filter = AppFilter.DEVELOPMENT)
        assertEquals(listOf(headless), filtered.visibleInstalled)
        assertEquals(setOf(browser.packageName), filtered.selectedIds)
    }
    @Test fun searchMatchesNameOrPackageIgnoringCaseAndDoesNotDeselectHiddenChoices() {
        val state = AppSelection.select(loaded(), headless.packageName, true, false)
        assertEquals(listOf(headless), state.copy(search = "  DEVELOPMENT  ").visibleInstalled)
        assertEquals(listOf(browser), state.copy(search = "LOCAL.BROW").visibleInstalled)
        assertTrue(state.copy(search = "absent").visibleInstalled.isEmpty())
        assertEquals(setOf(headless.packageName), state.copy(search = "absent").selectedIds)
    }
    @Test fun unknownEntriesCannotBecomeSelectedAndKnownChoicesToggleOnce() {
        var state = loaded()
        assertEquals(state, AppSelection.select(state, "unknown.package", true, false))
        state = AppSelection.select(state, headless.packageName, true, false)
        assertEquals(setOf(headless.packageName), state.selectedIds)
        assertEquals(state, AppSelection.select(state, headless.packageName, true, false))
        assertThrows(UnsupportedOperationException::class.java) { (state.selectedIds as MutableSet).clear() }
        assertTrue(AppSelection.select(state, headless.packageName, false, false).selectedIds.isEmpty())
    }
    @Test fun sampleAndInstalledSelectionsRemainSeparateEvenWhenAnIdCollides() {
        var state = AppSelection.select(AppSelectionState(), "example.browser", true, false)
        assertEquals(state, AppSelection.select(state, "unknown.sample", true, false))
        state = loading(state).let { AppSelection.succeeded(it, it.requestId, listOf(browser.copy(packageName = "example.browser"), headless), false) }
        assertTrue(state.selectedIds.isEmpty())
        state = AppSelection.select(state, headless.packageName, true, false)
        state = AppSelection.mode(state, AppCatalogMode.SAMPLE, false)
        assertEquals(setOf("example.browser"), state.selectedIds)
        state = AppSelection.mode(state, AppCatalogMode.INSTALLED, false)
        assertEquals(setOf(headless.packageName), state.selectedIds)
    }
    @Test fun successfulRefreshPrunesVanishedChoicesButNeverSelectsNewPackages() {
        var state = AppSelection.select(loaded(), headless.packageName, true, false)
        state = AppSelection.beginRefresh(state, false)
        val next = AppSelection.succeeded(state, state.requestId, listOf(browser), false)
        assertTrue(next.selectedIds.isEmpty())
        assertEquals(listOf(browser), next.installed)
        assertFalse(next.failed)
    }
    @Test fun failedRefreshPreservesLastSuccessfulListAndChoices() {
        val previous = AppSelection.select(loaded(), headless.packageName, true, false)
        val request = AppSelection.beginRefresh(previous, false)
        val failed = AppSelection.failed(request, request.requestId)
        assertEquals(previous.installed, failed.installed)
        assertEquals(previous.installedSelected, failed.installedSelected)
        assertTrue(failed.failed)
        assertFalse(failed.loading)
        assertTrue(failed.loaded)
    }
    @Test fun failedFirstLoadNeverFallsBackToFakeInstalledEntries() {
        val state = loading().let { AppSelection.failed(it, it.requestId) }
        assertTrue(state.failed)
        assertFalse(state.loaded)
        assertTrue(state.installed.isEmpty())
        assertTrue(state.selectedIds.isEmpty())
    }
    @Test fun sourceSwitchAndNewRequestRejectOutOfOrderSuccessAndFailure() {
        val first = loading()
        val sample = AppSelection.mode(first, AppCatalogMode.SAMPLE, false)
        assertEquals(sample, AppSelection.succeeded(sample, first.requestId, listOf(browser), false))
        assertEquals(sample, AppSelection.failed(sample, first.requestId))
        val second = loading(sample)
        assertTrue(second.requestId > first.requestId)
        assertEquals(second, AppSelection.succeeded(second, first.requestId, listOf(browser), false))
        val ready = AppSelection.succeeded(second, second.requestId, listOf(headless), false)
        assertEquals(ready, AppSelection.failed(ready, first.requestId))
        assertEquals(listOf(headless), ready.installed)
    }
    @Test fun activeSimulationLocksSourcesSelectionAndRefresh() {
        val state = AppSelection.select(loaded(), browser.packageName, true, false)
        assertEquals(state, AppSelection.mode(state, AppCatalogMode.SAMPLE, true))
        assertEquals(state, AppSelection.select(state, headless.packageName, true, true))
        assertEquals(state, AppSelection.select(state, browser.packageName, false, true))
        assertEquals(state, AppSelection.beginRefresh(state, true))
    }
    @Test fun inFlightSuccessCannotChangeActiveSelectionAndReconcilesAfterStop() {
        val selected = AppSelection.select(loaded(), headless.packageName, true, false)
        val request = AppSelection.beginRefresh(selected, false)
        val active = AppSelection.succeeded(request, request.requestId, listOf(browser), true)
        assertEquals(setOf(headless.packageName), active.selectedIds)
        assertEquals(listOf(browser), active.installed)
        assertTrue(AppSelection.reconcile(active).selectedIds.isEmpty())
    }
    @Test fun emptySuccessfulRefreshIsDifferentFromFailureAndPrunesInstalledOnly() {
        var state = AppSelection.select(AppSelectionState(), "example.browser", true, false)
        state = loading(state).let { AppSelection.succeeded(it, it.requestId, listOf(browser), false) }
        state = AppSelection.select(state, browser.packageName, true, false)
        state = AppSelection.beginRefresh(state, false).let { AppSelection.succeeded(it, it.requestId, emptyList(), false) }
        assertTrue(state.loaded)
        assertFalse(state.failed)
        assertTrue(state.installedSelected.isEmpty())
        assertEquals(setOf("example.browser"), state.sampleSelected)
    }
    @Test fun pollingDuringLoadDoesNotCreateDuplicateRequestsAndDiagnosticsRedactInventory() {
        val request = loading()
        assertEquals(request, AppSelection.beginRefresh(request, false))
        val canary = "DO_NOT_LOG_PACKAGE_OR_LABEL"
        val state = loaded(listOf(InstalledAppEntry(canary, canary, true)))
        assertFalse(state.toString().contains(canary))
        assertFalse(state.installed.single().toString().contains(canary))
        assertThrows(UnsupportedOperationException::class.java) { (AppSelection.SAMPLE_IDS as MutableSet).clear() }
    }
}
