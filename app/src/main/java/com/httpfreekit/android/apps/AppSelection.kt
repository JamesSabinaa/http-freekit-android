package com.httpfreekit.android.apps

import java.util.Collections
import java.util.Locale

data class InstalledAppEntry(val packageName: String, val label: String, val development: Boolean) {
    override fun toString() = "InstalledAppEntry([REDACTED])"
}

fun interface InstalledAppCatalog { fun load(): List<InstalledAppEntry> }
enum class AppCatalogMode { SAMPLE, INSTALLED }
enum class AppFilter { ALL, DEVELOPMENT }

/** In-memory choices only. Package inventory and selection never enter preview diagnostics. */
data class AppSelectionState(
    val mode: AppCatalogMode = AppCatalogMode.SAMPLE,
    val installed: List<InstalledAppEntry> = emptyList(),
    val sampleSelected: Set<String> = emptySet(),
    val installedSelected: Set<String> = emptySet(),
    val filter: AppFilter = AppFilter.ALL,
    val search: String = "",
    val loading: Boolean = false,
    val loaded: Boolean = false,
    val failed: Boolean = false,
    val requestId: Long = 0,
) {
    val selectedIds: Set<String> get() = if (mode == AppCatalogMode.SAMPLE) sampleSelected else installedSelected
    val visibleInstalled: List<InstalledAppEntry> get() {
        val query = search.trim().lowercase(Locale.ROOT)
        return installed.filter { app ->
            (filter == AppFilter.ALL || app.development) &&
                (query.isEmpty() || app.label.lowercase(Locale.ROOT).contains(query) || app.packageName.lowercase(Locale.ROOT).contains(query))
        }
    }
    override fun toString() = "AppSelectionState(mode=$mode, loading=$loading, inventory=[REDACTED])"
}

sealed interface AppSelectionAction {
    data class Mode(val value: AppCatalogMode) : AppSelectionAction
    data class Filter(val value: AppFilter) : AppSelectionAction
    data class Search(val value: String) : AppSelectionAction
    data object Refresh : AppSelectionAction
}

object AppSelection {
    val SAMPLE_IDS: Set<String> = Collections.unmodifiableSet(linkedSetOf("example.browser", "example.debugclient", "example.chat"))

    fun mode(state: AppSelectionState, mode: AppCatalogMode, locked: Boolean): AppSelectionState =
        if (locked || state.mode == mode) state else state.copy(mode = mode, loading = false, requestId = state.requestId + 1)

    fun beginRefresh(state: AppSelectionState, locked: Boolean): AppSelectionState =
        if (locked || state.mode != AppCatalogMode.INSTALLED || state.loading) state else state.copy(
            loading = true, failed = false, requestId = state.requestId + 1,
        )

    fun succeeded(state: AppSelectionState, request: Long, entries: List<InstalledAppEntry>, locked: Boolean): AppSelectionState {
        if (state.mode != AppCatalogMode.INSTALLED || !state.loading || request != state.requestId) return state
        val snapshot = Collections.unmodifiableList(entries.sortedWith(
            compareBy<InstalledAppEntry> { it.label.lowercase(Locale.ROOT) }.thenBy { it.packageName },
        ).distinctBy { it.packageName })
        val next = state.copy(installed = snapshot, loaded = true, loading = false, failed = false)
        return if (locked) next else reconcile(next)
    }

    fun failed(state: AppSelectionState, request: Long): AppSelectionState =
        if (state.mode != AppCatalogMode.INSTALLED || !state.loading || request != state.requestId) state
        else state.copy(loading = false, failed = true)

    fun select(state: AppSelectionState, id: String, selected: Boolean, locked: Boolean): AppSelectionState {
        if (locked || (if (state.mode == AppCatalogMode.SAMPLE) id !in SAMPLE_IDS else state.installed.none { it.packageName == id })) return state
        val ids = if (selected) state.selectedIds + id else state.selectedIds - id
        return if (state.mode == AppCatalogMode.SAMPLE) state.copy(sampleSelected = immutable(ids))
        else state.copy(installedSelected = immutable(ids))
    }

    /** A successful scan can update inventory while active, but selection stays pinned until Stop. */
    fun reconcile(state: AppSelectionState): AppSelectionState = if (!state.loaded) state else state.copy(
        installedSelected = immutable(state.installedSelected.intersect(state.installed.map { it.packageName }.toSet())),
    )

    private fun immutable(ids: Set<String>): Set<String> = Collections.unmodifiableSet(LinkedHashSet(ids))
}
