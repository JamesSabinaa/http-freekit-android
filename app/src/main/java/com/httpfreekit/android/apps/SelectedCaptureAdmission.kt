package com.httpfreekit.android.apps

/** Local finite reasons only; never includes inventory or package details. */
enum class SelectedCaptureRejection {
    INSTALLED_MODE_REQUIRED,
    INVENTORY_NOT_READY,
    INVALID_COMPANION_PACKAGE,
    INVALID_SELECTION_SIZE,
    INVALID_SELECTED_PACKAGE,
    COMPANION_SELECTED,
    PACKAGE_NOT_INSTALLED,
}

sealed interface SelectedCaptureResult {
    class Accepted(val plan: SelectedCapturePlan) : SelectedCaptureResult {
        override fun toString() = "SelectedCaptureResult.Accepted([REDACTED])"
    }
    class Rejected(val reason: SelectedCaptureRejection) : SelectedCaptureResult {
        override fun toString() = "SelectedCaptureResult.Rejected([REDACTED])"
    }
}

/** Pure, whole-request admission only. Does not start capture or prove platform/transport readiness. */
object SelectedCaptureAdmission {
    // Keep compatible with CaptureVpnService's package admission, including letter-led segments.
    private val packageSyntax = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")

    fun prepare(selection: AppSelectionState, companionPackageName: String): SelectedCaptureResult {
        if (selection.mode != AppCatalogMode.INSTALLED) return reject(SelectedCaptureRejection.INSTALLED_MODE_REQUIRED)
        if (!selection.loaded || selection.loading || selection.failed) return reject(SelectedCaptureRejection.INVENTORY_NOT_READY)
        if (!packageSyntax.matches(companionPackageName)) return reject(SelectedCaptureRejection.INVALID_COMPANION_PACKAGE)
        val selected = LinkedHashSet(selection.installedSelected)
        if (selected.size !in 1..64) return reject(SelectedCaptureRejection.INVALID_SELECTION_SIZE)
        if (selected.any { !packageSyntax.matches(it) }) return reject(SelectedCaptureRejection.INVALID_SELECTED_PACKAGE)
        if (companionPackageName in selected) return reject(SelectedCaptureRejection.COMPANION_SELECTED)
        // The full successful inventory is authoritative here, never the search/filter projection.
        if (selected.any { name -> selection.installed.none { it.packageName == name } }) {
            return reject(SelectedCaptureRejection.PACKAGE_NOT_INSTALLED)
        }
        return SelectedCaptureResult.Accepted(SelectedCapturePlan(selected))
    }

    private fun reject(reason: SelectedCaptureRejection) = SelectedCaptureResult.Rejected(reason)
}
