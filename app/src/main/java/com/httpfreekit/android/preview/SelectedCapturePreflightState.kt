package com.httpfreekit.android.preview

import com.httpfreekit.android.apps.AppCatalogMode
import com.httpfreekit.android.apps.AppSelectionState
import com.httpfreekit.android.apps.SelectedCapturePlatformAdmission
import com.httpfreekit.android.apps.SelectedCapturePlatformResult
import com.httpfreekit.android.apps.SelectedPackageProbe

/** Finite presentation only: a past check is never a retained capture plan or Start authority. */
enum class SelectedCapturePreflightPhase { IDLE, CHECKING, CHECKED, REJECTED }

/** Main-thread-owned reducer. Invalidation does not release single-flight ownership. */
data class SelectedCapturePreflightState(
    val phase: SelectedCapturePreflightPhase = SelectedCapturePreflightPhase.IDLE,
    val generation: Long = 0,
    val activeRequest: Long? = null,
    val foreground: Boolean = false,
    val cleared: Boolean = false,
) {
    fun canCheck(selection: AppSelectionState, locked: Boolean): Boolean =
        !cleared && foreground && activeRequest == null && eligible(selection, locked)

    fun begin(selection: AppSelectionState, locked: Boolean): SelectedCapturePreflightState =
        if (!canCheck(selection, locked)) this else copy(
            generation = generation + 1, activeRequest = generation + 1,
            phase = SelectedCapturePreflightPhase.CHECKING,
        )

    fun invalidate(): SelectedCapturePreflightState = copy(
        generation = generation + 1, phase = SelectedCapturePreflightPhase.IDLE,
    )

    fun started(): SelectedCapturePreflightState = if (cleared) this else invalidate().copy(foreground = true)
    fun stopped(): SelectedCapturePreflightState = invalidate().copy(foreground = false)
    fun clear(): SelectedCapturePreflightState = stopped().copy(cleared = true)

    fun complete(request: Long, outcome: SelectedCapturePreflightPhase, selection: AppSelectionState,
        locked: Boolean): SelectedCapturePreflightState {
        if (request != activeRequest) return this
        val publish = !cleared && foreground && request == generation && eligible(selection, locked)
        return copy(activeRequest = null, phase = if (publish &&
            (outcome == SelectedCapturePreflightPhase.CHECKED || outcome == SelectedCapturePreflightPhase.REJECTED)) outcome
            else SelectedCapturePreflightPhase.IDLE)
    }

    companion object {
        private fun eligible(selection: AppSelectionState, locked: Boolean): Boolean =
            !locked && selection.mode == AppCatalogMode.INSTALLED && selection.loaded &&
                !selection.loading && !selection.failed
    }
}

/** Runs only on the owned worker. Discard plans immediately; never retain provider failures. */
internal fun checkSelectedCapture(selection: AppSelectionState, companionPackageName: String,
    probe: SelectedPackageProbe): SelectedCapturePreflightPhase = try {
    when (SelectedCapturePlatformAdmission.check(selection, companionPackageName, probe)) {
        is SelectedCapturePlatformResult.Checked -> SelectedCapturePreflightPhase.CHECKED
        is SelectedCapturePlatformResult.Rejected -> SelectedCapturePreflightPhase.REJECTED
    }
} catch (_: Exception) {
    SelectedCapturePreflightPhase.REJECTED
}
