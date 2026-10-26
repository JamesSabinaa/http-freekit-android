package com.httpfreekit.android.preview

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import android.os.Handler
import android.os.Looper
import com.httpfreekit.android.apps.AppCatalogMode
import com.httpfreekit.android.apps.AppSelection
import com.httpfreekit.android.apps.AppSelectionAction
import com.httpfreekit.android.apps.AppSelectionState
import com.httpfreekit.android.apps.InstalledAppCatalog
import java.time.Instant
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Future
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import com.httpfreekit.android.apps.SelectedPackageProbe
import com.httpfreekit.android.apps.SelectedPackageAvailability

/** Retains the local preview across configuration changes, never across a new process. */
class PreviewViewModel(
    private val installedApps: InstalledAppCatalog,
    private val companionPackageName: String = "",
    private val selectedPackageProbe: SelectedPackageProbe = SelectedPackageProbe { SelectedPackageAvailability.UNAVAILABLE },
) : ViewModel() {
    var preflight by mutableStateOf(SelectedCapturePreflightState())
        private set
    private val checkWorker = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, SynchronousQueue(),
        { task -> Thread(task, "selected-app-preflight").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    private var checkCancellation: CheckCancellation? = null

    private class CheckCancellation {
        val cancelled = AtomicBoolean(false)
        val thread = AtomicReference<Thread?>(null)
        fun cancel() { cancelled.set(true); thread.get()?.interrupt() }
    }

    private fun invalidatePreflight() {
        preflight = preflight.invalidate()
        checkCancellation?.cancel()
    }

    fun onActivityStarted() {
        if (cleared) return
        checkCancellation?.cancel()
        preflight = preflight.started()
    }

    fun onActivityStopped() {
        if (cleared) return
        checkCancellation?.cancel()
        preflight = preflight.stopped()
    }

    fun checkSelectedApps() {
        val next = preflight.begin(apps, state.canStop)
        if (next == preflight) return
        preflight = next
        val request = checkNotNull(next.activeRequest)
        val selection = apps
        val cancellation = CheckCancellation()
        checkCancellation = cancellation
        try {
            checkWorker.execute {
                cancellation.thread.set(Thread.currentThread())
                val outcome = try {
                    if (cancellation.cancelled.get()) SelectedCapturePreflightPhase.REJECTED
                    else checkSelectedCapture(selection, companionPackageName, selectedPackageProbe)
                } finally {
                    cancellation.thread.set(null)
                    // Do not let cancellation interrupt leak into the next task.
                    Thread.interrupted()
                }
                main.post {
                    if (!cleared) {
                        preflight = preflight.complete(request, outcome, apps, state.canStop)
                        if (checkCancellation === cancellation) checkCancellation = null
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            checkCancellation = null
            preflight = preflight.complete(request, SelectedCapturePreflightPhase.REJECTED, apps, state.canStop)
        }
    }
    var state by mutableStateOf(PreviewState())
        private set
    var apps by mutableStateOf(AppSelectionState())
        private set
    private val main = Handler(Looper.getMainLooper())
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1),
        { task -> Thread(task, "installed-app-catalog").apply { isDaemon = true } }, ThreadPoolExecutor.DiscardOldestPolicy())
    private var pending: Future<*>? = null
    private var cleared = false

    fun dispatch(action: PreviewAction) {
        if (action is PreviewAction.SelectApp) {
            val next = AppSelection.select(apps, action.id, action.selected, state.canStop)
            if (next != apps) {
                invalidatePreflight()
                apps = next
                state = state.copy(selectedAppIds = apps.selectedIds, problem = null)
            }
            return
        }
        if (action == PreviewAction.LoadSampleComputer) {
            if (state.canStop) return
            invalidatePreflight()
            apps = AppSelection.mode(apps, AppCatalogMode.SAMPLE, false)
            pending?.cancel(true)
        }
        val wasLocked = state.canStop
        state = PreviewCoordinator.reduce(state, action)
        if (wasLocked != state.canStop || action == PreviewAction.Stop || action == PreviewAction.Restart) invalidatePreflight()
        if (wasLocked && !state.canStop) apps = AppSelection.reconcile(apps)
        state = state.copy(selectedAppIds = apps.selectedIds)
    }

    fun dispatchApps(action: AppSelectionAction) {
        when (action) {
            is AppSelectionAction.Mode -> {
                val next = AppSelection.mode(apps, action.value, state.canStop)
                if (next == apps) return
                invalidatePreflight()
                apps = next
                state = state.copy(selectedAppIds = apps.selectedIds, problem = null)
                pending?.cancel(true)
                if (action.value == AppCatalogMode.INSTALLED) refresh()
            }
            is AppSelectionAction.Filter -> apps = apps.copy(filter = action.value)
            is AppSelectionAction.Search -> apps = apps.copy(search = action.value.take(256))
            AppSelectionAction.Refresh -> refresh()
        }
    }

    private fun refresh() {
        invalidatePreflight()
        val next = AppSelection.beginRefresh(apps, state.canStop)
        if (next == apps || cleared) return
        apps = next
        val request = apps.requestId
        pending?.cancel(true)
        worker.purge()
        pending = worker.submit {
            try {
                val entries = installedApps.load()
                main.post {
                    if (!cleared) {
                        apps = AppSelection.succeeded(apps, request, entries, state.canStop)
                        state = state.copy(selectedAppIds = apps.selectedIds)
                    }
                }
            } catch (_: RuntimeException) {
                main.post { if (!cleared) apps = AppSelection.failed(apps, request) }
            }
        }
    }

    fun reviewInvitation(payload: String) {
        val wasLocked = state.canStop
        state = PreviewCoordinator.review(state, payload, Instant.now())
        if (wasLocked != state.canStop) invalidatePreflight()
    }

    override fun onCleared() {
        cleared = true
        preflight = preflight.clear()
        checkCancellation?.cancel()
        checkCancellation = null
        checkWorker.shutdownNow()
        pending?.cancel(true)
        worker.shutdownNow()
        main.removeCallbacksAndMessages(null)
        super.onCleared()
    }
}
