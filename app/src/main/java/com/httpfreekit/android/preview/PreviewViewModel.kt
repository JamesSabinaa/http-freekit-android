package com.httpfreekit.android.preview

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import java.time.Instant

/** Retains the local preview across configuration changes, never across a new process. */
class PreviewViewModel : ViewModel() {
    var state by mutableStateOf(PreviewState())
        private set

    fun dispatch(action: PreviewAction) {
        state = PreviewCoordinator.reduce(state, action)
    }

    fun reviewInvitation(payload: String) {
        state = PreviewCoordinator.review(state, payload, Instant.now())
    }
}
