package com.httpfreekit.android.preview

import android.os.Looper
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.httpfreekit.android.MainActivity
import com.httpfreekit.android.R
import com.httpfreekit.android.apps.AppCatalogMode
import com.httpfreekit.android.apps.AppSelectionAction
import com.httpfreekit.android.apps.InstalledAppCatalog
import com.httpfreekit.android.apps.InstalledAppEntry
import com.httpfreekit.android.apps.SelectedPackageAvailability
import com.httpfreekit.android.apps.SelectedPackageProbe
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Authored controlled-fixture tests only. No inventory mutation, shell, permission or capture action. */
@RunWith(AndroidJUnit4::class)
class SelectedCapturePreflightActivityTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    private lateinit var model: PreviewViewModel
    private val availability = AtomicReference(SelectedPackageAvailability.AVAILABLE)
    private val entered = CountDownLatch(1)
    private val release = CountDownLatch(1)
    private val calls = AtomicInteger()
    private val interruptions = AtomicInteger()
    @Volatile private var hold = false
    @Volatile private var offMain = false

    @Before fun installControlledRetainedModel() {
        compose.activityRule.scenario.onActivity { activity ->
            // Replace only this test Activity's store, then recreate so production lifecycle forwarding
            // and Compose both resolve the controlled retained ViewModel through the unchanged API.
            activity.viewModelStore.clear()
            val factory = object : ViewModelProvider.Factory {
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    @Suppress("UNCHECKED_CAST")
                    return PreviewViewModel(InstalledAppCatalog {
                        listOf(InstalledAppEntry(FIXTURE, "Controlled app", true))
                    }, activity.applicationContext.packageName, SelectedPackageProbe {
                        offMain = Looper.myLooper() != Looper.getMainLooper()
                        calls.incrementAndGet()
                        entered.countDown()
                        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
                        while (hold && release.count > 0 && System.nanoTime() < deadline) {
                            try { release.await(20, TimeUnit.MILLISECONDS) }
                            catch (_: InterruptedException) { interruptions.incrementAndGet() }
                        }
                        availability.get()
                    }) as T
                }
            }
            model = ViewModelProvider(activity, factory)[PreviewViewModel::class.java]
        }
        compose.activityRule.scenario.recreate()
        compose.runOnIdle { model.dispatchApps(AppSelectionAction.Mode(AppCatalogMode.INSTALLED)) }
        compose.waitUntil(5_000) { model.apps.loaded && !model.apps.loading }
        compose.runOnIdle { model.dispatch(PreviewAction.SelectApp(FIXTURE, true)) }
        safeUi {
            compose.onNode(hasText(compose.activity.getString(R.string.page_apps)) and hasClickAction())
                .performScrollTo().performClick()
        }
    }

    @After fun releaseFixture() { release.countDown() }

    @Test fun explicitActionChecksOffMainAndNeverUpgradesPreviewReadiness() {
        val before = model.state
        assertEquals(0, calls.get())
        clickCheck()
        waitPhase(SelectedCapturePreflightPhase.CHECKED)
        assertTrue(offMain)
        assertEquals(1, calls.get())
        assertEquals(before, model.state)
        assertNoCapture()
        safeUi {
            val status = compose.onNodeWithTag("selected-check-status").fetchSemanticsNode()
            assertEquals("checked", status.config[SemanticsProperties.StateDescription])
        }
    }

    @Test fun unavailablePackageRejectsWithoutChangingSelectionOrPreview() {
        availability.set(SelectedPackageAvailability.DISABLED)
        val before = model.state
        clickCheck()
        waitPhase(SelectedCapturePreflightPhase.REJECTED)
        assertEquals(before, model.state)
        assertEquals(setOf(FIXTURE), model.apps.installedSelected)
        assertNoCapture()
    }

    @Test fun selectionCancellationAndIgnoredInterruptRemainSingleFlight() {
        hold = true
        clickCheck()
        assertTrue("Controlled probe did not enter", entered.await(5, TimeUnit.SECONDS))
        compose.runOnIdle {
            model.dispatch(PreviewAction.SelectApp(FIXTURE, false))
            assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
            assertNotNull(model.preflight.activeRequest)
            model.checkSelectedApps()
            model.dispatch(PreviewAction.SelectApp(FIXTURE, true))
            model.checkSelectedApps()
        }
        assertEquals(1, calls.get())
        compose.waitUntil(5_000) { interruptions.get() > 0 }
        release.countDown()
        compose.waitUntil(5_000) { model.preflight.activeRequest == null }
        assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
        assertTrue("Controlled worker did not observe cancellation", interruptions.get() > 0)
        clickCheck()
        waitPhase(SelectedCapturePreflightPhase.CHECKED)
        assertEquals(2, calls.get())
    }

    @Test fun actualActivityBackgroundAndReturnInvalidateWithoutAutomaticCheck() {
        clickCheck()
        waitPhase(SelectedCapturePreflightPhase.CHECKED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitForIdle()
        assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
        assertEquals(1, calls.get())
        assertNoCapture()
    }

    @Test fun configurationRecreationRetainsSelectionButSuppressesOldCompletion() {
        hold = true
        clickCheck()
        assertTrue("Controlled probe did not enter", entered.await(5, TimeUnit.SECONDS))
        compose.activityRule.scenario.recreate()
        compose.activityRule.scenario.onActivity { activity ->
            assertSame(model, ViewModelProvider(activity)[PreviewViewModel::class.java])
            assertEquals(setOf(FIXTURE), model.apps.installedSelected)
            model.checkSelectedApps()
        }
        assertEquals(1, calls.get())
        release.countDown()
        compose.waitUntil(5_000) { model.preflight.activeRequest == null }
        assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
    }

    @Test fun refreshAndModeChangesInvalidateWithoutAutomaticChecks() {
        clickCheck()
        waitPhase(SelectedCapturePreflightPhase.CHECKED)
        compose.runOnIdle { model.dispatchApps(AppSelectionAction.Refresh) }
        compose.waitUntil(5_000) { model.apps.loaded && !model.apps.loading }
        assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
        assertEquals(1, calls.get())
        clickCheck()
        waitPhase(SelectedCapturePreflightPhase.CHECKED)
        compose.runOnIdle {
            model.dispatchApps(AppSelectionAction.Mode(AppCatalogMode.SAMPLE))
            assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
            model.checkSelectedApps()
            model.dispatchApps(AppSelectionAction.Mode(AppCatalogMode.INSTALLED))
        }
        compose.waitUntil(5_000) { !model.apps.loading }
        assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
        assertEquals(2, calls.get())
    }

    @Test fun previewLockAndStopSuppressPendingCheckWithoutRequestingPermissions() {
        compose.runOnIdle {
            model.dispatch(PreviewAction.LoadSampleComputer)
            model.dispatchApps(AppSelectionAction.Mode(AppCatalogMode.INSTALLED))
        }
        compose.waitUntil(5_000) { !model.apps.loading }
        hold = true
        clickCheck()
        assertTrue("Controlled probe did not enter", entered.await(5, TimeUnit.SECONDS))
        compose.runOnIdle {
            // Both are local preview reducer actions in one main-thread turn. No permission UI or
            // platform consent is requested, and a checked result cannot authorize this simulation.
            model.dispatch(PreviewAction.Connect)
            assertTrue(model.state.canStop)
            assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
            model.checkSelectedApps()
            model.dispatch(PreviewAction.Stop)
            model.checkSelectedApps()
            assertFalse(model.state.canStop)
        }
        assertEquals(1, calls.get())
        release.countDown()
        compose.waitUntil(5_000) { model.preflight.activeRequest == null }
        assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
    }

    @Test fun clearingActualOwnerCancelsAndPermanentlySuppressesLatePublication() {
        hold = true
        clickCheck()
        assertTrue("Controlled probe did not enter", entered.await(5, TimeUnit.SECONDS))
        compose.activityRule.scenario.onActivity { it.viewModelStore.clear() }
        assertTrue(model.preflight.cleared)
        release.countDown()
        compose.runOnIdle { model.checkSelectedApps(); model.onActivityStarted() }
        assertTrue(model.preflight.cleared)
        assertEquals(SelectedCapturePreflightPhase.IDLE, model.preflight.phase)
        assertEquals(1, calls.get())
    }

    private fun clickCheck() = safeUi {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag("selected-check-action"))
        compose.onNodeWithTag("selected-check-action").performScrollTo().performClick()
    }

    private fun waitPhase(phase: SelectedCapturePreflightPhase) {
        compose.waitUntil(5_000) { model.preflight.phase == phase }
    }

    private fun assertNoCapture() = safeUi {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag("selected-check-no-capture"))
        compose.onNodeWithTag("selected-check-no-capture").performScrollTo().assertIsDisplayed()
        assertFalse(model.state.canStop)
        assertEquals(PreviewPhase.IDLE, model.state.phase)
        assertFalse(model.state.vpnConsent)
    }

    // Never allow Compose assertion trees/provider exceptions to print package inventory.
    private fun safeUi(action: () -> Unit) {
        try { action() }
        catch (_: AssertionError) { throw AssertionError("Controlled selected-app UI assertion failed") }
        catch (_: Exception) { throw AssertionError("Controlled selected-app UI action failed") }
    }

    companion object { private const val FIXTURE = "com.httpfreekit.fixture.installedapps" }
}
