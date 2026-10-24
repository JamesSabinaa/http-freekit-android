package com.httpfreekit.android.preview

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToIndex
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.android.MainActivity
import com.httpfreekit.android.R
import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises the shipped activity using only its public, sample-only preview controls. */
@RunWith(AndroidJUnit4::class)
class PreviewActivityTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Before fun startInPortrait() {
        rotate(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT, Configuration.ORIENTATION_PORTRAIT)
    }

    @Test fun noCaptureWarningAppearsOnEveryPreviewPage() {
        assertPreviewWarning()
        for ((page, lowerContent) in listOf(
            R.string.page_apps to R.string.sample_chat,
            R.string.page_setup to R.string.help_stop_title,
            R.string.page_diagnostics to R.string.restart_preview,
            R.string.page_home to R.string.try_sample,
        )) {
            openPage(page)
            assertPreviewWarning()
            scrollBodyTo(lowerContent)
            compose.onNodeWithText(label(R.string.preview_banner)).assertIsDisplayed()
        }
        assertPreviewWarning()
        compose.onNodeWithText(label(R.string.no_traffic_captured)).assertIsDisplayed()
    }

    @Test fun sampleComputerAndAppSelectionsSurviveRotation() {
        loadSampleAndSelectApps()
        openPage(R.string.page_apps)
        rotate(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE, Configuration.ORIENTATION_LANDSCAPE)
        // The Apps page is rememberSaveable state; selections/computer belong to the activity ViewModel.
        assertPreviewWarning()
        assertAppSelected(R.string.sample_browser)
        assertAppSelected(R.string.sample_debug)
        rotate(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT, Configuration.ORIENTATION_PORTRAIT)
        assertAppSelected(R.string.sample_browser)
        assertAppSelected(R.string.sample_debug)
        openPage(R.string.page_home)
        assertPreviewWarning()
        compose.onNodeWithText(sampleTransport()).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.selected_apps_count, 2)).assertIsDisplayed()
    }

    @Test fun simulatedConsentReachesReadyAndStopWithoutClaimingCapture() {
        loadSampleAndSelectApps()
        clickBody(R.string.start_preview)
        compose.onNodeWithText(label(R.string.notification_title)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.notification_body)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.allow_preview)).performClick()
        compose.onNodeWithText(label(R.string.vpn_title)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.vpn_body)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.allow_preview)).performClick()
        compose.waitUntil(timeoutMillis = 15_000) {
            compose.onAllNodes(hasText(label(R.string.phase_connected))).fetchSemanticsNodes().isNotEmpty()
        }
        assertPreviewWarning()
        compose.onNodeWithText(label(R.string.phase_connected)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.no_traffic_captured)).assertIsDisplayed()
        saveSampleScreenshot()
        clickBody(R.string.stop_preview)
        assertPreviewWarning()
        compose.onNodeWithText(label(R.string.phase_idle)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.start_preview)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.no_traffic_captured)).assertIsDisplayed()
    }

    @Test fun deniedNotificationAndCancelledVpnConsentStayInPreview() {
        loadSampleAndSelectApps()
        clickBody(R.string.start_preview)
        compose.onNodeWithText(label(R.string.notification_title)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.deny)).performClick()
        assertBodyText(R.string.error_notifications)
        clickBody(R.string.start_preview)
        compose.onNodeWithText(label(R.string.notification_title)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.allow_preview)).performClick()
        compose.onNodeWithText(label(R.string.vpn_title)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.cancel)).performClick()
        assertBodyText(R.string.error_consent)
        assertPreviewWarning()
        compose.onNodeWithText(label(R.string.phase_disconnected)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.no_traffic_captured)).assertIsDisplayed()
    }

    private fun loadSampleAndSelectApps() {
        clickBody(R.string.try_sample)
        assertPreviewWarning()
        compose.onNodeWithText(sampleTransport()).assertIsDisplayed()
        openPage(R.string.page_apps)
        for (app in listOf(R.string.sample_browser, R.string.sample_debug)) {
            scrollBodyTo(app)
            compose.onNode(hasText(label(app)) and isToggleable()).assertIsOff().performClick().assertIsOn()
        }
        openPage(R.string.page_home)
        assertPreviewWarning()
        compose.onNodeWithText(label(R.string.selected_apps_count, 2)).assertIsDisplayed()
    }

    private fun assertAppSelected(app: Int) {
        scrollBodyTo(app)
        compose.onNode(hasText(label(app)) and isToggleable()).assertIsOn()
    }

    private fun openPage(page: Int) {
        compose.onNode(hasText(label(page)) and hasClickAction()).performScrollTo().performClick()
    }

    private fun assertPreviewWarning() {
        compose.onNode(hasScrollToIndexAction()).performScrollToIndex(0)
        compose.onNodeWithText(label(R.string.preview_banner)).assertIsDisplayed()
    }

    private fun scrollBodyTo(text: Int) {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label(text)))
    }

    private fun clickBody(text: Int) {
        scrollBodyTo(text)
        compose.onNode(hasText(label(text)) and hasClickAction()).performClick()
    }

    private fun assertBodyText(text: Int) {
        scrollBodyTo(text)
        compose.onNodeWithText(label(text)).assertIsDisplayed()
    }

    private fun rotate(requested: Int, expected: Int) {
        compose.activityRule.scenario.onActivity { it.requestedOrientation = requested }
        compose.waitUntil(timeoutMillis = 15_000) {
            compose.activity.resources.configuration.orientation == expected
        }
        compose.waitForIdle()
    }

    private fun saveSampleScreenshot() {
        compose.waitForIdle()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val screenshot = requireNotNull(instrumentation.uiAutomation.takeScreenshot()) { "No rendered screenshot returned" }
        try {
            val output = File(instrumentation.targetContext.filesDir, "sample-preview-ready.png")
            output.outputStream().use { stream ->
                assertTrue("PNG compression failed", screenshot.compress(Bitmap.CompressFormat.PNG, 100, stream))
            }
            assertTrue("Screenshot is empty", output.length() > 0)
        } finally {
            screenshot.recycle()
        }
    }

    private fun sampleTransport() = label(R.string.computer_transport, "Studio computer", "USB")
    private fun label(resource: Int, vararg arguments: Any) = compose.activity.getString(resource, *arguments)
}
