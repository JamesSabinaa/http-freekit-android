package com.httpfreekit.android.preview

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.activity.compose.setContent
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.android.MainActivity
import com.httpfreekit.android.R
import com.httpfreekit.android.apps.AppSelectionState
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Settings navigation is real; it must never manufacture certificate or capture verification. */
@RunWith(AndroidJUnit4::class)
class CertificateHelpActivityTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Before fun startInPortrait() {
        rotate(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT, Configuration.ORIENTATION_PORTRAIT)
    }

    @Test fun realSecuritySettingsReturnAndRotationKeepTrustUnverified() {
        assertUnverified()
        openHelp()
        saveHelpScreenshot()
        val appPackage = compose.activity.packageName
        compose.onNodeWithTag("certificate-open-security-settings").performScrollTo().performClick()

        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        // The workflow uses stock Android images. Observe the actual foreground Settings window.
        compose.waitUntil(timeoutMillis = 15_000) {
            automation.rootInActiveWindow?.packageName?.toString() == "com.android.settings"
        }
        automation.executeShellCommand("input keyevent KEYCODE_BACK").close()
        compose.waitUntil(timeoutMillis = 15_000) {
            automation.rootInActiveWindow?.packageName?.toString() == appPackage
        }
        compose.onNodeWithTag("certificate-help-panel").assertIsDisplayed()
        rotate(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE, Configuration.ORIENTATION_LANDSCAPE)
        compose.onNodeWithTag("certificate-help-panel").assertIsDisplayed()
        compose.onNodeWithTag("certificate-help-close").performClick()
        openPage(R.string.page_home)
        assertUnverified()
        rotate(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT, Configuration.ORIENTATION_PORTRAIT)
        assertUnverified()
    }

    @Test fun unavailableSettingsAndCopiedDebugExamplesNeverChangeReadiness() {
        val settingsCalls = AtomicInteger()
        val modelActions = AtomicInteger()
        val copies = mutableListOf<String>()
        compose.activityRule.scenario.onActivity { activity ->
            activity.setContent {
                PreviewApp(
                    state = PreviewState(), apps = AppSelectionState(),
                    onAction = { modelActions.incrementAndGet() },
                    onAppsAction = { modelActions.incrementAndGet() },
                    onInvitation = { modelActions.incrementAndGet() },
                    onOpenSecuritySettings = { settingsCalls.incrementAndGet(); false },
                    onCopyConfiguration = { copies.add(it) },
                )
            }
        }
        openHelp()
        compose.onNodeWithTag("certificate-open-security-settings").performScrollTo().performClick()
        compose.onNodeWithTag("certificate-settings-unavailable").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("debug-config-toggle").performScrollTo().performClick()
        for (tag in listOf("debug-manifest-copy", "debug-trust-copy")) {
            compose.onNodeWithTag(tag).performScrollTo().performClick()
        }
        compose.runOnIdle {
            assertEquals(1, settingsCalls.get())
            assertEquals(2, copies.size)
            assertTrue(copies.any { it.contains("android:networkSecurityConfig=") })
            assertTrue(copies.any { it.contains("overridePins=\"false\"") })
            assertEquals(0, modelActions.get())
        }
        compose.onNodeWithTag("certificate-help-close").performClick()
        openPage(R.string.page_home)
        assertUnverified()
    }

    private fun openHelp() {
        openPage(R.string.page_setup)
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag("certificate-help-toggle"))
        compose.onNodeWithTag("certificate-help-toggle").performClick()
        compose.onNodeWithTag("certificate-help-panel").assertIsDisplayed()
    }

    private fun openPage(resource: Int) {
        compose.onNode(hasText(label(resource)) and hasClickAction()).performScrollTo().performClick()
    }

    private fun assertUnverified() {
        for ((tag, check) in listOf("readiness-https" to R.string.check_https, "readiness-capture" to R.string.check_traffic)) {
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag(tag))
            compose.onNodeWithTag(tag).assertIsDisplayed().assertTextContains(label(check))
                .assertTextContains(label(R.string.check_not_verified))
        }
        compose.onNodeWithText(label(R.string.preview_banner)).assertIsDisplayed()
    }

    private fun rotate(requested: Int, expected: Int) {
        compose.activityRule.scenario.onActivity { it.requestedOrientation = requested }
        compose.waitUntil(timeoutMillis = 15_000) {
            compose.activity.resources.configuration.orientation == expected
        }
        compose.waitForIdle()
    }

    private fun saveHelpScreenshot() {
        compose.waitForIdle()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val screenshot = requireNotNull(instrumentation.uiAutomation.takeScreenshot())
        try {
            val output = File(instrumentation.targetContext.filesDir, "certificate-help.png")
            output.outputStream().use { assertTrue(screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)) }
            assertTrue(output.length() > 0)
        } finally { screenshot.recycle() }
    }

    private fun label(resource: Int) = compose.activity.getString(resource)
}
