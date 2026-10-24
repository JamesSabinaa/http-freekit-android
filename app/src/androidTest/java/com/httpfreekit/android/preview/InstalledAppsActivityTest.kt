package com.httpfreekit.android.preview

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.os.ParcelFileDescriptor
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextReplacement
import androidx.test.espresso.Espresso
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.android.MainActivity
import com.httpfreekit.android.R
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Public installed-catalog controls; diagnostics name only the synthetic headless fixture. */
@RunWith(AndroidJUnit4::class)
class InstalledAppsActivityTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    private var fixtureUser: String? = null

    @Before fun prepareEnabledFixture() {
        val user = shell("am get-current-user").trim()
        assertTrue("Current fixture profile could not be determined", user.matches(Regex("[0-9]{1,5}")))
        fixtureUser = user
        setFixtureEnabled(true)
        rotate(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT, Configuration.ORIENTATION_PORTRAIT)
    }

    @After fun restoreOnlyFixture() {
        if (fixtureUser != null) setFixtureEnabled(true)
    }

    @Test fun headlessFixtureSupportsSearchDevelopmentFilterAndToggle() {
        openInstalled()
        search(FIXTURE_LABEL)
        waitFixture(present = true)
        safeUi("Known fixture label or package was absent") {
            assertTrue(compose.onAllNodes(hasTestTag(FIXTURE_TAG) and hasText(FIXTURE_LABEL) and hasText(FIXTURE_PACKAGE))
                .fetchSemanticsNodes(atLeastOneRootRequired = false).size == 1)
        }
        search(FIXTURE_PACKAGE)
        clickTag("apps-filter-development")
        waitFixture(present = true)
        assertChip("apps-filter-development")
        clickTag("apps-filter-all")
        assertChip("apps-filter-all")
        assertFixtureSelected(false)
        clickTag(FIXTURE_TAG)
        assertFixtureSelected(true)
        clickTag(FIXTURE_TAG)
        assertFixtureSelected(false)
        assertPreviewWarning()
    }

    @Test fun installedSelectionSurvivesRefreshAndRotationWithoutCapture() {
        openInstalled()
        search(FIXTURE_PACKAGE)
        waitFixture(present = true)
        clickTag(FIXTURE_TAG)
        assertFixtureSelected(true)
        clickTag("apps-refresh")
        waitFixture(present = true)
        assertFixtureSelected(true)
        rotate(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE, Configuration.ORIENTATION_LANDSCAPE)
        waitFixture(present = true)
        assertFixtureSelected(true)
        assertPreviewWarning()
        rotate(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT, Configuration.ORIENTATION_PORTRAIT)
        waitFixture(present = true)
        assertFixtureSelected(true)
        assertPreviewWarning()
    }

    @Test fun successfulRefreshPrunesDisabledFixtureAndDoesNotReselectIt() {
        openInstalled()
        search(FIXTURE_PACKAGE)
        waitFixture(present = true)
        clickTag(FIXTURE_TAG)
        assertFixtureSelected(true)
        try {
            setFixtureEnabled(false)
            clickTag("apps-refresh")
            waitFixture(present = false)
            assertPreviewWarning()
        } finally {
            // Restore this package even when refresh/assertion fails. The workflow also cleans it.
            setFixtureEnabled(true)
        }
        clickTag("apps-refresh")
        waitFixture(present = true)
        assertFixtureSelected(false)
    }

    @Test fun sampleAndInstalledSelectionsRemainSeparate() {
        clickBody(R.string.try_sample)
        openApps()
        safeUi("Known sample app selection failed") {
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label(R.string.sample_browser)) and isToggleable())
            compose.onNode(hasText(label(R.string.sample_browser)) and isToggleable()).performScrollTo().performClick()
        }
        assertSampleSelected(true)
        clickTag("apps-mode-installed")
        search(FIXTURE_PACKAGE)
        waitFixture(present = true)
        assertFixtureSelected(false)
        clickTag(FIXTURE_TAG)
        assertFixtureSelected(true)
        clickTag("apps-mode-sample")
        assertSampleSelected(true)
        safeUi("Known sample app deselection failed") {
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label(R.string.sample_browser)) and isToggleable())
            compose.onNode(hasText(label(R.string.sample_browser)) and isToggleable()).performScrollTo().performClick()
        }
        assertSampleSelected(false)
        clickTag("apps-mode-installed")
        waitFixture(present = true)
        assertFixtureSelected(true)
        clickTag("apps-mode-sample")
        assertSampleSelected(false)
        assertPreviewWarning()
    }

    private fun openApps() = safeUi("Apps page navigation failed") {
        compose.onNode(hasText(label(R.string.page_apps)) and hasClickAction()).performScrollTo().performClick()
    }

    private fun openInstalled() {
        openApps()
        clickTag("apps-mode-installed")
        waitReady()
        assertPreviewWarning()
    }

    private fun clickBody(resource: Int) = safeUi("Sample preview control failed") {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label(resource)))
        compose.onNode(hasText(label(resource)) and hasClickAction()).performScrollTo().performClick()
    }

    private fun clickTag(tag: String) = safeUi("Known catalog control failed") {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag(tag))
        compose.onNodeWithTag(tag).performScrollTo().performClick()
    }

    private fun search(value: String) = safeUi("Fixture-only catalog search failed") {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag("apps-search"))
        compose.onNodeWithTag("apps-search").performScrollTo().performTextReplacement(value)
        Espresso.closeSoftKeyboard()
        compose.waitForIdle()
    }

    private fun waitReady() = safeUi("Installed catalog did not finish loading") {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag("apps-catalog-status"))
        compose.waitUntil(timeoutMillis = 15_000) { catalogReady() }
    }

    private fun waitFixture(present: Boolean) = safeUi("Known fixture catalog result was not observed") {
        waitReady()
        if (present) {
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag(FIXTURE_TAG))
        } else {
            // A successful fixed-package search must show its empty result, not an offscreen row.
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label(R.string.apps_no_matches)))
        }
        compose.waitUntil(timeoutMillis = 15_000) {
            tagNodes(FIXTURE_TAG).isNotEmpty() == present
        }
    }

    private fun catalogReady(): Boolean {
        val node = tagNodes("apps-catalog-status").singleOrNull() ?: return false
        return node.config.contains(SemanticsProperties.StateDescription) &&
            node.config[SemanticsProperties.StateDescription] == "ready"
    }

    private fun tagNodes(tag: String) = compose.onAllNodes(hasTestTag(tag))
        .fetchSemanticsNodes(atLeastOneRootRequired = false)

    private fun assertChip(tag: String) = safeUi("Known catalog filter was not selected") {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag(tag))
        val node = tagNodes(tag).singleOrNull()
        assertTrue(node != null && node.config.contains(SemanticsProperties.Selected) && node.config[SemanticsProperties.Selected])
    }

    private fun assertFixtureSelected(selected: Boolean) = safeUi("Known fixture selection was not retained") {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag(FIXTURE_TAG))
        compose.waitUntil(timeoutMillis = 15_000) {
            val node = tagNodes(FIXTURE_TAG).singleOrNull()
            node != null && node.config.contains(SemanticsProperties.ToggleableState) &&
                node.config[SemanticsProperties.ToggleableState] == if (selected) ToggleableState.On else ToggleableState.Off
        }
    }

    private fun assertSampleSelected(selected: Boolean) = safeUi("Known sample selection changed across catalog modes") {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label(R.string.sample_browser)) and isToggleable())
        compose.onNode(hasText(label(R.string.sample_browser)) and isToggleable()).performScrollTo()
        val nodes = compose.onAllNodes(hasText(label(R.string.sample_browser)) and isToggleable())
            .fetchSemanticsNodes(atLeastOneRootRequired = false)
        assertTrue(nodes.size == 1 && nodes[0].config[SemanticsProperties.ToggleableState] ==
            if (selected) ToggleableState.On else ToggleableState.Off)
    }

    private fun assertPreviewWarning() = safeUi("No-capture banner was not visible") {
        compose.onNodeWithText(label(R.string.preview_banner)).assertIsDisplayed()
    }

    private fun rotate(requested: Int, expected: Int) = safeUi("Installed preview rotation did not finish") {
        compose.activityRule.scenario.onActivity { it.requestedOrientation = requested }
        compose.waitUntil(timeoutMillis = 15_000) { compose.activity.resources.configuration.orientation == expected }
        compose.waitForIdle()
    }

    private fun label(resource: Int) = compose.activity.getString(resource)

    private fun setFixtureEnabled(enabled: Boolean) {
        val user = requireNotNull(fixtureUser) { "Fixture profile is unavailable" }
        val action = if (enabled) "enable" else "disable-user"
        val expected = if (enabled) "enabled" else "disabled-user"
        val result = shell("pm $action --user $user $FIXTURE_PACKAGE")
        assertTrue("Known fixture enabled state could not be restored or changed",
            result.contains(FIXTURE_PACKAGE) && result.contains("new state: $expected"))
    }

    private fun shell(command: String): String {
        val descriptor = try {
            InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)
        } catch (_: Exception) {
            throw AssertionError("Fixture shell command could not start")
        }
        val reader = Executors.newSingleThreadExecutor { operation -> Thread(operation, "fixture-command-reader").apply { isDaemon = true } }
        return try {
            reader.submit<String> {
                ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
                    val data = ByteArray(512)
                    var count = 0
                    while (count < data.size) {
                        val received = input.read(data, count, data.size - count)
                        if (received < 0) break
                        count += received
                    }
                    assertTrue("Fixture shell response exceeded its bound", count < data.size)
                    String(data, 0, count, Charsets.UTF_8)
                }
            }.get(10, TimeUnit.SECONDS)
        } catch (_: Exception) {
            throw AssertionError("Bounded fixture shell command failed")
        } finally {
            try {
                descriptor.close()
            } catch (_: Exception) {
                throw AssertionError("Fixture command descriptor did not close")
            } finally {
                reader.shutdownNow()
                val joined = try { reader.awaitTermination(2, TimeUnit.SECONDS) } catch (_: InterruptedException) { false }
                assertTrue("Fixture command reader did not stop", joined)
            }
        }
    }

    // Compose failures can otherwise print an entire semantics tree containing installed packages.
    private fun <T> safeUi(message: String, action: () -> T): T = try {
        action()
    } catch (_: AssertionError) {
        throw AssertionError(message)
    } catch (_: Exception) {
        throw AssertionError(message)
    }

    companion object {
        private const val FIXTURE_PACKAGE = "com.httpfreekit.fixture.installedapps"
        private const val FIXTURE_LABEL = "FreeKit Catalog Fixture"
        private const val FIXTURE_TAG = "installed-app:$FIXTURE_PACKAGE"
    }
}
