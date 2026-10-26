package com.httpfreekit.android.preview

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.graphics.Rect
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsFocused
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
import androidx.compose.ui.test.performScrollToIndex
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextReplacement
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
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
        assertPackagedKeyboardResizeMode()
        openInstalled()
        search(FIXTURE_PACKAGE)
        waitFixture(present = true)
        clickTag(FIXTURE_TAG)
        assertFixtureSelected(true)
        clickTag("apps-refresh")
        waitFixture(present = true)
        assertFixtureSelected(true)
        focusSearchAndWaitForKeyboard(Configuration.ORIENTATION_PORTRAIT)
        assertPreviewWarning(requireKeyboard = true)
        rotate(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE, Configuration.ORIENTATION_LANDSCAPE)
        focusSearchAndWaitForKeyboard(Configuration.ORIENTATION_LANDSCAPE)
        assertPreviewWarning(requireKeyboard = true)
        waitFixture(present = true)
        assertFixtureSelected(true)
        assertPreviewWarning()
        rotate(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT, Configuration.ORIENTATION_PORTRAIT)
        focusSearchAndWaitForKeyboard(Configuration.ORIENTATION_PORTRAIT)
        assertPreviewWarning(requireKeyboard = true)
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
        clickMode("apps-mode-installed")
        search(FIXTURE_PACKAGE)
        waitFixture(present = true)
        assertFixtureSelected(false)
        clickTag(FIXTURE_TAG)
        assertFixtureSelected(true)
        clickMode("apps-mode-sample")
        assertSampleSelected(true)
        safeUi("Known sample app deselection failed") {
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label(R.string.sample_browser)) and isToggleable())
            compose.onNode(hasText(label(R.string.sample_browser)) and isToggleable()).performScrollTo().performClick()
        }
        assertSampleSelected(false)
        clickMode("apps-mode-installed")
        waitFixture(present = true)
        assertFixtureSelected(true)
        clickMode("apps-mode-sample")
        assertSampleSelected(false)
        assertPreviewWarning()
    }

    private fun openApps() = safeUi("Apps page navigation failed") {
        compose.onNode(hasText(label(R.string.page_apps)) and hasClickAction()).performScrollTo().performClick()
    }

    private fun openInstalled() {
        openApps()
        clickMode("apps-mode-installed")
        waitReady()
        assertPreviewWarning()
    }

    private fun clickBody(resource: Int) = safeUi("Sample preview control failed") {
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label(resource)))
        compose.onNode(hasText(label(resource)) and hasClickAction()).performScrollTo().performClick()
    }

    private fun clickMode(tag: String) {
        clickTag(tag)
        safeUi("Clicked catalog source was not selected", ::catalogDiagnostics) {
            val node = tagNodes(tag).singleOrNull()
            assertTrue(node != null && node.config.contains(SemanticsProperties.Selected) && node.config[SemanticsProperties.Selected])
        }
    }

    private fun clickTag(tag: String) {
        if (tag != FIXTURE_TAG) {
            // Nested horizontal controls can remain composed while vertically clipped. Their
            // scroll-to action owns only the horizontal row; position the vertical owner first.
            safeUi("Catalog controls vertical reset failed", ::catalogDiagnostics) {
                compose.onNode(hasScrollToIndexAction()).performScrollToIndex(0)
            }
        }
        safeUi("Known catalog control lookup failed", ::catalogDiagnostics) {
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag(tag))
        }
        safeUi("Known catalog control was not displayed and enabled", ::catalogDiagnostics) {
            compose.onNodeWithTag(tag).performScrollTo().assertIsDisplayed().assertIsEnabled()
        }
        safeUi("Known catalog control touch failed", ::catalogDiagnostics) {
            compose.onNodeWithTag(tag).performClick()
        }
    }

    private fun search(value: String) {
        waitReady()
        safeUi("Fixture-only search field scrolling failed") {
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag("apps-search"))
            compose.onNodeWithTag("apps-search").performScrollTo()
        }
        safeUi("Fixture-only search text replacement failed") {
            compose.onNodeWithTag("apps-search").performTextReplacement(value)
        }
        safeUi("Fixture-only search keyboard dismissal failed") { Espresso.closeSoftKeyboard() }
        safeUi("Fixture-only search idle synchronization failed") { compose.waitForIdle() }
    }

    private fun assertPackagedKeyboardResizeMode() = safeUi("Packaged activity keyboard resize mode was absent") {
        val activity = compose.activity
        val info = activity.packageManager.getActivityInfo(activity.componentName, 0)
        assertTrue((info.softInputMode and WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST) ==
            WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
    }

    private fun focusSearchAndWaitForKeyboard(expectedOrientation: Int) {
        val deadline = SystemClock.uptimeMillis() + 15_000
        fun remaining(): Long {
            val remaining = deadline - SystemClock.uptimeMillis()
            assertTrue("Search keyboard precondition deadline elapsed", remaining > 0)
            return remaining
        }
        val initialWindow = keyboardWindow(observeInputManager = true)
        var initialFieldFocused: Boolean? = null
        val diagnostics = {
            "initialWindow=(${initialWindow.describe()}),initialFieldFocused=$initialFieldFocused,current=(${keyboardDiagnostics()})"
        }
        safeUi("Fixture-only search window was not ready", diagnostics) {
            compose.waitUntil(timeoutMillis = remaining()) {
                val window = keyboardWindow()
                window.ready && window.orientation == expectedOrientation
            }
        }
        val alreadySatisfied = safeUi("Fixture-only initial search focus could not be observed", diagnostics) {
            initialFieldFocused = searchFocused()
            keyboardVisible() && initialFieldFocused == true
        }
        if (!alreadySatisfied) {
            safeUi("Fixture-only search field scrolling failed", diagnostics) {
                compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag("apps-search"))
            }
            safeUi("Fixture-only search field was not displayed and enabled", diagnostics) {
                compose.onNodeWithTag("apps-search").performScrollTo().assertIsDisplayed().assertIsEnabled()
            }
            safeUi("Fixture-only search editor touch failed", diagnostics) {
                compose.onNodeWithTag("apps-search").performClick()
            }
        }
        safeUi("Fixture-only search editor was not focused", diagnostics) {
            compose.onNodeWithTag("apps-search").assertIsFocused()
        }
        safeUi("Fixture-only search IME did not become visible", diagnostics) {
            compose.waitUntil(timeoutMillis = remaining()) { keyboardVisible() }
        }
    }

    private fun keyboardVisible(): Boolean {
        var visible = false
        compose.activityRule.scenario.onActivity { activity ->
            visible = ViewCompat.getRootWindowInsets(activity.window.decorView)
                ?.isVisible(WindowInsetsCompat.Type.ime()) == true
        }
        return visible
    }

    private fun waitReady() {
        safeUi("Installed catalog status scrolling failed", ::catalogDiagnostics) {
            compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasTestTag("apps-catalog-status"))
        }
        safeUi("Installed catalog ready state was not observed", ::catalogDiagnostics) {
            compose.waitUntil(timeoutMillis = 15_000) { catalogReady() }
        }
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

    private fun assertPreviewWarning(requireKeyboard: Boolean = false) {
        var imeVisible = false
        var orientation = Configuration.ORIENTATION_UNDEFINED
        var rootHeight = -1
        safeUi("Preview keyboard visibility could not be observed") {
            compose.activityRule.scenario.onActivity { activity ->
                val root = activity.window.decorView
                imeVisible = ViewCompat.getRootWindowInsets(root)?.isVisible(WindowInsetsCompat.Type.ime()) == true
                orientation = activity.resources.configuration.orientation
                rootHeight = root.height
            }
        }
        val bounds = safeUi("Known banner geometry could not be observed") {
            compose.onAllNodes(hasText(label(R.string.preview_banner)))
                .fetchSemanticsNodes(atLeastOneRootRequired = false).singleOrNull()?.boundsInWindow
                ?.let { "[${it.left},${it.top},${it.right},${it.bottom}]" } ?: "absent"
        }
        // Only public window metadata and this fixed banner's numeric geometry may enter reports.
        safeUi("No-capture banner was not visible (api=${Build.VERSION.SDK_INT}, orientation=$orientation, imeVisible=$imeVisible, rootHeight=$rootHeight, bannerBounds=$bounds, requireKeyboard=$requireKeyboard)") {
            if (requireKeyboard) assertTrue(imeVisible)
            compose.onNodeWithText(label(R.string.preview_banner)).assertIsDisplayed()
        }
    }

    private fun rotate(requested: Int, expected: Int) = safeUi("Installed preview rotation window was not ready", ::keyboardDiagnostics) {
        val before = keyboardWindow()
        compose.activityRule.scenario.onActivity { it.requestedOrientation = requested }
        compose.waitUntil(timeoutMillis = 15_000) {
            val after = keyboardWindow()
            val geometryChanged = before.orientation == expected || before.rootWidth <= 0 || after.rootWidth != before.rootWidth
            after.ready && after.orientation == expected && geometryChanged
        }
        compose.waitForIdle()
    }

    private data class KeyboardWindow(
        val available: Boolean = false,
        val orientation: Int = Configuration.ORIENTATION_UNDEFINED,
        val attached: Boolean = false,
        val laidOut: Boolean = false,
        val layoutRequested: Boolean = true,
        val windowFocused: Boolean = false,
        val hasInsets: Boolean = false,
        val rootWidth: Int = 0,
        val rootHeight: Int = 0,
        val imeVisible: Boolean = false,
        val imeBottom: Int = 0,
        val visibleBottomGap: Int = 0,
        val currentFocusPresent: Boolean = false,
        val immActive: Boolean = false,
        val immCurrentFocusActive: Boolean = false,
        val immAcceptingText: Boolean = false,
    ) {
        val ready: Boolean get() = available && attached && laidOut && !layoutRequested && windowFocused &&
            hasInsets && rootWidth > 0 && rootHeight > 0

        fun describe() = "available=$available,api=${Build.VERSION.SDK_INT},orientation=$orientation," +
            "attached=$attached,laidOut=$laidOut,layoutRequested=$layoutRequested,windowFocused=$windowFocused," +
            "hasInsets=$hasInsets,rootWidth=$rootWidth,rootHeight=$rootHeight,imeVisible=$imeVisible," +
            "imeBottom=$imeBottom,visibleBottomGap=$visibleBottomGap,currentFocusPresent=$currentFocusPresent," +
            "immActive=$immActive,immCurrentFocusActive=$immCurrentFocusActive,immAcceptingText=$immAcceptingText"
    }

    private fun keyboardWindow(observeInputManager: Boolean = false): KeyboardWindow {
        var state = KeyboardWindow()
        try {
            compose.activityRule.scenario.onActivity { activity ->
                val root = activity.window.decorView
                val insets = ViewCompat.getRootWindowInsets(root)
                val frame = Rect()
                val location = IntArray(2)
                root.getWindowVisibleDisplayFrame(frame)
                root.getLocationOnScreen(location)
                val imm = if (observeInputManager) activity.getSystemService(InputMethodManager::class.java) else null
                val focus = activity.currentFocus
                state = KeyboardWindow(
                    available = true,
                    orientation = activity.resources.configuration.orientation,
                    attached = root.isAttachedToWindow,
                    laidOut = root.isLaidOut,
                    layoutRequested = root.isLayoutRequested,
                    windowFocused = root.hasWindowFocus(),
                    hasInsets = insets != null,
                    rootWidth = root.width,
                    rootHeight = root.height,
                    imeVisible = insets?.isVisible(WindowInsetsCompat.Type.ime()) == true,
                    imeBottom = insets?.getInsets(WindowInsetsCompat.Type.ime())?.bottom ?: 0,
                    visibleBottomGap = (location[1] + root.height - frame.bottom).coerceAtLeast(0),
                    currentFocusPresent = focus != null,
                    immActive = imm?.isActive == true,
                    immCurrentFocusActive = focus != null && imm?.isActive(focus) == true,
                    immAcceptingText = imm?.isAcceptingText == true,
                )
            }
        } catch (_: AssertionError) {
            // A not-yet-resumed scenario is not a ready window; the bounded assertion still must pass.
        } catch (_: Exception) {
            // Never retain or report platform exception messages or view identities.
        }
        return state
    }

    private fun searchFocused(): Boolean {
        val node = tagNodes("apps-search").singleOrNull() ?: return false
        return node.config.contains(SemanticsProperties.Focused) && node.config[SemanticsProperties.Focused]
    }

    private fun keyboardDiagnostics(): String {
        val window = keyboardWindow(observeInputManager = true).describe()
        val field = try {
            val node = tagNodes("apps-search").singleOrNull()
            if (node == null) "absent" else {
                val focused = node.config.contains(SemanticsProperties.Focused) && node.config[SemanticsProperties.Focused]
                val enabled = !node.config.contains(SemanticsProperties.Disabled)
                val bounds = node.boundsInWindow
                "focused=$focused,enabled=$enabled,bounds=[${bounds.left},${bounds.top},${bounds.right},${bounds.bottom}]"
            }
        } catch (_: ComposeTimeoutException) {
            "unavailable"
        } catch (_: AssertionError) {
            "unavailable"
        } catch (_: Exception) {
            "unavailable"
        }
        return "$window,searchField=($field)"
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
    private fun <T> safeUi(message: String, diagnostics: (() -> String)? = null, action: () -> T): T = try {
        action()
    } catch (_: ComposeTimeoutException) {
        throw AssertionError(if (diagnostics == null) message else "$message (${diagnostics()})")
    } catch (_: AssertionError) {
        throw AssertionError(if (diagnostics == null) message else "$message (${diagnostics()})")
    } catch (_: Exception) {
        throw AssertionError(if (diagnostics == null) message else "$message (${diagnostics()})")
    }

    private fun catalogDiagnostics(): String = try {
        fun source(tag: String): String {
            val node = tagNodes(tag).singleOrNull() ?: return "absent"
            val selected = node.config.contains(SemanticsProperties.Selected) && node.config[SemanticsProperties.Selected]
            val enabled = !node.config.contains(SemanticsProperties.Disabled)
            val bounds = node.boundsInWindow
            return "selected=$selected,enabled=$enabled,bounds=[${bounds.left},${bounds.top},${bounds.right},${bounds.bottom}]"
        }
        val statusNode = tagNodes("apps-catalog-status").singleOrNull()
        val observed = if (statusNode != null && statusNode.config.contains(SemanticsProperties.StateDescription))
            statusNode.config[SemanticsProperties.StateDescription] else null
        val status = observed?.takeIf { it in setOf("loading", "ready", "error", "idle") } ?: "absent"
        "sampleSource=(${source("apps-mode-sample")}),installedSource=(${source("apps-mode-installed")})," +
            "refresh=(${source("apps-refresh")}),status=$status"
    } catch (_: ComposeTimeoutException) {
        "catalogState=unavailable"
    } catch (_: AssertionError) {
        "catalogState=unavailable"
    } catch (_: Exception) {
        "catalogState=unavailable"
    }

    companion object {
        private const val FIXTURE_PACKAGE = "com.httpfreekit.fixture.installedapps"
        private const val FIXTURE_LABEL = "FreeKit Catalog Fixture"
        private const val FIXTURE_TAG = "installed-app:$FIXTURE_PACKAGE"
    }
}
