package com.httpfreekit.android.apps

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Current-user package observations only; these do not establish future capture readiness. */
@RunWith(AndroidJUnit4::class)
class PackageManagerSelectedPackageProbeTest {
    @Test fun currentCompanionIsAvailable() {
        val application = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val probe = PackageManagerSelectedPackageProbe(application)

        assertEquals(SelectedPackageAvailability.AVAILABLE, probe.availability(application.packageName))
    }

    @Test fun missingPackageIsNotInstalled() {
        val application = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val probe = PackageManagerSelectedPackageProbe(application)

        assertEquals(
            SelectedPackageAvailability.NOT_INSTALLED,
            probe.availability("com.httpfreekit.fixture.nonexistent.selectedpackageprobe"),
        )
    }

    @Test fun headlessFixtureIsAvailable() {
        val application = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val probe = PackageManagerSelectedPackageProbe(application)

        // The existing preview-runtime workflow installs this enabled headless fixture before tests.
        assertEquals(
            SelectedPackageAvailability.AVAILABLE,
            probe.availability("com.httpfreekit.fixture.installedapps"),
        )
    }
}
