package com.httpfreekit.android.apps

import org.junit.Assert.*
import org.junit.Test

class SelectedCapturePlatformAdmissionTest {
    private val companion = "com.httpfreekit.android.debug"
    private val first = "local.browser"
    private val second = "local.headless"

    private fun state(names: Set<String> = linkedSetOf(first, second)) = AppSelectionState(
        mode = AppCatalogMode.INSTALLED,
        installed = names.map { InstalledAppEntry(it, "Private label", it == second) },
        installedSelected = names,
        loaded = true,
    )

    private fun check(
        selection: AppSelectionState = state(),
        probe: SelectedPackageProbe = SelectedPackageProbe { SelectedPackageAvailability.AVAILABLE },
        identity: String = companion,
    ) = SelectedCapturePlatformAdmission.check(selection, identity, probe)

    private fun rejected(result: SelectedCapturePlatformResult, reason: SelectedCapturePlatformRejection) {
        assertTrue(result is SelectedCapturePlatformResult.Rejected)
        assertEquals(reason, (result as SelectedCapturePlatformResult.Rejected).reason)
    }

    @Test fun allB5RejectionReasonsMakeZeroPlatformCalls() {
        val valid = state()
        val tooMany = (1..65).map { "local.app$it" }.toSet()
        val invalid = state(linkedSetOf(first, "local.1invalid"))
        val cases = listOf(
            Triple(valid.copy(mode = AppCatalogMode.SAMPLE), companion, SelectedCaptureRejection.INSTALLED_MODE_REQUIRED),
            Triple(valid.copy(loaded = false), companion, SelectedCaptureRejection.INVENTORY_NOT_READY),
            Triple(valid.copy(loading = true), companion, SelectedCaptureRejection.INVENTORY_NOT_READY),
            Triple(valid.copy(failed = true), companion, SelectedCaptureRejection.INVENTORY_NOT_READY),
            Triple(valid, "bad", SelectedCaptureRejection.INVALID_COMPANION_PACKAGE),
            Triple(state(emptySet()), companion, SelectedCaptureRejection.INVALID_SELECTION_SIZE),
            Triple(state(tooMany), companion, SelectedCaptureRejection.INVALID_SELECTION_SIZE),
            Triple(invalid, companion, SelectedCaptureRejection.INVALID_SELECTED_PACKAGE),
            Triple(state(linkedSetOf(first, companion)), companion, SelectedCaptureRejection.COMPANION_SELECTED),
            Triple(valid.copy(installedSelected = linkedSetOf(first, "unknown.package")), companion, SelectedCaptureRejection.PACKAGE_NOT_INSTALLED),
        )
        var calls = 0
        val probe = SelectedPackageProbe { calls++; SelectedPackageAvailability.AVAILABLE }
        for ((selection, identity, b5Reason) in cases) {
            assertEquals(b5Reason, (SelectedCaptureAdmission.prepare(selection, identity) as SelectedCaptureResult.Rejected).reason)
            rejected(check(selection, probe, identity), SelectedCapturePlatformRejection.SELECTION_REJECTED)
        }
        assertEquals(0, calls)
    }

    @Test fun successfulCheckProbesEveryExactSelectedPackageOnceIncludingHiddenHeadlessApps() {
        val calls = mutableListOf<String>()
        val selection = state().copy(
            installed = state().installed + InstalledAppEntry("local.unselected", "Unselected", true),
            sampleSelected = setOf("example.browser"),
            search = "no matches", filter = AppFilter.DEVELOPMENT,
        )
        assertTrue(selection.visibleInstalled.isEmpty())
        val result = check(selection, SelectedPackageProbe { calls += it; SelectedPackageAvailability.AVAILABLE })
        assertTrue(result is SelectedCapturePlatformResult.Checked)
        assertEquals(listOf(first, second), calls)
        assertEquals(linkedSetOf(first, second), (result as SelectedCapturePlatformResult.Checked).plan.selectedPackages)
        assertEquals(SelectedCapturePolicy.TCP_80_443_REFUSE_UDP_443, result.plan.policy)
    }

    @Test fun maximumSelectionIsFullyProbedWithoutPruning() {
        val names = (1..64).map { "local.app$it" }.toCollection(LinkedHashSet())
        val calls = mutableListOf<String>()
        val result = check(state(names), SelectedPackageProbe { calls += it; SelectedPackageAvailability.AVAILABLE })
        assertEquals(names.toList(), calls)
        assertEquals(names, (result as SelectedCapturePlatformResult.Checked).plan.selectedPackages)
    }

    @Test fun disappearanceDisableOrUnknownAfterCatalogSuccessRejectsEntireSelection() {
        val failures = mapOf(
            SelectedPackageAvailability.NOT_INSTALLED to SelectedCapturePlatformRejection.PACKAGE_NOT_INSTALLED,
            SelectedPackageAvailability.DISABLED to SelectedCapturePlatformRejection.PACKAGE_DISABLED,
            SelectedPackageAvailability.UNAVAILABLE to SelectedCapturePlatformRejection.PACKAGE_LOOKUP_FAILED,
        )
        for ((availability, reason) in failures) {
            for (failedPackage in listOf(first, second)) {
                val calls = mutableListOf<String>()
                val result = check(probe = SelectedPackageProbe {
                    calls += it
                    if (it == failedPackage) availability else SelectedPackageAvailability.AVAILABLE
                })
                rejected(result, reason)
                assertEquals(if (failedPackage == first) listOf(first) else listOf(first, second), calls)
            }
        }
    }

    @Test fun runtimeAndSecurityFailuresAreFiniteAndRedactedAtEitherProbePosition() {
        val errors = listOf(
            SecurityException("secret provider text $first"),
            IllegalArgumentException("private path"),
            IllegalStateException("inventory contents"),
            RuntimeException("secret"),
        )
        for (error in errors) for (failedPackage in listOf(first, second)) {
            val result = check(probe = SelectedPackageProbe {
                if (it == failedPackage) throw error
                SelectedPackageAvailability.AVAILABLE
            })
            rejected(result, SelectedCapturePlatformRejection.PACKAGE_LOOKUP_FAILED)
            assertEquals("SelectedCapturePlatformResult.Rejected([REDACTED])", result.toString())
            assertFalse(result.toString().contains(error.message!!))
        }
    }

    @Test fun fatalJvmErrorsAreNotConvertedToLookupFailures() {
        val errors = listOf(AssertionError("fatal"), LinkageError("fatal"), OutOfMemoryError("fatal"))
        for (error in errors) {
            try {
                check(probe = SelectedPackageProbe { throw error })
                fail("Fatal error must propagate")
            } catch (actual: Error) {
                assertSame(error, actual)
            }
        }
    }

    @Test fun mutatingCallerSelectionAndInventoryDuringProbeCannotChangeAdmittedSnapshot() {
        val selected = linkedSetOf(first, second)
        val inventory = state().installed.toMutableList()
        val selection = state().copy(installedSelected = selected, installed = inventory)
        val calls = mutableListOf<String>()
        val result = check(selection, SelectedPackageProbe {
            calls += it
            selected.clear()
            selected += "local.injected"
            inventory.clear()
            SelectedPackageAvailability.AVAILABLE
        }) as SelectedCapturePlatformResult.Checked
        assertEquals(listOf(first, second), calls)
        assertEquals(linkedSetOf(first, second), result.plan.selectedPackages)
        selected.clear()
        assertEquals(linkedSetOf(first, second), result.plan.selectedPackages)
    }

    @Test fun checkedPlanIsUnmodifiableAndResultStringsRetainNoPackageOrLabels() {
        val result = check() as SelectedCapturePlatformResult.Checked
        assertEquals("SelectedCapturePlatformResult.Checked([REDACTED])", result.toString())
        assertEquals("SelectedCapturePlan([REDACTED])", result.plan.toString())
        try {
            (result.plan.selectedPackages as MutableSet<String>).add("local.injected")
            fail("Plan must be immutable")
        } catch (_: UnsupportedOperationException) {
            assertEquals(linkedSetOf(first, second), result.plan.selectedPackages)
        }
        for (reason in SelectedCapturePlatformRejection.entries) {
            assertEquals("SelectedCapturePlatformResult.Rejected([REDACTED])", SelectedCapturePlatformResult.Rejected(reason).toString())
        }
    }

    @Test fun eachCheckReobservesAvailabilityRatherThanCachingOldSuccess() {
        var available = true
        var calls = 0
        val probe = SelectedPackageProbe {
            calls++
            if (available) SelectedPackageAvailability.AVAILABLE else SelectedPackageAvailability.NOT_INSTALLED
        }
        val old = check(probe = probe) as SelectedCapturePlatformResult.Checked
        available = false
        rejected(check(probe = probe), SelectedCapturePlatformRejection.PACKAGE_NOT_INSTALLED)
        assertEquals(3, calls)
        assertEquals(linkedSetOf(first, second), old.plan.selectedPackages)
    }

    @Test fun defaultOrExplicitEnabledRequiresEnabledAndNotSuspended() {
        // Public PackageManager constants are inlined; this helper invokes no Android methods.
        for (setting in listOf(0, 1)) {
            for (enabled in listOf(false, true)) for (suspended in listOf(false, true)) {
                assertEquals(
                    if (enabled && !suspended) SelectedPackageAvailability.AVAILABLE else SelectedPackageAvailability.DISABLED,
                    classifySelectedPackageAvailability(true, enabled, suspended, setting),
                )
            }
        }
    }

    @Test fun everyExplicitDisabledStateRejectsEvenIfApplicationInfoSaysEnabled() {
        // DISABLED, DISABLED_USER, DISABLED_UNTIL_USED (API26+).
        for (setting in listOf(2, 3, 4)) {
            for (enabled in listOf(false, true)) for (suspended in listOf(false, true)) {
                assertEquals(SelectedPackageAvailability.DISABLED, classifySelectedPackageAvailability(true, enabled, suspended, setting))
            }
        }
    }

    @Test fun unknownEnabledSettingsFailClosed() {
        for (setting in listOf(-1, 5, Int.MIN_VALUE, Int.MAX_VALUE)) {
            for (enabled in listOf(false, true)) for (suspended in listOf(false, true)) {
                assertEquals(SelectedPackageAvailability.UNAVAILABLE, classifySelectedPackageAvailability(true, enabled, suspended, setting))
            }
        }
    }

    @Test fun notInstalledFlagRejectsRegardlessOfOtherObservedState() {
        for (setting in listOf(-1, 0, 1, 2, 3, 4, 5)) {
            for (enabled in listOf(false, true)) for (suspended in listOf(false, true)) {
                assertEquals(SelectedPackageAvailability.NOT_INSTALLED, classifySelectedPackageAvailability(false, enabled, suspended, setting))
            }
        }
    }
}
