package com.httpfreekit.android.apps

import org.junit.Assert.*
import org.junit.Test

class SelectedCapturePlanTest {
    private val companion = "com.httpfreekit.android.debug"
    private val chosen = "private.selectedCanary"
    private val inventoryCanary = "private.inventoryCanary"
    private val labelCanary = "PRIVATE_LABEL_CANARY"

    private fun state() = AppSelectionState(
        mode = AppCatalogMode.INSTALLED,
        installed = listOf(InstalledAppEntry(chosen, labelCanary, true), InstalledAppEntry(inventoryCanary, labelCanary, false)),
        installedSelected = setOf(chosen), loaded = true,
    )
    private fun result(state: AppSelectionState = state()) = SelectedCaptureAdmission.prepare(state, companion)
    private fun plan(state: AppSelectionState = state()) = (result(state) as SelectedCaptureResult.Accepted).plan

    @Test fun mutableCallerCollectionsCannotChangeAcceptedPlan() {
        val ids = linkedSetOf(chosen)
        val inventory = arrayListOf(InstalledAppEntry(chosen, labelCanary, true))
        val plan = plan(state().copy(installed = inventory, installedSelected = ids))
        ids.clear()
        ids.add(inventoryCanary)
        inventory.clear()
        assertEquals(setOf(chosen), plan.selectedPackages)
    }
    @Test fun exposedSelectedSetRejectsMutation() {
        val plan = plan()
        val exposed = plan.selectedPackages as MutableSet<String>
        assertThrows(UnsupportedOperationException::class.java) { exposed.add(inventoryCanary) }
        assertThrows(UnsupportedOperationException::class.java) { exposed.remove(chosen) }
        assertThrows(UnsupportedOperationException::class.java) { exposed.clear() }
        assertEquals(setOf(chosen), plan.selectedPackages)
    }
    @Test fun constructorAlsoDefensivelyCopiesItsRestrictedInput() {
        val ids = linkedSetOf(chosen)
        val plan = SelectedCapturePlan(ids)
        ids.clear()
        assertEquals(setOf(chosen), plan.selectedPackages)
    }
    @Test fun laterSuccessfulRefreshCannotPrunePlanSnapshot() {
        val original = state()
        val plan = plan(original)
        val request = AppSelection.beginRefresh(original, false)
        val refreshed = AppSelection.succeeded(request, request.requestId, emptyList(), false)
        assertTrue(refreshed.installedSelected.isEmpty())
        assertEquals(setOf(chosen), plan.selectedPackages)
    }
    @Test fun laterSelectionAndModeChangesCannotChangePlanSnapshot() {
        val original = state()
        val plan = plan(original)
        val deselected = AppSelection.select(original, chosen, false, false)
        val sample = AppSelection.mode(deselected, AppCatalogMode.SAMPLE, false)
        val sampleSelected = AppSelection.select(sample, "example.browser", true, false)
        assertEquals(setOf("example.browser"), sampleSelected.selectedIds)
        assertEquals(setOf(chosen), plan.selectedPackages)
    }
    @Test fun planAndBothResultStringsNeverExposePrivateState() {
        val accepted = result() as SelectedCaptureResult.Accepted
        val rejected = result(state().copy(installedSelected = setOf(chosen, "private.unknownCanary"))) as SelectedCaptureResult.Rejected
        assertEquals(SelectedCaptureRejection.PACKAGE_NOT_INSTALLED, rejected.reason)
        val strings = listOf(accepted.toString(), accepted.plan.toString(), rejected.toString())
        strings.forEach { text ->
            assertTrue(text.contains("[REDACTED]"))
            listOf(chosen, inventoryCanary, labelCanary, "private.unknownCanary", companion).forEach { canary ->
                assertFalse(text.contains(canary))
            }
        }
        assertEquals(setOf(chosen), accepted.plan.selectedPackages)
    }
    @Test fun allRejectionResultStringsAreRedacted() {
        SelectedCaptureRejection.entries.forEach { reason ->
            assertEquals("SelectedCaptureResult.Rejected([REDACTED])", SelectedCaptureResult.Rejected(reason).toString())
        }
    }
    @Test fun policyIsOneFixedLocalDescriptorWithImmutablePortsAndNoInterceptedFallback() {
        val policy = plan().policy
        assertEquals(listOf(SelectedCapturePolicy.TCP_80_443_REFUSE_UDP_443), SelectedCapturePolicy.entries.toList())
        assertSame(policy, plan().policy)
        assertEquals(setOf(80, 443), policy.interceptedTcpPorts)
        assertEquals(setOf(443), policy.refusedUdpPorts)
        assertFalse(policy.interceptedDirectFallbackAllowed)
        assertThrows(UnsupportedOperationException::class.java) { (policy.interceptedTcpPorts as MutableSet<Int>).add(8080) }
        assertThrows(UnsupportedOperationException::class.java) { (policy.refusedUdpPorts as MutableSet<Int>).clear() }
    }
}
