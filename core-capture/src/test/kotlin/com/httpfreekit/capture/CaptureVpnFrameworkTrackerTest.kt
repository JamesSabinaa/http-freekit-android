package com.httpfreekit.capture

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class CaptureVpnFrameworkTrackerTest {
    private fun tracker() = CaptureVpnFrameworkTracker<String>().apply { begin(emptyList()); prepared(emptyList()) }
    private fun ready(tracker: CaptureVpnFrameworkTracker<String>, key: String) {
        tracker.available(key); tracker.capabilities(key, true); tracker.links(key, true); tracker.connected(key, true)
    }
    @Test fun readinessRequiresAvailableCapabilitiesLinksAndConnectedForNewGeneration() {
        val state = tracker()
        state.capabilities("new", true); state.links("new", true); state.connected("new", true)
        assertFalse(state.acceptReady()); assertFalse(state.isReady())
        state.available("new"); state.connected("new", false)
        assertFalse(state.acceptReady())
        state.connected("new", true); assertTrue(state.acceptReady()); assertTrue(state.isReady())
        state.links("new", false); assertFalse(state.isReady())
        state.links("new", true); assertTrue(state.isReady())
    }
    @Test fun preexistingAndRegistrationRaceGenerationsCannotBeAccepted() {
        val prior = CaptureVpnFrameworkTracker<String>()
        prior.begin(listOf("prior")); prior.prepared(listOf("prior")); ready(prior, "prior")
        assertFalse(prior.acceptReady()); assertTrue(prior.availableKeys().isEmpty())
        ready(prior, "new"); assertTrue(prior.acceptReady())
        val raced = CaptureVpnFrameworkTracker<String>()
        raced.begin(emptyList()); ready(raced, "during-register"); raced.prepared(emptyList())
        assertFalse(raced.acceptReady())
    }
    @Test fun ambiguousMatchesFailClosedEvenAfterFirstAcceptance() {
        val state = tracker(); ready(state, "one"); assertTrue(state.acceptReady())
        ready(state, "two"); assertFalse(state.isReady())
        rejected("invalid_request") { state.acceptReady() }
        assertFalse(state.removed(setOf("one", "two")))
        state.lost("one"); assertTrue(state.removed(setOf("two")))
    }
    @Test fun exactAcceptedLossAndAbsenceIgnoreUnrelatedNetworksAndSealNeverReopens() {
        val state = tracker(); ready(state, "one"); assertTrue(state.acceptReady())
        state.lost("unrelated"); assertFalse(state.removed(setOf("one")))
        assertTrue(state.removed(setOf("other")))
        state.lost("one"); assertFalse(state.isReady()); assertFalse(state.removed(setOf("one")))
        assertTrue(state.removed(emptySet()))
        state.available("one"); rejected("invalid_request") { state.acceptReady() }
        state.seal(); ready(state, "later"); assertFalse(state.isReady())
        rejected("closed") { state.acceptReady() }; rejected("closed") { state.removed(emptySet()) }
    }
    @Test fun failedStartupRemovalTracksOnlyNewMatchingObservedGenerations() {
        val state = CaptureVpnFrameworkTracker<String>()
        state.begin(listOf("prior")); state.prepared(listOf("prior"))
        state.queryMatching("prior"); assertTrue(state.removed(setOf("prior")))
        state.queryMatching("new"); state.failed()
        assertFalse(state.removed(setOf("new", "prior")))
        assertTrue(state.removed(setOf("prior")))
        // No accepted/observed target means vacuous absence, never a claim about unseen future agents.
        assertTrue(tracker().removed(emptySet()))
        assertFalse(tracker().removed(emptySet(), newMatchingPresent = true))
    }
    @Test fun sixteenNetworkBoundAndLatchedFailureDoNotFabricateCleanup() {
        val state = tracker()
        repeat(16) { state.available("network-$it") }
        state.available("overflow"); rejected("capacity") { state.acceptReady() }
        assertFalse(state.isReady()); assertEquals(16, state.availableKeys().size)
        assertFalse(state.removed(emptySet(), newMatchingPresent = true))
        assertTrue(state.removed(emptySet()))
        assertFalse(state.toString().contains("network"))
    }
    @Test fun profileRejectsWrongFamilyPrefixMtuDuplicateOrMissingDefaultRoute() {
        val v4 = byteArrayOf(198.toByte(), 18, 0, 1)
        val v6 = byteArrayOf(0xfd.toByte(), 0, 0x66, 0x72, 0x65, 0x65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        val valid = listOf(v4 to 32, v6 to 128)
        assertTrue(captureVpnLinksMatch(1500, valid.reversed(), true, true))
        assertFalse(captureVpnLinksMatch(1499, valid, true, true))
        assertFalse(captureVpnLinksMatch(1500, valid, false, true))
        assertFalse(captureVpnLinksMatch(1500, valid, true, false))
        assertFalse(captureVpnLinksMatch(1500, listOf(v4 to 24, v6 to 128), true, true))
        assertFalse(captureVpnLinksMatch(1500, listOf(v4 to 32, v4 to 32), true, true))
        assertFalse(captureVpnLinksMatch(1500, valid + (v4 to 32), true, true))
        v6[15] = 2; assertFalse(captureVpnLinksMatch(1500, valid, true, true))
    }
    @Test fun mtuIsActuallyQueriedAndOnlyUnchangedGenerationProfileCanKeepVerification() {
        var reads = 0
        val initial = CaptureVpnLinkObservation(true, null, "PRIVATE_CANARY")
        assertFalse(initial.matches())
        val verified = initial.observed { reads++; 1500 }
        assertTrue(verified.matches()); assertEquals(1, reads)
        val refreshed = CaptureVpnLinkObservation(true, null, "PRIVATE_CANARY").refreshed(verified)
        assertTrue(refreshed.matches()); refreshed.observed { error("No query expected") }
        assertFalse(CaptureVpnLinkObservation(true, null, "changed").refreshed(verified).matches())
        assertFalse(CaptureVpnLinkObservation(false, null, "PRIVATE_CANARY").refreshed(verified).matches())
        assertFalse(CaptureVpnLinkObservation(true, 1499, "PRIVATE_CANARY").refreshed(verified).matches())
        assertFalse(initial.observed { null }.matches()); assertFalse(initial.observed { error("PRIVATE_CANARY") }.matches())
        assertFalse(CaptureVpnLinkObservation(true, null, null).observed { 1500 }.matches())
        assertFalse(verified.toString().contains("PRIVATE_CANARY"))
    }
    @Test fun cancellationAndDeadlinesNeverPretendToReleaseRegistration() {
        var unregisters = 0
        val registration = CaptureVpnRegistration({}, { unregisters++ }); registration.prepare()
        rejected("closed") { awaitCaptureVpnFramework(10, { true }, { error("not called") }, {}) }
        var clock = 0L
        rejected("connect_failed") { awaitCaptureVpnFramework(10, { false }, { clock = 10_000_000; true }, {}, { clock }) }
        assertEquals(0, unregisters)
        registration.close(); registration.close(); assertEquals(1, unregisters)
        rejected("closed") { registration.prepare() }
    }
    @Test fun waitUsesBoundedPausesAndChecksCancellationAfterPredicate() {
        var clock = 0L; var calls = 0; var cancelled = false
        awaitCaptureVpnFramework(100, { false }, { ++calls == 3 }, { assertTrue(it in 1..25); clock += it * 1_000_000 }, { clock })
        assertEquals(3, calls)
        rejected("closed") { awaitCaptureVpnFramework(100, { cancelled }, { cancelled = true; true }, {}) }
        rejected("invalid_request") { awaitCaptureVpnFramework(30001, { false }, { true }, {}) }
    }
    @Test fun failedRegistrationAndUnregisterRetainOwnershipForActualRetry() {
        var closes = 0
        val registration = CaptureVpnRegistration({ throw IllegalStateException("PRIVATE_CANARY") }, {
            closes++; if (closes == 1) error("PRIVATE_CANARY")
        })
        try { registration.prepare(); fail() } catch (_: IllegalStateException) { }
        try { registration.close(); fail() } catch (_: IllegalStateException) { }
        registration.close(); registration.close(); assertEquals(2, closes)
    }
    @Test fun closeCannotOvertakePendingRegistrationAndActuallyJoinsItsCaller() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val closed = CountDownLatch(1)
        val error = AtomicReference<Throwable?>(); var unregisters = 0
        val registration = CaptureVpnRegistration({ entered.countDown(); check(release.await(2, TimeUnit.SECONDS)) }, { unregisters++ })
        val opener = Thread { try { registration.prepare() } catch (caught: Throwable) { error.set(caught) } }
        val closer = Thread { try { registration.close() } catch (caught: Throwable) { error.set(caught) } finally { closed.countDown() } }
        opener.start(); assertTrue(entered.await(2, TimeUnit.SECONDS)); closer.start()
        try { assertFalse(closed.await(50, TimeUnit.MILLISECONDS)) } finally { release.countDown() }
        opener.join(2000); closer.join(2000)
        assertFalse(opener.isAlive); assertFalse(closer.isAlive); assertNull(error.get()); assertEquals(1, unregisters)
    }
    private fun rejected(code: String, action: () -> Unit) {
        try { action(); fail("Expected framework refusal") } catch (failure: CaptureException) {
            assertEquals(code, failure.code); assertNull(failure.cause); assertEquals(0, failure.suppressed.size)
        }
    }
}
