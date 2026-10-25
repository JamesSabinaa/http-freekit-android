package com.httpfreekit.capturetest

import com.httpfreekit.capture.CaptureServiceSnapshot
import com.httpfreekit.capture.CaptureSnapshot
import org.junit.Assert.*
import org.junit.Test

class CaptureFailureTest {
    private fun snapshot() = CaptureServiceSnapshot("active", true, 1, true, true,
        CaptureSnapshot(true, false, true, false, false, true, 2, 3, 4, 1, 0, 1, 0, 0, 0, 0, false), null)

    @Test fun exactImmutablePrimitiveFactsPreserveAbsentAndActiveSnapshots() {
        val error = IllegalStateException("auth_guard_admission")
        val active = CaptureFailure.values("uid", "local-auth-refusal", error, snapshot(), ResearchCaptureService.GuardObservation(2, 2, 0, false), 1, false, CaptureTrafficOutcome(10, 3, 0))
        assertEquals(39, active.size); assertEquals("auth_guard_admission", active["captureFailureCheck"])
        assertEquals("3", active["captureFailureOwnedSockets"]); assertEquals("false", active["captureFailureFailed"])
        assertTrue(active.entries.sumOf { it.key.toByteArray().size + it.value.toByteArray().size } < 4096)
        assertThrows(UnsupportedOperationException::class.java) { (active as MutableMap<String, String>)["CANARY"] = "private" }
        val absent = CaptureFailure.values("ipv6", "selected-ipv6", error, null, null, null, null, CaptureTrafficOutcome(0, -1, 0))
        assertEquals("false", absent["captureFailureServicePresent"]); assertEquals("absent", absent["captureFailureServiceState"])
        assertEquals("null", absent["captureFailureNativeRunning"]); assertEquals("null", absent["captureFailureGuardProtects"])
    }

    @Test fun ForeignMessagesAndMalformedFieldsNeverBecomeDiagnosticMaterial() {
        val secret = IllegalStateException("CANARY_PRIVATE").apply {
            initCause(IllegalStateException("CANARY_CAUSE")); addSuppressed(IllegalStateException("CANARY_SUPPRESSED"))
        }
        val value = CaptureFailure.values("direct", "udp443-positive-control", secret, null, null, null, null, CaptureTrafficOutcome(15, 3, 0))
        assertEquals("other", value["captureFailureCheck"]); assertFalse(value.toString().contains("CANARY"))
        assertThrows(IllegalArgumentException::class.java) { CaptureFailure.values("uid", "CANARY", secret, null, null, null, null, CaptureTrafficOutcome(0, -1, 0)) }
        assertThrows(IllegalArgumentException::class.java) { CaptureFailure.values("uid", "setup", secret, null, null, null, null, CaptureTrafficOutcome(99, 0, 0)) }
    }

    @Test fun OriginalFramesAreExactProjectRootsBoundedAndExcludeProviderCauses() {
        val own = StackTraceElement("com.httpfreekit.capturetest.CapturePolicyInteropTest", "selectedTcpUsesTunAndNonselectedUidBypasses", "CapturePolicyInteropTest.kt", 123)
        val wrong = StackTraceElement("foreign.CANARY", "private", "CapturePolicyInteropTest.kt", 7)
        val wrongFile = StackTraceElement("com.httpfreekit.capturetest.CapturePolicyInteropTest", "private", "CANARY.kt", 7)
        val error = IllegalStateException("CANARY").apply { stackTrace = arrayOf(wrong, wrongFile, *Array(30) { own }) }
        val frames = CaptureFailure.frames(error)
        assertEquals(16, frames.size); assertTrue(frames.all { it == own })
        error.stackTrace = arrayOf(*Array(128) { wrong }, own)
        assertTrue(CaptureFailure.frames(error).isEmpty())
    }
}
