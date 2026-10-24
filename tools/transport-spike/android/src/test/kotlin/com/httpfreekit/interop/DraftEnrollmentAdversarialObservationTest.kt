package com.httpfreekit.interop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DraftEnrollmentAdversarialObservationTest {
    @Test fun allFourIndependentPositiveVectorsProduceOnlyBoundedFiniteFacts() {
        for ((scenario, count) in listOf("proof_misuse" to 19, "wrong_tls" to 11, "pending_cancel" to 13, "published_cancel" to 19)) {
            val values = observation(scenario).values()
            assertEquals(count, values.size)
            assertEquals("1", values["draftAdversarialVersion"])
            assertEquals(scenario, values["draftAdversarialScenario"])
            assertEquals((scenario == "published_cancel").toString(), values["draftAdversarialCredentialSaved"])
            assertTrue(values.keys.all { it.matches(Regex("draftAdversarial[A-Za-z]{1,40}")) })
            assertTrue(values.entries.sumOf { it.key.toByteArray().size + it.value.toByteArray().size } < 4096)
        }
    }

    @Test fun observationsCopyCallerFactsAndExposeNoMutableMap() {
        val facts = facts("wrong_tls")
        val result = observation("wrong_tls", facts)
        facts["TlsFailureType"] = "PRIVATE_CANARY"
        facts["private"] = "PRIVATE_CANARY"
        assertEquals("SSLException", result.values()["draftAdversarialTlsFailureType"])
        assertFalse(result.toString().contains("PRIVATE_CANARY"))
        try {
            @Suppress("UNCHECKED_CAST")
            (result.values() as MutableMap<String, String>)["private"] = "PRIVATE_CANARY"
            throw AssertionError("Expected immutable observation")
        } catch (_: UnsupportedOperationException) { /* Explicit immutable view. */ }
    }

    @Test fun missingUnexpectedOrUnsafeFactsNeverBecomePositiveEvidence() {
        for (scenario in listOf("proof_misuse", "wrong_tls", "pending_cancel", "published_cancel")) {
            val valid = facts(scenario)
            for (key in valid.keys) {
                rejected { observation(scenario, valid.toMutableMap().apply { remove(key) }) }
                rejected { observation(scenario, valid.toMutableMap().apply { put(key, "PRIVATE_CANARY") }) }
            }
            rejected { observation(scenario, valid.toMutableMap().apply { put("PRIVATE_CANARY", "PRIVATE_CANARY") }) }
            for (failed in 0..2) rejected { DraftEnrollmentAdversarialObservation(scenario, failed != 0, scenario == "published_cancel", failed != 1, failed != 2, valid) }
            rejected { DraftEnrollmentAdversarialObservation(scenario, true, scenario != "published_cancel", true, true, valid) }
        }
        rejected { observation("PRIVATE_CANARY", linkedMapOf()) }
    }

    @Test fun publishedRefusalNeedsCanonicalActualUtcBeforeTheSavedLeafBoundary() {
        val valid = facts("published_cancel")
        for (time in listOf("0", "01700000000000", "946684799999", "4102444800001", "1e12", "-1", "PRIVATE_CANARY")) {
            rejected { observation("published_cancel", valid.toMutableMap().apply { put("RefusalObservedUtcMillis", time) }) }
        }
        for (time in listOf("1700000000000", "1699999999999")) rejected {
            observation("published_cancel", valid.toMutableMap().apply { put("CredentialExpiresUtcMillis", time) })
        }
        observation("published_cancel", valid.toMutableMap().apply {
            put("RefusalObservedUtcMillis", "946684800000"); put("CredentialExpiresUtcMillis", "946684800001")
        })
    }

    @Test fun publicAlternatePortCannotAliasPrivateSeedPortsOrAcceptNoncanonicalInput() {
        assertEquals(1, DraftEnrollmentAdversarialObservation.peerPort("1", 12345, 23456))
        assertEquals(65535, DraftEnrollmentAdversarialObservation.peerPort("65535", 12345, 23456))
        for (value in listOf(null, "", "0", "01", "+1", " 1", "1\n", "65536", "12345", "23456", "PRIVATE_CANARY")) rejected {
            DraftEnrollmentAdversarialObservation.peerPort(value, 12345, 23456)
        }
    }

    private fun observation(scenario: String, facts: Map<String, String> = facts(scenario)) =
        DraftEnrollmentAdversarialObservation(scenario, true, scenario == "published_cancel", true, true, facts)
    private fun facts(scenario: String): MutableMap<String, String> = when (scenario) {
        "proof_misuse" -> linkedMapOf("PurposeHttp" to "403", "PurposeCode" to "authentication_failed", "WireContextHttp" to "403",
            "WireContextCode" to "authentication_failed", "SignedContextHttp" to "403", "SignedContextCode" to "authentication_failed",
            "SameChallengeHttp" to "200", "SameChallengeType" to "pair_pending", "ReplayHttp" to "403", "ReplayCode" to "authentication_failed",
            "FreshStatusHttp" to "200", "FreshStatusType" to "pair_pending", "BindingUnchanged" to "true")
        "wrong_tls" -> linkedMapOf("TlsFailureType" to "SSLException", "FreshStatusHttp" to "200", "FreshStatusType" to "pair_pending",
            "BindingUnchanged" to "true", "ExpectedTrustUnchanged" to "true")
        "pending_cancel" -> linkedMapOf("CancelHttp" to "200", "CancelCode" to "pairing_cancelled", "ReplayHttp" to "403",
            "ReplayCode" to "authentication_failed", "FreshStatusHttp" to "200", "FreshStatusCode" to "pairing_cancelled", "BindingUnchanged" to "true")
        "published_cancel" -> linkedMapOf("ApprovalHttp" to "200", "ApprovalType" to "pair_approved", "SavedCredentialUnchanged" to "true",
            "BeforeMtlsHttp" to "200", "CancelHttp" to "200", "CancelCode" to "pairing_cancelled", "AfterMtlsHttp" to "403",
            "FreshStatusHttp" to "200", "FreshStatusCode" to "pairing_cancelled", "CredentialExpiresUtcMillis" to "1700000001000",
            "RefusalObservedUtcMillis" to "1700000000000", "KeyManagerUsableAtRefusal" to "true", "BindingUnchanged" to "true")
        else -> error("Unexpected test vector")
    }
    private fun rejected(action: () -> Unit) {
        try { action(); throw AssertionError("Expected finite observation rejection") }
        catch (failure: DraftEnrollmentStateException) {
            assertEquals("Invalid enrollment research state", failure.message)
            assertEquals(null, failure.cause); assertEquals(0, failure.suppressed.size)
        }
    }
}
