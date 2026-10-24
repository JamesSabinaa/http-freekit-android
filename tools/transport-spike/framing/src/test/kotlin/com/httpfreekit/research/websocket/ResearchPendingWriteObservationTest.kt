package com.httpfreekit.research.websocket

import org.junit.Assert.*
import org.junit.Test

class ResearchPendingWriteObservationTest {
    private fun ms(value: Long) = value * 1_000_000

    @Test fun lateResponseDoesNotCountTowardSnapshotSeparation() {
        val proof = ResearchPendingWriteObservation()
        assertFalse(proof.sample(7, true, 0, 0))
        assertFalse(proof.sample(7, true, ms(10), ms(510)))
        assertEquals(10L, proof.longestCandidateMillis)
        assertTrue(proof.sample(7, true, ms(520), ms(530)))
        assertEquals(520L, proof.longestCandidateMillis)
    }

    @Test fun firstReceiveProvidesTheUpperBoundRatherThanFirstRequestStart() {
        val proof = ResearchPendingWriteObservation()
        assertFalse(proof.sample(1, true, 0, ms(500)))
        assertFalse(proof.sample(1, true, ms(600), ms(900)))
        assertEquals(100L, proof.longestCandidateMillis)
        assertTrue(proof.sample(1, true, ms(901), ms(1000)))
    }

    @Test fun nanosecondBoundaryIsNotRoundedUp() {
        val proof = ResearchPendingWriteObservation()
        assertFalse(proof.sample(1, true, 0, ms(1)))
        assertFalse(proof.sample(1, true, ms(251) - 1, ms(251) - 1))
        assertEquals(249L, proof.longestCandidateMillis)
        assertTrue(proof.sample(1, true, ms(251), ms(251)))
        assertEquals(250L, proof.longestCandidateMillis)
    }

    @Test fun aNewWriteIdStartsANewCandidate() {
        val proof = ResearchPendingWriteObservation()
        assertFalse(proof.sample(1, true, 0, 0))
        assertFalse(proof.sample(2, true, ms(500), ms(500)))
        assertEquals(0L, proof.longestCandidateMillis)
        assertFalse(proof.sample(2, true, ms(749), ms(749)))
        assertTrue(proof.sample(2, true, ms(750), ms(750)))
    }

    @Test fun aFalseFullPredicateClearsTheCandidateEvenWithTheSameId() {
        val proof = ResearchPendingWriteObservation()
        assertFalse(proof.sample(1, true, 0, 0))
        assertFalse(proof.sample(1, false, ms(500), ms(500)))
        assertFalse(proof.sample(1, true, ms(1000), ms(1000)))
        assertEquals(0L, proof.longestCandidateMillis)
        assertTrue(proof.sample(1, true, ms(1250), ms(1250)))
    }

    @Test fun longestConservativeSpanSurvivesCandidateResets() {
        val proof = ResearchPendingWriteObservation()
        assertFalse(proof.sample(1, true, 0, 0))
        assertFalse(proof.sample(1, true, ms(100), ms(100)))
        assertFalse(proof.sample(2, true, ms(110), ms(110)))
        assertFalse(proof.sample(2, true, ms(160), ms(160)))
        assertFalse(proof.sample(2, false, ms(200), ms(200)))
        assertEquals(100L, proof.longestCandidateMillis)
    }

    @Test fun invalidOrOverlappingSamplesCannotChangeTheCandidate() {
        val invalid = listOf<(ResearchPendingWriteObservation) -> Unit>(
            { it.sample(-1, false, ms(200), ms(200)) },
            { it.sample(0, true, ms(200), ms(200)) },
            { it.sample(7, true, -1, ms(200)) },
            { it.sample(7, true, ms(200), ms(199)) },
            { it.sample(7, true, ms(99), ms(200)) },
            { it.sample(6, false, ms(200), ms(200)) },
        )
        for (attempt in invalid) {
            val proof = ResearchPendingWriteObservation()
            assertFalse(proof.sample(7, true, 0, ms(100)))
            assertThrows(IllegalArgumentException::class.java) { attempt(proof) }
            assertEquals(0L, proof.longestCandidateMillis)
            assertTrue(proof.sample(7, true, ms(350), ms(350)))
        }
    }

    @Test fun idleSamplesCannotStartAWriteObservation() {
        val proof = ResearchPendingWriteObservation()
        assertFalse(proof.sample(0, false, 0, ms(250)))
        assertFalse(proof.sample(0, false, ms(300), ms(500)))
        assertEquals(0L, proof.longestCandidateMillis)
        assertFalse(proof.sample(1, true, ms(600), ms(600)))
        assertTrue(proof.sample(1, true, ms(850), ms(850)))
    }
}
