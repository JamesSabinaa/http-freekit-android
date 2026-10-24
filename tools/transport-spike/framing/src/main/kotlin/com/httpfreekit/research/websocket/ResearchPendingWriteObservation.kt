package com.httpfreekit.research.websocket

/**
 * Caller-confined research proof for one unfinished write observed through sequential probes.
 * Each peer snapshot must occur within the supplied exact, relative monotonic call interval.
 * This owns no clock, I/O, timer, queue or model lease. Call completion is not snapshot time.
 */
class ResearchPendingWriteObservation {
    private var lastCallEnd = -1L
    private var lastWriteId = 0L
    private var candidate = 0L
    private var firstSnapshotUpper = 0L
    var longestCandidateMillis: Long = 0L
        private set

    fun sample(writeId: Long, observed: Boolean, startedNanos: Long, receivedNanos: Long): Boolean {
        require(writeId >= lastWriteId && (!observed || writeId > 0) && startedNanos >= 0 &&
            receivedNanos >= startedNanos && startedNanos >= lastCallEnd) { "Invalid pending-write sample" }
        lastCallEnd = receivedNanos
        lastWriteId = writeId
        if (!observed) {
            candidate = 0L
            return false
        }
        if (candidate != writeId) {
            candidate = writeId
            firstSnapshotUpper = receivedNanos
            return false
        }
        // S1 <= first receive; S2 >= this start, hence S2-S1 >= this lower bound.
        val provedNanos = startedNanos - firstSnapshotUpper
        longestCandidateMillis = maxOf(longestCandidateMillis, provedNanos / 1_000_000)
        return provedNanos >= 250_000_000
    }
}
