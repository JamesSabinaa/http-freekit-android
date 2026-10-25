package com.httpfreekit.capture

/** One common budget for accepted SOCKS sockets, raw egress sockets and intercepted transports. */
internal class CaptureSocketBudget {
    private var used = 0
    @Synchronized fun acquire(): Lease {
        if (used >= 32) throw CaptureException("capacity")
        used++
        return Lease(this)
    }
    @Synchronized fun count(): Int = used
    @Synchronized private fun release() { check(used > 0); used-- }
    class Lease(private val budget: CaptureSocketBudget) {
        private var released = false
        @Synchronized fun release() { if (!released) { budget.release(); released = true } }
    }
}
