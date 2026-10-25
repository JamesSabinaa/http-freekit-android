package com.httpfreekit.capturetest

import org.junit.Assert.*
import org.junit.Test

class CaptureTrafficReplyTest {
    private val keys = setOf("bytes", "sha256", "failureCode")

    @Test fun routeOutcomesRequireZeroDataAndTheRequestedRouteCategory() {
        assertNotNull(CaptureTrafficReply.decode(17, 0, keys, 0, null, null))
        assertNotNull(CaptureTrafficReply.decode(18, 2, keys, 0, null, "traffic_route_nonvpn_timeout_p1_i1_v1"))
        assertNotNull(CaptureTrafficReply.decode(17, 3, keys, 0, null, "traffic_route_unavailable"))
        assertNull(CaptureTrafficReply.decode(17, 2, keys, 0, null, "traffic_route_nonvpn_timeout_p1_i1_v0"))
        assertNull(CaptureTrafficReply.decode(17, 0, keys, 1, null, null))
        assertNull(CaptureTrafficReply.decode(18, 0, keys, 0, "a".repeat(64), null))
        assertNull(CaptureTrafficReply.decode(17, 2, keys, 0, null, null))
    }

    @Test fun failedDataAndSuccessfulRepliesCannotExchangeFailureOrRouteEvidence() {
        assertNotNull(CaptureTrafficReply.decode(10, 0, keys, 32787, "a".repeat(64), null))
        assertNotNull(CaptureTrafficReply.decode(10, 3, keys, 0, null, "traffic_tcp_eof_protocol"))
        assertNotNull(CaptureTrafficReply.decode(15, 2, keys, 0, null, "traffic_datagram_timeout"))
        assertNull(CaptureTrafficReply.decode(10, 0, keys, 32787, "a".repeat(64), "traffic_tcp_write_io"))
        assertNull(CaptureTrafficReply.decode(10, 3, keys, 0, null, "traffic_route_unavailable"))
        assertNull(CaptureTrafficReply.decode(10, 3, keys, 0, null, null))
    }

    @Test fun unknownMaterialAndWrongTypesAreRejectedWithoutStringifyingProviderObjects() {
        val foreign = object { override fun toString(): String = error("CANARY_PROVIDER") }
        for (code in listOf("traffic_tcp_reply_io CANARY", "traffic_route_vpn_timeout_p2_i1_v0", foreign))
            assertNull(CaptureTrafficReply.decode(10, 3, keys, 0, null, code))
        assertNull(CaptureTrafficReply.decode(10, 0, keys, true, null, null))
        assertNull(CaptureTrafficReply.decode(10, 0, keys, 0, foreign, null))
        assertNull(CaptureTrafficReply.decode(10, 0, keys + "CANARY", 0, null, null))
        assertNull(CaptureTrafficReply.decode(99, 0, keys, 0, null, null))
        val observed = CaptureFailure.values("uid", "route-readiness", IllegalStateException("traffic_route_vpn_timeout_p1_i1_v0"),
            null, null, null, null, CaptureTrafficOutcome(17, 2, 0))
        assertEquals(39, observed.size)
        assertEquals("traffic_route_vpn_timeout_p1_i1_v0", observed["captureFailureCheck"])
    }
}
