package com.httpfreekit.capturetest

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith

/** One cold, unbound transaction. This test never requests consent or creates a capture owner. */
@RunWith(AndroidJUnit4::class)
class CaptureColdTcpInteropTest {
    @Test(timeout = 60000)
    fun coldUnboundHttpRequiresStrictEof() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        var client: TrafficClient? = null
        var ownerAbsentBefore = false
        var ownerAbsentAfter = false
        var routeObserved = false
        var httpAttempts = 0
        var trafficCommand = 0
        var trafficStatus = -1
        var trafficBytes = 0
        var trafficSha256 = "none"
        var failurePhase = "none"
        var failureCode = "none"
        var cleanupJoined = false
        var phase = "setup"

        fun fail(at: String, code: String) {
            if (failurePhase == "none") { failurePhase = at; failureCode = code }
        }
        fun attempt(command: Int) {
            trafficCommand = command
            trafficStatus = -1; trafficBytes = 0; trafficSha256 = "none"
        }
        fun retain(result: TrafficClient.Result) {
            trafficStatus = result.status; trafficBytes = result.bytes
            trafficSha256 = result.sha256 ?: "none"
        }
        fun unexpected() = fail(phase, if (phase == "route") "cold_route_reply" else if (phase == "http") "cold_tcp_reply" else "cold_setup")

        try {
            ownerAbsentBefore = ownerAbsent()
            if (!ownerAbsentBefore) fail("owner-check", "cold_owner_present")
            if (failurePhase == "none") {
                val port = InstrumentationRegistry.getArguments().getString("directPort")?.toIntOrNull()
                require(port != null && port in 1024..65535)
                // CONFIGURE1 and WAIT_NON_VPN18 perform IPC/framework inspection, not data I/O.
                val connected = TrafficClient(instrumentation.targetContext, port)
                client = connected
                phase = "route"; attempt(18)
                val route = connected.command(18)
                retain(route)
                if (route.status == 0 && route.bytes == 0 && route.sha256 == null && route.failureCode == null) {
                    routeObserved = true
                } else fail("route", finiteFailure(route.failureCode, "cold_route_reply"))

                if (failurePhase == "none") {
                    phase = "http"; attempt(10); httpAttempts++
                    val http = connected.command(10)
                    retain(http)
                    if (http.status != 0) fail("http", finiteFailure(http.failureCode, "cold_tcp_reply"))
                    else if (http.bytes != 32787 || http.sha256 != REPLY_SHA256 || http.failureCode != null) {
                        fail("http", "cold_tcp_reply")
                    }
                }
            }
        } catch (_: Exception) {
            unexpected()
        } catch (_: AssertionError) {
            unexpected()
        } finally {
            // Do not replace the route/data tuple with FINISH2's reply or erase its first failure.
            try {
                client?.let { it.close(); cleanupJoined = true }
            } catch (_: Exception) {
                fail("client-cleanup", "cold_client_cleanup")
            } catch (_: AssertionError) {
                fail("client-cleanup", "cold_client_cleanup")
            }
            try {
                ownerAbsentAfter = ownerAbsent()
                if (!ownerAbsentAfter) fail("owner-check", "cold_owner_present")
            } catch (_: Exception) {
                fail("owner-check", "cold_owner_present")
            } catch (_: AssertionError) {
                fail("owner-check", "cold_owner_present")
            }
        }

        val observation = Bundle().apply {
            putString("coldVersion", "1"); putString("coldScenario", "cold-http")
            putString("coldOwnerAbsentBefore", ownerAbsentBefore.toString())
            putString("coldOwnerAbsentAfter", ownerAbsentAfter.toString())
            putString("coldRouteObserved", routeObserved.toString()); putString("coldHttpAttempts", httpAttempts.toString())
            putString("coldTrafficCommand", trafficCommand.toString()); putString("coldTrafficStatus", trafficStatus.toString())
            putString("coldTrafficBytes", trafficBytes.toString()); putString("coldTrafficSha256", trafficSha256)
            putString("coldFailurePhase", failurePhase); putString("coldFailureCode", failureCode)
            putString("coldCleanupJoined", cleanupJoined.toString())
        }
        try { instrumentation.sendStatus(if (failurePhase == "none") 2 else 3, observation) }
        catch (_: Exception) { throw fixedFailure() }
        if (failurePhase != "none") throw fixedFailure()
    }

    private fun ownerAbsent() = ResearchCaptureService.current == null && ResearchCaptureService.configuration == null

    private fun finiteFailure(value: String?, fallback: String): String = if (value in FAILURE_CODES) value!! else fallback

    private fun fixedFailure() = AssertionError("Cold TCP comparison failed.").apply { stackTrace = emptyArray() }

    companion object {
        private const val REPLY_SHA256 = "05dfd86ee3ecc0267ceb6234e1955c1e8c80e34b6323b2b1c87c7d1d84042255"
        private val FAILURE_CODES = buildSet {
            for (stage in listOf("connect", "write", "shutdown", "reply", "eof", "close")) {
                for (category in listOf("timeout", "io", "protocol", "other", "reset", "aborted", "closed", "bad_fd", "not_connected")) {
                    add("traffic_tcp_${stage}_$category")
                }
            }
            for (present in 0..1) for (internet in 0..1) for (vpn in 0..1) {
                add("traffic_route_nonvpn_timeout_p${present}_i${internet}_v$vpn")
            }
            add("traffic_route_unavailable"); add("traffic_command_failed"); add("traffic_close_io")
        }
    }
}
