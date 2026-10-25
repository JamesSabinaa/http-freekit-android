package com.httpfreekit.capturetest

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Rect
import android.net.VpnService
import android.os.Bundle
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.capture.CaptureSnapshot
import com.httpfreekit.capture.CaptureVpnService
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicLong
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CapturePolicyInteropTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val arguments = InstrumentationRegistry.getArguments()
    private val directPort = port("directPort")
    private val interceptedPort = port("interceptedPort")
    private val receiver = HostReceiver(port("controlPort"))
    private var phase = "setup"
    private var starts = 0
    private var stops = 0
    private var routeChecks = 0
    private var consentDialog = false
    private var consentActivity: Activity? = null
    private val firstFailure = AtomicReference<Pair<String, Throwable>?>(null)
    private var scenario = "permission"

    @Test(timeout = 120000)
    fun localNetworkDenialPreventsTun() {
        check(Build.VERSION.SDK_INT == 37) { "api37_only" }
        TrafficClient.resetObservation()
        try {
            phase = "platform-consent"; consent()
            check(context.checkSelfPermission("android.permission.ACCESS_LOCAL_NETWORK") == PackageManager.PERMISSION_DENIED) { "local_permission_not_denied" }
            phase = "local-network-denial"
            val old = ResearchCaptureService.current
            ResearchCaptureService.configuration = ResearchCaptureService.Config(interceptedPort, setOf(ResearchCaptureService.TRAFFIC), ResearchCaptureService.Mode.NORMAL)
            context.startForegroundService(Intent(context, ResearchCaptureService::class.java).setAction(CaptureVpnService.ACTION_START))
            await { ResearchCaptureService.current?.let { it !== old && it.captureSnapshot().state == "failed" } == true }
            val service = current()
            val rejected = service.captureSnapshot()
            check(rejected.failureCode == "local_network_permission" && !rejected.tunEstablished && rejected.capture == null && service.captureRequestCalls() == 0) { "denied_permission_created_capture" }
            context.startService(Intent(context, ResearchCaptureService::class.java).setAction(CaptureVpnService.ACTION_STOP))
            check(service.awaitStopped(30000) && !service.captureSnapshot().tunEstablished && service.captureSnapshot().capture == null) { "denied_stop_not_joined" }
            instrumentation.sendStatus(2, Bundle().apply {
                putString("captureVersion", "1"); putString("captureScenario", "permission")
                putString("captureConsentGranted", "true"); putString("captureConsentDialogObserved", consentDialog.toString())
                putString("captureLocalNetworkPermission", "denied"); putString("captureFactoryCalls", "0")
                putString("captureTunEstablished", "false"); putString("captureCaptureOwnerAbsent", "true"); putString("captureStopJoined", "true")
            })
        } catch (caught: Throwable) {
            if (caught !is Exception && caught !is AssertionError) throw caught
            observeFailure(caught)
            val original = firstFailure.get() ?: (phase to caught)
            val failedPhase = original.first
            val service = ResearchCaptureService.current
            val cleanup = try {
                if (service != null) { context.startService(Intent(context, ResearchCaptureService::class.java).setAction(CaptureVpnService.ACTION_STOP)); service.awaitStopped(30000) } else true
            } catch (_: Exception) { false }
            val failure = AssertionError("Capture research permission failed at $failedPhase (${CaptureFailure.type(original.second)}); cleanup=$cleanup.")
            failure.stackTrace = CaptureFailure.frames(original.second)
            throw failure
        } finally {
            consentActivity?.let { activity -> instrumentation.runOnMainSync { activity.finish() } }; consentActivity = null
        }
    }

    @Test(timeout = 120000)
    fun selectedTcpUsesTunAndNonselectedUidBypasses() = runCase("uid") { facts ->
        val uid = context.packageManager.getApplicationInfo(ResearchCaptureService.TRAFFIC, 0).uid
        check(uid != Process.myUid() && uid != context.packageManager.getApplicationInfo(ResearchCaptureService.INERT, 0).uid) { "separate_uid" }
        withTraffic { traffic ->
            start(traffic)
            phase = "local-auth-baseline"
            val (admissions, guards) = authenticationBaseline()
            phase = "local-auth-refusal"
            rejectLocalAuthentication()
            await { snapshot().capture!!.activeFlows == 0 }
            val afterAuth = snapshot().capture!!
            check(afterAuth.interceptedTcpFlows == admissions.interceptedTcpFlows && afterAuth.directTcpFlows == admissions.directTcpFlows && afterAuth.udpTargets == admissions.udpTargets) { "auth_egress" }
            check(current().guardObservation() == guards) { "auth_guard_admission" }
            phase = "selected-traffic"
            val selected = receiver.snapshot()
            tcp(traffic, 10); tcp(traffic, 11)
            val selectedAfter = receiver.snapshot()
            delta(selected, selectedAfter, "interceptedHttp", 1); delta(selected, selectedAfter, "interceptedOpaque", 1)
            delta(selected, selectedAfter, "directHttp", 0); delta(selected, selectedAfter, "directOpaque", 0)
            stop()
            start(traffic, bypass = true)
            phase = "nonselected-traffic"
            val bypass = receiver.snapshot()
            tcp(traffic, 10); tcp(traffic, 11)
            val bypassAfter = receiver.snapshot()
            delta(bypass, bypassAfter, "directHttp", 1); delta(bypass, bypassAfter, "directOpaque", 1)
            delta(bypass, bypassAfter, "interceptedHttp", 0); delta(bypass, bypassAfter, "interceptedOpaque", 0)
            check(context.packageManager.getApplicationInfo(ResearchCaptureService.TRAFFIC, 0).uid == uid) { "uid_changed" }
            stop()
        }
        facts.putAll(mapOf("SelectedUidStable" to "true", "SelectedHttp" to "1", "SelectedOpaque" to "1", "BypassHttp" to "1", "BypassOpaque" to "1", "MissingAuthRejected" to "true", "WrongAuthRejected" to "true"))
    }

    @Test(timeout = 120000)
    fun directTcpUdpDnsAndUdp443Policy() = runCase("direct") { facts ->
        withTraffic { traffic ->
            route(traffic, expectedVpn = false)
            phase = "udp443-positive-control"
            val control = traffic.command(15)
            check(control.status == 0 && control.bytes == 256 && control.sha256 == UDP_HASH) { "udp_positive_control" }
            start(traffic)
            val before = receiver.snapshot()
            val drops = snapshot().capture!!.udp443Drops
            phase = "direct-protocols"
            tcp(traffic, 12)
            check(traffic.command(13).let { it.status == 0 && it.bytes == 256 && it.sha256 == UDP_HASH }) { "udp_bytes" }
            check(traffic.command(14).let { it.status == 0 && it.bytes == 33 && it.sha256 == DNS_HASH }) { "dns_bytes" }
            phase = "blocked-udp443"
            check(traffic.command(15).let { it.status == 2 && it.bytes == 0 && it.sha256 == null }) { "udp443_not_blocked" }
            val after = receiver.snapshot()
            delta(before, after, "directTcp", 1); delta(before, after, "udp", 1); delta(before, after, "dns", 1); delta(before, after, "udp443", 0)
            check(snapshot().capture!!.udp443Drops > drops) { "policy_drop_not_observed" }
            stop()
        }
        facts.putAll(mapOf("DirectTcp" to "1", "Udp" to "1", "Dns" to "1", "Udp443PositiveControl" to "true", "Udp443NoDelivery" to "true", "Udp443DropObserved" to "true"))
    }

    @Test(timeout = 120000)
    fun selectedIpv6UsesTun() = runCase("ipv6") { facts ->
        withTraffic { traffic ->
            start(traffic)
            phase = "selected-ipv6"
            val before = receiver.snapshot()
            tcp(traffic, 16)
            val after = receiver.snapshot()
            delta(before, after, "interceptedIpv6", 1); delta(before, after, "directHttp", 0)
            check(snapshot().capture!!.interceptedTcpFlows >= 1) { "ipv6_policy_admission" }
            stop()
        }
        facts.putAll(mapOf("OriginalIpv6Validated" to "true", "InterceptedIpv6" to "1"))
    }

    @Test(timeout = 120000)
    fun stopJoinsCaptureAndAllowsFreshStart() = runCase("stop") { facts ->
        withTraffic { traffic ->
            start(traffic)
            phase = "held-intercepted-request"
            val heldBaseline = receiver.armHeld()
            val result = AtomicReference<TrafficClient.Result?>()
            val failure = AtomicReference<Throwable?>()
            val requestCompleted = AtomicLong()
            val request = Thread({
                try { result.set(traffic.command(10)) } catch (caught: Throwable) { failure.set(caught) }
                finally { requestCompleted.set(SystemClock.elapsedRealtime()) }
            }, "capture-held-fixture-command")
            val requestStarted = SystemClock.elapsedRealtime()
            request.start()
            try {
                await { receiver.snapshot().getValue("heldConnections") == 1 && snapshot().capture!!.activeFlows > 0 }
                stop(notification = true)
                request.join(2500)
                val completed = requestCompleted.get()
                check(!request.isAlive && completed >= requestStarted && completed - requestStarted < 4000) { "stop_did_not_interrupt_before_request_deadline" }
                failure.get()?.let { throw it }
                check(result.get()?.status in setOf(2, 3)) { "held_request_completed" }
                phase = "held-fixture-cleanup"
                receiver.closeHeld()
                await {
                    val closed = receiver.snapshot()
                    // The synchronous HTTP snapshot includes exactly its own control socket and timer.
                    closed.getValue("heldConnections") == 0 && closed.getValue("pendingCallbacks") == 0 &&
                        closed.getValue("activeSockets") == 1 && closed.getValue("timers") == 1
                }
                val closed = receiver.snapshot()
                check(closed.getValue("heldConnections") == 0 &&
                    closed.getValue("heldRequestsClosed") - heldBaseline.getValue("heldRequestsClosed") == 1 &&
                    closed.getValue("heldCloseRequests") - heldBaseline.getValue("heldCloseRequests") == 1) { "receiver_path_count" }
            } catch (caught: Throwable) {
                if (caught is Exception || caught is AssertionError) observeFailure(caught)
                throw caught
            } finally {
                if (request.isAlive) { stop(); request.join(12000) }
                check(!request.isAlive) { "fixture_request_not_joined" }
            }
            start(traffic)
            phase = "fresh-restart-traffic"
            tcp(traffic, 10)
            stop()
        }
        facts.putAll(mapOf("HeldRequestObserved" to "true", "HeldRequestInterrupted" to "true", "HeldFixtureCleanupJoined" to "true", "FreshStartForwards" to "true"))
    }

    @Test(timeout = 120000)
    fun protectAndBindFailuresFailClosed() = runCase("guards") { facts ->
        withTraffic { traffic ->
            for (mode in listOf(ResearchCaptureService.Mode.REFUSE_PROTECT, ResearchCaptureService.Mode.FAIL_BIND)) {
                start(traffic, mode = mode)
                phase = if (mode == ResearchCaptureService.Mode.REFUSE_PROTECT) "protect-refusal" else "bind-refusal"
                val before = receiver.snapshot()
                check(traffic.command(12).status in setOf(2, 3)) { "refused_flow_connected" }
                await { current().guardObservation().rejectedSocketsClosed && snapshot().capture!!.pendingOpens == 0 }
                val guards = current().guardObservation()
                check(guards.protects > 0 && guards.rejected > 0 && guards.rejectedSocketsClosed) { "refused_socket_not_closed" }
                check(if (mode == ResearchCaptureService.Mode.REFUSE_PROTECT) guards.binds == 0 && snapshot().capture!!.protectFailures > 0 else guards.binds > 0 && snapshot().capture!!.bindFailures > 0) { "guard_order" }
                check(snapshot().tunEstablished && snapshot().capture!!.nativeRunning) { "failure_route_not_retained" }
                delta(before, receiver.snapshot(), "directTcp", 0)
                stop()
            }
        }
        facts.putAll(mapOf("ProtectRefused" to "true", "BindRefused" to "true", "NoFlowConnect" to "true", "RefusedSocketsClosed" to "true", "RouteRetainedUntilStop" to "true"))
    }

    private fun runCase(scenario: String, block: (MutableMap<String, String>) -> Unit) {
        this.scenario = scenario
        TrafficClient.resetObservation()
        val facts = linkedMapOf<String, String>()
        try {
            phase = "platform-consent"
            consent()
            if (Build.VERSION.SDK_INT >= 37) {
                check(context.checkSelfPermission("android.permission.ACCESS_LOCAL_NETWORK") == PackageManager.PERMISSION_GRANTED &&
                    context.packageManager.checkPermission("android.permission.ACCESS_LOCAL_NETWORK", ResearchCaptureService.TRAFFIC) == PackageManager.PERMISSION_GRANTED) { "local_network_permission" }
            }
            block(facts)
            phase = "final-cleanup"
            stop()
            check(starts > 0 && starts == stops) { "start_stop_count" }
            check(routeChecks == starts * 2 + (if (scenario == "direct") 1 else 0)) { "route_transition_count" }
            val bundle = Bundle().apply {
                putString("captureVersion", "1"); putString("captureScenario", scenario)
                putString("captureStarts", starts.toString()); putString("captureStops", stops.toString())
                putString("captureConsentGranted", "true"); putString("captureConsentDialogObserved", consentDialog.toString())
                putString("captureTunAndNativeObserved", "true"); putString("captureAllStopsJoined", "true")
                putString("captureTrafficWorkerJoined", "true")
                putString("captureNotificationObserved", "true")
                putString("captureRouteTransitionsObserved", "true")
                putString("captureLocalNetworkPermission", if (Build.VERSION.SDK_INT >= 37) "granted" else "not_required")
                facts.forEach { (key, value) -> putString("capture$key", value) }
            }
            instrumentation.sendStatus(2, bundle)
        } catch (caught: Throwable) {
            if (caught !is Exception && caught !is AssertionError) throw caught
            observeFailure(caught)
            val original = firstFailure.get() ?: (phase to caught)
            val failedPhase = original.first
            val cleanup = try { stop(); true } catch (_: Exception) { false }
            val type = CaptureFailure.type(original.second)
            val failure = AssertionError("Capture research $scenario failed at $failedPhase ($type); cleanup=$cleanup.")
            failure.stackTrace = CaptureFailure.frames(original.second)
            throw failure
        } finally {
            consentActivity?.let { activity -> instrumentation.runOnMainSync { activity.finish() } }
            consentActivity = null
        }
    }

    private fun withTraffic(block: (TrafficClient) -> Unit) {
        TrafficClient(context, directPort).use { client ->
            try { block(client) }
            catch (caught: Throwable) {
                if (caught is Exception || caught is AssertionError) observeFailure(caught)
                throw caught
            }
        }
    }

    private fun observeFailure(error: Throwable) {
        if (!firstFailure.compareAndSet(null, phase to error)) return
        try {
            val service = ResearchCaptureService.current
            val values = CaptureFailure.values(scenario, phase, error, service?.captureSnapshot(), service?.guardObservation(),
                service?.captureRequestCalls(), service?.interceptedFactoryClosed(), TrafficClient.observation())
            instrumentation.sendStatus(3, Bundle().apply { values.forEach { (name, value) -> putString(name, value) } })
        } catch (_: Exception) { /* Diagnostic failure never replaces the original failed assertion. */ }
    }

    private fun start(traffic: TrafficClient, bypass: Boolean = false, mode: ResearchCaptureService.Mode = ResearchCaptureService.Mode.NORMAL) {
        route(traffic, expectedVpn = false)
        phase = "tun-start"
        val old = ResearchCaptureService.current
        check(old == null || old.awaitStopped(1000)) { "previous_owner_live" }
        ResearchCaptureService.configuration = ResearchCaptureService.Config(interceptedPort, setOf(if (bypass) ResearchCaptureService.INERT else ResearchCaptureService.TRAFFIC), mode)
        context.startForegroundService(Intent(context, ResearchCaptureService::class.java).setAction(CaptureVpnService.ACTION_START))
        await { ResearchCaptureService.current?.let { it !== old && it.captureSnapshot().state in setOf("active", "failed") } == true }
        val state = snapshot()
        check(state.state == "active" && state.tunEstablished && state.selectedPackageCount == 1 && state.underlyingNetworkPresent && state.capture?.nativeRunning == true) { "tun_not_active" }
        stopAction()
        starts++
        route(traffic, expectedVpn = !bypass)
    }

    private fun stop(notification: Boolean = false) {
        try { stopOwned(notification) }
        catch (caught: Throwable) {
            if (caught is Exception || caught is AssertionError) observeFailure(caught)
            throw caught
        }
    }

    private fun stopOwned(notification: Boolean) {
        val service = ResearchCaptureService.current ?: return
        if (service.captureSnapshot().state == "stopped" && service.awaitStopped(1000)) return
        phase = "actual-stop-join"
        if (notification) stopAction().actionIntent.send()
        else context.startService(Intent(context, ResearchCaptureService::class.java).setAction(CaptureVpnService.ACTION_STOP))
        check(service.awaitStopped(30000)) { "lifecycle_not_joined" }
        val state = service.captureSnapshot()
        val owner = checkNotNull(state.capture) { "capture_snapshot_missing" }
        check(!state.tunEstablished && !state.lifecycleThreadAlive && state.failureCode == null && !owner.failed && owner.admissionClosed && !owner.nativeRunning && owner.nativeStopJoined && owner.tunClosed && !owner.configurationPresent && owner.activeFlows == 0 && owner.ownedSockets == 0 && owner.liveWorkers == 0 && owner.pendingOpens == 0 && service.interceptedFactoryClosed()) { "capture_resources_not_closed" }
        stops++
    }

    private fun stopAction(): Notification.Action {
        val notification = context.getSystemService(NotificationManager::class.java).activeNotifications.singleOrNull {
            it.notification.flags and Notification.FLAG_ONGOING_EVENT != 0 && it.notification.actions?.count { action -> action.title.toString() == "Stop" } == 1
        }?.notification ?: error("foreground_notification_missing")
        return notification.actions.single { it.title.toString() == "Stop" }
    }

    private fun consent() {
        ConsentActivity.reset()
        val activity = instrumentation.startActivitySync(Intent(context, ConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        consentActivity = activity
        run {
            val automation = instrumentation.uiAutomation
            automation.serviceInfo = automation.serviceInfo.apply { flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS }
            val end = SystemClock.elapsedRealtime() + 30000
            var startTouched = false
            while (VpnService.prepare(context) != null && SystemClock.elapsedRealtime() < end) {
                val root = automation.rootInActiveWindow
                if (!startTouched && root?.packageName?.toString() == "com.android.vpndialogs") {
                    // Older AOSP consent layouts gate the positive button behind this actual checkbox.
                    val checkbox = root.findAccessibilityNodeInfosByViewId("com.android.vpndialogs:id/check").singleOrNull()
                    if (checkbox?.isCheckable == true && !checkbox.isChecked && checkbox.isVisibleToUser && checkbox.isEnabled) {
                        val bounds = Rect(); checkbox.getBoundsInScreen(bounds); touch(bounds)
                    }
                    val button = root.findAccessibilityNodeInfosByViewId("android:id/button1").singleOrNull()
                    if (button?.isEnabled == true && button.isVisibleToUser) {
                        val bounds = Rect(); button.getBoundsInScreen(bounds)
                        if (!bounds.isEmpty) {
                            touch(bounds); consentDialog = true; startTouched = true
                        }
                    }
                }
                Thread.sleep(100)
            }
            check(ConsentActivity.awaitConsent(1000) && VpnService.prepare(context) == null) { "platform_consent_missing" }
        }
    }

    private fun touch(bounds: Rect) {
        check(!bounds.isEmpty) { "consent_bounds" }
        val down = SystemClock.uptimeMillis()
        for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
            val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action, bounds.exactCenterX(), bounds.exactCenterY(), 0)
            event.source = InputDevice.SOURCE_TOUCHSCREEN
            check(instrumentation.uiAutomation.injectInputEvent(event, true)) { "consent_touch" }; event.recycle()
        }
    }

    private fun authenticationBaseline(): Pair<CaptureSnapshot, ResearchCaptureService.GuardObservation> {
        val end = SystemClock.elapsedRealtime() + 15000
        var candidate: ResearchCaptureService.GuardObservation? = null
        var since = 0L
        while (true) {
            val state = snapshot()
            val capture = state.capture
            val guards = current().guardObservation()
            val now = SystemClock.elapsedRealtime()
            check(now < end) { "research_condition_timeout" }
            if (state.state == "active" && state.failureCode == null && state.tunEstablished && state.underlyingNetworkPresent &&
                state.lifecycleThreadAlive && capture != null && capture.started && capture.nativeRunning && !capture.failed &&
                !capture.admissionClosed && capture.activeFlows == 0 && capture.ownedSockets == 0 && capture.pendingOpens == 0) {
                if (candidate != guards) { candidate = guards; since = now }
                if (now - since >= 250) return capture to guards
            } else { candidate = null; since = 0L }
            Thread.sleep(25)
        }
    }

    private fun rejectLocalAuthentication() {
        val port = current().localSocksPort()
        check(port in 1..65535) { "local_listener_missing" }
        Socket().use { socket ->
            socket.soTimeout = 3000; socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port), 3000)
            socket.getOutputStream().write(byteArrayOf(5, 1, 0)); socket.getOutputStream().flush()
            check(socket.getInputStream().read() == 5 && socket.getInputStream().read() == 255) { "missing_auth_accepted" }
        }
        Socket().use { socket ->
            socket.soTimeout = 3000; socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port), 3000)
            socket.getOutputStream().write(byteArrayOf(5, 1, 2)); socket.getOutputStream().flush()
            check(socket.getInputStream().read() == 5 && socket.getInputStream().read() == 2) { "auth_negotiation" }
            socket.getOutputStream().write(byteArrayOf(1, 1, 98, 1, 99)); socket.getOutputStream().flush()
            check(socket.getInputStream().read() == 1 && socket.getInputStream().read() == 1) { "wrong_auth_accepted" }
        }
    }

    private fun route(traffic: TrafficClient, expectedVpn: Boolean) {
        phase = "route-readiness"
        val result = traffic.command(if (expectedVpn) 17 else 18)
        check(result.status == 0 && result.bytes == 0 && result.sha256 == null && result.failureCode == null) { result.failureCode ?: "traffic_invalid_reply" }
        routeChecks++
    }
    private fun tcp(traffic: TrafficClient, command: Int) {
        val result = traffic.command(command)
        check(result.status == 0) { result.failureCode ?: "tcp_bytes" }
        check(result.bytes == 32787 && result.sha256 == TCP_HASH) { "tcp_bytes" }
    }
    private fun current(): ResearchCaptureService = checkNotNull(ResearchCaptureService.current) { "service_missing" }
    private fun snapshot() = current().captureSnapshot()
    private fun port(name: String): Int = arguments.getString(name)?.takeIf { it.matches(Regex("[1-9][0-9]{0,4}")) }?.toIntOrNull()?.takeIf { it in 1024..65535 } ?: error("research_port")
    private fun delta(before: Map<String, Int>, after: Map<String, Int>, name: String, count: Int) { check(after.getValue(name) - before.getValue(name) == count) { "receiver_path_count" } }
    private fun await(condition: () -> Boolean) { val end = SystemClock.elapsedRealtime() + 15000; while (!condition()) { check(SystemClock.elapsedRealtime() < end) { "research_condition_timeout" }; Thread.sleep(25) } }
    companion object {
        private const val TCP_HASH = "05dfd86ee3ecc0267ceb6234e1955c1e8c80e34b6323b2b1c87c7d1d84042255"
        private const val UDP_HASH = "ca8c15a2b7d76a0dc5c39dc35deffcfc596d14194b5c09a7513acb1577e99dbe"
        private const val DNS_HASH = "ab8bd414e49bcfde5e1bcc7277d8947246a42dbd5802ee81db4cc4e90bddd8d3"
    }
}
