package com.httpfreekit.interop

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Rect
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.view.InputDevice
import android.view.MotionEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.capture.CaptureVpnService
import com.httpfreekit.capture.transport.CaptureTransportSnapshot
import com.httpfreekit.capturetest.TrafficClient
import com.httpfreekit.protocol.DraftEnrollmentMessage
import com.httpfreekit.protocol.HttpOriginConnect
import com.httpfreekit.security.AndroidDeviceIdentityStore
import com.httpfreekit.security.AndroidEnrolledCredentialStore
import com.httpfreekit.security.EnrolledCredentialRecord
import java.io.File
import java.io.FileInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.time.Instant
import java.util.concurrent.TimeUnit
import org.junit.Test
import org.junit.runner.RunWith

/** One fixed synthetic traffic UID; the test never opens the original flow or the local SOCKS port. */
@RunWith(AndroidJUnit4::class)
class DraftEnrolledTunInteropTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var phase = "input-consumed"
    private var category = "none"

    @Test(timeout = 240000)
    fun selectedUidHttpReachesEnrolledDesktopThroughTun() {
        var seed: DraftEnrollmentSeed? = null
        var files: DraftEnrollmentResearchFiles? = null
        var http: DraftEnrollmentHttpsClient? = null
        var store: AndroidEnrolledCredentialStore? = null
        var keys: AndroidDeviceIdentityStore? = null
        var identityOwned = false
        var traffic: TrafficClient? = null
        var activity: Activity? = null
        var forgotten = false
        var completed = false
        var httpAttempts = 0
        var cleanup = true
        var restoreInterrupt = false
        var failure: SafeFailure? = null
        val gate = PrivateGate()
        try {
            val privateFiles = DraftEnrollmentResearchFiles(context).also { files = it }
            gate.requireAbsent()
            val input = privateFiles.consumeInput().also { seed = it }
            val portText = InstrumentationRegistry.getArguments().getString("webSocketPort")
            check(portText != null && portText.matches(Regex("[1-9][0-9]{3,4}"))) { "Enrolled TUN gateway unavailable" }
            val port = portText.toInt()
            check(port in 1024..65535 && port != input.setupPort && port != input.credentialPort) { "Enrolled TUN gateway unavailable" }
            mark("input-consumed")
            val identities = AndroidDeviceIdentityStore().also { keys = it }
            val credentials = AndroidEnrolledCredentialStore(context).also { store = it }
            check(identities.load(input.desktopId) == null && credentials.load(input.desktopId) == null) { "Enrolled TUN identity already exists" }
            identityOwned = true
            val identity = identities.create(input.desktopId)
            val original = DraftEnrollmentResearchChecks.keyEvidence(identity)
            val gateway = DraftEnrollmentHttpsClient.certificate(input.gatewayCertificateDer)
            val client = DraftEnrollmentHttpsClient(gateway, input.gatewaySpkiSha256, input.logicalName,
                input.setupPort, input.credentialPort).also { http = it }
            val requested = listOf(HttpOriginConnect.CAPABILITY, "tcp-https-connect")
            val registered = client.exchange(DraftEnrollmentResearchChecks.pair(input, identity, requested)) as? DraftEnrollmentMessage.Registered
                ?: error("Enrolled TUN reservation unavailable")
            check(registered.desktopId == input.desktopId && registered.invitationId == input.invitationId &&
                registered.deviceSpkiSha256 == DraftEnrollmentResearchChecks.b64(DraftEnrollmentResearchChecks.hash(identity.publicKey.encoded)) &&
                registered.reservationExpiresAt == input.invitationExpiresAt && Instant.now().isBefore(Instant.parse(registered.resultExpiresAt))) {
                "Enrolled TUN reservation changed"
            }
            input.clearInvitationSecret()
            val proof = DraftEnrollmentProofSession(client, identity, input.desktopId, input.gatewaySpkiSha256,
                input.invitationId, registered.enrollmentId, registered.reservationExpiresAt)
            check(proof.status() is DraftEnrollmentMessage.Pending) { "Enrolled TUN reservation not pending" }
            mark("strict-csr-reserved"); mark("awaiting-host-approval")
            val approvalDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
            var approved: DraftEnrollmentMessage.Approved? = null
            while (approved == null) {
                check(System.nanoTime() - approvalDeadline < 0) { "Enrolled TUN approval deadline" }
                when (val reply = proof.status()) {
                    is DraftEnrollmentMessage.Pending -> Thread.sleep(reply.retryAfterMillis.toLong())
                    is DraftEnrollmentMessage.Approved -> approved = reply
                    else -> error("Enrolled TUN approval ended")
                }
            }
            val grant = checkNotNull(approved)
            val certificates = DraftEnrollmentResearchChecks.validateApproved(grant, identity, input.desktopId,
                registered.enrollmentId, registered.resultExpiresAt, requested)
            check(grant.capabilities.toSet() == requested.toSet() && grant.capabilities.size == requested.size) { "Enrolled TUN capabilities changed" }
            val leaf = certificates.first.encoded
            credentials.save(EnrolledCredentialRecord(input.desktopId, gateway, input.gatewaySpkiSha256,
                input.logicalName, listOf(certificates.first), certificates.second))
            fun requireCredential() {
                val loaded = checkNotNull(credentials.load(input.desktopId)) { "Enrolled TUN credential missing" }
                check(loaded.record.clientCertificateChain.single().encoded.contentEquals(leaf)) { "Enrolled TUN credential changed" }
                val alias = checkNotNull(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null))
                check(checkNotNull(loaded.clientKeyManager.getPrivateKey(alias)).encoded == null) { "Enrolled TUN key exportable" }
                DraftEnrollmentResearchChecks.sameHashes(original, DraftEnrollmentResearchChecks.keyEvidence(identity))
            }
            requireCredential(); client.close(); http = null
            mark("credential-saved-reloaded")
            val uid = context.packageManager.getApplicationInfo(DraftEnrolledTunService.TRAFFIC_PACKAGE, 0).uid
            check(uid != Process.myUid()) { "Enrolled TUN traffic UID not separate" }
            if (Build.VERSION.SDK_INT >= 37) {
                check(context.checkSelfPermission("android.permission.ACCESS_LOCAL_NETWORK") == PackageManager.PERMISSION_GRANTED &&
                    context.packageManager.checkPermission("android.permission.ACCESS_LOCAL_NETWORK", DraftEnrolledTunService.TRAFFIC_PACKAGE) == PackageManager.PERMISSION_GRANTED) {
                    "Enrolled TUN local permission missing"
                }
            }
            activity = consent { activity = it }
            await(5000) { (activity as? DraftEnrolledTunConsentActivity)?.researchResumed() == true }
            mark("vpn-consent-granted")
            val producer = TrafficClient(context, port).also { traffic = it }
            DraftEnrolledTunService.configure(input.desktopId,
                InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port))
            context.startForegroundService(Intent(context, DraftEnrolledTunService::class.java).setAction(CaptureVpnService.ACTION_START))
            await(30000) { DraftEnrolledTunService.current?.captureSnapshot()?.state in setOf("active", "failed") }
            val service = checkNotNull(DraftEnrolledTunService.current)
            fun requireActive() {
                val state = service.captureSnapshot(); val owner = state.capture
                check(state.state == "active" && state.tunEstablished && state.selectedPackageCount == 1 &&
                    state.underlyingNetworkPresent && state.lifecycleThreadAlive && state.failureCode == null &&
                    owner != null && owner.started && owner.nativeRunning && !owner.failed && !owner.admissionClosed) { "Enrolled TUN not active" }
            }
            requireActive()
            val stop = notificationStop()
            mark("tun-native-active")
            check(producer.command(17).let { it.status == 0 && it.bytes == 0 && it.sha256 == null }) { "Enrolled TUN selected route unavailable" }
            requireActive(); mark("selected-uid-route-observed")
            mark("http-command-started")
            httpAttempts++
            val response = producer.command(19)
            if (response.status != 0) category = response.failureCode?.takeIf {
                it.matches(Regex("traffic_tcp_(?:connect|write|shutdown|reply|eof|close)_(?:reset|aborted|closed|bad_fd|not_connected|timeout|io|protocol|other)")) ||
                    it in setOf("traffic_close_io", "traffic_command_failed")
            } ?: "none"
            check(response.status == 0 && response.bytes == 32787 && response.sha256 == RESPONSE_HASH && response.failureCode == null) {
                "Enrolled TUN HTTP exchange failed"
            }
            // Command19's only OK path follows its fixed upload, actual SHUT_WR and strict response EOF.
            mark("http-response-validated")
            await(15000) {
                val capture = service.captureSnapshot().capture
                val transport = service.factorySnapshot()
                capture != null && capture.activeFlows == 0 && capture.ownedSockets == 0 && capture.pendingOpens == 0 &&
                    transport != null && drained(transport)
            }
            requireActive()
            val observed = checkNotNull(service.captureSnapshot().capture)
            check(observed.interceptedTcpFlows == 1 && observed.directTcpFlows == 0 && observed.udpTargets == 0 &&
                observed.udp443Drops == 0 && observed.protectFailures == 0 && observed.bindFailures == 0) { "Enrolled TUN routing changed" }
            val guards = service.guardSnapshot()
            check(guards.protectAttempts == 2 && guards.protectSuccesses == 2 && guards.bindAttempts == 2 && guards.bindSuccesses == 2) {
                "Enrolled TUN gateway protection missing"
            }
            requireCredential(); mark("local-stream-drained")
            gate.consume()
            requireActive(); check(drained(checkNotNull(service.factorySnapshot()))) { "Enrolled TUN changed before Stop" }
            mark("gateway-complete-acknowledged")
            stop.actionIntent.send()
            check(service.awaitStopped(30000)) { "Enrolled TUN lifecycle not joined" }
            val stopped = service.captureSnapshot(); val capture = checkNotNull(stopped.capture)
            val final = checkNotNull(service.factorySnapshot())
            check(stopped.state == "stopped" && !stopped.tunEstablished && !stopped.lifecycleThreadAlive && stopped.failureCode == null &&
                !capture.failed && capture.admissionClosed && !capture.nativeRunning && capture.nativeStopJoined && capture.tunClosed &&
                !capture.configurationPresent && capture.activeFlows == 0 && capture.ownedSockets == 0 && capture.pendingOpens == 0 && capture.liveWorkers == 0) {
                "Enrolled TUN resources remain"
            }
            check(final.closed && final.admissionClosed && final.failureCode == null && final.pendingOpens == 0 && final.pendingCalls == 0 &&
                final.retainedTransports == 0 && final.liveWorkers == 0 && !final.sessionLease && final.streamLeases == 0 && final.chargedBytes == 0L &&
                final.pendingIngressBytes == 0L && final.backendOutputBytes == 0L && final.backendIncomingBytes == 0L) { "Enrolled TUN factory remains" }
            mark("capture-stop-joined")
            check(producer.command(18).let { it.status == 0 && it.bytes == 0 && it.sha256 == null }) { "Enrolled TUN non-VPN route unavailable" }
            check(context.packageManager.getApplicationInfo(DraftEnrolledTunService.TRAFFIC_PACKAGE, 0).uid == uid) { "Enrolled TUN traffic UID changed" }
            mark("non-vpn-route-observed")
            producer.close(); traffic = null
            mark("traffic-worker-joined")
            requireCredential()
            instrumentation.runOnMainSync { activity?.finish() }
            check(DraftEnrolledTunConsentActivity.awaitDestroyed(5000)) { "Enrolled TUN consent Activity remains" }
            activity = null
            DraftEnrolledTunService.clearStoppedConfiguration()
            credentials.forget(input.desktopId); privateFiles.clearRecovery(); gate.requireAbsent()
            check(identities.load(input.desktopId) == null && credentials.load(input.desktopId) == null) { "Enrolled TUN owned identity remains" }
            forgotten = true
            instrumentation.sendStatus(3, Bundle().apply {
                fun put(name: String, value: Any) = putString("draftTun$name", value.toString())
                put("Version", 1); put("CredentialSavedReloaded", true); put("KeyNonexportable", true); put("OriginalCredentialUnchanged", true)
                put("VpnConsentGranted", true); put("SeparateTrafficUid", true); put("SelectedUidVpnObserved", true)
                put("TunAndNativeObserved", true); put("ForegroundNotificationObserved", true); put("HttpAttempts", httpAttempts)
                put("HttpOutputHalfClosed", response.status == 0); put("StrictResponseEof", response.status == 0)
                put("LocalStreamsDrained", true); put("HostCompleteAcknowledged", true)
                put("ProtectAttempts", guards.protectAttempts); put("ProtectSuccesses", guards.protectSuccesses)
                put("BindAttempts", guards.bindAttempts); put("BindSuccesses", guards.bindSuccesses)
                put("SelectedPackageCount", stopped.selectedPackageCount); put("InterceptedTcpFlows", observed.interceptedTcpFlows)
                put("DirectTcpFlows", observed.directTcpFlows); put("UdpTargets", observed.udpTargets); put("Udp443Drops", observed.udp443Drops)
                put("ProtectFailures", observed.protectFailures); put("BindFailures", observed.bindFailures)
                put("ResponseBodyBytes", response.bytes); put("ResponseBodySha256", checkNotNull(response.sha256))
                put("CaptureStopped", stopped.state == "stopped"); put("TunClosed", capture.tunClosed); put("NativeStopJoined", capture.nativeStopJoined)
                put("ConfigurationAbsent", !capture.configurationPresent); put("LifecycleJoined", !stopped.lifecycleThreadAlive)
                put("ActiveFlows", capture.activeFlows); put("OwnedSockets", capture.ownedSockets); put("PendingOpens", capture.pendingOpens); put("LiveWorkers", capture.liveWorkers)
                put("FactoryClosed", final.closed); put("FactoryPendingOpens", final.pendingOpens); put("FactoryPendingCalls", final.pendingCalls)
                put("RetainedTransports", final.retainedTransports); put("FactoryLiveWorkers", final.liveWorkers); put("SessionLease", final.sessionLease)
                put("StreamLeases", final.streamLeases); put("ChargedBytes", final.chargedBytes); put("PendingIngressBytes", final.pendingIngressBytes)
                put("BackendOutputBytes", final.backendOutputBytes); put("BackendIncomingBytes", final.backendIncomingBytes)
                put("NonVpnRouteObserved", true); put("TrafficWorkerJoined", true); put("OwnedStateAbsent", forgotten)
            })
            mark("owned-state-forgotten"); completed = true
        } catch (caught: Throwable) {
            if (caught !is Exception && caught !is AssertionError) throw caught
            if (caught is InterruptedException) restoreInterrupt = true
            failure = safeFailure(caught)
        } finally {
            restoreInterrupt = Thread.interrupted() || restoreInterrupt
            seed?.clearInvitationSecret()
            if (!completed) {
                fun attempt(action: () -> Unit) {
                    try { action() }
                    catch (caught: Exception) { if (caught is InterruptedException) restoreInterrupt = true; cleanup = false }
                    catch (_: AssertionError) { cleanup = false }
                    finally { restoreInterrupt = Thread.interrupted() || restoreInterrupt }
                }
                attempt {
                    DraftEnrolledTunService.current?.let { service ->
                        if (!service.awaitStopped(1)) context.startService(Intent(context, DraftEnrolledTunService::class.java).setAction(CaptureVpnService.ACTION_STOP))
                        check(service.awaitStopped(30000) && !service.captureSnapshot().tunEstablished)
                    }
                }
                attempt { traffic?.close() }; attempt { http?.close() }
                attempt { instrumentation.runOnMainSync { activity?.finish() }; if (activity != null) check(DraftEnrolledTunConsentActivity.awaitDestroyed(5000)) }
                attempt { DraftEnrolledTunService.clearStoppedConfiguration() }
                attempt { gate.clearOwned() }
                if (cleanup && identityOwned && !forgotten) attempt {
                    store?.forget(checkNotNull(seed).desktopId); files?.clearRecovery()
                    check(keys?.load(checkNotNull(seed).desktopId) == null && store?.load(checkNotNull(seed).desktopId) == null)
                }
            }
            if (restoreInterrupt) Thread.currentThread().interrupt()
        }
        failure?.let { failed -> throw AssertionError("Enrolled TUN research failed at ${failed.phase} (${failed.type}); category=$category; cleanup=$cleanup.").apply { stackTrace = failed.frames } }
    }

    private fun drained(value: CaptureTransportSnapshot) = !value.closed && !value.admissionClosed && value.failureCode == null &&
        value.sessionLease && value.pendingOpens == 0 && value.pendingCalls == 0 && value.retainedTransports == 1 &&
        value.streamLeases == 0 && value.chargedBytes == 0L && value.pendingIngressBytes == 0L && value.backendOutputBytes == 0L && value.backendIncomingBytes == 0L

    private fun mark(value: String) {
        phase = value
        instrumentation.sendStatus(2, Bundle().apply { putString("draftTunVersion", "1"); putString("draftTunPhase", value) })
    }

    private fun notificationStop(): Notification.Action {
        val notification = context.getSystemService(NotificationManager::class.java).activeNotifications.singleOrNull {
            it.notification.flags and Notification.FLAG_ONGOING_EVENT != 0 && it.notification.actions?.count { action -> action.title.toString() == "Stop" } == 1
        }?.notification ?: error("Enrolled TUN notification missing")
        return checkNotNull(notification.actions.single { it.title.toString() == "Stop" }.also { check(it.actionIntent != null) })
    }

    private fun consent(retain: (Activity) -> Unit): Activity {
        DraftEnrolledTunConsentActivity.reset()
        val activity = instrumentation.startActivitySync(Intent(context, DraftEnrolledTunConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        retain(activity)
        val automation = instrumentation.uiAutomation
        automation.serviceInfo = automation.serviceInfo.apply { flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS }
        val deadline = SystemClock.elapsedRealtime() + 30000
        var touched = false
        while (VpnService.prepare(context) != null && SystemClock.elapsedRealtime() < deadline) {
            val root = automation.rootInActiveWindow
            if (!touched && root?.packageName?.toString() == "com.android.vpndialogs") {
                val checkbox = root.findAccessibilityNodeInfosByViewId("com.android.vpndialogs:id/check").singleOrNull()
                if (checkbox?.isCheckable == true && !checkbox.isChecked && checkbox.isVisibleToUser && checkbox.isEnabled) {
                    val bounds = Rect(); checkbox.getBoundsInScreen(bounds); touch(bounds)
                }
                val button = root.findAccessibilityNodeInfosByViewId("android:id/button1").singleOrNull()
                if (button?.isEnabled == true && button.isVisibleToUser) {
                    val bounds = Rect(); button.getBoundsInScreen(bounds)
                    if (!bounds.isEmpty) { touch(bounds); touched = true }
                }
            }
            Thread.sleep(100)
        }
        check(DraftEnrolledTunConsentActivity.awaitConsent(1000) && VpnService.prepare(context) == null) { "Enrolled TUN consent unavailable" }
        return activity
    }

    private fun touch(bounds: Rect) {
        check(!bounds.isEmpty) { "Enrolled TUN consent bounds" }
        val down = SystemClock.uptimeMillis()
        for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
            val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action, bounds.exactCenterX(), bounds.exactCenterY(), 0)
            try { event.source = InputDevice.SOURCE_TOUCHSCREEN; check(instrumentation.uiAutomation.injectInputEvent(event, true)) { "Enrolled TUN consent touch" } }
            finally { event.recycle() }
        }
    }

    private fun await(millis: Long, condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis)
        while (true) {
            check(System.nanoTime() - deadline < 0) { "Enrolled TUN observation deadline" }
            val observed = condition()
            check(System.nanoTime() - deadline < 0) { "Enrolled TUN observation deadline" }
            if (observed) return
            Thread.sleep(25)
        }
    }

    private inner class PrivateGate {
        private fun directory(): File = File(context.noBackupFilesDir.canonicalFile, "draft-enrollment-research").also {
            check(it.canonicalFile == it.absoluteFile) { "Enrolled TUN gate path changed" }
            val stat = Os.lstat(it.path)
            check(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid() && stat.st_mode and 511 == 448) { "Enrolled TUN gate directory not private" }
        }
        private fun file() = File(directory(), "tun-complete-v1.bin")
        private fun exists(file: File): Boolean = try { Os.lstat(file.path); true }
        catch (failure: ErrnoException) { if (failure.errno == OsConstants.ENOENT) false else throw failure }
        fun requireAbsent() { check(!exists(file())) { "Unexpected enrolled TUN acknowledgment" } }
        fun consume() {
            val target = file()
            await(20000) { exists(target) }
            check(target.canonicalFile == target.absoluteFile) { "Enrolled TUN gate path changed" }
            val entryBefore = Os.lstat(target.path)
            check(OsConstants.S_ISREG(entryBefore.st_mode) && entryBefore.st_uid == Process.myUid() &&
                entryBefore.st_nlink == 1L && entryBefore.st_mode and 511 == 384 && entryBefore.st_size == ACK.size.toLong()) {
                "Enrolled TUN gate not a private bounded file"
            }
            // A wrong-type replacement (including a FIFO) must not block before fstat can reject it.
            val descriptor = Os.open(target.path, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_NONBLOCK, 0)
            val source = try { FileInputStream(descriptor) } catch (failure: Exception) {
                try { Os.close(descriptor) } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
                throw failure
            }
            source.use { input ->
                val before = Os.fstat(descriptor)
                check(OsConstants.S_ISREG(before.st_mode) && before.st_uid == Process.myUid() && before.st_nlink == 1L &&
                    before.st_mode and 511 == 384 && before.st_size == ACK.size.toLong() &&
                    before.st_dev == entryBefore.st_dev && before.st_ino == entryBefore.st_ino) { "Enrolled TUN gate not a private bounded file" }
                val bytes = ByteArray(ACK.size + 1); var size = 0
                while (size < bytes.size) { val count = input.read(bytes, size, bytes.size - size); if (count < 0) break; check(count > 0); size += count }
                val after = Os.fstat(descriptor); val entry = Os.lstat(target.path)
                check(before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
                    after.st_uid == before.st_uid && after.st_nlink == 1L && after.st_mode and 511 == 384 &&
                    entry.st_dev == before.st_dev && entry.st_ino == before.st_ino && entry.st_uid == before.st_uid && entry.st_nlink == 1L &&
                    entry.st_mode and 511 == 384 && OsConstants.S_ISREG(entry.st_mode) &&
                    size == ACK.size && bytes.copyOf(size).contentEquals(ACK)) { "Enrolled TUN acknowledgment changed" }
                check(target.delete()) { "Enrolled TUN acknowledgment not consumed" }
            }
            requireAbsent()
        }
        fun clearOwned() {
            val target = file()
            if (exists(target)) {
                val stat = Os.lstat(target.path)
                check(target.canonicalFile == target.absoluteFile && OsConstants.S_ISREG(stat.st_mode) && stat.st_uid == Process.myUid() &&
                    stat.st_nlink == 1L && stat.st_mode and 63 == 0 && stat.st_size in 0L..64L) { "Enrolled TUN gate cleanup unavailable" }
                check(target.delete()) { "Enrolled TUN gate remains" }
            }
            requireAbsent()
        }
    }

    private class SafeFailure(val phase: String, val type: String, val frames: Array<StackTraceElement>)
    private fun safeFailure(error: Throwable): SafeFailure {
        val type = when (error) { is AssertionError -> "AssertionError"; is IllegalArgumentException -> "IllegalArgumentException"; is java.io.IOException -> "IOException"; else -> "IllegalStateException" }
        val roots = mapOf("DraftEnrolledTunInteropTest.kt" to "com.httpfreekit.interop.DraftEnrolledTunInteropTest",
            "DraftEnrolledTunService.kt" to "com.httpfreekit.interop.DraftEnrolledTunService",
            "DraftEnrolledTunConsentActivity.kt" to "com.httpfreekit.interop.DraftEnrolledTunConsentActivity",
            "DraftEnrollmentResearchChecks.kt" to "com.httpfreekit.interop.DraftEnrollmentResearchChecks",
            "DraftEnrollmentResearchFiles.kt" to "com.httpfreekit.interop.DraftEnrollmentResearchFiles",
            "DraftEnrollmentHttpsClient.kt" to "com.httpfreekit.interop.DraftEnrollmentHttpsClient",
            "TrafficClient.kt" to "com.httpfreekit.capturetest.TrafficClient",
            "EnrolledCaptureTcpFactory.kt" to "com.httpfreekit.capture.transport.EnrolledCaptureTcpFactory")
        val frames = error.stackTrace.take(128).filter { frame -> roots[frame.fileName]?.let { root ->
            (frame.className == root || frame.className.startsWith(root + "$")) && frame.lineNumber in 1..100000 &&
                frame.methodName.matches(Regex("(?:[A-Za-z_$][A-Za-z0-9_$]*|<init>|<clinit>)")) } == true }.take(16).toTypedArray()
        return SafeFailure(phase, type, frames)
    }

    companion object {
        private const val RESPONSE_HASH = "62a22a63bb850ba7b263fccff99e868133570394d36d6ee16fd32e9d7c1a4601"
        private val ACK = "FREEKIT-C5-COMPLETE-V1\n".toByteArray(Charsets.US_ASCII)
    }
}
