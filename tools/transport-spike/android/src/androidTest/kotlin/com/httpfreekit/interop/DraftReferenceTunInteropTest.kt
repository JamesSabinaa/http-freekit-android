package com.httpfreekit.interop

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
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
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.TimeUnit
import org.junit.Test
import org.junit.runner.RunWith

/** Original application traffic belongs exclusively to the separately selected traffic UID. */
@RunWith(AndroidJUnit4::class)
class DraftReferenceTunInteropTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var phase = "input-consumed"
    private var category = "none"

    @Test(timeout = 240000)
    fun selectedUidHttpReachesReferenceOriginThroughTun() = runTransaction(20)

    @Test(timeout = 240000)
    fun selectedUidH1HttpsReachesReferenceOriginThroughTun() = runTransaction(21)

    private fun runTransaction(command: Int) {
        check(command == 20 || command == 21)
        var seed: DraftEnrollmentSeed? = null
        var files: DraftEnrollmentResearchFiles? = null
        var http: DraftEnrollmentHttpsClient? = null
        var caClient: DraftInterceptionCaClient? = null
        var store: AndroidEnrolledCredentialStore? = null
        var keys: AndroidDeviceIdentityStore? = null
        var identityOwned = false
        var traffic: TrafficClient? = null
        var activity: Activity? = null
        var forgotten = false
        var completed = false
        var trafficAttempts = 0
        var cleanup = true
        var restoreInterrupt = false
        var failure: SafeFailure? = null
        val cleanupFailures = ArrayList<SafeFailure>()
        val gate = PrivateGate()
        try {
            val privateFiles = DraftEnrollmentResearchFiles(context).also { files = it }
            gate.requireAbsent()
            val input = privateFiles.consumeInput().also { seed = it }
            val portText = InstrumentationRegistry.getArguments().getString("webSocketPort")
            check(portText != null && portText.matches(Regex("[1-9][0-9]{3,4}")))
            val port = portText.toInt()
            check(port in 1024..65535 && port != input.setupPort && port != input.credentialPort)
            mark("input-consumed")
            val identities = AndroidDeviceIdentityStore().also { keys = it }
            val credentials = AndroidEnrolledCredentialStore(context).also { store = it }
            check(identities.load(input.desktopId) == null && credentials.load(input.desktopId) == null)
            identityOwned = true
            val identity = identities.create(input.desktopId)
            val original = DraftEnrollmentResearchChecks.keyEvidence(identity)
            val gateway = DraftEnrollmentHttpsClient.certificate(input.gatewayCertificateDer)
            val client = DraftEnrollmentHttpsClient(gateway, input.gatewaySpkiSha256, input.logicalName,
                input.setupPort, input.credentialPort).also { http = it }
            val requested = listOf(HttpOriginConnect.CAPABILITY, "tcp-https-connect")
            val registered = client.exchange(DraftEnrollmentResearchChecks.pair(input, identity, requested)) as? DraftEnrollmentMessage.Registered
                ?: error("Reference reservation unavailable")
            check(registered.desktopId == input.desktopId && registered.invitationId == input.invitationId &&
                registered.deviceSpkiSha256 == DraftEnrollmentResearchChecks.b64(DraftEnrollmentResearchChecks.hash(identity.publicKey.encoded)) &&
                registered.reservationExpiresAt == input.invitationExpiresAt && Instant.now().isBefore(Instant.parse(registered.resultExpiresAt)))
            input.clearInvitationSecret()
            val proof = DraftEnrollmentProofSession(client, identity, input.desktopId, input.gatewaySpkiSha256,
                input.invitationId, registered.enrollmentId, registered.reservationExpiresAt)
            check(proof.status() is DraftEnrollmentMessage.Pending)
            mark("strict-csr-reserved"); mark("awaiting-host-approval")
            val approvalDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
            var approved: DraftEnrollmentMessage.Approved? = null
            while (approved == null) {
                check(System.nanoTime() - approvalDeadline < 0)
                when (val reply = proof.status()) {
                    is DraftEnrollmentMessage.Pending -> Thread.sleep(reply.retryAfterMillis.toLong())
                    is DraftEnrollmentMessage.Approved -> approved = reply
                    else -> error("Reference approval ended")
                }
            }
            val grant = checkNotNull(approved)
            val certificates = DraftEnrollmentResearchChecks.validateApproved(grant, identity, input.desktopId,
                registered.enrollmentId, registered.resultExpiresAt, requested)
            check(grant.capabilities.toSet() == requested.toSet() && grant.capabilities.size == requested.size)
            val leaf = certificates.first.encoded
            credentials.save(EnrolledCredentialRecord(input.desktopId, gateway, input.gatewaySpkiSha256,
                input.logicalName, listOf(certificates.first), certificates.second))
            fun requireCredential() {
                val loaded = checkNotNull(credentials.load(input.desktopId))
                check(loaded.record.clientCertificateChain.single().encoded.contentEquals(leaf))
                val alias = checkNotNull(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null))
                check(checkNotNull(loaded.clientKeyManager.getPrivateKey(alias)).encoded == null)
                DraftEnrollmentResearchChecks.sameHashes(original, DraftEnrollmentResearchChecks.keyEvidence(identity))
            }
            // Retain the actual approved binding, never a host-provided public-CA substitute.
            val recovery = DraftEnrollmentRecovery(input.setupPort, input.credentialPort, input.desktopId,
                DraftEnrollmentResearchChecks.unb64(input.gatewaySpkiSha256), input.logicalName, input.invitationId,
                registered.enrollmentId, grant.deviceId, identity.publicKey.encoded, original,
                DraftEnrollmentResearchChecks.hash(leaf), DraftEnrollmentResearchChecks.hash(certificates.second.encoded),
                DraftEnrollmentResearchChecks.unb64(grant.interceptionCaCertificateSha256), grant.capabilities,
                registered.reservationExpiresAt, registered.resultExpiresAt, grant.credentialExpiresAt)
            privateFiles.saveRecovery(recovery)
            val recoveryBytes = DraftEnrollmentStateCodec.encodeRecovery(recovery)
            requireCredential(); client.close(); http = null
            mark("credential-saved-reloaded")
            val retained = privateFiles.readRecovery()
            check(recoveryBytes.contentEquals(DraftEnrollmentStateCodec.encodeRecovery(retained)))
            val getter = DraftInterceptionCaSavedCredential.open(context, retained,
                InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), input.credentialPort)).also { caClient = it }
            val publicCa = getter.fetch()
            val caDer = publicCa.certificateDer
            check(caDer.size in 1..4096 && MessageDigest.isEqual(DraftEnrollmentResearchChecks.hash(caDer), retained.interceptionCaCertificateSha256) &&
                MessageDigest.isEqual(publicCa.certificateSha256, retained.interceptionCaCertificateSha256))
            getter.close(); requireCaJoined(getter.snapshot()); caClient = null
            requireCredential()
            check(recoveryBytes.contentEquals(DraftEnrollmentStateCodec.encodeRecovery(privateFiles.readRecovery())))
            mark("authenticated-ca-fetched")
            val uid = context.packageManager.getApplicationInfo(DraftReferenceTunService.TRAFFIC_PACKAGE, 0).uid
            check(uid != Process.myUid())
            if (Build.VERSION.SDK_INT >= 37) {
                check(context.checkSelfPermission("android.permission.ACCESS_LOCAL_NETWORK") == PackageManager.PERMISSION_GRANTED &&
                    context.packageManager.checkPermission("android.permission.ACCESS_LOCAL_NETWORK", DraftReferenceTunService.TRAFFIC_PACKAGE) == PackageManager.PERMISSION_GRANTED)
            }
            requireTrafficAuthorization()
            activity = consent { activity = it }
            await(5000) { (activity as? DraftReferenceTunConsentActivity)?.researchResumed() == true }
            mark("vpn-consent-granted")
            // Existing constructor directPort configuration is required, but sends no direct data transaction.
            val producer = TrafficClient(context, port).also { traffic = it }
            check(producer.command(3, Bundle().apply { putByteArray("caDer", caDer) }).let {
                it.status == 0 && it.bytes == 0 && it.sha256 == null && it.failureCode == null
            })
            caDer.fill(0)
            DraftReferenceTunService.configure(input.desktopId,
                InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port))
            context.startForegroundService(Intent(context, DraftReferenceTunService::class.java).setAction(CaptureVpnService.ACTION_START))
            await(30000) { DraftReferenceTunService.current?.captureSnapshot()?.state in setOf("active", "failed") }
            val service = checkNotNull(DraftReferenceTunService.current)
            fun requireActive() {
                val state = service.captureSnapshot(); val owner = state.capture
                check(state.state == "active" && state.tunEstablished && state.selectedPackageCount == 1 &&
                    state.underlyingNetworkPresent && state.lifecycleThreadAlive && state.failureCode == null &&
                    owner != null && owner.started && owner.nativeRunning && !owner.failed && !owner.admissionClosed)
            }
            requireActive()
            val stop = notificationStop()
            mark("tun-native-active")
            check(producer.command(17).let { it.status == 0 && it.bytes == 0 && it.sha256 == null && it.failureCode == null })
            requireActive(); mark("selected-uid-route-observed")
            mark("traffic-command-started")
            trafficAttempts++
            val response = producer.command(command)
            if (response.status != 0) category = response.failureCode?.takeIf { it in TRAFFIC_FAILURES } ?: "none"
            check(response.status == 0 && response.bytes == 81 && response.sha256 == responseHash() && response.failureCode == null)
            // Commands20/21 publish success only after fixed request/full strict H1 validation,
            // actual raw SHUT_WR, independent raw EOF and socket closure. Command21 additionally
            // requires platform chain/name verification. Neither ALPN nor verified close_notify is inferred.
            mark("traffic-response-validated")
            await(15000) {
                val capture = service.captureSnapshot().capture
                val transport = service.factorySnapshot()
                capture != null && capture.activeFlows == 0 && capture.ownedSockets == 0 && capture.pendingOpens == 0 &&
                    transport != null && drained(transport)
            }
            requireActive()
            val observed = checkNotNull(service.captureSnapshot().capture)
            check(observed.interceptedTcpFlows == 1 && observed.directTcpFlows == 0 && observed.udpTargets == 0 &&
                observed.udp443Drops == 0 && observed.protectFailures == 0 && observed.bindFailures == 0)
            val guards = service.guardSnapshot()
            check(guards.protectAttempts >= 2 && guards.protectSuccesses == guards.protectAttempts &&
                guards.bindAttempts == guards.protectAttempts && guards.bindSuccesses == guards.bindAttempts)
            requireCredential(); mark("local-stream-drained")
            // Only the independent host can publish this gate after actual COMPLETE/EOF/1000 Close/joins.
            gate.consume()
            requireActive(); check(drained(checkNotNull(service.factorySnapshot())))
            mark("gateway-complete-acknowledged")
            stop.actionIntent.send()
            check(service.awaitStopped(30000))
            val stopped = service.captureSnapshot(); val capture = checkNotNull(stopped.capture)
            val final = checkNotNull(service.factorySnapshot())
            check(stopped.state == "stopped" && !stopped.tunEstablished && !stopped.lifecycleThreadAlive && stopped.failureCode == null &&
                !capture.failed && capture.admissionClosed && !capture.nativeRunning && capture.nativeStopJoined && capture.tunClosed &&
                !capture.configurationPresent && capture.activeFlows == 0 && capture.ownedSockets == 0 && capture.pendingOpens == 0 && capture.liveWorkers == 0)
            check(capture.interceptedTcpFlows == observed.interceptedTcpFlows && capture.directTcpFlows == 0 && capture.udpTargets == 0 &&
                capture.udp443Drops == 0 && capture.protectFailures == 0 && capture.bindFailures == 0)
            val finalGuards = service.guardSnapshot()
            check(finalGuards.protectAttempts == guards.protectAttempts && finalGuards.protectSuccesses == guards.protectSuccesses &&
                finalGuards.bindAttempts == guards.bindAttempts && finalGuards.bindSuccesses == guards.bindSuccesses)
            check(final.closed && final.admissionClosed && final.failureCode == null && final.pendingOpens == 0 && final.pendingCalls == 0 &&
                final.retainedTransports == 0 && final.liveWorkers == 0 && !final.sessionLease && final.streamLeases == 0 && final.chargedBytes == 0L &&
                final.pendingIngressBytes == 0L && final.backendOutputBytes == 0L && final.backendIncomingBytes == 0L)
            mark("capture-stop-joined")
            check(producer.command(18).let { it.status == 0 && it.bytes == 0 && it.sha256 == null && it.failureCode == null })
            check(context.packageManager.getApplicationInfo(DraftReferenceTunService.TRAFFIC_PACKAGE, 0).uid == uid)
            mark("non-vpn-route-observed")
            producer.close(); traffic = null
            mark("traffic-worker-joined")
            requireCredential()
            check(recoveryBytes.contentEquals(DraftEnrollmentStateCodec.encodeRecovery(privateFiles.readRecovery())))
            instrumentation.runOnMainSync { activity?.finish() }
            check(DraftReferenceTunConsentActivity.awaitDestroyed(5000)); activity = null
            DraftReferenceTunService.clearStoppedConfiguration()
            credentials.forget(input.desktopId); privateFiles.clearRecovery(); gate.requireAbsent()
            check(identities.load(input.desktopId) == null && credentials.load(input.desktopId) == null)
            forgotten = true
            mark("owned-state-forgotten")
            instrumentation.sendStatus(3, Bundle().apply {
                fun put(name: String, value: Any) = putString("draftReferenceTun$name", value.toString())
                put("Version", 1); put("CredentialSavedReloaded", true); put("KeyNonexportable", true); put("OriginalCredentialUnchanged", true)
                put("AuthenticatedCaFetched", true); put("SeparateTrafficUid", uid != Process.myUid()); put("VpnConsentGranted", true)
                put("SelectedUidVpnObserved", true); put("TunAndNativeObserved", true); put("ForegroundNotificationObserved", true)
                put("TrafficAttempts", trafficAttempts); put("RequestBodyValidated", response.status == 0); put("ResponseBodyValidated", response.status == 0)
                put("OutputHalfClosed", response.status == 0); put("StrictResponseEof", response.status == 0); put("SocketClosed", response.status == 0)
                put("TlsUsed", command == 21 && response.status == 0); put("TlsPeerVerified", command == 21 && response.status == 0)
                put("LocalStreamsDrained", true); put("HostCompleteAcknowledged", true)
                put("ProtectAttempts", finalGuards.protectAttempts); put("ProtectSuccesses", finalGuards.protectSuccesses)
                put("BindAttempts", finalGuards.bindAttempts); put("BindSuccesses", finalGuards.bindSuccesses)
                put("SelectedPackageCount", stopped.selectedPackageCount); put("InterceptedTcpFlows", capture.interceptedTcpFlows)
                put("DirectTcpFlows", capture.directTcpFlows); put("UdpTargets", capture.udpTargets); put("Udp443Drops", capture.udp443Drops)
                put("ProtectFailures", capture.protectFailures); put("BindFailures", capture.bindFailures); put("ResponseBodyBytes", response.bytes)
                put("CaptureStopped", stopped.state == "stopped"); put("TunClosed", capture.tunClosed); put("NativeStopJoined", capture.nativeStopJoined)
                put("ConfigurationAbsent", !capture.configurationPresent); put("LifecycleJoined", !stopped.lifecycleThreadAlive)
                put("ActiveFlows", capture.activeFlows); put("OwnedSockets", capture.ownedSockets); put("PendingOpens", capture.pendingOpens); put("LiveWorkers", capture.liveWorkers)
                put("FactoryClosed", final.closed); put("FactoryPendingOpens", final.pendingOpens); put("FactoryPendingCalls", final.pendingCalls)
                put("RetainedTransports", final.retainedTransports); put("FactoryLiveWorkers", final.liveWorkers); put("SessionLease", final.sessionLease)
                put("StreamLeases", final.streamLeases); put("ChargedBytes", final.chargedBytes); put("PendingIngressBytes", final.pendingIngressBytes)
                put("BackendOutputBytes", final.backendOutputBytes); put("BackendIncomingBytes", final.backendIncomingBytes)
                put("NonVpnRouteObserved", true); put("TrafficWorkerJoined", true); put("ConsentUiDestroyed", true); put("OwnedStateAbsent", forgotten)
            })
            completed = true
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
                    catch (caught: Exception) { if (caught is InterruptedException) restoreInterrupt = true; cleanup = false; cleanupFailures += safeFailure(caught) }
                    catch (caught: AssertionError) { cleanup = false; cleanupFailures += safeFailure(caught) }
                    finally { restoreInterrupt = Thread.interrupted() || restoreInterrupt }
                }
                attempt {
                    DraftReferenceTunService.current?.let { service ->
                        if (!service.awaitStopped(1)) context.startService(Intent(context, DraftReferenceTunService::class.java).setAction(CaptureVpnService.ACTION_STOP))
                        check(service.awaitStopped(30000) && !service.captureSnapshot().tunEstablished)
                    }
                }
                attempt { traffic?.close() }; attempt { http?.close() }
                attempt { caClient?.let { it.close(); requireCaJoined(it.snapshot()) } }
                attempt { instrumentation.runOnMainSync { activity?.finish() }; if (activity != null) check(DraftReferenceTunConsentActivity.awaitDestroyed(5000)) }
                attempt { DraftReferenceTunService.clearStoppedConfiguration() }
                attempt { gate.clearOwned() }
                if (identityOwned && !forgotten) attempt { store?.forget(checkNotNull(seed).desktopId) }
                attempt { files?.clearRecovery() }
                if (identityOwned && !forgotten) attempt {
                    check(keys?.load(checkNotNull(seed).desktopId) == null && store?.load(checkNotNull(seed).desktopId) == null)
                }
            }
            if (restoreInterrupt) Thread.currentThread().interrupt()
        }
        failure?.let { failed ->
            throw AssertionError("Reference TUN research failed at ${failed.phase} type=${failed.type} category=$category cleanup=$cleanup").apply {
                stackTrace = failed.frames
                cleanupFailures.forEach { suppressed -> addSuppressed(AssertionError("Reference TUN cleanup failed type=${suppressed.type}").apply { stackTrace = suppressed.frames }) }
            }
        }
    }

    private fun requireCaJoined(value: DraftInterceptionCaClientSnapshot) {
        check(value.closed && !value.activeCall && !value.rawSocketOwned && !value.tlsSocketOwned &&
            !value.deadlineAlive && !value.tlsCloserAlive && !value.cleanupFailed)
    }

    @Suppress("DEPRECATION") // Public API26 signer representation, not a TLS or security-check suppression.
    private fun requireTrafficAuthorization() {
        val manager = context.packageManager
        val packages = listOf("com.httpfreekit.interop.test", "com.httpfreekit.capturetest", DraftReferenceTunService.TRAFFIC_PACKAGE)
        val signers = packages.map { name ->
            checkNotNull(manager.getPackageInfo(name, PackageManager.GET_SIGNATURES).signatures).also { check(it.size == 1) }.single()
        }
        check(signers.all { it == signers.first() })
        val permission = "com.httpfreekit.capturetest.permission.CONTROL_TRAFFIC"
        val declared = manager.getPermissionInfo(permission, 0)
        check(declared.packageName == "com.httpfreekit.capturetest" &&
            declared.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE == PermissionInfo.PROTECTION_SIGNATURE &&
            manager.checkPermission(permission, context.packageName) == PackageManager.PERMISSION_GRANTED &&
            manager.checkPermission(permission, DraftReferenceTunService.TRAFFIC_PACKAGE) == PackageManager.PERMISSION_GRANTED)
        val service = manager.getServiceInfo(ComponentName(DraftReferenceTunService.TRAFFIC_PACKAGE,
            "com.httpfreekit.capturetraffic.TrafficService"), 0)
        check(service.exported && service.permission == permission)
    }

    private fun responseHash(): String {
        val request = ByteArray(4096) { ((it * 31 + 7) and 255).toByte() }
        fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
        val response = ("reference-origin:" + hex(DraftEnrollmentResearchChecks.hash(request))).toByteArray(Charsets.US_ASCII)
        check(response.size == 81)
        return hex(DraftEnrollmentResearchChecks.hash(response))
    }

    private fun drained(value: CaptureTransportSnapshot) = !value.closed && !value.admissionClosed && value.failureCode == null &&
        value.sessionLease && value.pendingOpens == 0 && value.pendingCalls == 0 && value.retainedTransports == 1 &&
        value.streamLeases == 0 && value.chargedBytes == 0L && value.pendingIngressBytes == 0L && value.backendOutputBytes == 0L && value.backendIncomingBytes == 0L

    private fun mark(value: String) {
        phase = value
        instrumentation.sendStatus(2, Bundle().apply { putString("draftReferenceTunVersion", "1"); putString("draftReferenceTunPhase", value) })
    }

    private fun notificationStop(): Notification.Action {
        val notification = context.getSystemService(NotificationManager::class.java).activeNotifications.singleOrNull {
            it.notification.flags and Notification.FLAG_ONGOING_EVENT != 0 && it.notification.actions?.count { action -> action.title.toString() == "Stop" } == 1
        }?.notification ?: error("Reference TUN notification missing")
        return checkNotNull(notification.actions.single { it.title.toString() == "Stop" }.also { check(it.actionIntent != null) })
    }

    private fun consent(retain: (Activity) -> Unit): Activity {
        DraftReferenceTunConsentActivity.reset()
        val activity = instrumentation.startActivitySync(Intent(context, DraftReferenceTunConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
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
        check(DraftReferenceTunConsentActivity.awaitConsent(1000) && VpnService.prepare(context) == null)
        return activity
    }

    private fun touch(bounds: Rect) {
        check(!bounds.isEmpty)
        val down = SystemClock.uptimeMillis()
        for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
            val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action, bounds.exactCenterX(), bounds.exactCenterY(), 0)
            try { event.source = InputDevice.SOURCE_TOUCHSCREEN; check(instrumentation.uiAutomation.injectInputEvent(event, true)) }
            finally { event.recycle() }
        }
    }

    private fun await(millis: Long, condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis)
        while (true) {
            check(System.nanoTime() - deadline < 0)
            val observed = condition()
            check(System.nanoTime() - deadline < 0)
            if (observed) return
            Thread.sleep(25)
        }
    }

    private inner class PrivateGate {
        private fun directory(): File = File(context.noBackupFilesDir.canonicalFile, "draft-enrollment-research").also {
            check(it.canonicalFile == it.absoluteFile)
            val stat = Os.lstat(it.path)
            check(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid() && stat.st_mode and 511 == 448)
        }
        private fun file() = File(directory(), "reference-tun-complete-v1.bin")
        private fun exists(file: File): Boolean = try { Os.lstat(file.path); true }
        catch (failure: ErrnoException) { if (failure.errno == OsConstants.ENOENT) false else throw failure }
        fun requireAbsent() { check(!exists(file())) }
        fun consume() {
            val target = file()
            await(20000) { exists(target) }
            check(target.canonicalFile == target.absoluteFile)
            val entryBefore = Os.lstat(target.path)
            check(OsConstants.S_ISREG(entryBefore.st_mode) && entryBefore.st_uid == Process.myUid() &&
                entryBefore.st_nlink == 1L && entryBefore.st_mode and 511 == 384 && entryBefore.st_size == ACK.size.toLong())
            // NOFOLLOW/NONBLOCK rejects a substituted symlink/FIFO without an unbounded open.
            val descriptor = Os.open(target.path, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_NONBLOCK, 0)
            val source = try { FileInputStream(descriptor) } catch (failure: Exception) {
                try { Os.close(descriptor) } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
                throw failure
            }
            source.use { input ->
                val before = Os.fstat(descriptor)
                check(OsConstants.S_ISREG(before.st_mode) && before.st_uid == Process.myUid() && before.st_nlink == 1L &&
                    before.st_mode and 511 == 384 && before.st_size == ACK.size.toLong() &&
                    before.st_dev == entryBefore.st_dev && before.st_ino == entryBefore.st_ino)
                val bytes = ByteArray(ACK.size + 1); var size = 0
                while (size < bytes.size) { val count = input.read(bytes, size, bytes.size - size); if (count < 0) break; check(count > 0); size += count }
                val after = Os.fstat(descriptor); val entry = Os.lstat(target.path)
                check(before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
                    after.st_uid == before.st_uid && after.st_nlink == 1L && after.st_mode and 511 == 384 &&
                    entry.st_dev == before.st_dev && entry.st_ino == before.st_ino && entry.st_uid == before.st_uid && entry.st_nlink == 1L &&
                    entry.st_mode and 511 == 384 && OsConstants.S_ISREG(entry.st_mode) &&
                    size == ACK.size && bytes.copyOf(size).contentEquals(ACK))
                check(target.delete())
            }
            requireAbsent()
        }
        fun clearOwned() {
            val target = file()
            if (exists(target)) {
                val stat = Os.lstat(target.path)
                check(target.canonicalFile == target.absoluteFile && OsConstants.S_ISREG(stat.st_mode) && stat.st_uid == Process.myUid() &&
                    stat.st_nlink == 1L && stat.st_mode and 63 == 0 && stat.st_size in 0L..64L)
                check(target.delete())
            }
            requireAbsent()
        }
    }

    private class SafeFailure(val phase: String, val type: String, val frames: Array<StackTraceElement>)
    private fun safeFailure(error: Throwable): SafeFailure {
        val type = when (error) {
            is AssertionError -> "AssertionError"
            is java.io.IOException -> "IOException"
            is SecurityException -> "SecurityException"
            is java.util.concurrent.TimeoutException -> "TimeoutException"
            is IllegalStateException -> "IllegalStateException"
            else -> "Other"
        }
        val roots = mapOf("DraftReferenceTunInteropTest.kt" to "com.httpfreekit.interop.DraftReferenceTunInteropTest",
            "DraftReferenceTunService.kt" to "com.httpfreekit.interop.DraftReferenceTunService",
            "DraftReferenceTunConsentActivity.kt" to "com.httpfreekit.interop.DraftReferenceTunConsentActivity",
            "DraftEnrollmentResearchChecks.kt" to "com.httpfreekit.interop.DraftEnrollmentResearchChecks",
            "DraftEnrollmentResearchFiles.kt" to "com.httpfreekit.interop.DraftEnrollmentResearchFiles",
            "DraftEnrollmentHttpsClient.kt" to "com.httpfreekit.interop.DraftEnrollmentHttpsClient",
            "DraftInterceptionCaSavedCredential.kt" to "com.httpfreekit.interop.DraftInterceptionCaSavedCredential",
            "DraftInterceptionCaClient.kt" to "com.httpfreekit.interop.DraftInterceptionCaClient",
            "TrafficClient.kt" to "com.httpfreekit.capturetest.TrafficClient",
            "EnrolledCaptureTcpFactory.kt" to "com.httpfreekit.capture.transport.EnrolledCaptureTcpFactory")
        val frames = error.stackTrace.take(128).filter { frame -> roots[frame.fileName]?.let { root ->
            (frame.className == root || frame.className.startsWith(root + "$")) && frame.lineNumber in 1..100000 &&
                frame.methodName.matches(Regex("(?:[A-Za-z_$][A-Za-z0-9_$]*|<init>|<clinit>)")) } == true }.take(16).toTypedArray()
        return SafeFailure(phase, type, frames)
    }

    companion object {
        private val ACK = "FREEKIT-REFERENCE-TUN-COMPLETE-V1\n".toByteArray(Charsets.US_ASCII)
        private val TRAFFIC_FAILURES = setOf("traffic_reference_configuration", "traffic_reference_connect", "traffic_reference_tls",
            "traffic_reference_write", "traffic_reference_shutdown", "traffic_reference_reply", "traffic_reference_eof", "traffic_reference_close")
    }
}
