package com.httpfreekit.interop

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Rect
import android.net.VpnService
import android.os.Bundle
import android.os.IBinder
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.httpfreekit.capture.CaptureTcpConnection
import com.httpfreekit.capture.transport.EnrolledCaptureTcpFactory
import com.httpfreekit.protocol.DraftEnrollmentMessage
import com.httpfreekit.protocol.HttpOriginConnect
import com.httpfreekit.security.AndroidDeviceIdentityStore
import com.httpfreekit.security.AndroidEnrolledCredentialStore
import com.httpfreekit.security.EnrolledCredentialRecord
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.Test
import org.junit.runner.RunWith

/** Interface/protection proof only. It never establishes a TUN or starts the capture service. */
@RunWith(AndroidJUnit4::class)
class DraftCaptureFactoryInteropTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var phase = "input-consumed"

    @Test(timeout = 180000)
    fun enrolledHttpOriginUsesProtectedGateway() {
        var seed: DraftEnrollmentSeed? = null
        var files: DraftEnrollmentResearchFiles? = null
        var http: DraftEnrollmentHttpsClient? = null
        var credentials: AndroidEnrolledCredentialStore? = null
        var identities: AndroidDeviceIdentityStore? = null
        var created = false
        var forgotten = false
        var completed = false
        var activity: Activity? = null
        var binding: PreparedBinding? = null
        var factory: EnrolledCaptureTcpFactory? = null
        var relay: ApplicationRelay? = null
        var failure: SafeFailure? = null
        var cleanup = true
        try {
            val ownedFiles = DraftEnrollmentResearchFiles(context).also { files = it }
            val input = ownedFiles.consumeInput().also { seed = it }
            val rawPort = InstrumentationRegistry.getArguments().getString("webSocketPort")
            check(rawPort != null && Regex("[1-9][0-9]{0,4}").matches(rawPort)) { "Factory port unavailable" }
            val port = rawPort.toInt()
            check(port in 1..65535 && port != input.setupPort && port != input.credentialPort) { "Factory port unavailable" }
            mark("input-consumed")
            val keys = AndroidDeviceIdentityStore().also { identities = it }
            val store = AndroidEnrolledCredentialStore(context).also { credentials = it }
            check(keys.load(input.desktopId) == null && store.load(input.desktopId) == null) { "Research identity already exists" }
            created = true
            val identity = keys.create(input.desktopId)
            val original = DraftEnrollmentResearchChecks.keyEvidence(identity)
            val gateway = DraftEnrollmentHttpsClient.certificate(input.gatewayCertificateDer)
            val client = DraftEnrollmentHttpsClient(gateway, input.gatewaySpkiSha256, input.logicalName,
                input.setupPort, input.credentialPort).also { http = it }
            val requested = listOf(HttpOriginConnect.CAPABILITY)
            val registered = client.exchange(DraftEnrollmentResearchChecks.pair(input, identity, requested)) as? DraftEnrollmentMessage.Registered
                ?: error("Factory enrollment was not registered")
            check(registered.desktopId == input.desktopId && registered.invitationId == input.invitationId &&
                registered.deviceSpkiSha256 == DraftEnrollmentResearchChecks.b64(DraftEnrollmentResearchChecks.hash(identity.publicKey.encoded)) &&
                registered.reservationExpiresAt == input.invitationExpiresAt &&
                Instant.now().isBefore(Instant.parse(registered.resultExpiresAt))) { "Factory enrollment context changed" }
            input.clearInvitationSecret()
            val proof = DraftEnrollmentProofSession(client, identity, input.desktopId, input.gatewaySpkiSha256,
                input.invitationId, registered.enrollmentId, registered.reservationExpiresAt)
            check(proof.status() is DraftEnrollmentMessage.Pending) { "Factory enrollment was not pending" }
            mark("strict-csr-reserved")
            mark("awaiting-host-approval")
            val approvalDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
            var approved: DraftEnrollmentMessage.Approved? = null
            while (approved == null) {
                check(System.nanoTime() - approvalDeadline < 0) { "Factory approval deadline" }
                when (val result = proof.status()) {
                    is DraftEnrollmentMessage.Pending -> Thread.sleep(result.retryAfterMillis.toLong())
                    is DraftEnrollmentMessage.Approved -> approved = result
                    else -> error("Factory enrollment ended")
                }
            }
            val result = checkNotNull(approved)
            val certificates = DraftEnrollmentResearchChecks.validateApproved(result, identity, input.desktopId,
                registered.enrollmentId, registered.resultExpiresAt, requested)
            check(result.capabilities == requested) { "Factory capabilities changed" }
            val originalLeaf = certificates.first.encoded
            store.save(EnrolledCredentialRecord(input.desktopId, gateway, input.gatewaySpkiSha256, input.logicalName,
                listOf(certificates.first), certificates.second))
            val loaded = checkNotNull(AndroidEnrolledCredentialStore(context).load(input.desktopId)) { "Factory saved credential missing" }
            check(loaded.record.clientCertificateChain.single().encoded.contentEquals(originalLeaf)) { "Factory saved leaf changed" }
            val alias = checkNotNull(loaded.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null))
            check(checkNotNull(loaded.clientKeyManager.getPrivateKey(alias)).encoded == null) { "Factory key exportable" }
            DraftEnrollmentResearchChecks.sameHashes(original, DraftEnrollmentResearchChecks.keyEvidence(identity))
            client.close(); http = null
            mark("credential-saved-reloaded")

            activity = consent { activity = it }
            val prepared = PreparedBinding(context).also { binding = it }
            val service = prepared.bind()
            service.awaitUnderlyingNetwork()
            check(VpnService.prepare(context) == null && service.snapshot().networkPresent) { "Factory VPN preparation missing" }
            mark("vpn-consent-bound")
            val transport = EnrolledCaptureTcpFactory(loaded, InetSocketAddress(loopback(), port), service.guard(),
                setOf(HttpOriginConnect.CAPABILITY)).also { factory = it }
            prepared.onDisconnect { transport.interrupt() }
            service.onNetworkLost { transport.interrupt() }
            val connection = transport.open(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 2)), 80)
            val application = ApplicationRelay(connection).also { relay = it }
            application.start()
            check(service.snapshot().let { it.protectAttempts == 2 && it.protectSuccesses == 2 && it.bindAttempts == 2 && it.bindSuccesses == 2 &&
                it.networkPresent && it.failureCode == null }) { "Factory platform protection missing" }
            mark("factory-opened")
            val requestBytes = application.writeRequest()
            check(requestBytes == 16421 && application.socket().isOutputShutdown) { "Factory application half-close missing" }
            mark("application-output-shut")
            val response = readResponse(application.socket())
            check(response.first == 32787 && response.second == RESPONSE_HASH) { "Factory response mismatch" }
            application.awaitCompleted()
            check(service.snapshot().failureCode == null && transport.snapshot().failureCode == null) { "Factory failed during exchange" }
            mark("reply-bytes-eof-validated")
            DraftEnrollmentResearchChecks.sameHashes(original, DraftEnrollmentResearchChecks.keyEvidence(identity))
            val same = checkNotNull(store.load(input.desktopId))
            check(same.record.clientCertificateChain.single().encoded.contentEquals(originalLeaf)) { "Factory credential changed" }
            val currentAlias = checkNotNull(same.clientKeyManager.chooseClientAlias(arrayOf("EC"), null, null))
            check(checkNotNull(same.clientKeyManager.getPrivateKey(currentAlias)).encoded == null) { "Factory key exportable" }
            application.closeGracefully()
            check(transport.snapshot().failureCode == null) { "Factory failed during graceful closure" }
            prepared.requireConnected()
            transport.close()
            val final = transport.snapshot()
            check((final.failureCode == null || final.failureCode == "closed") && final.closed &&
                final.pendingOpens == 0 && final.pendingCalls == 0 && final.retainedTransports == 0 && final.liveWorkers == 0 &&
                !final.sessionLease && final.streamLeases == 0 && final.chargedBytes == 0L && final.pendingIngressBytes == 0L &&
                final.backendOutputBytes == 0L && final.backendIncomingBytes == 0L) { "Factory resources remained" }
            prepared.close()
            prepared.requireConnected()
            instrumentation.runOnMainSync { activity?.finish() }
            check(DraftCaptureFactoryConsentActivity.awaitDestroyed(5000)) { "Factory Activity remained" }
            val guard = service.snapshot()
            check(guard.observerJoined && !guard.observerRegistered && guard.destroyed && guard.failureCode == null) { "Factory service remained" }
            mark("factory-resources-joined")
            store.forget(input.desktopId); ownedFiles.clearRecovery()
            check(keys.load(input.desktopId) == null && store.load(input.desktopId) == null) { "Factory owned identity remained" }
            forgotten = true
            instrumentation.sendStatus(3, Bundle().apply {
                fun put(name: String, value: Any) = putString("draftFactory$name", value.toString())
                put("Version", 1); put("CredentialSavedReloaded", true); put("KeyNonexportable", true); put("OriginalCredentialUnchanged", true)
                put("VpnConsentGranted", true)
                // Audited bound-component scope: this helper has no Builder/TUN/native owner.
                put("NoTunEstablished", service.javaClass == DraftCaptureFactoryVpnService::class.java)
                put("ProtectAttempts", guard.protectAttempts); put("ProtectSuccesses", guard.protectSuccesses)
                put("BindAttempts", guard.bindAttempts); put("BindSuccesses", guard.bindSuccesses)
                put("RequestBodyBytes", requestBytes); put("ResponseBodyBytes", response.first); put("ResponseBodySha256", response.second)
                put("ApplicationOutputHalfClosed", true); put("StrictResponseEof", true); put("FactoryClosed", final.closed)
                put("PendingOpens", final.pendingOpens); put("PendingCalls", final.pendingCalls); put("RetainedTransports", final.retainedTransports)
                put("LiveWorkers", final.liveWorkers); put("SessionLease", final.sessionLease); put("StreamLeases", final.streamLeases)
                put("ChargedBytes", final.chargedBytes); put("PendingIngressBytes", final.pendingIngressBytes)
                put("BackendOutputBytes", final.backendOutputBytes); put("BackendIncomingBytes", final.backendIncomingBytes)
                put("RelayJoined", application.joined()); put("ServiceObserverJoined", guard.observerJoined)
                put("ServiceDestroyed", guard.destroyed); put("OwnedStateAbsent", forgotten)
            })
            mark("owned-state-forgotten")
            completed = true
        } catch (caught: Throwable) {
            if (caught !is Exception && caught !is AssertionError) throw caught
            failure = safeFailure(caught)
        } finally {
            seed?.clearInvitationSecret()
            if (!completed) {
                fun attempt(action: () -> Unit) { try { action() } catch (_: Exception) { cleanup = false } catch (_: AssertionError) { cleanup = false } }
                attempt { relay?.close() }; attempt { factory?.close() }; attempt { binding?.close() }; attempt { http?.close() }
                attempt { instrumentation.runOnMainSync { activity?.finish() }; if (activity != null) check(DraftCaptureFactoryConsentActivity.awaitDestroyed(5000)) }
                if (cleanup && created && !forgotten) attempt {
                    credentials?.forget(checkNotNull(seed).desktopId); files?.clearRecovery()
                    check(identities?.load(checkNotNull(seed).desktopId) == null && credentials?.load(checkNotNull(seed).desktopId) == null)
                }
            }
        }
        failure?.let { failed ->
            throw AssertionError("Capture factory research failed at ${failed.phase} (${failed.type}); cleanup=$cleanup.").apply { stackTrace = failed.frames }
        }
    }

    private fun mark(value: String) {
        phase = value
        instrumentation.sendStatus(2, Bundle().apply { putString("draftFactoryVersion", "1"); putString("draftFactoryPhase", value) })
    }
    private fun consent(retain: (Activity) -> Unit): Activity {
        DraftCaptureFactoryConsentActivity.reset()
        val activity = instrumentation.startActivitySync(Intent(context, DraftCaptureFactoryConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        retain(activity)
        run {
            val automation = instrumentation.uiAutomation
            automation.serviceInfo = automation.serviceInfo.apply { flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS }
            val end = SystemClock.elapsedRealtime() + 30000
            var touched = false
            while (VpnService.prepare(context) != null && SystemClock.elapsedRealtime() < end) {
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
            check(DraftCaptureFactoryConsentActivity.awaitConsent(1000) && VpnService.prepare(context) == null) { "Factory platform consent missing" }
            return activity
        }
    }
    private fun touch(bounds: Rect) {
        check(!bounds.isEmpty) { "Factory consent bounds" }
        val down = SystemClock.uptimeMillis()
        for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
            val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action, bounds.exactCenterX(), bounds.exactCenterY(), 0)
            try { event.source = InputDevice.SOURCE_TOUCHSCREEN; check(instrumentation.uiAutomation.injectInputEvent(event, true)) { "Factory consent touch" } }
            finally { event.recycle() }
        }
    }

    private fun readResponse(socket: Socket): Pair<Int, String> {
        val input = socket.getInputStream()
        val header = ByteArrayOutputStream()
        var tail = 0
        while (tail != 0x0d0a0d0a) {
            val byte = input.read(); check(byte >= 0 && header.size() < 4096) { "Factory response headers incomplete" }
            check(byte in 32..126 || byte == 13 || byte == 10) { "Factory response headers invalid" }
            header.write(byte); tail = (tail shl 8) or byte
        }
        val lines = header.toByteArray().toString(Charsets.US_ASCII).removeSuffix("\r\n\r\n").split("\r\n")
        check(lines.first().matches(Regex("HTTP/1\\.1 200(?: [ -~]*)?"))) { "Factory HTTP status" }
        val fields = lines.drop(1).map { line ->
            val colon = line.indexOf(':'); check(colon > 0 && line.substring(0, colon).matches(Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))) { "Factory header syntax" }
            line.substring(0, colon).lowercase() to line.substring(colon + 1).trim()
        }
        val lengths = fields.filter { it.first == "content-length" }
        check(lengths.size == 1 && lengths.single().second == "32787" && fields.none { it.first == "transfer-encoding" }) { "Factory response framing" }
        val hash = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192); var count = 0
        while (count < 32787) {
            val size = input.read(buffer, 0, minOf(buffer.size, 32787 - count))
            check(size > 0) { "Factory response body incomplete" }
            for (index in 0 until size) check(buffer[index] == (((count + index) * 7) % 253).toByte()) { "Factory response body changed" }
            hash.update(buffer, 0, size); count += size
        }
        check(input.read() == -1) { "Factory response EOF missing" }
        return count to hash.digest().joinToString("") { "%02x".format(it) }
    }

    private class PreparedBinding(private val context: Context) : AutoCloseable {
        private val ready = CountDownLatch(1)
        private val service = AtomicReference<DraftCaptureFactoryVpnService?>()
        private val disconnected = AtomicBoolean()
        private val interruptFailed = AtomicBoolean()
        private val interrupt = AtomicReference<(() -> Unit)?>()
        private var bound = false
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                if (name == ComponentName(context, DraftCaptureFactoryVpnService::class.java) && binder is DraftCaptureFactoryVpnService.LocalBinder) service.set(binder.service())
                ready.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) {
                disconnected.set(true)
                try { interrupt.get()?.invoke() } catch (_: Exception) { interruptFailed.set(true) }
            }
            override fun onBindingDied(name: ComponentName) { onServiceDisconnected(name); ready.countDown() }
            override fun onNullBinding(name: ComponentName) { ready.countDown() }
        }
        fun bind(): DraftCaptureFactoryVpnService {
            bound = context.bindService(Intent(context, DraftCaptureFactoryVpnService::class.java).setAction(DraftCaptureFactoryVpnService.ACTION_GUARD), connection, Context.BIND_AUTO_CREATE)
            check(bound && ready.await(5000, TimeUnit.MILLISECONDS) && !disconnected.get()) { "Factory service binding failed" }
            return checkNotNull(service.get()) { "Factory service unavailable" }
        }
        fun onDisconnect(action: () -> Unit) { interrupt.set(action); if (disconnected.get()) action() }
        // Normal unbind has no disconnect callback; retain the whole binding's loss history.
        fun requireConnected() { check(service.get() != null && !disconnected.get() && !interruptFailed.get()) { "Factory service disconnected" } }
        override fun close() {
            var failed = interruptFailed.get()
            val owned = service.get()
            if (bound && owned == null) failed = true // No handle exists to attest observer/destroy joins.
            try { if (owned != null) check(owned.closeObserver()) } catch (_: Exception) { failed = true }
            try { if (bound) { context.unbindService(connection); bound = false } } catch (_: Exception) { failed = true }
            try { if (owned != null) check(owned.awaitDestroyed()) } catch (_: Exception) { failed = true }
            interrupt.set(null)
            check(!failed && !interruptFailed.get()) { "Factory service cleanup failed" }
        }
        override fun toString() = "FactoryPreparedBinding([REDACTED])"
    }

    private class ApplicationRelay(private val transport: CaptureTcpConnection) : AutoCloseable {
        private var listener: ServerSocket? = null
        private var application: Socket? = null
        private var bridge: Socket? = null
        private val stopping = AtomicBoolean()
        private val failed = AtomicBoolean()
        private val workers = ArrayList<Thread>(2)
        private var didJoin = false
        fun start() {
            val server = ServerSocket().also { listener = it }
            server.bind(InetSocketAddress(loopback(), 0), 1); server.soTimeout = 5000
            val app = Socket().also { application = it }
            app.soTimeout = 15000; app.connect(server.localSocketAddress, 5000)
            val local = server.accept().also { bridge = it }
            check(local.port == app.localPort && local.inetAddress == app.localAddress) { "Factory application pair changed" }
            server.close()
            workers.add(Thread({ pump(local.getInputStream(), transport.output) { transport.shutdownOutput() } }, "factory-application-upload"))
            workers.add(Thread({ pump(transport.input, local.getOutputStream()) { local.shutdownOutput() } }, "factory-application-download"))
            workers.forEach { it.start() }
        }
        private fun pump(input: java.io.InputStream, output: java.io.OutputStream, eof: () -> Unit) {
            try {
                val bytes = ByteArray(8192)
                while (true) { val count = input.read(bytes); if (count < 0) break; check(count > 0); output.write(bytes, 0, count); output.flush() }
                eof()
            } catch (_: Exception) { if (!stopping.get()) failed.set(true) }
        }
        fun socket(): Socket = checkNotNull(application)
        fun writeRequest(): Int {
            val output = socket().getOutputStream()
            output.write("POST /factory-research HTTP/1.1\r\nHost: factory-origin.invalid\r\nContent-Length: 16421\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
            val bytes = ByteArray(8192); val hash = MessageDigest.getInstance("SHA-256"); var count = 0
            while (count < 16421) {
                val size = minOf(bytes.size, 16421 - count)
                for (index in 0 until size) bytes[index] = ((count + index) % 251).toByte()
                output.write(bytes, 0, size); hash.update(bytes, 0, size); count += size
            }
            output.flush()
            check(hash.digest().joinToString("") { "%02x".format(it) } == REQUEST_HASH) { "Factory request body changed" }
            socket().shutdownOutput()
            return count
        }
        fun awaitCompleted() { joinWorkers(); check(!failed.get()) { "Factory relay failed" } }
        private fun joinWorkers() {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            workers.forEach { thread -> val left = deadline - System.nanoTime(); if (thread.isAlive && left > 0) TimeUnit.NANOSECONDS.timedJoin(thread, left) }
            check(workers.none { it.isAlive }) { "Factory relay not joined" }; didJoin = true
        }
        fun joined() = didJoin && workers.none { it.isAlive }
        fun closeGracefully() {
            check(joined() && !failed.get() && !stopping.get()) { "Factory relay incomplete" }
            // Gateway EOF can precede the actual normal WebSocket close/model completion.
            transport.close()
            stopping.set(true); var failed = false
            fun attempt(action: () -> Unit) { try { action() } catch (_: Exception) { failed = true } }
            attempt { application?.close() }; attempt { bridge?.close() }; attempt { listener?.close() }
            attempt { joinWorkers() }
            check(!failed) { "Factory relay cleanup failed" }
        }
        override fun close() {
            stopping.set(true); var failed = false
            fun attempt(action: () -> Unit) { try { action() } catch (_: Exception) { failed = true } }
            attempt { transport.interrupt() }; attempt { application?.close() }; attempt { bridge?.close() }; attempt { listener?.close() }
            attempt { joinWorkers() }; attempt { transport.close() }
            check(!failed) { "Factory relay cleanup failed" }
        }
        override fun toString() = "FactoryApplicationRelay([REDACTED])"
    }

    private class SafeFailure(val phase: String, val type: String, val frames: Array<StackTraceElement>)
    private fun safeFailure(error: Throwable): SafeFailure {
        val type = when (error) { is AssertionError -> "AssertionError"; is IllegalArgumentException -> "IllegalArgumentException"; is java.io.IOException -> "IOException"; else -> "IllegalStateException" }
        val roots = mapOf("DraftCaptureFactoryInteropTest.kt" to "com.httpfreekit.interop.DraftCaptureFactoryInteropTest",
            "DraftCaptureFactoryConsentActivity.kt" to "com.httpfreekit.interop.DraftCaptureFactoryConsentActivity",
            "DraftCaptureFactoryVpnService.kt" to "com.httpfreekit.interop.DraftCaptureFactoryVpnService",
            "DraftEnrollmentResearchChecks.kt" to "com.httpfreekit.interop.DraftEnrollmentResearchChecks",
            "DraftEnrollmentResearchFiles.kt" to "com.httpfreekit.interop.DraftEnrollmentResearchFiles",
            "DraftEnrollmentHttpsClient.kt" to "com.httpfreekit.interop.DraftEnrollmentHttpsClient",
            "EnrolledCaptureTcpFactory.kt" to "com.httpfreekit.capture.transport.EnrolledCaptureTcpFactory")
        val frames = error.stackTrace.take(128).filter { frame -> roots[frame.fileName]?.let { root ->
            (frame.className == root || frame.className.startsWith(root + "$")) && frame.lineNumber in 1..100000 &&
                frame.methodName.matches(Regex("(?:[A-Za-z_$][A-Za-z0-9_$]*|<init>|<clinit>)")) } == true }.take(16).toTypedArray()
        return SafeFailure(phase, type, frames)
    }
    companion object {
        private const val REQUEST_HASH = "d4cc764821eb57cbfff27c890ae26b2648a3f7a5c296698831124f02b25c3529"
        private const val RESPONSE_HASH = "62a22a63bb850ba7b263fccff99e868133570394d36d6ee16fd32e9d7c1a4601"
        private fun loopback(): InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    }
}
