package com.httpfreekit.interop

import com.httpfreekit.security.EnrolledCredentialRecord
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.security.Principal
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.AfterClass
import org.junit.Assert.*
import org.junit.Test

/** Actual compiled shared getter over real pinned Node mTLS. Software host scope only. */
class DraftInterceptionCaTlsTest {
    @Test(timeout = 45000) fun actualCredentialEndpointReturnsDefensiveCaAndReopensSavedApprovalWithoutGlobalTrustChanges() = proof("reference-reopen") {
        val defaults = listOf(SSLContext.getDefault(), HttpsURLConnection.getDefaultSSLSocketFactory(), HttpsURLConnection.getDefaultHostnameVerifier())
        val providers = Security.getProviders().map { it.name }
        fixture("reference") { peer ->
            val recovery = DraftEnrollmentStateCodec.decodeRecovery(DraftEnrollmentStateCodec.encodeRecovery(peer.recovery))
            peer.client(recovery).use { client ->
                repeat(2) {
                    val value = client.fetch(); assertArrayEquals(peer.referenceDer, value.certificateDer)
                    val expected = DraftInterceptionCaNodePeer.hash(peer.referenceDer)
                    assertArrayEquals(expected, value.certificateSha256)
                    value.certificateDer.fill(0); value.certificateSha256.fill(0); value.certificate.notAfter.time = 0
                    assertArrayEquals(peer.referenceDer, value.certificateDer); assertArrayEquals(expected, value.certificateSha256)
                    assertTrue(value.certificate.notAfter.after(Date())); assertIdle(client, false)
                }
                peer.pause(); expect(setOf(DraftInterceptionCaFailure.TRANSPORT)) { client.fetch() }; assertIdle(client, false)
            }
            peer.reopen()
            val restored = EnrolledCredentialRecord(peer.record.desktopId, peer.record.gatewayCertificate, peer.record.gatewaySpkiSha256,
                peer.record.logicalServerName, peer.record.clientCertificateChain, peer.record.authenticatedEnrollmentAuthority)
            peer.client(recovery, credential = restored).use { client -> assertArrayEquals(peer.referenceDer, client.fetch().certificateDer); assertIdle(client, false) }
            peer.client(peer.copyRecovery(oldRecoveryDeadlines = true)).use { client -> assertArrayEquals(peer.referenceDer, client.fetch().certificateDer) }
            peer.awaitQuiet()
        }
        assertEquals(defaults, listOf(SSLContext.getDefault(), HttpsURLConnection.getDefaultSSLSocketFactory(), HttpsURLConnection.getDefaultHostnameVerifier()))
        assertEquals(providers, Security.getProviders().map { it.name })
    }

    @Test(timeout = 25000) fun realRsaInterceptionCaUsesTheSameApprovedEndpointAndDistinctTrustKeys() = proof("rsa-reference") {
        fixture("rsa-reference") { peer -> peer.client().use { client ->
            val result = client.fetch(); assertArrayEquals(peer.referenceDer, result.certificateDer)
            assertEquals("RSA", result.certificate.publicKey.algorithm); assertTrue(result.certificate.basicConstraints >= 0)
            result.certificate.verify(result.certificate.publicKey)
            for (other in listOf(peer.record.gatewayCertificate, peer.record.authenticatedEnrollmentAuthority) + peer.original + peer.record.clientCertificateChain)
                assertFalse(other.publicKey.encoded.contentEquals(result.certificate.publicKey.encoded))
            assertIdle(client, false)
        } }
    }

    @Test(timeout = 30000) fun mismatchedSavedContextAndOriginalOrIssuedOwnersCannotReachTheTlsListener() = proof("binding-before-network") {
        fixture("valid") { peer ->
            val hashes = listOf(peer.copyRecovery(desktop = "other-desktop"), peer.copyRecovery(pin = ByteArray(32)),
                peer.copyRecovery(name = "other.invalid"), peer.copyRecovery(spki = peer.recovery.originalDeviceSpki.also { it[it.lastIndex] = (it.last() + 1).toByte() }),
                peer.copyRecovery(originalHashes = listOf(ByteArray(32))), peer.copyRecovery(leafHash = ByteArray(32)),
                peer.copyRecovery(authorityHash = ByteArray(32)), peer.copyRecovery(expiresAt = "2020-01-01T00:00:00Z"))
            for (approval in hashes) expect(setOf(DraftInterceptionCaFailure.BINDING)) { peer.client(approval).use { it.fetch() } }
            expect(setOf(DraftInterceptionCaFailure.BINDING)) { peer.client(originals = peer.record.clientCertificateChain).use { it.fetch() } }
            val before = peer.snapshot().getValue("hostile").jsonObject
            assertEquals(0L, before.number("accepted")); assertEquals(0L, before.number("requests"))
            peer.client().use { assertArrayEquals(peer.referenceDer, it.fetch().certificateDer); assertIdle(it, false) }
            val after = peer.awaitQuiet().getValue("hostile").jsonObject
            assertEquals(1L, after.number("requests")); assertEquals(1L, after.number("authorized")); assertEquals(1L, after.number("completedResponses"))
        }
    }

    @Test(timeout = 180000) fun hostileTlsFramingAndCanonicalDerAreRefusedAfterActualAuthorizedPublication() {
        val matchingCorruptHash = setOf("malformed-der", "nonminimal-der", "ber-der", "trailing-der", "expired-ca", "leaf-ca", "bad-key-usage", "unsupported-key", "restricted-eku")
        val scenarios = listOf("duplicate-length", "duplicate-hash", "duplicate-other", "invalid-length", "missing-length", "oversize-length",
            "missing-type", "wrong-type", "invalid-hash", "changed-ca", "malformed-der", "nonminimal-der", "ber-der", "trailing-der",
            "expired-ca", "leaf-ca", "bad-key-usage", "unsupported-key", "restricted-eku", "response-trailing", "response-truncated", "transfer-encoding",
            "content-encoding", "trailer", "location", "upgrade", "bad-cache", "bad-connection", "redirect", "informational", "header-limit", "field-limit", "field-count", "folded-header", "bare-lf")
        for (scenario in scenarios) proof("hostile-$scenario", scenario in matchingCorruptHash) {
            fixture(scenario) { peer ->
                // These marked negative cases deliberately corrupt the trusted recovery hash to match malformed bytes.
                // They test canonicality/profile parsing, not legitimate server approval of malformed CA material.
                val approval = if (scenario in matchingCorruptHash) peer.copyRecovery(caHash = peer.responseHash) else peer.recovery
                peer.client(approval).use { client -> expect(setOf(DraftInterceptionCaFailure.RESPONSE)) { client.fetch() }; assertIdle(client, false) }
                val snapshot = peer.awaitQuiet().getValue("hostile").jsonObject
                assertEquals(1L, snapshot.number("requests")); assertEquals(1L, snapshot.number("authorized")); assertEquals(1L, snapshot.number("completedResponses"))
                assertTrue(snapshot.number("publishedBytes") > 0)
                if (scenario == "header-limit") assertEquals(8192L, snapshot.number("publishedBytes"))
            }
        }
    }

    @Test(timeout = 110000) fun currentRegistryMissingTlsIdentityWrongGatewayAndRealExpiryCannotSupplyCa() {
        proof("wrong-gateway") { fixture("wrong-gateway") { peer ->
            peer.client().use { client -> expect(setOf(DraftInterceptionCaFailure.TRANSPORT)) { client.fetch() }; assertIdle(client, false) }
            val state = peer.awaitQuiet().getValue("hostile").jsonObject
            assertTrue(state.number("accepted") >= 1); assertEquals(0L, state.number("requests")); assertEquals(0L, state.number("completedResponses"))
        } }
        proof("missing-tls-identity") { fixture("reference") { peer ->
            val refused = AtomicInteger(); val delegate = peer.manager
            val manager = object : X509ExtendedKeyManager() {
                override fun getClientAliases(type: String?, issuers: Array<out Principal>?) = delegate.getClientAliases(type, issuers)
                override fun chooseClientAlias(types: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? =
                    if (socket == null) delegate.chooseClientAlias(types, issuers, null) else { refused.incrementAndGet(); null }
                override fun chooseEngineClientAlias(types: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? { refused.incrementAndGet(); return null }
                override fun getServerAliases(type: String?, issuers: Array<out Principal>?) = delegate.getServerAliases(type, issuers)
                override fun chooseServerAlias(type: String?, issuers: Array<out Principal>?, socket: Socket?) = delegate.chooseServerAlias(type, issuers, socket)
                override fun getCertificateChain(alias: String?) = delegate.getCertificateChain(alias)
                override fun getPrivateKey(alias: String?) = delegate.getPrivateKey(alias)
            }
            peer.client(keyManager = manager).use { client -> expect(setOf(DraftInterceptionCaFailure.TRANSPORT, DraftInterceptionCaFailure.RESPONSE)) { client.fetch() }; assertIdle(client, false) }
            assertTrue(refused.get() > 0); peer.awaitQuiet()
        } }
        proof("revoked-current-registry") { fixture("reference") { peer ->
            assertTrue(peer.credentialExpiresAt > System.currentTimeMillis()); peer.revoke()
            assertEquals("device_revoked", peer.status().text("ended"))
            peer.client().use { client -> expect(setOf(DraftInterceptionCaFailure.RESPONSE)) { client.fetch() }; assertIdle(client, false) }; peer.awaitQuiet()
        } }
        proof("actual-credential-expiry") { fixture("expiry") { peer ->
            peer.client().use { assertArrayEquals(peer.referenceDer, it.fetch().certificateDer); assertIdle(it, false) }
            val until = peer.credentialExpiresAt + 20; val remaining = until - System.currentTimeMillis(); assertTrue(remaining in 1..60020)
            while (System.currentTimeMillis() <= until) Thread.sleep(minOf(1000L, maxOf(1L, until - System.currentTimeMillis())))
            expect(setOf(DraftInterceptionCaFailure.BINDING)) { peer.client().use { it.fetch() } }
            assertEquals("credential_expired", peer.status().text("ended")); peer.awaitQuiet()
        } }
    }

    @Test(timeout = 60000) fun actualReadTimeoutWholeDeadlineAndConcurrentCloseJoinEveryClientAndPeerOwner() {
        for (scenario in listOf("timeout", "hold-eof", "drip")) proof("deadline-$scenario") { fixture(scenario) { peer ->
            val started = System.nanoTime()
            peer.client().use { client -> expect(setOf(DraftInterceptionCaFailure.TRANSPORT)) { client.fetch() }; assertIdle(client, false) }
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(elapsed >= if (scenario == "drip") 9000 else 4000); assertTrue(elapsed < 15000)
            val state = peer.awaitQuiet().getValue("hostile").jsonObject
            assertEquals(1L, state.number("requests")); assertEquals(1L, state.number("authorized"))
            assertEquals(if (scenario == "hold-eof") 1L else 0L, state.number("completedResponses"))
        } }
        proof("concurrent-close") { fixture("timeout") { peer ->
            val executor = Executors.newSingleThreadExecutor(); val client = peer.client()
            try {
                val call = executor.submit(Callable { expect(setOf(DraftInterceptionCaFailure.CLOSED)) { client.fetch() } })
                peer.awaitRequest(); val before = client.snapshot()
                assertTrue(before.activeCall && before.rawSocketOwned && before.tlsSocketOwned && before.deadlineAlive)
                val started = System.nanoTime(); client.close(); val result = call.get(5, TimeUnit.SECONDS)
                currentObservations()["lastRefusal"] = JsonPrimitive(result.code.name)
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 5000); assertIdle(client, true); peer.awaitQuiet()
            } finally {
                client.close(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            }
        } }
    }

    private fun fixture(scenario: String, action: (DraftInterceptionCaNodePeer) -> Unit) {
        val peer = DraftInterceptionCaNodePeer(scenario)
        nodeVersions += peer.nodeVersion; nodeOpenSslVersions += peer.nodeOpenSsl
        try {
            action(peer)
            val state = peer.snapshot()["hostile"]
            if (state is JsonObject) for (key in listOf("requests", "authorized", "completedResponses", "publishedBytes")) currentObservations()[key] = JsonPrimitive(state.number(key))
        } finally { peer.close(); currentObservations()["peerCleanupJoined"] = JsonPrimitive(peer.joined) }
        check(peer.joined)
    }
    private fun expect(codes: Set<DraftInterceptionCaFailure>, action: () -> Any?): DraftInterceptionCaException {
        try { action() } catch (failure: DraftInterceptionCaException) {
            observations.get()?.set("lastRefusal", JsonPrimitive(failure.code.name))
            assertTrue(failure.code in codes); assertNull(failure.cause); assertTrue(failure.suppressed.isEmpty()); return failure
        }
        throw AssertionError("Expected a fixed CA refusal")
    }
    private fun assertIdle(client: DraftInterceptionCaClient, closed: Boolean) {
        val state = client.snapshot(); assertEquals(closed, state.closed)
        assertFalse(state.activeCall || state.rawSocketOwned || state.tlsSocketOwned || state.deadlineAlive || state.tlsCloserAlive || state.cleanupFailed)
        currentObservations()["idleClientSnapshotObserved"] = JsonPrimitive(true)
    }
    private fun proof(id: String, corruptExpectedHash: Boolean = false, action: () -> Unit) {
        val started = System.nanoTime()
        observations.set(linkedMapOf("idleClientSnapshotObserved" to JsonPrimitive(false), "peerCleanupJoined" to JsonPrimitive(false)))
        try {
            action(); record(id, "passed", corruptExpectedHash, started)
        } catch (failure: Throwable) {
            record(id, "failed", corruptExpectedHash, started)
            val safe = AssertionError("Interception CA TLS proof failed at $id.")
            safe.stackTrace = failure.stackTrace.filter { it.fileName in setOf("DraftInterceptionCaTlsTest.kt", "DraftInterceptionCaNodePeer.kt") && it.lineNumber in 1..100000 }.take(16).toTypedArray()
            throw safe
        } finally { observations.remove() }
    }
    companion object {
        private val cases = mutableListOf<JsonObject>()
        private val observations = ThreadLocal<MutableMap<String, JsonPrimitive>>()
        private val nodeVersions = java.util.Collections.synchronizedSet(mutableSetOf<String>())
        private val nodeOpenSslVersions = java.util.Collections.synchronizedSet(mutableSetOf<String>())
        private fun currentObservations() = checkNotNull(observations.get()) { "Missing CA proof owner" }
        @Synchronized private fun record(id: String, status: String, corrupted: Boolean, started: Long) {
            check(Regex("[a-z-]{1,80}").matches(id) && cases.none { it.text("case") == id })
            cases += JsonObject(linkedMapOf("case" to JsonPrimitive(id), "status" to JsonPrimitive(status),
                "controlledCorruptRecoveryFingerprint" to JsonPrimitive(corrupted),
                "elapsedMillis" to JsonPrimitive(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)), "observations" to JsonObject(currentObservations())) )
        }
        @AfterClass @JvmStatic fun writeFiniteReport() {
            fun git(vararg arguments: String): String {
                val process = ProcessBuilder("git", *arguments).start()
                var interrupted = Thread.interrupted(); var joined = false; var streamsClosed = true
                try {
                    joined = process.waitFor(5, TimeUnit.SECONDS)
                    check(joined) { "CA proof source unavailable" }
                    val bytes = process.inputStream.readNBytes(16385); val errors = process.errorStream.readNBytes(1025)
                    check(process.exitValue() == 0 && bytes.size <= 16384 && errors.isEmpty())
                    return bytes.toString(Charsets.UTF_8).trim()
                } catch (failure: InterruptedException) {
                    interrupted = true; throw AssertionError("CA proof source interrupted")
                } finally {
                    if (process.isAlive) process.destroyForcibly()
                    try { joined = process.waitFor(5, TimeUnit.SECONDS) } catch (_: InterruptedException) { interrupted = true; joined = false }
                    for (stream in listOf(process.inputStream, process.errorStream, process.outputStream))
                        try { stream.close() } catch (_: Exception) { streamsClosed = false }
                    if (interrupted) Thread.currentThread().interrupt()
                    check(joined && streamsClosed) { "CA proof source cleanup failed" }
                }
            }
            val source = git("rev-parse", "HEAD").also { check(Regex("[0-9a-f]{40}").matches(it)) }
            val dirty = git("status", "--porcelain", "--untracked-files=normal").isNotEmpty()
            val report = JsonObject(linkedMapOf("format" to JsonPrimitive("http-freekit-a23-jvm-tls-proof"), "revision" to JsonPrimitive(1),
                "sourceCommit" to JsonPrimitive(source), "sourceDirty" to JsonPrimitive(dirty), "jvmRuntime" to JsonPrimitive(System.getProperty("java.runtime.version")),
                "nodeVersions" to JsonArray(nodeVersions.sorted().map(::JsonPrimitive)), "nodeBundledOpenSslVersions" to JsonArray(nodeOpenSslVersions.sorted().map(::JsonPrimitive)),
                "expectedCaseCount" to JsonPrimitive(46), "observedCaseCount" to JsonPrimitive(cases.size),
                "allCasesObserved" to JsonPrimitive(cases.size == 46), "allPassed" to JsonPrimitive(cases.size == 46 && cases.all { it.text("status") == "passed" }),
                "scope" to JsonPrimitive("software-host-pinned-mtls"), "cases" to JsonArray(cases.sortedBy { it.text("case") }),
                "androidKeystoreExecution" to JsonPrimitive(false), "caInstallation" to JsonPrimitive(false), "productionIntegration" to JsonPrimitive(false)))
            val bytes = (report.toString() + "\n").toByteArray(Charsets.UTF_8); check(bytes.size <= 32768)
            val directory = Path.of("build/reports/interception-ca"); Files.createDirectories(directory)
            val target = directory.resolve("jvm-tls.json"); val temporary = directory.resolve("jvm-tls.json.pending")
            Files.write(temporary, bytes); Files.move(temporary, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
        }
    }
}
