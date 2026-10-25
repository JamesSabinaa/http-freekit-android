package com.httpfreekit.transport.websocket

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.*
import org.junit.Test

class OwnedGatewayWebSocketTest {
    @Test(timeout = 45000) fun onTimeReceiptSurvivesValidatedNormalCloseBeforeCallerResumes() {
        receiptHeldAcrossNormalClose(explicitInterrupt = false)
    }

    @Test(timeout = 45000) fun explicitInterruptAfterNormalCloseStillRejectsHeldReceipt() {
        receiptHeldAcrossNormalClose(explicitInterrupt = true)
    }

    private fun receiptHeldAcrossNormalClose(explicitInterrupt: Boolean) {
        val peer = GatewayNodePeer("queued-text-close")
        peer.use {
            val (raw, tls) = peer.connect()
            val inputRelease = java.util.concurrent.CountDownLatch(1)
            val flushEntered = java.util.concurrent.CountDownLatch(1)
            val flushRelease = java.util.concurrent.CountDownLatch(1)
            val callerEntered = java.util.concurrent.CountDownLatch(1)
            val callerRelease = java.util.concurrent.CountDownLatch(1)
            val armed = java.util.concurrent.atomic.AtomicBoolean()
            val wrapped = GatewayTestSocket(tls, beforeFlush = {
                if (armed.compareAndSet(true, false)) {
                    flushEntered.countDown(); check(flushRelease.await(10, TimeUnit.SECONDS))
                }
            }, beforePostUpgradeRead = { check(inputRelease.await(10, TimeUnit.SECONDS)) })
            OwnedGatewayWebSocket(wrapped, { flushRelease.countDown(); inputRelease.countDown(); raw.close() },
                peer.authority, "/companion/v1/control", null, beforeReceiptWait = {
                    callerEntered.countDown(); check(callerRelease.await(15, TimeUnit.SECONDS))
                }).use { backend ->
                val executor = Executors.newSingleThreadExecutor()
                try {
                    backend.start(deadline()); armed.set(true)
                    val writing = executor.submit<String> {
                        try { backend.writeText("receipt-before-close", deadline(15000)); "ok" }
                        catch (failure: GatewayWebSocketException) { failure.code }
                    }
                    assertTrue(callerEntered.await(5, TimeUnit.SECONDS))
                    assertTrue(flushEntered.await(5, TimeUnit.SECONDS))
                    assertFalse(writing.isDone)
                    assertEquals(1, backend.snapshot().pendingOutputSlots)
                    assertTrue(backend.snapshot().pendingOutputBytes > 0)
                    flushRelease.countDown()
                    await { backend.snapshot().pendingOutputSlots == 0 }
                    assertNull(backend.snapshot().failureCode)
                    inputRelease.countDown()
                    assertEquals("queued-before-close", (next(backend) as OwnedGatewayWebSocket.Incoming.Text).text())
                    assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Closed).normal)
                    assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
                    assertNull(backend.snapshot().failureCode)
                    assertFalse(writing.isDone)
                    if (explicitInterrupt) backend.interrupt()
                    callerRelease.countDown()
                    assertEquals(if (explicitInterrupt) "closed" else "ok", writing.get(5, TimeUnit.SECONDS))
                    if (!explicitInterrupt) assertNull(backend.snapshot().failureCode)
                } finally {
                    callerRelease.countDown(); flushRelease.countDown(); inputRelease.countDown()
                    executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
                }
            }
        }
        assertEquals("1", peer.closedFacts?.get("clientTextMessages"))
        assertEquals("true", peer.closedFacts?.get("clientCloseObserved"))
    }

    @Test(timeout = 45000) fun upgradeCallbackCannotAcknowledgeAnUnfinishedHandshakeFlush() {
        GatewayNodePeer("echo").use { peer ->
            val (raw, tls) = peer.connect()
            val entered = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            val wrapped = GatewayTestSocket(tls, beforeFlush = {
                entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
            })
            OwnedGatewayWebSocket(wrapped, { release.countDown(); raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                val executor = Executors.newSingleThreadExecutor()
                try {
                    val starting = executor.submit<Boolean> { backend.start(deadline()); true }
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    assertFalse(starting.isDone); assertFalse(backend.snapshot().open)
                    assertEquals(1, backend.snapshot().pendingOutputSlots)
                    release.countDown(); assertTrue(starting.get(5, TimeUnit.SECONDS))
                    assertTrue(backend.snapshot().open)
                } finally { release.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
            }
        }
    }

    @Test(timeout = 45000) fun handshakeDeadlineRequiresActualFlushEvenWhenPeerAlreadyUpgraded() {
        GatewayNodePeer("echo").use { peer ->
            val (raw, tls) = peer.connect()
            val entered = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            val wrapped = GatewayTestSocket(tls, beforeFlush = {
                entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
            })
            OwnedGatewayWebSocket(wrapped, { release.countDown(); raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                val executor = Executors.newSingleThreadExecutor()
                try {
                    val starting = executor.submit<String> {
                        try { backend.start(deadline(300)); "unexpected_success" }
                        catch (failure: GatewayWebSocketException) { failure.code }
                    }
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    assertEquals("deadline", starting.get(5, TimeUnit.SECONDS))
                    assertFalse(backend.snapshot().open)
                    assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
                } finally { release.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
            }
        }
    }
    @Test(timeout = 45000) fun receivedTextStaysOwnedUntilDeliveredBeforeActualPeerClose() {
        val peer = GatewayNodePeer("queued-text-close")
        peer.use {
            val (raw, tls) = peer.connect()
            OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                backend.start(deadline())
                await { backend.snapshot().incomingMessages == 1 && backend.snapshot().admissionClosed }
                assertFalse(backend.snapshot().joined)
                assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Text).text() == "queued-before-close")
                assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Closed).normal)
                assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
            }
        }
        assertEquals("true", peer.closedFacts?.get("clientCloseObserved"))
    }

    @Test(timeout = 45000) fun localCloseFollowedByTlsEofNeverFabricatesReceivedPeerClose() {
        val peer = GatewayNodePeer("local-close-eof")
        peer.use {
            val (raw, tls) = peer.connect()
            OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                backend.start(deadline()); backend.requestClose()
                assertFalse((next(backend) as OwnedGatewayWebSocket.Incoming.Closed).normal)
                assertNotNull(backend.snapshot().failureCode)
                assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
            }
        }
        assertEquals("true", peer.closedFacts?.get("clientCloseObserved"))
        assertEquals("0", peer.closedFacts?.get("clientTextMessages"))
        assertEquals("0", peer.closedFacts?.get("clientBinaryMessages"))
    }
    @Test(timeout = 45000) fun emptyPingWaitsForActualFlushAndObservedPongIsSeparateFromDemand() {
        val peer = GatewayNodePeer("echo")
        peer.use {
            val (raw, tls) = peer.connect()
            val armed = java.util.concurrent.atomic.AtomicBoolean()
            val entered = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            val wrapped = GatewayTestSocket(tls, beforeFlush = {
                if (armed.get()) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
            })
            OwnedGatewayWebSocket(wrapped, { release.countDown(); raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                backend.start(deadline()); armed.set(true)
                val executor = Executors.newSingleThreadExecutor()
                try {
                    val ping = executor.submit<Boolean> { backend.writePing(deadline()); true }
                    assertTrue(entered.await(5, TimeUnit.SECONDS)); assertFalse(ping.isDone)
                    assertEquals(1, backend.snapshot().pendingOutputSlots)
                    release.countDown(); assertTrue(ping.get(5, TimeUnit.SECONDS))
                    val observed = listOf(next(backend), next(backend))
                    assertEquals(1, observed.count { it is OwnedGatewayWebSocket.Incoming.Ping })
                    assertEquals(1, observed.count { it is OwnedGatewayWebSocket.Incoming.Pong })
                    backend.requestClose(); assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Closed).normal)
                    assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
                } finally { release.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
            }
        }
        assertEquals("1", peer.closedFacts?.get("clientPongs"))
    }
    @Test(timeout = 45000) fun streamsUseOnlyCanonicalSessionHeaderAndOwnedValidatedTls() {
        GatewayNodePeer("echo").use { peer ->
            val (raw, tls) = peer.connect()
            val session = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 23 })
            try {
                for ((path, header) in listOf("/companion/v1/control" to session,
                    "/companion/v1/streams" to null, "/companion/v1/streams" to (session + "="))) {
                    try { OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, path, header); fail() }
                    catch (failure: GatewayWebSocketException) { assertEquals("invalid_request", failure.code) }
                }
                OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, "/companion/v1/streams", session).use { backend ->
                    backend.start(deadline()); backend.writeBinary(byteArrayOf(7, 8, 9), deadline())
                    assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Binary).copyBytes().contentEquals(byteArrayOf(7, 8, 9)))
                    assertFalse(backend.toString().contains(session))
                    backend.requestClose(); assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Closed).normal)
                    assertTrue(backend.awaitJoined(deadline()))
                }
            } finally { raw.close(); tls.close() }
        }
    }
    @Test(timeout = 15000) fun inertConstructionCanBeInterruptedAndActuallyClosedWithoutStart() {
        val tls = javax.net.ssl.SSLContext.getDefault().socketFactory.createSocket() as javax.net.ssl.SSLSocket
        val backend = OwnedGatewayWebSocket(tls, { tls.close() }, "unused.invalid", "/companion/v1/control")
        assertFalse(backend.snapshot().readerAlive); assertFalse(backend.snapshot().writerAlive)
        assertFalse(tls.isClosed)
        backend.close(); backend.close()
        assertTrue(tls.isClosed); assertJoined(backend); assertFalse(backend.snapshot().started)
    }

    @Test(timeout = 45000) fun failedTlsCleanupRetainsWorkerUntilExplicitRetryActuallySucceeds() {
        GatewayNodePeer("echo").use { peer ->
            val (raw, tls) = peer.connect()
            val attempts = java.util.concurrent.atomic.AtomicInteger()
            val wrapped = GatewayTestSocket(tls, beforeClose = { if (attempts.incrementAndGet() == 1) throw java.io.IOException("close-canary") })
            val backend = OwnedGatewayWebSocket(wrapped, { raw.close() }, peer.authority, "/companion/v1/control")
            try {
                backend.start(deadline()); backend.interrupt()
                await { attempts.get() == 1 }
                assertFalse(backend.awaitJoined(deadline(100)))
                assertTrue(backend.snapshot().writerAlive)
                assertFalse(backend.snapshot().joined)
            } finally { backend.close() }
            assertTrue(attempts.get() >= 2); assertJoined(backend)
        }
    }

    @Test(timeout = 45000) fun operationDeadlineCannotBecomeASuccessfulFlushReceipt() {
        GatewayNodePeer("echo").use { peer ->
            val (raw, tls) = peer.connect()
            val armed = java.util.concurrent.atomic.AtomicBoolean()
            val entered = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            val wrapped = GatewayTestSocket(tls, beforeFlush = {
                if (armed.get()) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
            })
            OwnedGatewayWebSocket(wrapped, { release.countDown(); raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                backend.start(deadline()); armed.set(true)
                val executor = Executors.newSingleThreadExecutor()
                try {
                    val operation = executor.submit<String> {
                        try { backend.writeText("deadline-canary", deadline(300)); "unexpected_success" }
                        catch (failure: GatewayWebSocketException) { failure.code }
                    }
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    assertEquals("deadline", operation.get(5, TimeUnit.SECONDS))
                    assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
                } finally { release.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
            }
        }
    }
    @Test(timeout = 45000) fun independentFragmentsKeepUtf8AndBinaryBytesWithInterleavedPing() {
        val peer = GatewayNodePeer("fragmented")
        peer.use {
            val (raw, tls) = peer.connect()
            OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                backend.start(deadline())
                assertTrue(next(backend) is OwnedGatewayWebSocket.Incoming.Ping)
                assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Text).text() == "fragmented-\u20ac-backend")
                assertTrue(next(backend) is OwnedGatewayWebSocket.Incoming.Ping)
                val binary = (next(backend) as OwnedGatewayWebSocket.Incoming.Binary).copyBytes()
                assertTrue(binary.contentEquals(ByteArray(4097) { ((it * 29 + 3) and 255).toByte() }))
                backend.requestClose()
                assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Closed).normal)
                assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
            }
        }
        assertEquals("2", peer.closedFacts?.get("clientPongs"))
    }
    @Test(timeout = 45000) fun independentNodeTlsEchoPreservesTextBinaryAndNormalClose() {
        GatewayNodePeer("echo").use { peer ->
            val (raw, tls) = peer.connect()
            OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                assertFalse(backend.snapshot().started)
                backend.start(deadline())
                val text = "private-canary-\u00e9-\ud83c\udf0d"
                backend.writeText(text, deadline())
                assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Text).text() == text)
                val binary = ByteArray(65536) { (it % 251).toByte() }
                backend.writeBinary(binary, deadline())
                val received = next(backend) as OwnedGatewayWebSocket.Incoming.Binary
                assertTrue(binary.contentEquals(received.copyBytes()))
                val copy = received.copyBytes(); copy[0] = 99
                assertEquals(0, received.copyBytes()[0].toInt())
                assertFalse(received.toString().contains("private-canary"))
                assertFalse(backend.toString().contains(peer.authority))
                backend.requestClose()
                assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Closed).normal)
                assertTrue(backend.awaitJoined(deadline()))
                assertJoined(backend)
            }
        }
    }

    @Test(timeout = 180000) fun rejectsIndependentMalformedWireWithoutProviderOrPayloadDisclosure() {
        for (scenario in listOf("bad-mask", "bad-rsv", "bad-minimal16", "bad-minimal64", "oversized-frame",
            "fragmented-byte-limit", "empty-fragment-count129", "header-limit", "bad-extension", "bad-subprotocol", "invalid-utf8")) {
            GatewayNodePeer(scenario).use { peer ->
                val (raw, tls) = peer.connect()
                OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                    var refused = false
                    try {
                        backend.start(deadline())
                        val until = deadline()
                        while (System.nanoTime() - until < 0) {
                            val event = backend.pollIncoming(100)
                            if (event is OwnedGatewayWebSocket.Incoming.Closed) {
                                assertFalse(event.normal); refused = true; break
                            }
                        }
                    } catch (failure: GatewayWebSocketException) {
                        refused = true
                        assertNull(failure.cause)
                        assertFalse(failure.toString().contains(peer.authority))
                    }
                    assertTrue("Malformed scenario was accepted: $scenario", refused)
                    backend.interrupt(); assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
                    assertNotNull(backend.snapshot().failureCode)
                }
            }
        }
    }

    @Test(timeout = 45000) fun fullInputQueuePausesReaderAndInterruptWakesAllOwnedWorkers() {
        GatewayNodePeer("queued-input").use { peer ->
            val (raw, tls) = peer.connect()
            OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                backend.start(deadline())
                await { backend.snapshot().incomingMessages == 2 }
                val state = backend.snapshot()
                assertTrue(state.incomingBytes in 1..131072)
                assertTrue(state.readerAlive)
                backend.interrupt()
                assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
                assertTrue(next(backend) is OwnedGatewayWebSocket.Incoming.Closed)
                assertEquals(0, backend.snapshot().incomingMessages)
            }
        }
    }

    @Test(timeout = 45000) fun actualTlsBlockedWriteRetainsChargeUntilRawInterruptionAndActualJoins() {
        GatewayNodePeer("held-read").use { peer ->
            val (raw, tls) = peer.connect()
            val writes = AtomicLong(); val completed = AtomicLong()
            val traced = GatewayTestSocket(tls, beforeWrite = { writes.incrementAndGet() }, afterWrite = { completed.set(writes.get()) })
            OwnedGatewayWebSocket(traced, { raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                backend.start(deadline())
                val executor = Executors.newFixedThreadPool(10)
                try {
                    val producer = executor.submit<Boolean> {
                        try { repeat(512) { backend.writeBinary(ByteArray(65536) { 17 }, deadline(30000)) }; false }
                        catch (_: GatewayWebSocketException) { true }
                    }
                    var candidate = 0L; var since = 0L
                    await(15000) {
                        val entry = writes.get(); val done = completed.get()
                        val now = System.nanoTime()
                        if (entry != 0L && done < entry) {
                            if (candidate != entry) { candidate = entry; since = now }
                            now - since >= TimeUnit.MILLISECONDS.toNanos(250)
                        } else { candidate = 0; false }
                    }
                    assertFalse(producer.isDone)
                    val blocked = backend.snapshot()
                    assertTrue(blocked.pendingOutputSlots in 1..8)
                    assertTrue(blocked.pendingOutputBytes in 1..131072)
                    val queued = (1..9).map {
                        executor.submit<Boolean> {
                            try { backend.writeBinary(ByteArray(4096) { 11 }, deadline(30000)); false }
                            catch (_: GatewayWebSocketException) { true }
                        }
                    }
                    await { backend.snapshot().pendingOutputSlots == 8 }
                    assertTrue(backend.snapshot().pendingOutputBytes <= 131072)
                    backend.interrupt()
                    assertTrue(producer.get(5, TimeUnit.SECONDS))
                    queued.forEach { assertTrue(it.get(5, TimeUnit.SECONDS)) }
                    assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
                } finally { executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
            }
        }
    }

    @Test(timeout = 45000) fun actualFlushGatePreventsEarlyAcknowledgementAndDeadlineRetainsOwnership() {
        GatewayNodePeer("echo").use { peer ->
            val (raw, tls) = peer.connect()
            val entered = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            val armed = java.util.concurrent.atomic.AtomicBoolean(false)
            val wrapped = GatewayTestSocket(tls, beforeFlush = {
                if (armed.get()) { entered.countDown(); check(release.await(10, TimeUnit.SECONDS)) }
            })
            OwnedGatewayWebSocket(wrapped, { release.countDown(); raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                backend.start(deadline()); armed.set(true)
                val executor = Executors.newSingleThreadExecutor()
                try {
                    val writing = executor.submit<Boolean> { backend.writeText("flush-canary", deadline()); true }
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    assertFalse(writing.isDone)
                    assertEquals(1, backend.snapshot().pendingOutputSlots)
                    assertTrue(backend.snapshot().pendingOutputBytes > 0)
                    backend.requestClose()
                    release.countDown()
                    assertTrue(writing.get(5, TimeUnit.SECONDS))
                    val first = next(backend)
                    assertTrue("Gateway order event=${first.javaClass.simpleName}; normal=${(first as? OwnedGatewayWebSocket.Incoming.Closed)?.normal}; code=${backend.snapshot().failureCode}", first is OwnedGatewayWebSocket.Incoming.Text)
                    assertTrue((next(backend) as OwnedGatewayWebSocket.Incoming.Closed).normal)
                    assertTrue(backend.awaitJoined(deadline())); assertJoined(backend)
                } finally { release.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
            }
        }
    }

    @Test(timeout = 45000) fun badLocalValuesStayPrivateAndDoNotCreateUnownedWorkers() {
        GatewayNodePeer("echo").use { peer ->
            val (raw, tls) = peer.connect()
            try {
                try { OwnedGatewayWebSocket(tls, { raw.close() }, "header-canary\r\n", "/companion/v1/control"); fail() }
                catch (failure: GatewayWebSocketException) { assertEquals("invalid_request", failure.code); assertNull(failure.cause) }
                OwnedGatewayWebSocket(tls, { raw.close() }, peer.authority, "/companion/v1/control").use { backend ->
                    backend.start(deadline())
                    for (text in listOf("\ud800", "x".repeat(16385))) {
                        try { backend.writeText(text, deadline()); fail() }
                        catch (failure: GatewayWebSocketException) { assertEquals("invalid_request", failure.code) }
                    }
                    assertTrue(backend.snapshot().open)
                    assertEquals(0, backend.snapshot().pendingOutputSlots)
                }
            } finally { raw.close(); tls.close() }
        }
    }

    private fun next(backend: OwnedGatewayWebSocket): OwnedGatewayWebSocket.Incoming {
        val end = deadline()
        while (System.nanoTime() - end < 0) backend.pollIncoming(100)?.let { return it }
        throw AssertionError("Gateway event deadline")
    }
    private fun assertJoined(backend: OwnedGatewayWebSocket) {
        val state = backend.snapshot()
        assertTrue(state.joined); assertFalse(state.readerAlive); assertFalse(state.writerAlive)
        assertEquals(0, state.pendingOutputSlots); assertEquals(0L, state.pendingOutputBytes)
    }
    private fun deadline(millis: Long = 5000) = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis)
    private fun await(millis: Long = 5000, condition: () -> Boolean) {
        val end = deadline(millis)
        while (System.nanoTime() - end < 0) { if (condition()) return; Thread.sleep(5) }
        throw AssertionError("Gateway observation deadline")
    }
}
