package com.httpfreekit.engineprobe;

import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public final class NativeStopGateTest {
    @Test public void deadlineRetainsResourcesAndCannotStartAnotherNativeStop() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger(), closes = new AtomicInteger();
        try (NativeStopGate gate = new NativeStopGate(() -> {
            calls.incrementAndGet();
            entered.countDown();
            release.await();
            return true;
        })) {
            gate.prepareStart();
            NativeStopGate.Lease lease = gate.retain(closes::incrementAndGet);
            try {
                gate.requestStop();
                assertTrue(entered.await(1, TimeUnit.SECONDS));
                assertThrows(TimeoutException.class, () -> gate.awaitStop(1, TimeUnit.MILLISECONDS));
                assertFalse(gate.joined());
                assertFalse(lease.closeAfterJoin());
                assertEquals(0, closes.get());
                assertThrows(IllegalStateException.class, gate::requestStop);
                assertThrows(IllegalStateException.class, gate::prepareStart);
                assertThrows(IllegalStateException.class, () -> gate.repeatStop(1, TimeUnit.SECONDS));
                assertEquals(1, calls.get());
            } finally { release.countDown(); }
            assertTrue(gate.awaitStop(1, TimeUnit.SECONDS));
            assertTrue(lease.closeAfterJoin());
            assertEquals(1, closes.get());
            assertTrue(lease.closeAfterJoin());
            assertEquals(1, closes.get());
        }
    }

    @Test public void successfulJoinAllowsOneIdempotenceCheckAndClosesTheLease() throws Exception {
        AtomicInteger calls = new AtomicInteger(), closes = new AtomicInteger();
        try (NativeStopGate gate = new NativeStopGate(() -> { calls.incrementAndGet(); return true; })) {
            assertTrue(gate.stop(1, TimeUnit.SECONDS)); // Before start.
            gate.prepareStart();
            assertFalse(gate.joined());
            NativeStopGate.Lease lease = gate.retain(closes::incrementAndGet);
            assertTrue(gate.stop(1, TimeUnit.SECONDS));
            assertTrue(gate.repeatStop(1, TimeUnit.SECONDS));
            assertTrue(lease.closeAfterJoin());
            assertEquals(1, closes.get());
            assertEquals(3, calls.get());
        }
    }

    @Test public void failedNativeStopDoesNotAuthorizeClosingItsDescriptors() throws Exception {
        AtomicInteger closes = new AtomicInteger();
        try (NativeStopGate gate = new NativeStopGate(() -> false)) {
            gate.prepareStart();
            NativeStopGate.Lease lease = gate.retain(closes::incrementAndGet);
            assertFalse(gate.stop(1, TimeUnit.SECONDS));
            assertFalse(lease.closeAfterJoin());
            assertFalse(gate.joined());
            assertEquals(0, closes.get());
            assertThrows(IllegalStateException.class, gate::prepareStart);
            assertThrows(IllegalStateException.class, gate::requestStop);
            // This fixture intentionally remains retained, just as a failed
            // Android process must retain its FD until the host force-stops it.
        }
    }

    @Test public void repeatedStopCannotBorrowJoinEvidenceFromAnEarlierSuccess() throws Exception {
        CountDownLatch repeated = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger(), closes = new AtomicInteger();
        try (NativeStopGate gate = new NativeStopGate(() -> {
            if (calls.incrementAndGet() == 1) return true;
            repeated.countDown();
            release.await();
            return true;
        })) {
            gate.prepareStart();
            NativeStopGate.Lease lease = gate.retain(closes::incrementAndGet);
            assertTrue(gate.stop(1, TimeUnit.SECONDS));
            try {
                assertThrows(TimeoutException.class, () -> gate.repeatStop(1, TimeUnit.MILLISECONDS));
                assertTrue(repeated.await(1, TimeUnit.SECONDS));
                assertFalse(gate.joined());
                assertFalse(lease.closeAfterJoin());
                assertEquals(0, closes.get());
                assertThrows(IllegalStateException.class, () -> gate.repeatStop(1, TimeUnit.SECONDS));
                assertThrows(IllegalStateException.class, gate::prepareStart);
                assertEquals(2, calls.get());
            } finally { release.countDown(); }
            assertTrue(gate.awaitStop(1, TimeUnit.SECONDS));
            assertTrue(lease.closeAfterJoin());
            assertEquals(1, closes.get());
        }
    }

    @Test public void falseRepeatedStopInvalidatesPriorJoinAndForbidsRetry() throws Exception {
        AtomicInteger calls = new AtomicInteger(), closes = new AtomicInteger();
        try (NativeStopGate gate = new NativeStopGate(() -> calls.incrementAndGet() == 1)) {
            gate.prepareStart();
            NativeStopGate.Lease lease = gate.retain(closes::incrementAndGet);
            assertTrue(gate.stop(1, TimeUnit.SECONDS));
            assertFalse(gate.repeatStop(1, TimeUnit.SECONDS));
            assertFalse(gate.joined());
            assertFalse(lease.closeAfterJoin());
            assertEquals(0, closes.get());
            assertThrows(IllegalStateException.class, () -> gate.repeatStop(1, TimeUnit.SECONDS));
            assertThrows(IllegalStateException.class, gate::requestStop);
            assertEquals(2, calls.get());
        }
    }
}
