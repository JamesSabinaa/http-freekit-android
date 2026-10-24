package com.httpfreekit.engineprobe;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** A deadline cannot cancel JNI. Keep borrowed descriptors alive until a real join. */
final class NativeStopGate implements AutoCloseable {
    private static final Set<Lease> RETAINED = new HashSet<>();
    private final Callable<Boolean> operation;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "bounded-native-stop");
        thread.setDaemon(true);
        return thread;
    });
    private Future<Boolean> pending;
    private volatile boolean joined;

    NativeStopGate(Callable<Boolean> operation) { this.operation = operation; }

    synchronized void prepareStart() {
        if (pending != null && (!pending.isDone() || !joined)) {
            throw new IllegalStateException("Previous native Stop is unresolved");
        }
        pending = null;
        joined = false;
    }

    synchronized void requestStop() {
        if (pending != null) throw new IllegalStateException("Native Stop already requested");
        joined = false;
        pending = worker.submit(() -> {
            boolean result = operation.call();
            if (result) joined = true;
            return result;
        });
    }

    boolean awaitStop(long timeout, TimeUnit unit) throws Exception {
        Future<Boolean> request;
        synchronized (this) { request = pending; }
        if (request == null) throw new IllegalStateException("Native Stop not requested");
        return request.get(timeout, unit);
    }

    boolean stop(long timeout, TimeUnit unit) throws Exception {
        requestStop();
        return awaitStop(timeout, unit);
    }

    boolean repeatStop(long timeout, TimeUnit unit) throws Exception {
        synchronized (this) {
            if (!joined || pending == null || !pending.isDone()) {
                throw new IllegalStateException("Cannot repeat an unresolved native Stop");
            }
            pending = null;
        }
        return stop(timeout, unit);
    }

    synchronized boolean wasRequested() { return pending != null; }
    boolean joined() { return joined; }

    Lease retain(AutoCloseable resources) {
        Lease lease = new Lease(this, resources);
        synchronized (RETAINED) { RETAINED.add(lease); }
        return lease;
    }

    @Override public void close() {
        // shutdownNow/interrupt cannot terminate pthread_join inside JNI.
        worker.shutdown();
    }

    static final class Lease {
        private final NativeStopGate gate;
        private final AutoCloseable resources;
        private boolean closed;

        private Lease(NativeStopGate gate, AutoCloseable resources) {
            this.gate = gate;
            this.resources = resources;
        }

        synchronized boolean closeAfterJoin() throws Exception {
            if (closed) return true;
            if (!gate.joined()) return false;
            resources.close();
            closed = true;
            synchronized (RETAINED) { RETAINED.remove(this); }
            return true;
        }
    }
}
