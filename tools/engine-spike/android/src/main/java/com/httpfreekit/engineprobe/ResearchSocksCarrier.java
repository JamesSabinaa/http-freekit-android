package com.httpfreekit.engineprobe;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Test-only directional EOF over an ADB carrier that cannot preserve raw TCP half-close. */
final class ResearchSocksCarrier implements AutoCloseable {
    static final String IDENTITY = "freekit-native-stream/1";
    static final int DATA = 1, END_WRITE = 2, MAX_DATA = 16384;
    private final Object changed = new Object();
    private final ServerSocket listener = new ServerSocket();
    private final List<Session> sessions = new ArrayList<>(4);
    private final AtomicBoolean closing = new AtomicBoolean();
    private final AtomicReference<IOException> failure = new AtomicReference<>();
    private final ScheduledThreadPoolExecutor deadlines;
    private final Thread acceptor;
    private final int remotePort, admission, connectMillis, readMillis, lifetimeMillis;

    ResearchSocksCarrier(int remotePort, int admission) throws IOException {
        this(remotePort, admission, 5000, 15000, 30000);
    }

    ResearchSocksCarrier(int remotePort, int admission, int connectMillis, int readMillis, int lifetimeMillis) throws IOException {
        if (remotePort < 1 || remotePort > 65535 || admission < 1 || admission > 4 ||
                connectMillis < 1 || connectMillis > 5000 || readMillis < 1 || readMillis > 15000 ||
                lifetimeMillis < 1 || lifetimeMillis > 30000) {
            listener.close();
            throw new IllegalArgumentException("Invalid research carrier limits");
        }
        this.remotePort = remotePort;
        this.admission = admission;
        this.connectMillis = connectMillis;
        this.readMillis = readMillis;
        this.lifetimeMillis = lifetimeMillis;
        deadlines = new ScheduledThreadPoolExecutor(1, task -> daemon(task, "research-socks-deadline"));
        deadlines.setRemoveOnCancelPolicy(true);
        try {
            listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 4);
        } catch (IOException problem) {
            listener.close();
            deadlines.shutdownNow();
            throw problem;
        }
        acceptor = daemon(this::accept, "research-socks-accept");
        acceptor.start();
    }

    int localPort() { return listener.getLocalPort(); }

    void checkHealthy() throws IOException {
        IOException problem = failure.get();
        if (problem != null) throw new IOException("Research SOCKS carrier failed", problem);
    }

    /** Neither deadlines nor cancellation count as completion: both typed EOFs and real joins do. */
    void awaitCompleted(int expected, long timeout, TimeUnit unit) throws IOException, InterruptedException {
        if (expected != admission) throw new IllegalArgumentException("Unexpected research session count");
        long end = System.nanoTime() + unit.toNanos(timeout);
        synchronized (changed) {
            while (!allFinished()) {
                checkHealthy();
                long remaining = end - System.nanoTime();
                if (remaining <= 0) throw new SocketTimeoutException("Research SOCKS sessions did not complete");
                TimeUnit.NANOSECONDS.timedWait(changed, remaining);
            }
        }
        join(acceptor, end);
        for (Session session : snapshot()) {
            join(session.upload, end);
            join(session.download, end);
        }
        checkHealthy();
        if (completedCount() != expected) throw new IOException("Research SOCKS sessions did not join successfully");
    }

    int completedCount() {
        int completed = 0;
        for (Session session : snapshot()) if (session.successfullyJoined()) completed++;
        return completed;
    }

    boolean isStopped() {
        if (!closing.get() || acceptor.isAlive() || !deadlines.isTerminated()) return false;
        for (Session session : snapshot()) {
            if (alive(session.upload) || alive(session.download)) return false;
        }
        return true;
    }

    @Override public void close() throws IOException {
        closing.set(true);
        closeQuietly(listener);
        for (Session session : snapshot()) session.closeSockets();
        deadlines.shutdownNow();
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        try {
            join(acceptor, end);
            for (Session session : snapshot()) {
                join(session.upload, end);
                join(session.download, end);
            }
            long remaining = end - System.nanoTime();
            if (remaining > 0) deadlines.awaitTermination(remaining, TimeUnit.NANOSECONDS);
        } catch (InterruptedException problem) {
            Thread.currentThread().interrupt();
            throw new IOException("Research SOCKS cleanup was interrupted", problem);
        }
        if (!isStopped()) throw new IOException("Research SOCKS threads did not stop");
    }

    private void accept() {
        try {
            for (int index = 0; index < admission && !closing.get(); index++) {
                Socket nativeSocket = listener.accept();
                Session session = new Session(nativeSocket, index);
                synchronized (changed) {
                    if (closing.get()) { session.closeSockets(); return; }
                    sessions.add(session);
                }
                session.deadline = deadlines.schedule(() -> {
                    if (!closing.get() && !(session.uploadEnded && session.downloadEnded)) {
                        session.fail(new SocketTimeoutException("Research SOCKS session lifetime exceeded"));
                    }
                }, lifetimeMillis, TimeUnit.MILLISECONDS);
                session.carrier.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), remotePort), connectMillis);
                session.configure();
                synchronized (changed) {
                    if (closing.get()) { session.closeSockets(); return; }
                    session.upload.start();
                    session.download.start();
                }
            }
        } catch (IOException | RuntimeException problem) {
            if (!closing.get()) fail(problem);
        } finally {
            closeQuietly(listener);
            synchronized (changed) { changed.notifyAll(); }
        }
    }

    private List<Session> snapshot() {
        synchronized (changed) { return new ArrayList<>(sessions); }
    }

    private boolean allFinished() {
        if (sessions.size() != admission) return false;
        for (Session session : sessions) if (session.finished.get() != 2) return false;
        return true;
    }

    private void fail(Exception problem) {
        IOException reported = problem instanceof IOException ? (IOException) problem : new IOException("Invalid research carrier state", problem);
        if (failure.compareAndSet(null, reported)) {
            closeQuietly(listener);
            for (Session session : snapshot()) session.closeSockets();
        }
        synchronized (changed) { changed.notifyAll(); }
    }

    private final class Session {
        final Socket nativeSocket, carrier = new Socket();
        final Thread upload, download;
        final AtomicInteger finished = new AtomicInteger();
        volatile boolean uploadEnded, downloadEnded, failed;
        volatile ScheduledFuture<?> deadline;

        Session(Socket nativeSocket, int index) {
            this.nativeSocket = nativeSocket;
            upload = daemon(() -> pump(true), "research-socks-upload-" + index);
            download = daemon(() -> pump(false), "research-socks-download-" + index);
        }

        void configure() throws IOException {
            for (Socket socket : new Socket[]{nativeSocket, carrier}) {
                socket.setSoLinger(false, 0);
                socket.setTcpNoDelay(true);
                socket.setSoTimeout(readMillis);
            }
        }

        void pump(boolean outgoing) {
            try {
                if (outgoing) upload(); else download();
            } catch (IOException | RuntimeException problem) {
                if (!closing.get()) fail(problem);
            } finally {
                if (finished.incrementAndGet() == 2) {
                    ScheduledFuture<?> timer = deadline;
                    if (timer != null) timer.cancel(false);
                    closeSockets();
                }
                synchronized (changed) { changed.notifyAll(); }
            }
        }

        void upload() throws IOException {
            DataOutputStream output = new DataOutputStream(carrier.getOutputStream());
            byte[] bytes = new byte[MAX_DATA];
            int count;
            while ((count = nativeSocket.getInputStream().read(bytes)) != -1) {
                output.writeByte(DATA);
                output.writeInt(count);
                output.write(bytes, 0, count);
                output.flush();
            }
            output.writeByte(END_WRITE);
            output.writeInt(0);
            output.flush();
            uploadEnded = true;
        }

        void download() throws IOException {
            DataInputStream input = new DataInputStream(carrier.getInputStream());
            byte[] bytes = new byte[MAX_DATA];
            while (true) {
                int kind;
                try { kind = input.readUnsignedByte(); }
                catch (EOFException problem) { throw new EOFException("Research carrier ended before END_WRITE"); }
                int length = input.readInt();
                if (kind == END_WRITE && length == 0) {
                    nativeSocket.shutdownOutput();
                    downloadEnded = true;
                    return;
                }
                if (kind != DATA || length < 1 || length > MAX_DATA) throw new IOException("Invalid research stream frame");
                input.readFully(bytes, 0, length);
                nativeSocket.getOutputStream().write(bytes, 0, length);
                nativeSocket.getOutputStream().flush();
            }
        }

        void fail(Exception problem) {
            failed = true;
            ResearchSocksCarrier.this.fail(problem);
        }

        void closeSockets() { closeQuietly(nativeSocket); closeQuietly(carrier); }

        boolean successfullyJoined() {
            return !failed && uploadEnded && downloadEnded && finished.get() == 2 && !upload.isAlive() && !download.isAlive();
        }
    }

    private static Thread daemon(Runnable operation, String name) {
        Thread thread = new Thread(operation, name);
        thread.setDaemon(true);
        return thread;
    }

    private static boolean alive(Thread thread) { return thread != null && thread.isAlive(); }

    private static void join(Thread thread, long end) throws InterruptedException, IOException {
        if (thread == null || !thread.isAlive()) return;
        long remaining = end - System.nanoTime();
        if (remaining > 0) TimeUnit.NANOSECONDS.timedJoin(thread, remaining);
        if (thread.isAlive()) throw new IOException("Research SOCKS thread did not join");
    }

    private static void closeQuietly(AutoCloseable resource) {
        try { resource.close(); } catch (Exception ignored) { /* Completion still requires actual joins. */ }
    }
}
