package com.httpfreekit.capture.transport;

import com.httpfreekit.capture.CapturePolicyServer;
import com.httpfreekit.capture.CaptureSocketGuard;
import com.httpfreekit.capture.CaptureTcpConnection;
import com.httpfreekit.capture.InterceptedTcpFactory;
import com.httpfreekit.capture.ProtectedEgressFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

/** Test-only access to Kotlin-internal public JVM bytecode; all relay I/O is production code. */
public final class CapturePolicyPeer implements AutoCloseable {
    private final InterceptedTcpFactory factory;
    private final AtomicInteger egressAttempts = new AtomicInteger();
    private final AtomicInteger interrupts = new AtomicInteger();
    private final AtomicInteger closes = new AtomicInteger();
    private final AtomicInteger inputEofs = new AtomicInteger();
    private final AtomicInteger shutdowns = new AtomicInteger();
    private final ProtectedEgressFactory egress;
    private final CapturePolicyServer policy;
    private Socket app;

    public CapturePolicyPeer(InterceptedTcpFactory factory, InetAddress address, int port) throws Exception {
        this.factory = factory;
        egress = new ProtectedEgressFactory(new CaptureSocketGuard() {
            public boolean protect(Socket socket) { egressAttempts.incrementAndGet(); return false; }
            public boolean protect(DatagramSocket socket) { egressAttempts.incrementAndGet(); return false; }
            public void bind(Socket socket) { throw new IllegalStateException("Unexpected direct bind"); }
            public void bind(DatagramSocket socket) { throw new IllegalStateException("Unexpected UDP bind"); }
        });
        InterceptedTcpFactory observed = new InterceptedTcpFactory() {
            public CaptureTcpConnection open(InetAddress originalAddress, int originalPort) {
                CaptureTcpConnection actual = factory.open(originalAddress, originalPort);
                return new CaptureTcpConnection() {
                    private final InputStream input = new FilterInputStream(actual.getInput()) {
                        private boolean ended;
                        private int observed(int value) {
                            if (value < 0 && !ended) { ended = true; inputEofs.incrementAndGet(); }
                            return value;
                        }
                        public int read() throws IOException { return observed(in.read()); }
                        public int read(byte[] bytes, int offset, int length) throws IOException {
                            return observed(in.read(bytes, offset, length));
                        }
                    };
                    public InputStream getInput() { return input; }
                    public OutputStream getOutput() { return actual.getOutput(); }
                    public void shutdownOutput() { actual.shutdownOutput(); shutdowns.incrementAndGet(); }
                    public void interrupt() { interrupts.incrementAndGet(); actual.interrupt(); }
                    public void close() { actual.close(); closes.incrementAndGet(); }
                };
            }
            public void close() { factory.close(); }
        };
        policy = new CapturePolicyServer(observed, egress, 15000L, 60000L);
        try {
            policy.start();
            app = new Socket();
            app.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), policy.getPort()), 5000);
            app.setSoTimeout(8000); app.setTcpNoDelay(true);
            authenticate();
            DataOutputStream output = new DataOutputStream(app.getOutputStream());
            output.write(new byte[]{5, 1, 0, (byte) (address.getAddress().length == 4 ? 1 : 4)});
            output.write(address.getAddress()); output.writeShort(port); output.flush();
            byte[] reply = new byte[10]; new DataInputStream(app.getInputStream()).readFully(reply);
            assertArrayEquals(new byte[]{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}, reply);
        } catch (Exception | Error failure) {
            try { close(); } catch (Exception | Error cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    private void authenticate() throws IOException {
        DataInputStream input = new DataInputStream(app.getInputStream());
        DataOutputStream output = new DataOutputStream(app.getOutputStream());
        output.write(new byte[]{5, 1, 2}); output.flush();
        assertEquals(5, input.readUnsignedByte()); assertEquals(2, input.readUnsignedByte());
        // Configuration stays private to this test process and is never printed or retained.
        String configuration = policy.configuration();
        byte[] user = credential(configuration, "username"), password = credential(configuration, "password");
        try {
            output.writeByte(1); output.writeByte(user.length); output.write(user);
            output.writeByte(password.length); output.write(password); output.flush();
        } finally { Arrays.fill(user, (byte) 0); Arrays.fill(password, (byte) 0); }
        assertEquals(1, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte());
    }

    private static byte[] credential(String configuration, String key) {
        String prefix = "  " + key + ": '";
        for (String line : configuration.split("\n")) {
            if (line.startsWith(prefix) && line.endsWith("'"))
                return line.substring(prefix.length(), line.length() - 1).getBytes(StandardCharsets.US_ASCII);
        }
        throw new IllegalStateException("Missing private SOCKS configuration");
    }

    public Socket getApp() { return app; }

    public void finish() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (policy.facts().getFlows() != 0 && System.nanoTime() < deadline) Thread.sleep(20);
        CapturePolicyServer.Facts facts = policy.facts();
        assertFalse(facts.getSealed()); assertFalse(facts.getFailed());
        assertEquals(0, facts.getFlows()); assertEquals(0, facts.getPending());
        assertEquals(2, facts.getWorkers()); // Session accept/watch remain owned until explicit Stop.
        assertEquals(1, facts.getIntercepted()); assertEquals(0, facts.getDirect());
        assertEquals(0, facts.getUdp()); assertEquals(0, facts.getDrops());
        assertEquals(0, egressAttempts.get()); assertEquals(0, interrupts.get());
        assertEquals(1, inputEofs.get()); assertEquals(1, shutdowns.get()); assertEquals(1, closes.get());
    }

    @FunctionalInterface private interface Cleanup { void run() throws Exception; }
    private static final class CleanupState {
        private Throwable failure;
        private boolean interrupted = Thread.interrupted();
        void attempt(Cleanup cleanup) {
            try { cleanup.run(); }
            catch (Exception | AssertionError caught) {
                if (caught instanceof InterruptedException) interrupted = true;
                if (failure == null) failure = caught;
                else if (failure != caught) failure.addSuppressed(caught);
            } finally { if (Thread.interrupted()) interrupted = true; }
        }
    }

    @Override public void close() throws Exception {
        CleanupState cleanup = new CleanupState();
        try {
            cleanup.attempt(() -> { if (app != null) app.close(); });
            cleanup.attempt(policy::interrupt);
            cleanup.attempt(() -> { factory.close(); policy.factoryClosed(); });
            cleanup.attempt(egress::close);
            cleanup.attempt(() -> policy.join(System.nanoTime() + TimeUnit.SECONDS.toNanos(10)));
            cleanup.attempt(policy::destroySecrets);
            cleanup.attempt(() -> {
                CapturePolicyServer.Facts facts = policy.facts();
                assertTrue(facts.getSealed()); assertEquals(0, facts.getFlows());
                assertEquals(0, facts.getPending()); assertEquals(0, facts.getWorkers());
                assertEquals(0, egressAttempts.get()); assertEquals(0, facts.getDirect()); assertEquals(0, facts.getUdp());
            });
        } finally { if (cleanup.interrupted) Thread.currentThread().interrupt(); }
        if (cleanup.failure instanceof Error) throw (Error) cleanup.failure;
        if (cleanup.failure instanceof Exception) throw (Exception) cleanup.failure;
    }
}
