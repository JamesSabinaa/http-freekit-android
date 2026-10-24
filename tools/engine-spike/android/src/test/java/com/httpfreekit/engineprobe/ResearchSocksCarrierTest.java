package com.httpfreekit.engineprobe;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.Test;

/** Real loopback streams, including delayed replies after directional EOF. No Android stubs. */
public final class ResearchSocksCarrierTest {
    @Test(timeout = 15000) public void requestEofKeepsCarrierOpenForAGatedStreamingReply() throws Exception {
        byte[] request = bytes(ResearchSocksCarrier.MAX_DATA + 37, 251);
        byte[] reply = bytes(2 * ResearchSocksCarrier.MAX_DATA + 19, 253);
        CountDownLatch prefix = new CountDownLatch(1), replyTail = new CountDownLatch(1);
        try (Fixture fixture = new Fixture(1)) {
            try (Socket nativeSocket = fixture.connect(); Socket carrier = fixture.accept()) {
                FutureTask<Void> peer = new FutureTask<>(() -> {
                    ByteArrayOutputStream received = new ByteArrayOutputStream();
                    DataInputStream input = new DataInputStream(carrier.getInputStream());
                    byte[] part;
                    while ((part = record(input)) != null) {
                        received.write(part);
                        if (received.size() >= 4096) prefix.countDown();
                    }
                    assertArrayEquals(request, received.toByteArray());
                    carrier.setSoTimeout(100);
                    // Typed END_WRITE must not be a raw TCP shutdown on this carrier.
                    assertThrows(SocketTimeoutException.class, input::read);
                    carrier.setSoTimeout(2000);
                    send(carrier, Arrays.copyOfRange(reply, 0, 4096));
                    assertTrue(replyTail.await(3, TimeUnit.SECONDS));
                    send(carrier, Arrays.copyOfRange(reply, 4096, reply.length));
                    end(carrier);
                    return null;
                });
                Thread worker = start(peer);
                try {
                    nativeSocket.getOutputStream().write(request, 0, 4096);
                    assertTrue(prefix.await(3, TimeUnit.SECONDS));
                    nativeSocket.getOutputStream().write(request, 4096, request.length - 4096);
                    nativeSocket.shutdownOutput();
                    byte[] first = new byte[4096];
                    new DataInputStream(nativeSocket.getInputStream()).readFully(first);
                    assertArrayEquals(Arrays.copyOf(reply, 4096), first);
                    replyTail.countDown();
                    ByteArrayOutputStream received = new ByteArrayOutputStream();
                    received.write(first);
                    copyToEof(nativeSocket, received);
                    assertArrayEquals(reply, received.toByteArray());
                    peer.get(4, TimeUnit.SECONDS);
                    fixture.relay.awaitCompleted(1, 3, TimeUnit.SECONDS);
                    assertEquals(1, fixture.relay.completedCount());
                } finally {
                    replyTail.countDown();
                    carrier.close();
                    worker.join(3000);
                    assertFalse(worker.isAlive());
                }
            }
        }
    }

    @Test(timeout = 10000) public void remoteEofLeavesNativeUploadDirectionUsable() throws Exception {
        try (Fixture fixture = new Fixture(1);
             Socket nativeSocket = fixture.connect(); Socket carrier = fixture.accept()) {
            end(carrier);
            assertEquals(-1, nativeSocket.getInputStream().read());
            byte[] request = bytes(8193, 239);
            nativeSocket.getOutputStream().write(request);
            nativeSocket.shutdownOutput();
            assertArrayEquals(request, records(carrier));
            fixture.relay.awaitCompleted(1, 3, TimeUnit.SECONDS);
            assertEquals(1, fixture.relay.completedCount());
        }
    }

    @Test(timeout = 10000) public void fragmentedFrameHeaderAndPayloadPreserveBytesAndTypedEof() throws Exception {
        try (Fixture fixture = new Fixture(1);
             Socket nativeSocket = fixture.connect(); Socket carrier = fixture.accept()) {
            nativeSocket.shutdownOutput();
            assertEquals(0, records(carrier).length);
            ByteArrayOutputStream encoded = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(encoded);
            byte[] value = bytes(37, 127);
            output.writeByte(ResearchSocksCarrier.DATA);
            output.writeInt(value.length);
            output.write(value);
            output.writeByte(ResearchSocksCarrier.END_WRITE);
            output.writeInt(0);
            for (byte part : encoded.toByteArray()) {
                carrier.getOutputStream().write(part);
                carrier.getOutputStream().flush();
            }
            ByteArrayOutputStream received = new ByteArrayOutputStream();
            copyToEof(nativeSocket, received);
            assertArrayEquals(value, received.toByteArray());
            fixture.relay.awaitCompleted(1, 3, TimeUnit.SECONDS);
        }
    }

    @Test(timeout = 15000) public void malformedKindsAndUnsignedLengthsAbortWithoutCompletingASession() throws Exception {
        int[][] invalid = {{1, 0}, {1, 16385}, {1, -1}, {2, 1}, {3, 0}};
        for (int[] header : invalid) {
            try (Fixture fixture = new Fixture(1);
                 Socket nativeSocket = fixture.connect(); Socket carrier = fixture.accept()) {
                DataOutputStream output = new DataOutputStream(carrier.getOutputStream());
                output.writeByte(header[0]);
                output.writeInt(header[1]);
                output.flush();
                assertThrows(IOException.class, () -> fixture.relay.awaitCompleted(1, 2, TimeUnit.SECONDS));
                fixture.relay.close();
                assertTrue(fixture.relay.isStopped());
                assertEquals(0, fixture.relay.completedCount());
            }
        }
    }

    @Test(timeout = 15000) public void rawCarrierEofAndTruncatedHeadersOrPayloadsCannotBecomeSuccessfulEndWrite() throws Exception {
        byte[][] invalid = {new byte[0], {1, 0}, {1, 0, 0, 0, 7, 1, 2, 3}};
        for (byte[] partial : invalid) {
            try (Fixture fixture = new Fixture(1);
                 Socket nativeSocket = fixture.connect(); Socket carrier = fixture.accept()) {
                carrier.getOutputStream().write(partial);
                carrier.shutdownOutput();
                assertThrows(IOException.class, () -> fixture.relay.awaitCompleted(1, 2, TimeUnit.SECONDS));
                fixture.relay.close();
                assertTrue(fixture.relay.isStopped());
                assertEquals(0, fixture.relay.completedCount());
            }
        }
    }

    @Test(timeout = 10000) public void closingIdleAcceptAndReadWorkersJoinsWithoutInventingCompletion() throws Exception {
        try (Fixture fixture = new Fixture(4);
             Socket nativeSocket = fixture.connect(); Socket carrier = fixture.accept()) {
            fixture.relay.close();
            fixture.relay.close();
            assertTrue(fixture.relay.isStopped());
            assertEquals(0, fixture.relay.completedCount());
        }
    }

    @Test(timeout = 10000) public void closingBackpressuredWritesUnblocksAllOwnedWorkers() throws Exception {
        try (Fixture fixture = new Fixture(1);
             Socket nativeSocket = fixture.connect(); Socket carrier = fixture.accept()) {
            nativeSocket.setSendBufferSize(1024);
            carrier.setReceiveBufferSize(1024);
            CountDownLatch began = new CountDownLatch(1);
            FutureTask<Boolean> writing = new FutureTask<>(() -> {
                began.countDown();
                byte[] block = bytes(16384, 251);
                try {
                    for (int index = 0; index < 1024; index++) nativeSocket.getOutputStream().write(block);
                    return false;
                } catch (IOException expected) { return true; }
            });
            Thread sender = start(writing);
            try {
                assertTrue(began.await(2, TimeUnit.SECONDS));
                assertThrows(TimeoutException.class, () -> writing.get(150, TimeUnit.MILLISECONDS));
                fixture.relay.close();
                assertTrue(fixture.relay.isStopped());
                assertEquals(0, fixture.relay.completedCount());
                assertTrue(writing.get(3, TimeUnit.SECONDS));
            } finally {
                nativeSocket.close();
                sender.join(3000);
                assertFalse(sender.isAlive());
            }
        }
    }

    @Test(timeout = 10000) public void lifetimeExpiryAbandonsSocketsButCannotCountAsCompletion() throws Exception {
        try (ServerSocket peer = listener();
             ResearchSocksCarrier relay = new ResearchSocksCarrier(peer.getLocalPort(), 1, 1000, 2000, 100);
             Socket nativeSocket = connected(relay.localPort()); Socket carrier = peer.accept()) {
            assertThrows(IOException.class, () -> relay.awaitCompleted(1, 2, TimeUnit.SECONDS));
            relay.close();
            assertTrue(relay.isStopped());
            assertEquals(0, relay.completedCount());
        }
    }

    @Test(timeout = 10000) public void admissionStopsAfterExactlyFourJoinedSuccessfulSessions() throws Exception {
        try (Fixture fixture = new Fixture(4)) {
            int localPort = fixture.relay.localPort();
            for (int index = 0; index < 4; index++) {
                try (Socket nativeSocket = fixture.connect(); Socket carrier = fixture.accept()) {
                    nativeSocket.shutdownOutput();
                    assertEquals(0, records(carrier).length);
                    end(carrier);
                    assertEquals(-1, nativeSocket.getInputStream().read());
                }
            }
            fixture.relay.awaitCompleted(4, 3, TimeUnit.SECONDS);
            assertEquals(4, fixture.relay.completedCount());
            assertThrows(IOException.class, () -> {
                try (Socket ignored = connected(localPort)) { fail("A fifth session was admitted"); }
            });
            fixture.relay.close();
            assertTrue(fixture.relay.isStopped());
            assertEquals(4, fixture.relay.completedCount());
        }
    }

    private static final class Fixture implements AutoCloseable {
        final ServerSocket peer = listener();
        final ResearchSocksCarrier relay;
        Fixture(int admission) throws IOException { relay = new ResearchSocksCarrier(peer.getLocalPort(), admission); }
        Socket connect() throws IOException { return connected(relay.localPort()); }
        Socket accept() throws IOException { Socket socket = peer.accept(); socket.setSoTimeout(3000); return socket; }
        @Override public void close() throws IOException { try { relay.close(); } finally { peer.close(); } }
    }

    private static ServerSocket listener() throws IOException {
        ServerSocket listener = new ServerSocket();
        listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 4);
        listener.setSoTimeout(3000);
        return listener;
    }

    private static Socket connected(int port) throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 1000);
        socket.setSoTimeout(3000);
        return socket;
    }

    private static Thread start(FutureTask<?> task) {
        Thread worker = new Thread(task, "research-carrier-fixture");
        worker.setDaemon(true);
        worker.start();
        return worker;
    }

    private static byte[] bytes(int count, int divisor) {
        byte[] bytes = new byte[count];
        for (int index = 0; index < count; index++) bytes[index] = (byte) (index % divisor);
        return bytes;
    }

    private static byte[] record(DataInputStream input) throws IOException {
        int kind = input.readUnsignedByte(), count = input.readInt();
        if (kind == ResearchSocksCarrier.END_WRITE) { assertEquals(0, count); return null; }
        assertEquals(ResearchSocksCarrier.DATA, kind);
        assertTrue(count >= 1 && count <= ResearchSocksCarrier.MAX_DATA);
        byte[] bytes = new byte[count];
        input.readFully(bytes);
        return bytes;
    }

    private static byte[] records(Socket socket) throws IOException {
        DataInputStream input = new DataInputStream(socket.getInputStream());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] part;
        while ((part = record(input)) != null) bytes.write(part);
        return bytes.toByteArray();
    }

    private static void send(Socket carrier, byte[] bytes) throws IOException {
        DataOutputStream output = new DataOutputStream(carrier.getOutputStream());
        for (int offset = 0; offset < bytes.length; offset += ResearchSocksCarrier.MAX_DATA) {
            int count = Math.min(ResearchSocksCarrier.MAX_DATA, bytes.length - offset);
            output.writeByte(ResearchSocksCarrier.DATA);
            output.writeInt(count);
            output.write(bytes, offset, count);
            output.flush();
        }
    }

    private static void end(Socket carrier) throws IOException {
        DataOutputStream output = new DataOutputStream(carrier.getOutputStream());
        output.writeByte(ResearchSocksCarrier.END_WRITE);
        output.writeInt(0);
        output.flush();
    }

    private static void copyToEof(Socket socket, ByteArrayOutputStream output) throws IOException {
        byte[] bytes = new byte[1024];
        int count;
        while ((count = socket.getInputStream().read(bytes)) != -1) output.write(bytes, 0, count);
    }
}
