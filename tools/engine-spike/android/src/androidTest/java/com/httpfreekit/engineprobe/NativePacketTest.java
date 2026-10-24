package com.httpfreekit.engineprobe;

import static org.junit.Assert.*;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Synthetic datagrams only. This test never creates a VPN or changes routes. */
@RunWith(AndroidJUnit4.class)
public final class NativePacketTest {
    private static final int HELLO = 1, PACKET = 2, STOP = 3, STOPPED = 4;
    private static final int MAX_PACKET = 65535;

    private static synchronized void frame(DataOutputStream output, int kind, byte[] bytes) throws Exception {
        assertTrue(bytes.length <= (kind == PACKET ? MAX_PACKET : 4096));
        output.writeByte(kind);
        output.writeInt(bytes.length);
        output.write(bytes);
        output.flush();
    }

    private static byte[] json(JSONObject object) {
        return object.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String readAsset(Context context, String name) throws Exception {
        try (InputStream input = context.getAssets().open(name);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] bytes = new byte[4096];
            int count;
            while ((count = input.read(bytes)) != -1) output.write(bytes, 0, count);
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static void phase(String value) {
        Bundle status = new Bundle();
        status.putString("native_probe_phase", value);
        InstrumentationRegistry.getInstrumentation().sendStatus(2, status);
    }

    @Test(timeout = 180000)
    public void reconstructsFourPacketFlowsThroughPinnedJni() throws Exception {
        phase("arguments-start");
        Bundle arguments = InstrumentationRegistry.getArguments();
        int bridgePort = Integer.parseInt(arguments.getString("bridgePort", "0"));
        int socksPort = Integer.parseInt(arguments.getString("socksPort", "0"));
        assertTrue(bridgePort > 0 && bridgePort <= 65535 && socksPort > 0 && socksPort <= 65535);
        phase("arguments-ready");
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        phase("source-asset-start");
        JSONObject source = new JSONObject(readAsset(context, "engine-source.json"));
        phase("source-asset-ready");
        phase("jni-load-start");
        NativeEngine engine = new NativeEngine(); // JNI_OnLoad must register this class.
        phase("jni-loaded");
        try (NativeStopGate stopGate = new NativeStopGate(engine::TProxyStopService)) {
            phase("jni-running-check-start");
            assertFalse(engine.TProxyIsRunning());
            phase("jni-running-check-done");
            phase("jni-prestop-start");
            assertTrue(stopGate.stop(10, TimeUnit.SECONDS));
            phase("jni-prestop-done");
            File configuration = new File(context.getCacheDir(), "native-engine-research.yaml");
            String yaml = "tunnel:\n  mtu: 1500\n  ipv4: 10.0.0.1\n  ipv6: 'fd00::1'\n"
                    + "socks5:\n  address: 127.0.0.1\n  port: " + socksPort + "\n  udp: 'udp'\n"
                    + "misc:\n  log-file: null\n  log-level: error\n  max-session-count: 8\n"
                    + "  connect-timeout: 5000\n  tcp-read-write-timeout: 15000\n";
            Files.write(configuration.toPath(), yaml.getBytes(StandardCharsets.UTF_8));
            phase("configuration-ready");
            FileDescriptor nativeEnd = new FileDescriptor(), packetEnd = new FileDescriptor();
            ParcelFileDescriptor nativeDescriptor = null;
            NativeStopGate.Lease resources = null;
            Thread pump = null;
            AtomicBoolean shuttingDown = new AtomicBoolean();
            AtomicReference<Throwable> pumpFailure = new AtomicReference<>();
            boolean pairCreated = false, originalOpen = false, nativeMayOwnDescriptor = false, resourcesReleased = false;
            phase("bridge-connect-start");
            try (Socket bridge = new Socket(InetAddress.getByName("127.0.0.1"), bridgePort)) {
                phase("bridge-connected");
                bridge.setSoTimeout(90000);
                DataInputStream input = new DataInputStream(bridge.getInputStream());
                DataOutputStream output = new DataOutputStream(bridge.getOutputStream());
                Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, nativeEnd, packetEnd);
                pairCreated = true;
                originalOpen = true;
                nativeDescriptor = ParcelFileDescriptor.dup(nativeEnd);
                originalOpen = false;
                Os.close(nativeEnd);
                phase("descriptors-ready");
                stopGate.prepareStart();
                ParcelFileDescriptor borrowed = nativeDescriptor;
                resources = stopGate.retain(() -> {
                    try { borrowed.close(); }
                    finally { if (packetEnd.valid()) Os.close(packetEnd); }
                });
                nativeMayOwnDescriptor = true;
                // This public API supplies the live descriptor; no hidden FD reflection.
                phase("jni-start-start");
                assertTrue(engine.TProxyStartService(configuration.getAbsolutePath(), nativeDescriptor.getFd()));
                phase("jni-started");
                assertFalse("A second start must not replace the live engine", engine.TProxyStartService(configuration.getAbsolutePath(), nativeDescriptor.getFd()));
                pump = new Thread(() -> {
                    byte[] bytes = new byte[MAX_PACKET];
                    try {
                        while (!shuttingDown.get()) {
                            int count = Os.read(packetEnd, bytes, 0, bytes.length);
                            if (count == 0) break;
                            byte[] packet = new byte[count];
                            System.arraycopy(bytes, 0, packet, 0, count);
                            frame(output, PACKET, packet);
                        }
                    } catch (Throwable error) {
                        if (!shuttingDown.get()) pumpFailure.set(error);
                    }
                }, "native-packet-output");
                pump.setDaemon(true);
                frame(output, HELLO, json(new JSONObject()
                        .put("bridge", "freekit-native-probe/1").put("engineCommit", source.getString("engineCommit"))
                        .put("api", Build.VERSION.SDK_INT).put("abi", Build.SUPPORTED_ABIS[0])
                        .put("pageSize", Os.sysconf(OsConstants._SC_PAGESIZE))
                        .put("jniLoaded", true).put("running", engine.TProxyIsRunning())));
                // The control greeting must precede any unsolicited native packets.
                phase("hello-sent");
                pump.start();
                while (true) {
                    int kind = input.readUnsignedByte();
                    int length = input.readInt();
                    assertTrue("Invalid frame length", length >= 0 && length <= MAX_PACKET);
                    if (kind == STOP) { assertEquals(0, length); break; }
                    assertEquals(PACKET, kind);
                    assertTrue(length > 0);
                    byte[] packet = new byte[length];
                    input.readFully(packet);
                    assertEquals("A packet must remain one datagram", length, Os.write(packetEnd, packet, 0, length));
                    if (pumpFailure.get() != null) throw new AssertionError("Packet output failed", pumpFailure.get());
                }
                assertTrue("Engine exited before Stop", engine.TProxyIsRunning());
                phase("jni-statistics-start");
                long[] stats = engine.TProxyGetStats();
                assertEquals(4, stats.length);
                JSONArray counters = new JSONArray();
                for (long value : stats) { assertTrue("Missing native traffic statistics", value > 0); counters.put(value); }
                phase("jni-stop-start");
                assertTrue("JNI stop must join the upstream worker", stopGate.stop(10, TimeUnit.SECONDS));
                phase("jni-joined");
                assertFalse(engine.TProxyIsRunning());
                assertTrue("Repeated stop must be harmless", stopGate.repeatStop(10, TimeUnit.SECONDS));
                phase("jni-repeat-stop-done");
                shuttingDown.set(true);
                Os.shutdown(packetEnd, OsConstants.SHUT_RDWR);
                pump.join(3000);
                assertFalse("Packet output thread did not stop", pump.isAlive());
                if (pumpFailure.get() != null) throw new AssertionError("Packet output failed", pumpFailure.get());
                assertTrue(resources.closeAfterJoin());
                resourcesReleased = true;
                nativeDescriptor = null;
                pairCreated = false;
                phase("descriptors-closed");
                frame(output, STOPPED, json(new JSONObject().put("stopped", true)
                        .put("running", engine.TProxyIsRunning()).put("packetPumpStopped", true)
                        .put("descriptorsClosed", true).put("statisticsBeforeStop", counters)));
            } finally {
                shuttingDown.set(true);
                try {
                    if (nativeMayOwnDescriptor && !stopGate.wasRequested()) {
                        phase("cleanup-stop-start");
                        try {
                            stopGate.stop(10, TimeUnit.SECONDS);
                            phase("cleanup-stop-returned");
                        } catch (Exception failure) {
                            phase("cleanup-stop-unconfirmed");
                        }
                    }
                } finally {
                    if (resources != null && !resourcesReleased) {
                        if (stopGate.joined()) {
                            if (packetEnd.valid()) Os.shutdown(packetEnd, OsConstants.SHUT_RDWR);
                            if (pump != null) pump.join(3000);
                            if (pump == null || !pump.isAlive()) {
                                resourcesReleased = resources.closeAfterJoin();
                            } else phase("packet-pump-retained");
                        } else {
                            // The static lease keeps PFD/peer/Stop alive even after
                            // this failed test unwinds. Only host force-stop may
                            // terminate an unresolved native worker.
                            phase("descriptors-retained");
                        }
                    } else if (resources == null) {
                        if (nativeDescriptor != null) nativeDescriptor.close();
                        if (pairCreated && packetEnd.valid()) {
                            try { Os.shutdown(packetEnd, OsConstants.SHUT_RDWR); } finally { Os.close(packetEnd); }
                        }
                    }
                    if (originalOpen && nativeEnd.valid()) Os.close(nativeEnd);
                    if (!nativeMayOwnDescriptor || resourcesReleased) Files.deleteIfExists(configuration.toPath());
                }
            }
        }
    }
}
