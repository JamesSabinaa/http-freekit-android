// Research diagnostic only: software credentials arrive through bounded stdin, never arguments/files.
// JSSE is an independent host implementation, not Android Conscrypt or an ADB reproduction.
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.*;

class CompanionStreamPressure {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BURST = 32 * 1024 * 1024;
    private static final AtomicLong entered = new AtomicLong(), completed = new AtomicLong(), bytes = new AtomicLong();
    private static final AtomicBoolean failed = new AtomicBoolean(), active = new AtomicBoolean();
    private static final AtomicLong producerBytes = new AtomicLong();
    private static final AtomicBoolean producerActive = new AtomicBoolean(), producerFailed = new AtomicBoolean();
    private static final Object COUNTERS = new Object();

    private static byte[] uploadHeader() {
        return ("POST http://fixture.invalid/research HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: " + BURST + "\r\nConnection: close\r\n\r\n")
            .getBytes(StandardCharsets.US_ASCII);
    }
    private static void produce(OutputStream output) throws IOException {
        producerActive.set(true);
        try {
            byte[] head = uploadHeader(); output.write(head); producerBytes.addAndGet(head.length);
            for (int offset = 0; offset < BURST; offset += 4096) {
                byte[] chunk = new byte[Math.min(4096, BURST - offset)];
                for (int i = 0; i < chunk.length; i++) chunk[i] = (byte) ((offset + i) % 251);
                output.write(chunk); producerBytes.addAndGet(chunk.length);
            }
            output.flush();
        } finally { producerActive.set(false); }
    }
    private static String counters() {
        synchronized (COUNTERS) {
            return entered.get() + " " + completed.get() + " " + bytes.get() + " " + active.get() + " " + failed.get() + " " +
                producerBytes.get() + " " + producerActive.get() + " " + producerFailed.get();
        }
    }

    private static void check(boolean condition) throws IOException { if (!condition) throw new IOException("pressure_probe_failed"); }
    private static byte[] blob(DataInputStream input, int maximum) throws IOException {
        int size = input.readInt(); check(size > 0 && size <= maximum);
        byte[] value = new byte[size]; input.readFully(value); return value;
    }
    private static String header(InputStream input) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream(); int suffix = 0;
        while (result.size() < 8192) {
            int value = input.read(); check(value >= 9 && value <= 126);
            result.write(value); suffix = (suffix << 8) | value;
            if (suffix == 0x0d0a0d0a) return result.toString("US-ASCII");
        }
        throw new IOException("pressure_probe_failed");
    }
    // Exactly the existing Kotlin writer's calls, or one independently bounded combined write.
    private static void frame(OutputStream output, int opcode, byte[] payload, boolean combined) throws IOException {
        check(payload.length <= 4096);
        byte[] mask = new byte[4]; RANDOM.nextBytes(mask);
        ByteArrayOutputStream head = new ByteArrayOutputStream(8);
        head.write(0x80 | opcode);
        if (payload.length < 126) head.write(0x80 | payload.length);
        else { head.write(0xfe); head.write(payload.length >>> 8); head.write(payload.length & 255); }
        byte[] masked = payload.clone();
        for (int i = 0; i < masked.length; i++) masked[i] ^= mask[i % 4];
        if (combined) {
            byte[] packet = new byte[head.size() + 4 + masked.length];
            System.arraycopy(head.toByteArray(), 0, packet, 0, head.size());
            System.arraycopy(mask, 0, packet, head.size(), 4);
            System.arraycopy(masked, 0, packet, head.size() + 4, masked.length);
            output.write(packet);
        } else {
            for (byte value : head.toByteArray()) output.write(value & 255);
            output.write(mask); output.write(masked);
        }
        output.flush();
    }
    private static byte[] ready(InputStream stream) throws IOException {
        DataInputStream input = new DataInputStream(stream);
        check(input.readUnsignedByte() == 0x81);
        int size = input.readUnsignedByte(); check(size < 126 && size > 0);
        byte[] value = new byte[size]; input.readFully(value);
        check(new String(value, StandardCharsets.UTF_8).equals("{\"protocolVersion\":1,\"streamId\":\"pressure\",\"type\":\"ready\"}"));
        return value;
    }
    private static void binary(OutputStream output, byte[] payload, boolean combined) throws IOException {
        synchronized (COUNTERS) { entered.incrementAndGet(); active.set(true); }
        try {
            frame(output, 2, payload, combined);
            synchronized (COUNTERS) { completed.incrementAndGet(); bytes.addAndGet(payload.length); }
        } finally { synchronized (COUNTERS) { active.set(false); } }
    }
    public static void main(String[] args) {
        Socket raw = new Socket(), application = null, bridge = null; SSLSocket tls = null; Thread writer = null, producer = null;
        boolean success = false; String phase = "config";
        try {
            DataInputStream input = new DataInputStream(System.in);
            check(input.readInt() == 1);
            int port = input.readInt(), buffer = input.readInt(), mode = input.readInt(), seam = input.readInt();
            check(port > 0 && port <= 65535 && (buffer == 1024 || buffer == 65536) && (mode == 0 || mode == 1) && (seam == 0 || seam == 1));
            String name = new String(blob(input, 128), StandardCharsets.US_ASCII);
            byte[] gatewayDer = blob(input, 4096), leafDer = blob(input, 4096), keyDer = blob(input, 4096);
            String token = new String(blob(input, 64), StandardCharsets.US_ASCII);
            check(name.equals("android-node-research.invalid") && token.matches("[A-Za-z0-9_-]{43}"));
            phase = "credential";
            CertificateFactory certificates = CertificateFactory.getInstance("X.509");
            X509Certificate gateway = (X509Certificate) certificates.generateCertificate(new ByteArrayInputStream(gatewayDer));
            X509Certificate leaf = (X509Certificate) certificates.generateCertificate(new ByteArrayInputStream(leafDer));
            gateway.checkValidity(); leaf.checkValidity();
            PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyDer));
            Arrays.fill(keyDer, (byte) 0);
            KeyStore trust = KeyStore.getInstance("PKCS12"); trust.load(null, null); trust.setCertificateEntry("gateway", gateway);
            TrustManagerFactory tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); tm.init(trust);
            char[] password = new char[0];
            KeyStore keys = KeyStore.getInstance("PKCS12"); keys.load(null, null);
            keys.setKeyEntry("client", key, password, new java.security.cert.Certificate[] { leaf });
            KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(keys, password);
            SSLContext context = SSLContext.getInstance("TLS"); context.init(km.getKeyManagers(), tm.getTrustManagers(), RANDOM);
            phase = "connect";
            raw.setSendBufferSize(buffer); raw.setReceiveBufferSize(buffer); raw.setTcpNoDelay(true); raw.setSoLinger(false, 0);
            raw.connect(new InetSocketAddress("127.0.0.1", port), 5000); raw.setSoTimeout(5000);
            tls = (SSLSocket) context.getSocketFactory().createSocket(raw, name, port, true);
            tls.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
            SSLParameters parameters = tls.getSSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS");
            parameters.setServerNames(Collections.singletonList(new SNIHostName(name))); tls.setSSLParameters(parameters);
            phase = "handshake"; tls.startHandshake(); gateway.checkValidity();
            check(MessageDigest.isEqual(tls.getSession().getPeerCertificates()[0].getEncoded(), gatewayDer));
            phase = "upgrade";
            byte[] nonce = new byte[16]; RANDOM.nextBytes(nonce);
            String upgradeKey = Base64.getEncoder().encodeToString(nonce);
            OutputStream output = tls.getOutputStream(); InputStream network = tls.getInputStream();
            String request = "GET /companion/v1/streams HTTP/1.1\r\nHost: " + name + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + upgradeKey + "\r\nX-FreeKit-Session: " + token + "\r\n\r\n";
            output.write(request.getBytes(StandardCharsets.US_ASCII)); output.flush();
            String response = header(network);
            String accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest(
                (upgradeKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));
            check(response.startsWith("HTTP/1.1 101 ") && response.contains("Sec-WebSocket-Accept: " + accept + "\r\n"));
            phase = "ready";
            frame(output, 1, "{\"protocolVersion\":1,\"type\":\"open\",\"streamId\":\"pressure\"}".getBytes(StandardCharsets.UTF_8), mode == 1);
            ready(network); tls.setSoTimeout(0);
            phase = "local";
            if (seam == 1) {
                application = new Socket(); application.setSendBufferSize(1024); application.setReceiveBufferSize(1024); application.setTcpNoDelay(true);
                try (ServerSocket listener = new ServerSocket()) {
                    listener.setReuseAddress(false); listener.bind(new InetSocketAddress("127.0.0.1", 0), 1); listener.setSoTimeout(5000);
                    application.connect(listener.getLocalSocketAddress(), 5000);
                    bridge = listener.accept(); bridge.setSendBufferSize(1024); bridge.setReceiveBufferSize(1024); bridge.setTcpNoDelay(true);
                    check(bridge.getRemoteSocketAddress().equals(application.getLocalSocketAddress()) &&
                        bridge.getLocalSocketAddress().equals(application.getRemoteSocketAddress()));
                }
            }
            phase = "stream"; final boolean combined = mode == 1;
            final Socket accepted = bridge, producing = application;
            if (producing != null) producer = new Thread(() -> {
                try { produce(producing.getOutputStream()); producing.shutdownOutput(); }
                catch (Exception failure) { producerFailed.set(true); }
            }, "pressure-local-producer");
            writer = new Thread(() -> {
                try {
                    if (accepted != null) {
                        byte[] chunk = new byte[4096]; int count;
                        while ((count = accepted.getInputStream().read(chunk)) != -1) binary(output, Arrays.copyOf(chunk, count), combined);
                    } else {
                        binary(output, uploadHeader(), combined);
                        for (int offset = 0; offset < BURST; offset += 4096) {
                            byte[] chunk = new byte[Math.min(4096, BURST - offset)];
                            for (int i = 0; i < chunk.length; i++) chunk[i] = (byte) ((offset + i) % 251);
                            binary(output, chunk, combined);
                        }
                    }
                } catch (Exception failure) { failed.set(true); }
            }, "pressure-tls-writer");
            System.out.println("READY " + raw.getSendBufferSize() + " " + raw.getReceiveBufferSize() + " " +
                (application == null ? "0 0 0 0" : application.getSendBufferSize() + " " + application.getReceiveBufferSize() + " " + bridge.getSendBufferSize() + " " + bridge.getReceiveBufferSize())); System.out.flush();
            writer.start(); if (producer != null) producer.start();
            while (true) {
                int command = input.read();
                if (command == 2 || command < 0) break;
                check(command == 1);
                System.out.println("STATE " + counters());
                System.out.flush();
            }
            phase = "stop"; raw.close();
            if (application != null) application.close(); if (bridge != null) bridge.close();
            writer.join(5000); check(!writer.isAlive());
            if (producer != null) { producer.join(5000); check(!producer.isAlive()); }
            tls.close();
            System.out.println("STOPPED " + counters()); System.out.flush();
            success = true;
        } catch (Exception failure) { System.out.println("ERROR " + phase); System.out.flush(); }
        finally {
            try { raw.close(); } catch (IOException ignored) { }
            if (application != null) try { application.close(); } catch (IOException ignored) { success = false; }
            if (bridge != null) try { bridge.close(); } catch (IOException ignored) { success = false; }
            if (writer != null) {
                try { writer.join(5000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                if (writer.isAlive()) success = false;
            }
            if (producer != null) {
                try { producer.join(5000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                if (producer.isAlive()) success = false;
            }
            if (tls != null) try { tls.close(); } catch (IOException ignored) { success = false; }
        }
        if (!success) System.exit(1);
    }
}
