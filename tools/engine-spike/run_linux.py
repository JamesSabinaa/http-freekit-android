#!/usr/bin/env python3
"""Exercise the pinned native engine with synthetic packet fixtures; no TUN privileges.

The packet driver below is a bounded test fixture, not an application TCP stack.
All actual IP-to-stream reconstruction is performed by Hev/lwIP. The test adapter
and proxy listen only on loopback, and never dial the fixture destinations.
"""
import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ENGINE_COMMIT = "c0dfc4b07baa5e48022f5f88ac90488601f05674"
SUBMODULES = {
    "src/core": "ef82008f7e2058e56d76a79543a585bba4b7feef",
    "third-part/hev-task-system": "4039d2fdbb3577af380fa0096b90d0ad99969dfa",
    "third-part/lwip": "e6d5fc6cdc7c2ab379ffffd13dfdc99fb826a86c",
    "third-part/yaml": "94441ec8777eb319936735a58b376963d09c73d4",
}
BODY = bytes(i % 251 for i in range(16384 + 37))
REPLY = bytes((i * 7) % 253 for i in range(32768 + 19))


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        part = stream.recv(count - len(data))
        check(part, "Unexpected stream EOF")
        data.extend(part)
    return bytes(data)


def headers(stream):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        check(len(data) < 16384, "Oversized fixture headers")
        data.extend(exact(stream, 1))
    return bytes(data)


def listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(15)
    return server


def pipe(source, destination):
    while True:
        part = source.recv(2048)
        if not part:
            destination.shutdown(socket.SHUT_WR)
            return
        destination.sendall(part)


def proxy_fixture(server, expectations, gates=None):
    for index, (mode, target) in enumerate(expectations):
        connection, _ = server.accept()
        with connection:
            connection.settimeout(15)
            head = headers(connection)
            if mode == "http":
                check(head.startswith(f"POST http://{target}/fixture HTTP/1.1\r\n".encode()), "Wrong absolute-form HTTP authority")
                check(b"Host: fixture.invalid\r\n" in head, "Logical Host header was lost")
                # The sender withholds the body until this response arrives.
                # This fails if the adapter or engine buffers the entire request.
                connection.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            else:
                check(head == f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n\r\n".encode(), "Wrong CONNECT authority")
                connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            prefix = exact(connection, 4096)
            if gates is not None:
                gates[index][0].set()
            check(prefix + exact(connection, len(BODY) - 4096) == BODY, "Upload bytes changed")
            # Reply only after request write EOF. A full-close-on-EOF relay
            # cannot pass this exchange by sending the reply prematurely.
            check(connection.recv(1) == b"", "Client write EOF was not forwarded")
            if mode == "http":
                connection.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(REPLY)}\r\nConnection: close\r\n\r\n".encode())
            connection.sendall(REPLY[:4096])
            if gates is not None:
                check(gates[index][1].wait(15), "Download prefix was buffered until the full response")
            for offset in range(4096, len(REPLY), 997):
                connection.sendall(REPLY[offset:offset + 997])
            connection.shutdown(socket.SHUT_WR)


def socks_fixture(server, proxy_port, expectations):
    for mode, expected_target in expectations:
        client, _ = server.accept()
        with client:
            client.settimeout(15)
            version, methods = exact(client, 2)
            check(version == 5 and 0 in exact(client, methods), "Invalid SOCKS authentication negotiation")
            client.sendall(b"\x05\x00")
            version, command, reserved, address_type = exact(client, 4)
            check((version, command, reserved) == (5, 1, 0), "Expected SOCKS CONNECT")
            if address_type == 1:
                address = str(ipaddress.ip_address(exact(client, 4)))
                target = address
            else:
                check(address_type == 4, "Expected an original destination IP")
                address = str(ipaddress.ip_address(exact(client, 16)))
                target = f"[{address}]"
            port = struct.unpack("!H", exact(client, 2))[0]
            check(target == expected_target and port == (80 if mode == "http" else 443), "Engine lost the original destination")
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=15) as proxy:
                client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                if mode == "http":
                    head = headers(client)
                    check(head.startswith(b"POST /fixture HTTP/1.1\r\n"), "Unexpected origin-form fixture")
                    proxy.sendall(head.replace(b"POST /fixture ", f"POST http://{target}/fixture ".encode(), 1))
                else:
                    proxy.sendall(f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n\r\n".encode())
                    check(headers(proxy).startswith(b"HTTP/1.1 200 "), "Proxy refused CONNECT")
                # Test-only stream adapter. It never buffers an entire request.
                with ThreadPoolExecutor(max_workers=2) as relays:
                    first = relays.submit(pipe, client, proxy)
                    second = relays.submit(pipe, proxy, client)
                    first.result(timeout=15)
                    second.result(timeout=15)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


class PacketFixture:
    """One in-order fixture flow; deliberately lacks a production retransmission stack."""
    def __init__(self, channel, version, port, source_port):
        self.channel, self.version, self.port, self.source_port = channel, version, port, source_port
        self.source = ipaddress.ip_address("10.0.0.2" if version == 4 else "fd00::2").packed
        self.destination = ipaddress.ip_address("198.51.100.10" if version == 4 else "2001:db8::10").packed
        self.next_client = 100000 + source_port
        self.next_server = 0
        self.pending = bytearray()
        self.peer_closed = False
        self._send(2)
        self.next_client += 1
        while True:
            sequence, acknowledgement, flags, data = self._packet()
            if flags & 2:
                check(flags & 16 and acknowledgement == self.next_client, "Invalid fixture SYN acknowledgement")
                check(not data, "Unexpected data in SYN")
                self.next_server = (sequence + 1) & 0xFFFFFFFF
                self._send(16)
                break

    def _send(self, flags, payload=b""):
        tcp = struct.pack("!HHIIBBHHH", self.source_port, self.port, self.next_client,
                          self.next_server, 5 << 4, flags, 65535, 0, 0) + payload
        if self.version == 4:
            pseudo = self.source + self.destination + struct.pack("!BBH", 0, 6, len(tcp))
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, self.source, self.destination)
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        else:
            pseudo = self.source + self.destination + struct.pack("!I3xB", len(tcp), 6)
            ip = struct.pack("!IHBB16s16s", 6 << 28, len(tcp), 6, 64, self.source, self.destination)
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
        self.channel.send(ip + tcp)

    def _packet(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            packet = self.channel.recv(65535)
            version = packet[0] >> 4
            offset = (packet[0] & 15) * 4 if version == 4 else 40
            if version != self.version or len(packet) < offset + 20:
                continue
            if version == 4:
                if packet[9] != 6:
                    continue
                check(checksum(packet[:offset]) == 0, "Engine emitted an invalid IPv4 checksum")
                check(struct.unpack("!H", packet[2:4])[0] == len(packet), "Engine emitted an invalid IPv4 length")
                return_source, return_destination = packet[12:16], packet[16:20]
                pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(packet) - offset)
            else:
                if packet[6] != 6:
                    continue
                check(struct.unpack("!H", packet[4:6])[0] == len(packet) - offset, "Engine emitted an invalid IPv6 length")
                return_source, return_destination = packet[8:24], packet[24:40]
                pseudo = packet[8:40] + struct.pack("!I3xB", len(packet) - offset, 6)
            check(checksum(pseudo + packet[offset:]) == 0, "Engine emitted an invalid TCP checksum")
            source_port, destination_port, sequence, acknowledgement = struct.unpack("!HHII", packet[offset:offset + 12])
            if (source_port, destination_port) != (self.port, self.source_port):
                continue
            check((return_source, return_destination) == (self.destination, self.source),
                  "Engine emitted unexpected fixture addresses")
            flags = packet[offset + 13]
            check(not flags & 4, "Engine reset a fixture stream")
            size = (packet[offset + 12] >> 4) * 4
            return sequence, acknowledgement, flags, packet[offset + size:]
        raise TimeoutError("No packet for fixture flow")

    def _receive(self):
        sequence, acknowledgement, flags, data = self._packet()
        if data or flags & 1:
            if sequence == self.next_server:
                self.pending.extend(data)
                self.next_server = (self.next_server + len(data) + (1 if flags & 1 else 0)) & 0xFFFFFFFF
                self.peer_closed = bool(flags & 1)
            self._send(16)
        return acknowledgement

    def send(self, data):
        for offset in range(0, len(data), 1200):
            part = data[offset:offset + 1200]
            self._send(24, part)
            self.next_client += len(part)
            while self._receive() < self.next_client:
                pass

    def read_headers(self):
        while b"\r\n\r\n" not in self.pending:
            check(len(self.pending) < 16384 and not self.peer_closed, "Invalid response headers")
            self._receive()
        end = self.pending.index(b"\r\n\r\n") + 4
        result = bytes(self.pending[:end])
        del self.pending[:end]
        return result

    def read_exact(self, count):
        while len(self.pending) < count:
            check(not self.peer_closed, "Early fixture EOF")
            self._receive()
        result = bytes(self.pending[:count])
        del self.pending[:count]
        return result

    def close_write(self):
        self._send(17)
        self.next_client += 1
        while self._receive() < self.next_client:
            pass


def worker(engine_root):
    proxy, socks = listener(), listener()
    expectations = [(mode, target) for target in ("198.51.100.10", "[2001:db8::10]") for mode in ("http", "connect")]
    native_side, test_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    test_side.settimeout(15)
    library = ctypes.CDLL(str(engine_root / "bin/libhev-socks5-tunnel.so"))
    run = library.hev_socks5_tunnel_main_from_str
    run.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_int]
    run.restype = ctypes.c_int
    library.hev_socks5_tunnel_quit.argtypes = []
    library.hev_socks5_tunnel_quit.restype = None
    configuration = f"""tunnel:
  mtu: 1500
  ipv4: 10.0.0.1
  ipv6: 'fd00::1'
socks5:
  address: 127.0.0.1
  port: {socks.getsockname()[1]}
  udp: 'udp'
misc:
  log-file: null
  log-level: error
  max-session-count: 8
  connect-timeout: 5000
  tcp-read-write-timeout: 15000
""".encode()
    native_result = []
    native = threading.Thread(target=lambda: native_result.append(run(configuration, len(configuration), native_side.fileno())), daemon=True)
    gates = [(threading.Event(), threading.Event()) for _ in expectations]
    with ThreadPoolExecutor(max_workers=2) as peers:
        proxy_result = peers.submit(proxy_fixture, proxy, expectations, gates)
        socks_result = peers.submit(socks_fixture, socks, proxy.getsockname()[1], expectations)
        native.start()
        try:
            for index, (mode, target) in enumerate(expectations):
                flow = PacketFixture(test_side, 4 if index < 2 else 6, 80 if mode == "http" else 443, 41000 + index)
                if mode == "http":
                    flow.send(f"POST /fixture HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: {len(BODY)}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n".encode())
                    check(flow.read_headers() == b"HTTP/1.1 100 Continue\r\n\r\n", "Body was buffered before 100 Continue")
                flow.send(BODY[:4096])
                check(gates[index][0].wait(15), "Upload prefix was buffered until the full request")
                flow.send(BODY[4096:])
                flow.close_write()
                if mode == "http":
                    check(flow.read_headers().startswith(b"HTTP/1.1 200 OK\r\n"), "Wrong HTTP response")
                prefix = flow.read_exact(4096)
                gates[index][1].set()
                check(prefix + flow.read_exact(len(REPLY) - 4096) == REPLY, "Download bytes changed")
                print(json.dumps({"ipVersion": flow.version, "mode": mode, "uploadBytes": len(BODY), "downloadBytes": len(REPLY), "halfClose": True, "gatedStreaming": True, "replySha256": hashlib.sha256(REPLY).hexdigest()}), flush=True)
            proxy_result.result(timeout=15)
            socks_result.result(timeout=15)
        finally:
            library.hev_socks5_tunnel_quit()
            native.join(5)
            test_side.close()
            native_side.close()
            proxy.close()
            socks.close()
            check(not native.is_alive(), "Native engine failed to stop")
    check(native_result == [0], "Native engine exited unsuccessfully")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-root", type=Path, required=True)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    check(sys.platform.startswith("linux"), "The native packet spike requires Linux")
    root = arguments.engine_root.resolve()
    if arguments.worker:
        worker(root)
        return
    for relative, expected in {".": ENGINE_COMMIT, **SUBMODULES}.items():
        checkout = root / relative
        actual = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        check(actual == expected, f"Unexpected source revision in {relative}")
        dirty = subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"], text=True)
        check(not dirty, f"Source checkout is dirty: {relative}")
    subprocess.run(["make", "shared", "-j2"], cwd=root, check=True, timeout=180)
    environment = dict(os.environ)
    directories = [root / "third-part" / name / "bin" for name in ("yaml", "lwip", "hev-task-system")]
    environment["LD_LIBRARY_PATH"] = os.pathsep.join(map(str, directories))
    subprocess.run([sys.executable, str(Path(__file__).resolve()), "--engine-root", str(root), "--worker"], env=environment, check=True, timeout=120)


if __name__ == "__main__":
    main()
