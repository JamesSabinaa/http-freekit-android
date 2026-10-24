"""Host checks for the fixture machinery; these do not execute the native engine."""
import ipaddress
import socket
import struct
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from run_linux import BODY, REPLY, PacketFixture, checksum, exact, headers, listener, proxy_fixture, socks_fixture


class FixtureDriverTest(unittest.TestCase):
    def test_rfc1071_checksum_vector(self):
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)

    def test_fixture_packets_have_valid_ip_and_tcp_checksums(self):
        for version in (4, 6):
            sent = []
            class Capture:
                def send(self, packet):
                    sent.append(packet)
            flow = PacketFixture.__new__(PacketFixture)
            flow.channel, flow.version, flow.port, flow.source_port = Capture(), version, 80, 41000
            flow.next_client, flow.next_server = 1000, 2000
            flow.source = ipaddress.ip_address("10.0.0.2" if version == 4 else "fd00::2").packed
            flow.destination = ipaddress.ip_address("198.51.100.10" if version == 4 else "2001:db8::10").packed
            flow._send(24, b"fixture")
            packet = sent[0]
            offset = 20 if version == 4 else 40
            tcp = packet[offset:]
            if version == 4:
                self.assertEqual(checksum(packet[:20]), 0)
                self.assertEqual(struct.unpack("!H", packet[2:4])[0], len(packet))
                pseudo = flow.source + flow.destination + struct.pack("!BBH", 0, 6, len(tcp))
            else:
                self.assertEqual(struct.unpack("!H", packet[4:6])[0], len(tcp))
                pseudo = flow.source + flow.destination + struct.pack("!I3xB", len(tcp), 6)
            self.assertEqual(checksum(pseudo + tcp), 0)
            self.assertEqual(struct.unpack("!HHII", tcp[:12]), (41000, 80, 1000, 2000))

    def test_controlled_socks_adapter_streams_http_and_connect_for_both_ip_versions(self):
        expectations = [(mode, address) for address in ("198.51.100.10", "[2001:db8::10]") for mode in ("http", "connect")]
        gates = [(threading.Event(), threading.Event()) for _ in expectations]
        with listener() as proxy, listener() as socks, ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(proxy_fixture, proxy, expectations, gates)
            second = workers.submit(socks_fixture, socks, proxy.getsockname()[1], expectations)
            for index, (mode, address) in enumerate(expectations):
                with socket.create_connection(socks.getsockname(), timeout=5) as client:
                    client.sendall(b"\x05\x01\x00")
                    self.assertEqual(exact(client, 2), b"\x05\x00")
                    target = ipaddress.ip_address(address.strip("[]"))
                    port = 80 if mode == "http" else 443
                    client.sendall(bytes([5, 1, 0, 1 if target.version == 4 else 4]) + target.packed + struct.pack("!H", port))
                    self.assertEqual(exact(client, 10), b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                    if mode == "http":
                        client.sendall(f"POST /fixture HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: {len(BODY)}\r\n\r\n".encode())
                        self.assertEqual(headers(client), b"HTTP/1.1 100 Continue\r\n\r\n")
                    client.sendall(BODY[:4096])
                    self.assertTrue(gates[index][0].wait(5))
                    for offset in range(4096, len(BODY), 991):
                        client.sendall(BODY[offset:offset + 991])
                    client.shutdown(socket.SHUT_WR)
                    if mode == "http":
                        self.assertTrue(headers(client).startswith(b"HTTP/1.1 200 OK\r\n"))
                    prefix = exact(client, 4096)
                    gates[index][1].set()
                    self.assertEqual(prefix + exact(client, len(REPLY) - 4096), REPLY)
                    self.assertEqual(client.recv(1), b"")
            first.result(timeout=10)
            second.result(timeout=10)

    def test_return_packets_preserve_original_addresses(self):
        for version in (4, 6):
            with self.subTest(version=version):
                flow, packet = self.return_fixture(version)
                self.assertEqual(flow._packet(), (2000, 1000, 24, b"return fixture"))

    def test_valid_checksums_cannot_hide_wrong_return_addresses(self):
        for version in (4, 6):
            for wrong in ("source", "destination"):
                with self.subTest(version=version, wrong=wrong):
                    flow, packet = self.return_fixture(version, wrong)
                    offset = 20 if version == 4 else 40
                    if version == 4:
                        self.assertEqual(checksum(packet[:offset]), 0)
                        pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(packet) - offset)
                    else:
                        pseudo = packet[8:40] + struct.pack("!I3xB", len(packet) - offset, 6)
                    self.assertEqual(checksum(pseudo + packet[offset:]), 0)
                    with self.assertRaisesRegex(AssertionError, "unexpected fixture addresses"):
                        flow._packet()

    @staticmethod
    def return_fixture(version, wrong=None):
        client = ipaddress.ip_address("10.0.0.2" if version == 4 else "fd00::2").packed
        target = ipaddress.ip_address("198.51.100.10" if version == 4 else "2001:db8::10").packed
        other = ipaddress.ip_address("203.0.113.5" if version == 4 else "2001:db8::11").packed
        packets = []
        class Capture:
            def send(self, packet):
                packets.append(packet)
        sender = PacketFixture.__new__(PacketFixture)
        sender.channel, sender.version = Capture(), version
        sender.port, sender.source_port = 41000, 80
        sender.next_client, sender.next_server = 2000, 1000
        sender.source = other if wrong == "source" else target
        sender.destination = other if wrong == "destination" else client
        sender._send(24, b"return fixture")
        packet = packets.pop()
        class Reply:
            def recv(self, _maximum):
                return packet
        receiver = PacketFixture.__new__(PacketFixture)
        receiver.channel, receiver.version = Reply(), version
        receiver.port, receiver.source_port = 80, 41000
        receiver.source, receiver.destination = client, target
        return receiver, packet


if __name__ == "__main__":
    unittest.main()
