"""Real-stream checks for independent EOF without half-closing the ADB carrier."""
import socket
import struct
import threading
import unittest

from framed_stream import DATA, END_WRITE, MAX_DATA, FramedStream, FramedListener, exact


class FramedStreamTest(unittest.TestCase):
    def setUp(self):
        self.first, self.second = socket.socketpair()
        self.first.settimeout(2)
        self.second.settimeout(2)
        self.addCleanup(self.first.close)
        self.addCleanup(self.second.close)

    def test_reply_after_request_eof_keeps_carrier_and_reverse_direction_open(self):
        request = bytes(index % 251 for index in range(MAX_DATA + 37))
        reply = bytes(index % 253 for index in range(2 * MAX_DATA + 19))
        client, peer = FramedStream(self.first), FramedStream(self.second)
        failures = []

        def serve():
            try:
                received = bytearray()
                while part := peer.recv(997):
                    received.extend(part)
                self.assertEqual(received, request)
                # A raw carrier shutdown here would make this delayed reply impossible.
                peer.sendall(reply)
                peer.shutdown(socket.SHUT_WR)
            except BaseException as failure:
                failures.append(failure)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            received = bytearray()
            while part := client.recv(4096):
                received.extend(part)
            self.assertEqual(received, reply)
            self.assertTrue(client.read_ended and client.write_ended)
        finally:
            worker.join(3)
        self.assertFalse(worker.is_alive())
        if failures:
            raise failures[0]
        self.assertTrue(peer.read_ended and peer.write_ended)

    def test_incoming_end_write_does_not_end_outgoing_data(self):
        stream = FramedStream(self.first)
        self.second.sendall(struct.pack("!BI", END_WRITE, 0))
        self.assertEqual(stream.recv(10), b"")
        self.assertEqual(stream.recv(10), b"")
        stream.sendall(b"response")
        received = exact(self.second, 13)
        self.assertEqual(received, struct.pack("!BI", DATA, 8) + b"response")

    def test_fragmented_header_payload_and_bounded_reads(self):
        frame = struct.pack("!BI", DATA, 7) + b"fixture"
        sender = threading.Thread(target=lambda: [self.second.sendall(bytes([value])) for value in frame], daemon=True)
        sender.start()
        try:
            stream = FramedStream(self.first)
            self.assertEqual(stream.recv(2), b"fi")
            self.assertEqual(stream.recv(1000000), b"xture")
            self.assertEqual(stream.pending, b"")
        finally:
            sender.join(3)
        self.assertFalse(sender.is_alive())

    def test_invalid_frame_headers_reject_without_waiting_for_payload(self):
        for kind, length in ((DATA, 0), (DATA, MAX_DATA + 1), (END_WRITE, 1), (3, 0), (255, 0xFFFFFFFF)):
            with self.subTest(kind=kind, length=length):
                self.second.sendall(struct.pack("!BI", kind, length))
                with self.assertRaisesRegex(ValueError, "Invalid research stream frame"):
                    FramedStream(self.first).recv(1)

    def test_carrier_eof_before_end_write_is_an_error(self):
        self.second.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(EOFError, "before END_WRITE"):
            FramedStream(self.first).recv(1)

    def test_truncated_header_and_payload_cannot_be_successful_eof(self):
        for value in (b"\x01\x00", struct.pack("!BI", DATA, 7) + b"short"):
            with self.subTest(value=value):
                first, second = socket.socketpair()
                with first, second:
                    first.settimeout(2)
                    second.sendall(value)
                    second.shutdown(socket.SHUT_WR)
                    with self.assertRaises(EOFError):
                        FramedStream(first).recv(1)

    def test_local_eof_is_idempotent_and_later_writes_are_rejected(self):
        stream = FramedStream(self.first)
        stream.shutdown(socket.SHUT_WR)
        stream.shutdown(socket.SHUT_WR)
        stream.close()
        self.assertEqual(self.second.recv(100), struct.pack("!BI", END_WRITE, 0))
        self.assertEqual(self.second.recv(100), b"")
        with self.assertRaises(BrokenPipeError):
            stream.sendall(b"late")

    def test_receive_buffers_only_one_record_even_for_large_read_request(self):
        self.second.sendall(struct.pack("!BI", DATA, 2) + b"ab" + struct.pack("!BI", DATA, 2) + b"cd")
        stream = FramedStream(self.first)
        self.assertEqual(stream.recv(1000000), b"ab")
        self.assertEqual(stream.recv(1000000), b"cd")
        self.assertEqual(stream.recv(0), b"")
        with self.assertRaises(ValueError):
            stream.recv(-1)
        with self.assertRaises(ValueError):
            stream.shutdown(socket.SHUT_RDWR)

    def test_listener_wraps_only_the_accepted_socket(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(2)
            with socket.create_connection(server.getsockname(), timeout=2) as client:
                accepted, address = FramedListener(server).accept()
                with accepted:
                    self.assertIsInstance(accepted, FramedStream)
                    self.assertEqual(address[0], "127.0.0.1")
                    accepted.settimeout(1)
                    client.sendall(struct.pack("!BI", DATA, 2) + b"ok")
                    self.assertEqual(accepted.recv(2), b"ok")
                self.assertNotEqual(server.fileno(), -1)

    def test_close_on_eof_relay_preserves_delayed_reply_only_with_typed_eof(self):
        """Model ADB channel close on raw EOF; this is not an actual ADB run."""
        request = bytes(index % 251 for index in range(MAX_DATA + 37))
        reply = bytes(index % 253 for index in range(2 * MAX_DATA + 19))
        for framed in (False, True):
            with self.subTest(framed=framed):
                client_socket, relay_left = socket.socketpair()
                relay_right, peer_socket = socket.socketpair()
                sockets = (client_socket, relay_left, relay_right, peer_socket)
                for stream in sockets:
                    stream.settimeout(2)
                raw_eof, stopped = threading.Event(), threading.Event()
                request_ended, release_reply = threading.Event(), threading.Event()
                stop_lock = threading.Lock()
                relay_failures, peer_failures = [], []

                def close_carrier():
                    with stop_lock:
                        if stopped.is_set():
                            return
                        stopped.set()
                        for stream in (relay_left, relay_right):
                            try:
                                stream.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass

                def relay(source, destination):
                    try:
                        while True:
                            part = source.recv(997)
                            if not part:
                                raw_eof.set()
                                close_carrier()
                                return
                            destination.sendall(part)
                    except OSError as failure:
                        if not stopped.is_set():
                            relay_failures.append(failure)
                        close_carrier()

                client = FramedStream(client_socket) if framed else client_socket
                peer = FramedStream(peer_socket) if framed else peer_socket

                def serve():
                    try:
                        received = bytearray()
                        while part := peer.recv(1009):
                            received.extend(part)
                        self.assertEqual(received, request)
                        request_ended.set()
                        self.assertTrue(release_reply.wait(2))
                        peer.sendall(reply)
                        peer.shutdown(socket.SHUT_WR)
                    except BaseException as failure:
                        peer_failures.append(failure)

                workers = [threading.Thread(target=relay, args=(relay_left, relay_right), daemon=True),
                           threading.Thread(target=relay, args=(relay_right, relay_left), daemon=True),
                           threading.Thread(target=serve, daemon=True)]
                for worker in workers:
                    worker.start()
                try:
                    client.sendall(request)
                    client.shutdown(socket.SHUT_WR)
                    self.assertTrue(request_ended.wait(2), "Peer did not observe request write EOF")
                    # The reply is withheld until the complete request and its EOF arrive.
                    self.assertEqual(raw_eof.is_set(), not framed)
                    release_reply.set()
                    received = bytearray()
                    while part := client.recv(4096):
                        received.extend(part)
                    workers[-1].join(3)
                    self.assertFalse(workers[-1].is_alive())
                    if framed:
                        if peer_failures:
                            raise peer_failures[0]
                        self.assertEqual(received, reply)
                        self.assertTrue(client.read_ended and client.write_ended)
                        self.assertTrue(peer.read_ended and peer.write_ended)
                        self.assertFalse(raw_eof.is_set(), "Raw EOF preceded both typed END_WRITE records")
                    else:
                        self.assertNotEqual(received, reply, "The relay model must reject a raw-half-close control")
                    self.assertEqual(relay_failures, [])
                finally:
                    release_reply.set()
                    close_carrier()
                    for stream in sockets:
                        stream.close()
                    for worker in workers:
                        worker.join(3)
                self.assertFalse(any(worker.is_alive() for worker in workers))


if __name__ == "__main__":
    unittest.main()
