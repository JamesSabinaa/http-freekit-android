"""Research-only half-close carrier for SOCKS bytes across an ADB reverse stream.

ADB CLOSE ends both directions. Keep that carrier open while typed END_WRITE
records independently convey the local TCP write EOF. This is not companion wire.
"""
import socket
import struct
import threading

DATA, END_WRITE, MAX_DATA = 1, 2, 16384


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise EOFError("Research carrier ended before END_WRITE")
        result.extend(part)
    return bytes(result)


class FramedStream:
    """One reader and one writer; at most one bounded incoming record is buffered."""
    def __init__(self, stream):
        self.stream = stream
        self.pending = bytearray()
        self.read_ended = False
        self.write_ended = False
        self.write_lock = threading.Lock()

    def settimeout(self, seconds):
        self.stream.settimeout(seconds)

    def recv(self, count):
        if count < 0:
            raise ValueError("Invalid research read size")
        if count == 0 or self.read_ended:
            return b""
        if not self.pending:
            kind, length = struct.unpack("!BI", exact(self.stream, 5))
            if kind == END_WRITE and length == 0:
                self.read_ended = True
                return b""
            if kind != DATA or not 1 <= length <= MAX_DATA:
                raise ValueError("Invalid research stream frame")
            self.pending.extend(exact(self.stream, length))
        result = bytes(self.pending[:count])
        del self.pending[:count]
        return result

    def sendall(self, data):
        with self.write_lock:
            if self.write_ended:
                raise BrokenPipeError("Research write direction has ended")
            for offset in range(0, len(data), MAX_DATA):
                part = data[offset:offset + MAX_DATA]
                self.stream.sendall(struct.pack("!BI", DATA, len(part)) + part)

    def shutdown(self, direction):
        if direction != socket.SHUT_WR:
            raise ValueError("Only research write EOF is supported")
        with self.write_lock:
            if not self.write_ended:
                self.stream.sendall(struct.pack("!BI", END_WRITE, 0))
                self.write_ended = True

    def close(self):
        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class FramedListener:
    """Present the existing SOCKS fixture with half-close-capable accepted streams."""
    def __init__(self, listener):
        self.listener = listener

    def accept(self):
        stream, address = self.listener.accept()
        return FramedStream(stream), address
