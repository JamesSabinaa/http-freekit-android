"""Bounded test-only framing for synthetic packets, independent of companion wire."""
import json
import struct
from run_linux import check, exact

HELLO, PACKET, STOP, STOPPED = 1, 2, 3, 4
MAX_PACKET, MAX_CONTROL = 65535, 4096


def validate_frame(kind, length):
    check(kind in (HELLO, PACKET, STOP, STOPPED), "Unknown research bridge frame")
    check(0 <= length <= (MAX_PACKET if kind == PACKET else MAX_CONTROL), "Oversized research bridge frame")
    check(kind != STOP or length == 0, "STOP must have no body")
    check(kind != PACKET or length > 0, "A packet cannot be empty")


def write_frame(stream, kind, payload=b""):
    validate_frame(kind, len(payload))
    stream.sendall(struct.pack("!BI", kind, len(payload)) + payload)


def read_frame(stream):
    kind, length = struct.unpack("!BI", exact(stream, 5))
    validate_frame(kind, length)
    return kind, exact(stream, length)


def read_control(stream, kind):
    actual, payload = read_frame(stream)
    check(actual == kind, "Unexpected research bridge control frame")
    result = json.loads(payload.decode("utf-8"))
    check(isinstance(result, dict), "Control frame must be a JSON object")
    return result


class PacketChannel:
    """Socket-shaped datagram channel consumed by the existing PacketFixture."""
    def __init__(self, stream):
        self.stream = stream
        self.sent = self.received = 0

    def send(self, packet):
        write_frame(self.stream, PACKET, packet)
        self.sent += 1
        return len(packet)

    def recv(self, limit):
        kind, packet = read_frame(self.stream)
        check(kind == PACKET, "Expected a native IP packet")
        check(len(packet) <= limit, "Packet receive buffer would truncate a datagram")
        self.received += 1
        return packet

    def stop(self):
        write_frame(self.stream, STOP)
        # ACK/FIN packets already in flight may precede the stop response.
        for _ in range(2048):
            kind, payload = read_frame(self.stream)
            if kind == PACKET:
                self.received += 1
                continue
            check(kind == STOPPED, "Expected JNI stop evidence")
            result = json.loads(payload.decode("utf-8"))
            check(isinstance(result, dict), "Invalid JNI stop result")
            for field in ("stopped", "packetPumpStopped", "descriptorsClosed"):
                check(result.get(field) is True, f"Missing JNI shutdown evidence: {field}")
            check(result.get("running") is False, "Native engine is still running")
            stats = result.get("statisticsBeforeStop")
            check(isinstance(stats, list) and len(stats) == 4 and all(type(value) is int and value > 0 for value in stats), "Missing native packet/byte counters")
            return result
        raise AssertionError("Native packet queue did not settle before stop")
