"""Host checks for Android probe boundaries, not Android runtime evidence."""
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import build_android_probe as build
from android_bridge import HELLO, PACKET, STOP, STOPPED, PacketChannel, read_control, read_frame, write_frame
from run_android import await_bridge, capture_command, instrumentation_phases, validate_instrumentation
from verify_probe_apk import verify_manifest
from record_native_host import classify_log_tail


def elf(api=26, alignment=16384, machine=62):
    note = struct.pack("<III", 8, 4, 1) + b"Android\0" + struct.pack("<I", api)
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01" + bytes(10), 3, machine, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 176 + len(note), 176 + len(note), alignment)
    notes = struct.pack("<IIQQQQQQ", 4, 4, 176, 0, 0, len(note), len(note), 4)
    return header + load + notes + note


class AndroidProbeTest(unittest.TestCase):
    def test_host_emulator_categories_never_retain_arbitrary_log_content(self):
        with tempfile.TemporaryDirectory(prefix="freekit-host-log-") as directory:
            path = Path(directory) / "emulator.log"
            path.write_text("private arbitrary diagnostic string\nqemu: Segmentation fault (core dumped)\n")
            result = classify_log_tail(path)
            self.assertEqual(result["fatalLogMarkers"], ["segmentation_fault"])
            self.assertNotIn("private", json.dumps(result))
            self.assertNotIn("core dumped", json.dumps(result))

    def test_host_emulator_classifier_is_bounded_and_handles_absent_logs(self):
        with tempfile.TemporaryDirectory(prefix="freekit-host-log-") as directory:
            path = Path(directory) / "emulator.log"
            self.assertFalse(classify_log_tail(path)["logPresent"])
            path.write_bytes(b"FATAL: old marker\n" + b"x" * (256 * 1024))
            result = classify_log_tail(path)
            self.assertEqual(result["inspectedTailBytes"], 256 * 1024)
            self.assertEqual(result["fatalLogMarkers"], [])

    def test_android_phase_report_accepts_only_fixed_nonsecret_markers(self):
        output = ("INSTRUMENTATION_STATUS: native_probe_phase=jni-load-start\n"
                  "INSTRUMENTATION_STATUS: native_probe_phase=https://untrusted.invalid/secret\n"
                  "INSTRUMENTATION_STATUS: native_probe_phase=unknown-private-label\n"
                  "INSTRUMENTATION_STATUS: native_probe_phase=bridge-connected\n")
        self.assertEqual(instrumentation_phases(output), ["jni-load-start", "bridge-connected"])

    def test_exited_instrumentation_fails_before_blocking_in_accept(self):
        class Server:
            def gettimeout(self): return 60
            def settimeout(self, value): self.timeout = value
            def accept(self): raise AssertionError("Should not enter accept")
        class Process:
            def poll(self): return 1
        server = Server()
        with self.assertRaisesRegex(AssertionError, "Instrumentation exited"):
            await_bridge(server, Process())
        self.assertEqual(server.timeout, 60)

    def test_live_bridge_accept_preserves_connection_and_timeout(self):
        class Process:
            def poll(self): return None
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(60)
            with socket.create_connection(server.getsockname(), timeout=2) as client:
                connection, _ = await_bridge(server, Process())
                with connection:
                    client.sendall(b"bridge")
                    self.assertEqual(connection.recv(6), b"bridge")
                self.assertEqual(server.gettimeout(), 60)

    def test_cleanup_reports_actual_adb_error_and_bounds_its_output(self):
        completed = subprocess.CompletedProcess(["adb"], 1, stdout="status\0\n", stderr="adb: listener not found\n" + "x" * 5000)
        with patch("run_android.subprocess.run", return_value=completed):
            result = capture_command("reverse-remove-1234", ["adb", "reverse"])
        self.assertEqual(result["operation"], "reverse-remove-1234")
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(result["stdout"], "status")
        self.assertTrue(result["stderr"].startswith("adb: listener not found"))
        self.assertLessEqual(len(result["stderr"]), 4096)

    def test_fragmented_frames_preserve_one_complete_datagram(self):
        sender, receiver = socket.socketpair()
        with sender, receiver:
            receiver.settimeout(2)
            payload = b"\x00\xffpacket" * 37
            wire = struct.pack("!BI", PACKET, len(payload)) + payload + struct.pack("!BI", PACKET, 4) + b"next"
            worker = threading.Thread(target=lambda: [sender.sendall(wire[offset:offset + 3]) for offset in range(0, len(wire), 3)])
            worker.start()
            self.assertEqual(read_frame(receiver), (PACKET, payload))
            self.assertEqual(read_frame(receiver), (PACKET, b"next"))
            worker.join(2)
            self.assertFalse(worker.is_alive())

    def test_frames_reject_invalid_headers_before_reading_a_body(self):
        for kind, length in [(99, 1), (PACKET, 0), (PACKET, 65536), (HELLO, 4097), (STOP, 1)]:
            with self.subTest(kind=kind, length=length):
                sender, receiver = socket.socketpair()
                with sender, receiver:
                    receiver.settimeout(1)
                    sender.sendall(struct.pack("!BI", kind, length))
                    with self.assertRaises(AssertionError):
                        read_frame(receiver)

    def test_packet_channel_preserves_datagrams_and_validates_native_stop(self):
        sender, receiver = socket.socketpair()
        with sender, receiver:
            sender.settimeout(2)
            receiver.settimeout(2)
            result = {"stopped": True, "running": False, "packetPumpStopped": True,
                      "descriptorsClosed": True, "statisticsBeforeStop": [10, 1000, 12, 2000]}
            failures = []
            def peer():
                try:
                    self.assertEqual(read_frame(receiver), (PACKET, b"incoming packet"))
                    write_frame(receiver, PACKET, b"native packet")
                    self.assertEqual(read_frame(receiver), (STOP, b""))
                    write_frame(receiver, PACKET, b"final ACK")
                    write_frame(receiver, STOPPED, json.dumps(result).encode())
                except BaseException as error:
                    failures.append(error)
            worker = threading.Thread(target=peer)
            worker.start()
            channel = PacketChannel(sender)
            self.assertEqual(channel.send(b"incoming packet"), 15)
            self.assertEqual(channel.recv(65535), b"native packet")
            self.assertEqual(channel.stop(), result)
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual((channel.sent, channel.received), (1, 2))

    def test_control_json_and_truncated_frames_fail(self):
        for payload in (b"[]", b"{", b"\xff"):
            sender, receiver = socket.socketpair()
            with sender, receiver:
                write_frame(sender, HELLO, payload)
                with self.assertRaises((AssertionError, ValueError, UnicodeError)):
                    read_control(receiver, HELLO)
        sender, receiver = socket.socketpair()
        with sender, receiver:
            sender.sendall(struct.pack("!BI", PACKET, 10) + b"short")
            sender.shutdown(socket.SHUT_WR)
            with self.assertRaises(AssertionError):
                read_frame(receiver)

    def test_stop_requires_all_shutdown_fields_and_real_native_counters(self):
        valid = {"stopped": True, "running": False, "packetPumpStopped": True,
                 "descriptorsClosed": True, "statisticsBeforeStop": [1, 2, 3, 4]}
        for change in ({"running": True}, {"stopped": False}, {"packetPumpStopped": False},
                       {"descriptorsClosed": False}, {"statisticsBeforeStop": [True, 2, 3, 4]},
                       {"statisticsBeforeStop": [0, 2, 3, 4]}):
            sender, receiver = socket.socketpair()
            with sender, receiver:
                write_frame(receiver, STOPPED, json.dumps({**valid, **change}).encode())
                with self.assertRaises(AssertionError):
                    PacketChannel(sender).stop()

    def test_instrumentation_success_requires_test_execution_and_final_result(self):
        success = "Time: 1.2\nOK (1 test)\n\nINSTRUMENTATION_CODE: -1\n"
        validate_instrumentation(success)
        for output in ("INSTRUMENTATION_CODE: -1", "OK (0 tests)\nINSTRUMENTATION_CODE: -1", "OK (1 test)",
                       success + "FAILURES!!!", success.replace("CODE: -1", "CODE: 0")):
            with self.assertRaises(AssertionError):
                validate_instrumentation(output)

    def test_elf_gate_rejects_wrong_api_machine_or_page_alignment(self):
        with tempfile.TemporaryDirectory(prefix="freekit-elf-") as directory:
            library = Path(directory) / "probe.so"
            library.write_bytes(elf())
            self.assertEqual(build.inspect_elf(library, 62), {"androidApi": 26, "loadAlignments": [16384], "machine": 62})
            for data in (elf(api=29), elf(alignment=4096), elf(machine=183), b"not an ELF"):
                library.write_bytes(data)
                with self.assertRaises(AssertionError):
                    build.inspect_elf(library, 62)

    def test_research_manifest_rejects_extra_permissions_and_components(self):
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.httpfreekit.engineprobe.test">
          <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="37"/>
          <uses-permission android:name="android.permission.INTERNET"/>
          <instrumentation android:targetPackage="com.httpfreekit.engineprobe.test"/>
          <application android:extractNativeLibs="false"/>
        </manifest>'''
        verify_manifest(manifest)
        for invalid in (
            manifest.replace('<application ', '<uses-permission android:name="android.permission.REORDER_TASKS"/><application '),
            manifest.replace('<application android:extractNativeLibs="false"/>', '<application android:extractNativeLibs="false"><service android:name="UnexpectedService"/></application>'),
            manifest.replace('android:minSdkVersion="26"', 'android:minSdkVersion="29"'),
        ):
            with self.assertRaises(AssertionError):
                verify_manifest(invalid)

    def test_source_cache_rejects_dirty_or_mismatched_existing_source(self):
        with tempfile.TemporaryDirectory(prefix="freekit-source-") as directory:
            root = Path(directory)
            for relative in (".", "src/core", "third-part/lwip", "third-part/yaml", "third-part/hev-task-system"):
                (root / relative).mkdir(parents=True, exist_ok=True)
                (root / relative / "LICENSE").write_text("Controlled test notice\n")
            (root / ".gitignore").write_text("ignored.c\n")
            def git(*parts):
                return subprocess.check_output(["git", "-C", str(root), *parts], text=True).strip()
            git("init")
            git("add", ".")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "Fixture")
            commit = git("rev-parse", "HEAD")
            with patch.object(build, "ENGINE_COMMIT", commit), patch.object(build, "SUBMODULES", {}):
                build.verify_source(root)
                (root / "src/ignored.c").write_text("must reject ignored source injection")
                with self.assertRaisesRegex(AssertionError, "Ignored files"):
                    build.prepare_source(root, fetch=True)
                (root / "src/ignored.c").unlink()
                (root / "untracked").write_text("must reject")
                with self.assertRaisesRegex(AssertionError, "Dirty source"):
                    build.prepare_source(root, fetch=True)
            with patch.object(build, "ENGINE_COMMIT", "0" * 40), patch.object(build, "SUBMODULES", {}):
                with self.assertRaisesRegex(AssertionError, "Unexpected source revision"):
                    build.prepare_source(root, fetch=True)


if __name__ == "__main__":
    unittest.main()
