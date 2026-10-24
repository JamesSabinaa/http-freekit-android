#!/usr/bin/env python3
"""Drive the isolated Android JNI probe through owned ADB loopback mappings."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

from android_bridge import HELLO, PacketChannel, read_control
from run_linux import BODY, REPLY, ENGINE_COMMIT, PacketFixture, check, listener, proxy_fixture, socks_fixture

PACKAGE = "com.httpfreekit.engineprobe.test"
RUNNER = f"{PACKAGE}/androidx.test.runner.AndroidJUnitRunner"
PHASES = frozenset("""arguments-start arguments-ready source-asset-start source-asset-ready
jni-load-start jni-loaded jni-running-check-start jni-running-check-done jni-prestop-start
jni-prestop-done configuration-ready bridge-connect-start bridge-connected descriptors-ready
jni-start-start jni-started hello-sent jni-statistics-start jni-stop-start jni-joined
jni-repeat-stop-done descriptors-closed cleanup-stop-start cleanup-stop-returned
cleanup-stop-unconfirmed packet-pump-retained descriptors-retained""".split())


def instrumentation_phases(output):
    values = re.findall(r"^INSTRUMENTATION_STATUS: native_probe_phase=([a-z-]{1,64})\s*$", output, re.MULTILINE)
    return [value for value in values if value in PHASES]


def await_bridge(server, process, timeout=60):
    deadline, previous = time.monotonic() + timeout, server.gettimeout()
    try:
        while True:
            check(process.poll() is None, "Instrumentation exited before opening the packet bridge")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Android packet bridge did not connect within 60 seconds")
            server.settimeout(min(0.25, remaining))
            try:
                return server.accept()
            except socket.timeout:
                pass
    finally:
        server.settimeout(previous)


def capture_command(label, arguments, timeout=20):
    try:
        result = subprocess.run(arguments, timeout=timeout, check=False, capture_output=True, text=True)
        return {"operation": label, "returncode": result.returncode,
                "stdout": result.stdout.replace("\0", "")[:4096].strip(),
                "stderr": result.stderr.replace("\0", "")[:4096].strip()}
    except (OSError, subprocess.TimeoutExpired) as failure:
        return {"operation": label, "exception": type(failure).__name__}


def validate_instrumentation(output):
    check(re.search(r"\bOK \(1 test\)", output) is not None, "Instrumentation did not report one passing test")
    check(re.search(r"^INSTRUMENTATION_CODE: -1\s*$", output, re.MULTILINE) is not None, "Instrumentation did not finish successfully")
    check(not any(marker in output for marker in ("FAILURES!!!", "INSTRUMENTATION_FAILED", "Process crashed", "INSTRUMENTATION_STATUS_CODE: -2")), "Instrumentation reported a failure")


def fixtures(channel, expectations, gates, api):
    results = []
    for index, (mode, target) in enumerate(expectations):
        flow = PacketFixture(channel, 4 if index < 2 else 6, 80 if mode == "http" else 443, 41000 + index)
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
        while not flow.peer_closed:
            flow._receive()
        check(not flow.pending, "Unexpected bytes after the controlled response")
        result = {"api": api, "ipVersion": flow.version, "mode": mode, "uploadBytes": len(BODY),
                  "downloadBytes": len(REPLY), "halfClose": True, "gatedStreaming": True,
                  "nativePeerEof": True, "replySha256": hashlib.sha256(REPLY).hexdigest()}
        results.append(result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return results


def save_reports(directory, summary, error=None):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "results.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    cases = summary.get("cases", [])
    suite = ET.Element("testsuite", name="AndroidSyntheticNativeEngine", tests=str(len(cases) + 1), failures="1" if error else "0", errors="0", skipped="0")
    for case in cases:
        ET.SubElement(suite, "testcase", name=f"IPv{case['ipVersion']}-{case['mode']}")
    lifecycle = ET.SubElement(suite, "testcase", name="JNI-load-start-run-stop")
    if error:
        ET.SubElement(lifecycle, "failure", message=type(error).__name__).text = str(error)
    ET.ElementTree(suite).write(directory / "junit.xml", encoding="utf-8", xml_declaration=True)


def reserve_reverse(command, host_port, mappings):
    """Use a distinct explicit remote key without replacing an existing listener."""
    check(type(host_port) is int and 1 <= host_port <= 65535, "Invalid research reverse port")
    check(host_port not in mappings, "Research reverse ports must be distinct")
    endpoint = f"tcp:{host_port}"
    reply = command("reverse", "--no-rebind", endpoint, endpoint)
    # A successful explicit request owns this port even if its optional reply is malformed.
    mappings.append(host_port)
    check(reply in ("", str(host_port)), "Unexpected explicit reverse port response")
    return host_port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--api", type=int, choices=(26, 37), required=True)
    parser.add_argument("--test-apk", type=Path, required=True)
    parser.add_argument("--reports", type=Path, default=Path(__file__).parent / "android/build/reports/native-runtime")
    arguments = parser.parse_args()
    adb = [arguments.adb, "-s", arguments.serial]
    def command(*parts, timeout=60):
        return subprocess.check_output([*adb, *parts], text=True, timeout=timeout).strip()
    check(arguments.test_apk.is_file(), "Research instrumentation APK is absent")
    command("wait-for-device")
    actual_api = int(command("shell", "getprop", "ro.build.version.sdk"))
    check(actual_api == arguments.api, "The device API does not match the requested matrix entry")
    command("install", "-r", "-t", str(arguments.test_apk.resolve()), timeout=120)
    repository = Path(__file__).resolve().parents[2]
    summary = {"api": actual_api, "engineCommit": ENGINE_COMMIT, "scope": "synthetic JNI/datagrams; no VPN or real TLS",
               "repositoryCommit": subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip(),
               "sourceDirty": bool(subprocess.check_output(["git", "-C", str(repository), "status", "--porcelain"], text=True).strip()),
               "apkSha256": hashlib.sha256(arguments.test_apk.read_bytes()).hexdigest(),
               "model": command("shell", "getprop", "ro.product.model"), "cases": [], "passed": False, "reverseMappings": []}
    mappings, process, error = [], None, None
    def reverse(host_port):
        try:
            return reserve_reverse(command, host_port, mappings)
        finally:
            summary["reverseMappings"] = [{"devicePort": port, "hostPort": port} for port in mappings]
    try:
        arguments.reports.mkdir(parents=True, exist_ok=True)
        with listener() as bridge_server, listener() as socks, listener() as proxy, (arguments.reports / "instrumentation.txt").open("w+", encoding="utf-8") as output:
            for server in (bridge_server, socks, proxy):
                server.settimeout(60)
            bridge_port, socks_port = reverse(bridge_server.getsockname()[1]), reverse(socks.getsockname()[1])
            expectations = [(mode, target) for target in ("198.51.100.10", "[2001:db8::10]") for mode in ("http", "connect")]
            gates = [(threading.Event(), threading.Event()) for _ in expectations]
            process = subprocess.Popen([*adb, "shell", "am", "instrument", "-w", "-r", "-e", "class", "com.httpfreekit.engineprobe.NativePacketTest",
                                        "-e", "bridgePort", str(bridge_port), "-e", "socksPort", str(socks_port), RUNNER], stdout=output, stderr=subprocess.STDOUT, text=True)
            connection, _ = await_bridge(bridge_server, process)
            with connection:
                connection.settimeout(20)
                hello = read_control(connection, HELLO)
                check(hello.get("bridge") == "freekit-native-probe/1" and hello.get("engineCommit") == ENGINE_COMMIT, "Unexpected JNI source/bridge identity")
                check(hello.get("api") == actual_api and hello.get("jniLoaded") is True and hello.get("running") is True, "JNI did not load/start on the expected Android API")
                check(type(hello.get("pageSize")) is int and hello["pageSize"] > 0, "Missing Android page-size evidence")
                summary["jni"] = hello
                summary["pageSize"] = hello["pageSize"]
                channel = PacketChannel(connection)
                with ThreadPoolExecutor(max_workers=2) as peers:
                    proxy_result = peers.submit(proxy_fixture, proxy, expectations, gates)
                    socks_result = peers.submit(socks_fixture, socks, proxy.getsockname()[1], expectations)
                    summary["cases"] = fixtures(channel, expectations, gates, actual_api)
                    proxy_result.result(timeout=15)
                    socks_result.result(timeout=15)
                    summary["stop"] = channel.stop()
                    summary["bridgePackets"] = {"sent": channel.sent, "received": channel.received}
            process.wait(timeout=30)
            check(process.returncode == 0, "ADB instrumentation command failed")
            output.seek(0)
            instrumentation = output.read(1024 * 1024 + 1)
            check(len(instrumentation) <= 1024 * 1024, "Oversized instrumentation output")
            validate_instrumentation(instrumentation)
            summary["instrumentationTests"] = 1
            summary["passed"] = True
    except BaseException as failure:
        error = failure
        summary["failure"] = {"type": type(failure).__name__, "message": str(failure)}
        raise
    finally:
        cleanup_errors = []
        summary["instrumentationExitBeforeCleanup"] = process.poll() if process is not None else None
        if error is not None:
            summary["deviceDiagnostics"] = [
                capture_command("device-state", [*adb, "get-state"], timeout=5),
                capture_command("reverse-list", [*adb, "reverse", "--list"], timeout=5),
                capture_command("research-process", [*adb, "shell", "pidof", PACKAGE], timeout=5),
            ]
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired) as failure:
                cleanup_errors.append({"operation": "instrumentation-client-stop", "exception": type(failure).__name__})
        commands = [("force-stop", [*adb, "shell", "am", "force-stop", PACKAGE])]
        for port in mappings:
            commands.append((f"reverse-remove-{port}", [*adb, "reverse", "--remove", f"tcp:{port}"]))
        cleanup_results = [capture_command(label, command_arguments) for label, command_arguments in commands]
        cleanup_errors.extend(result for result in cleanup_results if result.get("returncode") != 0)
        summary["cleanup"] = cleanup_results
        if cleanup_errors:
            summary["passed"] = False
            summary["cleanupErrors"] = cleanup_errors
        summary["ownedMappingsRemoved"] = all(result.get("returncode") == 0 for result in cleanup_results if result["operation"].startswith("reverse-remove-"))
        summary["hostForceStopSucceeded"] = cleanup_results[0].get("returncode") == 0
        instrumentation_path = arguments.reports / "instrumentation.txt"
        if instrumentation_path.exists():
            with instrumentation_path.open("rb") as recorded:
                raw = recorded.read(1024 * 1024 + 1)
            summary["instrumentationOutputTruncated"] = len(raw) > 1024 * 1024
            summary["androidPhases"] = instrumentation_phases(raw[:1024 * 1024].decode("utf-8", errors="replace"))
        cleanup_failure = RuntimeError("Research process/mapping cleanup failed") if cleanup_errors else None
        save_reports(arguments.reports, summary, error or cleanup_failure)
        if error is None and cleanup_failure:
            raise cleanup_failure


if __name__ == "__main__":
    main()
