#!/usr/bin/env python3
"""Drive the isolated Android JNI probe through owned ADB loopback mappings."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

from android_bridge import HELLO, PacketChannel, read_control
from run_linux import BODY, REPLY, ENGINE_COMMIT, PacketFixture, check, listener, proxy_fixture, socks_fixture

PACKAGE = "com.httpfreekit.engineprobe.test"
RUNNER = f"{PACKAGE}/androidx.test.runner.AndroidJUnitRunner"


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
               "model": command("shell", "getprop", "ro.product.model"), "cases": [], "passed": False}
    mappings, process, error = [], None, None
    def reverse(host_port):
        value = command("reverse", "tcp:0", f"tcp:{host_port}")
        check(value.isdigit() and 0 < int(value) <= 65535, "ADB did not allocate an owned reverse port")
        mappings.append(int(value))
        return int(value)
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
            with ThreadPoolExecutor(max_workers=2) as peers:
                proxy_result = peers.submit(proxy_fixture, proxy, expectations, gates)
                socks_result = peers.submit(socks_fixture, socks, proxy.getsockname()[1], expectations)
                connection, _ = bridge_server.accept()
                with connection:
                    connection.settimeout(20)
                    hello = read_control(connection, HELLO)
                    check(hello.get("bridge") == "freekit-native-probe/1" and hello.get("engineCommit") == ENGINE_COMMIT, "Unexpected JNI source/bridge identity")
                    check(hello.get("api") == actual_api and hello.get("jniLoaded") is True and hello.get("running") is True, "JNI did not load/start on the expected Android API")
                    check(type(hello.get("pageSize")) is int and hello["pageSize"] > 0, "Missing Android page-size evidence")
                    summary["jni"] = hello
                    summary["pageSize"] = hello["pageSize"]
                    channel = PacketChannel(connection)
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
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired) as failure:
                cleanup_errors.append(type(failure).__name__)
        commands = [[*adb, "shell", "am", "force-stop", PACKAGE]]
        for port in mappings:
            commands.append([*adb, "reverse", "--remove", f"tcp:{port}"])
        for cleanup in commands:
            try:
                result = subprocess.run(cleanup, timeout=20, check=False, capture_output=True)
                if result.returncode:
                    cleanup_errors.append("ADB cleanup failed")
            except (OSError, subprocess.TimeoutExpired) as failure:
                cleanup_errors.append(type(failure).__name__)
        if cleanup_errors:
            summary["passed"] = False
            summary["cleanupErrors"] = cleanup_errors
        summary["ownedMappingsRemoved"] = not cleanup_errors
        cleanup_failure = RuntimeError("Research process/mapping cleanup failed") if cleanup_errors else None
        save_reports(arguments.reports, summary, error or cleanup_failure)
        if error is None and cleanup_failure:
            raise cleanup_failure


if __name__ == "__main__":
    main()
