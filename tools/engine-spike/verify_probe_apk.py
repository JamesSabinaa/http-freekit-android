#!/usr/bin/env python3
"""Reject incomplete or unexpectedly privileged native research APKs."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile

from build_android_probe import ABIS, NDK_VERSION, inspect_elf
from run_linux import ENGINE_COMMIT, SUBMODULES, check
from run_android import PACKAGE

ANDROID = "{http://schemas.android.com/apk/res/android}"


def verify_manifest(xml):
    manifest = ET.fromstring(xml)
    check(manifest.get("package") == PACKAGE, "Unexpected research APK package")
    sdk = manifest.find("uses-sdk")
    check(sdk is not None and sdk.get(ANDROID + "minSdkVersion") == "26" and sdk.get(ANDROID + "targetSdkVersion") == "37", "Unexpected research SDK limits")
    permissions = {node.get(ANDROID + "name") for node in manifest.findall("uses-permission")}
    check(permissions == {"android.permission.INTERNET"}, "Research APK must request INTERNET only")
    runner = manifest.find("instrumentation")
    check(runner is not None and runner.get(ANDROID + "targetPackage") == PACKAGE, "Instrumentation must target its isolated test package")
    application = manifest.find("application")
    check(application is not None and application.get(ANDROID + "extractNativeLibs") == "false", "Native libraries must be mapped from aligned APK entries")
    check(not any(application.findall(kind) for kind in ("activity", "activity-alias", "service", "receiver", "provider")), "Research APK must not expose application components")
    return {"package": PACKAGE, "minSdk": 26, "targetSdk": 37,
            "permissions": sorted(permissions), "applicationComponents": 0, "selfTargetedInstrumentation": True}


def verify_apk(path):
    libraries = {}
    with zipfile.ZipFile(path) as archive, path.open("rb") as raw:
        source = json.loads(archive.read("assets/engine-source.json"))
        check(source.get("engineCommit") == ENGINE_COMMIT and source.get("submodules") == SUBMODULES and source.get("ndkVersion") == NDK_VERSION, "Unexpected packaged native source identity")
        names = {f"lib/{abi}/libhev-socks5-tunnel.so" for abi in ABIS}
        check({name for name in archive.namelist() if name.endswith(".so")} == names, "Unexpected native library set")
        for abi, machine in ABIS.items():
            member = archive.getinfo(f"lib/{abi}/libhev-socks5-tunnel.so")
            check(member.compress_type == zipfile.ZIP_STORED, "Native library must be uncompressed")
            raw.seek(member.header_offset + 26)
            filename_length, extra_length = struct.unpack("<HH", raw.read(4))
            start = member.header_offset + 30 + filename_length + extra_length
            check(start % 16384 == 0, "Native APK entry lacks 16 KiB alignment")
            binary = archive.read(member)
            digest = hashlib.sha256(binary).hexdigest()
            check(digest == source["elf"][abi]["sha256"], "Packaged library differs from the verified native build")
            libraries[abi] = {**inspect_elf(binary, machine), "sha256": digest, "apkDataOffset": start}
        for name in ("hev-socks5-tunnel-LICENSE.txt", "hev-socks5-core-LICENSE.txt", "hev-task-system-LICENSE.txt", "lwip-LICENSE.txt", "yaml-LICENSE.txt", "http-freekit-probe-LICENSE.txt", "android-build-NOTICE.txt"):
            check(len(archive.read(f"assets/native-licenses/{name}")) > 100, "Missing public native licence notice")
    return {"engineCommit": ENGINE_COMMIT, "ndkVersion": NDK_VERSION, "libraries": libraries,
            "apkSha256": hashlib.sha256(path.read_bytes()).hexdigest(), "runtimeExecuted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--apkanalyzer", default="apkanalyzer")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    xml = subprocess.check_output([arguments.apkanalyzer, "manifest", "print", str(arguments.apk.resolve())], text=True, timeout=60)
    manifest = verify_manifest(xml)
    result = verify_apk(arguments.apk)
    result["manifest"] = manifest
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
