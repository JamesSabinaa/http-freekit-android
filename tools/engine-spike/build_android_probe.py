#!/usr/bin/env python3
"""Build the exact researched engine/JNI into an isolated Android test project."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

from run_linux import ENGINE_COMMIT, SUBMODULES, check

NDK_VERSION = "28.2.13676358"
ENGINE_URL = "https://github.com/heiher/hev-socks5-tunnel.git"
ABIS = {"arm64-v8a": 183, "x86_64": 62}


def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()


def verify_source(root):
    for relative, expected in {".": ENGINE_COMMIT, **SUBMODULES}.items():
        checkout = root / relative
        check(git(checkout, "rev-parse", "HEAD") == expected, f"Unexpected source revision in {relative}")
        check(not git(checkout, "status", "--porcelain", "--untracked-files=all"), f"Dirty source checkout: {relative}")
        check(not git(checkout, "ls-files", "--others", "--ignored", "--exclude-standard"), f"Ignored files in source cache: {relative}")
        for entry in git(checkout, "ls-files", "--stage").splitlines():
            metadata, path = entry.split("\t", 1)
            if metadata.startswith("120000 "):
                check((checkout / path).is_symlink(), f"Source symlink was checked out as a placeholder: {relative}/{path}")
    # Windows must check out actual symlinks, rather than text placeholders.
    for relative in ("src/core", "third-part/hev-task-system", "third-part/lwip", "third-part/yaml"):
        check((root / relative / "LICENSE").is_file(), f"Missing public licence in {relative}")


def prepare_source(root, fetch=False):
    if not root.exists():
        check(fetch, "Engine cache is absent; run with --fetch to fetch exact pinned source")
        root.mkdir(parents=True)
        subprocess.run(["git", "init", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "core.symlinks", "true"], check=True)
        subprocess.run(["git", "-C", str(root), "remote", "add", "origin", ENGINE_URL], check=True)
        subprocess.run(["git", "-C", str(root), "fetch", "--depth", "1", "origin", ENGINE_COMMIT], check=True, timeout=120)
        subprocess.run(["git", "-C", str(root), "checkout", "--detach", ENGINE_COMMIT], check=True)
        subprocess.run(["git", "-c", "core.symlinks=true", "-C", str(root), "submodule", "update", "--init", "--recursive", "--depth", "1"], check=True, timeout=240)
    # Existing mismatched/dirty caches are never reset or silently repaired.
    verify_source(root)


def inspect_elf(path, machine):
    data = path if isinstance(path, bytes) else path.read_bytes()
    check(data[:6] == b"\x7fELF\x02\x01", "Expected a little-endian 64-bit ELF")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    check(header[1] == 3 and header[2] == machine, "Unexpected ELF type or architecture")
    offset, entry_size, count = header[5], header[9], header[10]
    alignments, android_api = [], None
    for index in range(count):
        program = struct.unpack_from("<IIQQQQQQ", data, offset + index * entry_size)
        kind, _, file_offset, _, _, size, _, alignment = program
        if kind == 1:
            check(alignment >= 16384, "Native LOAD segment lacks 16 KiB alignment")
            alignments.append(alignment)
        if kind == 4:
            cursor, end = file_offset, file_offset + size
            while cursor + 12 <= end:
                names, description, note_type = struct.unpack_from("<III", data, cursor)
                cursor += 12
                name = data[cursor:cursor + names].rstrip(b"\0")
                cursor += (names + 3) & ~3
                desc = data[cursor:cursor + description]
                cursor += (description + 3) & ~3
                if name == b"Android" and note_type == 1 and len(desc) >= 4:
                    android_api = struct.unpack_from("<I", desc)[0]
    check(alignments and android_api == 26, "ELF Android API note is not API 26")
    return {"androidApi": android_api, "loadAlignments": alignments, "machine": machine}


def build(root, ndk, output, application_mk):
    properties = dict((key.strip(), value.strip()) for line in (ndk / "source.properties").read_text().splitlines()
                      if "=" in line for key, value in [line.split("=", 1)])
    check(properties.get("Pkg.Revision") == NDK_VERSION, "Unexpected NDK revision")
    output.mkdir(parents=True, exist_ok=True)
    command = [str(ndk / ("ndk-build.cmd" if os.name == "nt" else "ndk-build")),
               f"NDK_PROJECT_PATH={root}", f"APP_BUILD_SCRIPT={root / 'Android.mk'}",
               f"NDK_APPLICATION_MK={application_mk}", f"NDK_OUT={output / 'obj'}",
               f"NDK_LIBS_OUT={output / 'libs'}", "APP_MODULES=hev-socks5-tunnel", "-j2"]
    subprocess.run(command, cwd=root, check=True, timeout=300)
    verify_source(root)
    elf = {abi: inspect_elf(output / "libs" / abi / "libhev-socks5-tunnel.so", machine)
           for abi, machine in ABIS.items()}
    for abi in ABIS:
        binary = (output / "libs" / abi / "libhev-socks5-tunnel.so").read_bytes()
        check(b"com/httpfreekit/engineprobe/NativeEngine" in binary, "JNI class override was not compiled")
        elf[abi]["sha256"] = hashlib.sha256(binary).hexdigest()
    notices = output / "assets" / "native-licenses"
    notices.mkdir(parents=True, exist_ok=True)
    components = {"hev-socks5-tunnel": ".", "hev-socks5-core": "src/core",
                  "hev-task-system": "third-part/hev-task-system", "lwip": "third-part/lwip", "yaml": "third-part/yaml"}
    for name, relative in components.items():
        shutil.copyfile(root / relative / "LICENSE", notices / f"{name}-LICENSE.txt")
    shutil.copyfile(Path(__file__).resolve().parents[2] / "LICENSE", notices / "http-freekit-probe-LICENSE.txt")
    headers = []
    for name in ("Android.mk", "Application.mk"):
        lines = (root / name).read_text().splitlines()
        headers.append(name + ":\n" + "\n".join(line for line in lines if line.startswith("#")))
    (notices / "android-build-NOTICE.txt").write_text("\n\n".join(headers) + "\n")
    manifest = {"engineCommit": ENGINE_COMMIT, "submodules": SUBMODULES, "ndkVersion": NDK_VERSION,
                "jniClass": "com/httpfreekit/engineprobe/NativeEngine", "elf": elf,
                "scope": "synthetic Android JNI/datagram research; no VPN"}
    (output / "assets" / "engine-source.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-root", type=Path, required=True)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--application-mk", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true")
    arguments = parser.parse_args()
    prepare_source(arguments.engine_root.resolve(), arguments.fetch)
    build(arguments.engine_root.resolve(), arguments.ndk_root.resolve(), arguments.output_root.resolve(), arguments.application_mk.resolve())


if __name__ == "__main__":
    main()
