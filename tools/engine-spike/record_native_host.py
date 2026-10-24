#!/usr/bin/env python3
"""Retain fixed host-emulator facts/categories without publishing emulator logs."""
import argparse
import json
from pathlib import Path
import re

MARKERS = {
    "out_of_memory": r"out of memory|cannot allocate memory|std::bad_alloc",
    "segmentation_fault": r"segmentation fault|sigsegv|fatal signal\s+11\b",
    "illegal_instruction": r"illegal instruction|sigill|fatal signal\s+4\b",
    "abort": r"sigabrt|fatal signal\s+6\b|assertion[^\n]*failed",
    "kvm_error": r"kvm[^\n]*(?:failed|error)|acceleration[^\n]*failed",
    "disk_space": r"no space left on device|enospc",
    "fatal_emulator": r"\b(?:panic|fatal)\s*:",
}


def classify_log_tail(path):
    if not path.is_file():
        return {"logPresent": False, "inspectedTailBytes": 0, "fatalLogMarkers": []}
    with path.open("rb") as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - 256 * 1024))
        tail = stream.read(256 * 1024)
    decoded = tail.decode("utf-8", errors="replace")
    return {"logPresent": True, "inspectedTailBytes": len(tail),
            "fatalLogMarkers": [name for name, pattern in MARKERS.items() if re.search(pattern, decoded, re.IGNORECASE)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator-log", type=Path, required=True)
    parser.add_argument("--emulator-pid", type=int, required=True)
    parser.add_argument("--emulator-alive", choices=("true", "false"), required=True)
    parser.add_argument("--emulator-exit-code", type=int)
    parser.add_argument("--native-exit-code", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = {"beforeTeardown": True, "emulatorPid": arguments.emulator_pid,
              "emulatorAlive": arguments.emulator_alive == "true",
              "emulatorExitCode": arguments.emulator_exit_code, "nativeCommandExitCode": arguments.native_exit_code,
              **classify_log_tail(arguments.emulator_log)}
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
