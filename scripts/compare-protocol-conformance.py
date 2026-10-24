"""Compare complete actual Kotlin/Node A19 outcomes with the independent corpus."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


FORMAT, REVISION = "http-freekit-a19", "0.3"
CORPUS_FILES = ("codec.json", "lifecycle.json", "manifest.json")
MAX_CORPUS_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_CASES, MAX_STEPS = 256, 2048


class InvalidConformance(ValueError):
    """Static diagnostics only; reports can contain deliberately hostile canaries."""


def object_without_duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise InvalidConformance("Duplicate JSON member")
        result[name] = value
    return result


def reject_constant(_):
    raise InvalidConformance("Non-JSON numeric constant")


def read_json(path, maximum):
    try:
        with Path(path).open("rb") as source:
            encoded = source.read(maximum + 1)
        if len(encoded) > maximum:
            raise InvalidConformance("JSON input exceeds its size limit")
        result = json.loads(encoded.decode("utf-8"), object_pairs_hook=object_without_duplicates,
                            parse_constant=reject_constant)
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise InvalidConformance("Missing, oversized or invalid JSON input") from None
    if not isinstance(result, dict):
        raise InvalidConformance("Expected a JSON envelope")
    return encoded, result


def require_envelope(value, kind):
    if value.get("format") != FORMAT or value.get("revision") != REVISION or value.get("kind") != kind:
        raise InvalidConformance("Unsupported conformance envelope")


def ids(value):
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CASES:
        raise InvalidConformance("Missing or excessive case IDs")
    if any(not isinstance(item, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", item) is None for item in value):
        raise InvalidConformance("Invalid case ID")
    if len(set(value)) != len(value):
        raise InvalidConformance("Duplicate case ID")
    if value != sorted(value):
        raise InvalidConformance("Case IDs are not in manifest order")
    return value


def typed_json(value):
    """Unlike Python equality, preserve bool/integer/float distinctions in outcomes."""
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        raise InvalidConformance("Invalid normalized outcome") from None


def corpus(directory):
    digest = hashlib.sha256()
    envelopes = {}
    for name in CORPUS_FILES:
        encoded, value = read_json(Path(directory) / name, MAX_CORPUS_BYTES)
        digest.update(name.encode("utf-8") + b"\0" + encoded + b"\0")
        envelopes[name] = value
    manifest, codec, lifecycle = (envelopes[name] for name in ("manifest.json", "codec.json", "lifecycle.json"))
    require_envelope(manifest, "manifest")
    require_envelope(codec, "codec")
    require_envelope(lifecycle, "lifecycle")
    if set(manifest) != {"format", "revision", "kind", "codecIds", "lifecycleIds"} or any(
            set(envelope) != {"format", "revision", "kind", "cases"} for envelope in (codec, lifecycle)):
        raise InvalidConformance("Unexpected corpus envelope fields")
    manifest_ids = {"codec": ids(manifest.get("codecIds")), "lifecycle": ids(manifest.get("lifecycleIds"))}
    if set(manifest_ids["codec"]) & set(manifest_ids["lifecycle"]):
        raise InvalidConformance("Case IDs overlap between corpus kinds")
    expected = {}
    for kind, envelope in (("codec", codec), ("lifecycle", lifecycle)):
        cases = envelope.get("cases")
        if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
            raise InvalidConformance("Invalid corpus case array")
        if ids([case.get("id") for case in cases]) != manifest_ids[kind]:
            raise InvalidConformance("Corpus cases do not match the ordered manifest")
        expected[kind] = []
        for case in cases:
            if kind == "codec":
                if not isinstance(case.get("expect"), dict):
                    raise InvalidConformance("Missing independent codec expectation")
                expected[kind].append({"id": case["id"], "actual": case["expect"]})
            else:
                steps = case.get("steps")
                if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS or any(
                        not isinstance(step, dict) or not isinstance(step.get("expect"), dict) for step in steps):
                    raise InvalidConformance("Missing or excessive lifecycle expectations")
                expected[kind].append({"id": case["id"], "steps": [step["expect"] for step in steps]})
    return digest.hexdigest(), manifest_ids, expected


def verified_report(path, implementation, digest, manifest_ids, expected):
    _, report = read_json(path, MAX_REPORT_BYTES)
    require_envelope(report, "results")
    if set(report) != {"format", "revision", "kind", "implementation", "corpusSha256", "codec", "lifecycle"}:
        raise InvalidConformance("Unexpected result envelope fields")
    if report["implementation"] != implementation or report["corpusSha256"] != digest:
        raise InvalidConformance("Wrong implementation or stale corpus digest")
    actual = {}
    for kind in ("codec", "lifecycle"):
        rows = report[kind]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise InvalidConformance("Invalid actual-result array")
        if ids([row.get("id") for row in rows]) != manifest_ids[kind]:
            raise InvalidConformance("Actual results do not match the complete ordered manifest")
        fields = {"id", "actual"} if kind == "codec" else {"id", "steps"}
        if any(set(row) != fields for row in rows):
            raise InvalidConformance("Unexpected actual-result fields")
        if typed_json(rows) != typed_json(expected[kind]):
            raise InvalidConformance("Actual outcomes differ from the independent corpus")
        actual[kind] = rows
    return actual


def compare(directory, kotlin_path, node_path):
    digest, manifest_ids, expected = corpus(directory)
    kotlin = verified_report(kotlin_path, "kotlin", digest, manifest_ids, expected)
    node = verified_report(node_path, "node", digest, manifest_ids, expected)
    if typed_json(kotlin) != typed_json(node):
        raise InvalidConformance("Kotlin and Node actual outcomes disagree")
    return {"format": FORMAT, "revision": REVISION, "corpusSha256": digest,
            "codecCases": len(manifest_ids["codec"]), "lifecycleCases": len(manifest_ids["lifecycle"]),
            "lifecycleSteps": sum(len(row["steps"]) for row in expected["lifecycle"]),
            "implementations": ["kotlin", "node"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--kotlin", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = compare(arguments.corpus, arguments.kotlin, arguments.node)
    except InvalidConformance as failure:
        print(f"Protocol conformance comparison failed: {failure}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
