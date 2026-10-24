"""Bound and validate the synthetic A19 corpus without executing an implementation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

FORMAT, REVISION = "http-freekit-a19", "0.3"
FILES = ("codec.json", "lifecycle.json", "manifest.json")
MAX_FILE_BYTES, MAX_INPUT_BYTES, MAX_DEPTH = 2 * 1024 * 1024, 65537, 32
MAX_SAFE = 9007199254740991
CAUSES = {"unsupported_version", "unsupported_capability", "authentication_failed", "device_revoked",
          "proxy_unavailable", "session_limit", "stream_limit", "invalid_message", "network_unreachable",
          "session_expired", "desktop_stopped", "cancelled", "message_too_large"}
CONTROL_PHASES = {"awaiting_hello", "awaiting_ready", "active", "closed", "failed"}
STREAM_PHASES = {"awaiting_open", "awaiting_ready", "open", "half_closed", "draining", "closing",
                 "complete", "cancelled", "failed"}


class InvalidCorpus(ValueError):
    """Fixed diagnostics, never supplied strings, payloads or paths."""


def require(condition, code):
    if not condition:
        raise InvalidCorpus(code)


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), "invalid_object_fields")


def integer(value, low=0, high=MAX_SAFE):
    require(type(value) is int and low <= value <= high, "invalid_integer")
    return value


def named(value, expression):
    require(type(value) is str and re.fullmatch(expression, value) is not None, "invalid_identifier")


def unique_members(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_member")
        result[key] = value
    return result


def no_noninteger(_):
    raise InvalidCorpus("noninteger_json_number")


def read_file(path):
    try:
        with path.open("rb") as stream:
            encoded = stream.read(MAX_FILE_BYTES + 1)
        require(len(encoded) <= MAX_FILE_BYTES, "file_size_limit")
        text = encoded.decode("utf-8")
        depth, quoted, escaped = 0, False, False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                require(depth <= MAX_DEPTH, "corpus_depth_limit")
            elif char in "]}":
                depth -= 1
                require(depth >= 0, "invalid_json")
        value = json.loads(text, object_pairs_hook=unique_members, parse_float=no_noninteger,
                           parse_constant=no_noninteger)
    except InvalidCorpus:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise InvalidCorpus("unreadable_or_invalid_json") from None
    return encoded, value


def input_length(value):
    require(type(value) is dict, "invalid_byte_input")
    if set(value) == {"wireHex"}:
        parts, count = [value["wireHex"]], 0
    else:
        fields(value, {"prefixHex", "repeatHex", "repeatCount", "suffixHex"})
        require(type(value["repeatHex"]) is str and re.fullmatch(r"[0-9a-f]{2}", value["repeatHex"]) is not None,
                "invalid_repeat_byte")
        count = integer(value["repeatCount"], 0, MAX_INPUT_BYTES)
        parts = [value["prefixHex"], value["suffixHex"]]
    size = count
    for part in parts:
        require(type(part) is str and len(part) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", part) is not None,
                "invalid_hex_bytes")
        size += len(part) // 2
    require(size <= MAX_INPUT_BYTES, "rendered_input_limit")
    return size


def clock(value):
    fields(value, {"utcMillis", "monotonicMillis"})
    integer(value["utcMillis"])
    integer(value["monotonicMillis"])


def ordered_ids(values):
    require(type(values) is list and 1 <= len(values) <= 256, "case_count_limit")
    for value in values:
        named(value, r"[a-z][a-z0-9-]{0,79}")
    require(values == sorted(set(values)), "unordered_or_duplicate_ids")


def flags(record, names):
    require(all(type(record[name]) is bool for name in names), "invalid_boolean")


def snapshot(value, created_controls, created_streams, pool):
    fields(value, {"pool", "controls", "streams"})
    fields(value["pool"], {"sessionLeases", "streamLeases", "chargedBytes"})
    require(type(value["controls"]) is dict and set(value["controls"]) == created_controls, "control_snapshot_refs")
    require(type(value["streams"]) is dict and set(value["streams"]) == created_streams, "stream_snapshot_refs")
    totals = {"sessionLeases": 0, "streamLeases": 0, "chargedBytes": 0}
    for record in value["streams"].values():
        fields(record, {"control", "phase", "cause", "streamLease", "webSocketClosed", "resourcesReleased",
                        "chargedFrames", "client", "gateway"})
        require(type(record["control"]) is str and record["control"] in created_controls and
                type(record["phase"]) is str and record["phase"] in STREAM_PHASES, "invalid_stream_snapshot")
        require(record["cause"] is None or (type(record["cause"]) is str and record["cause"] in CAUSES), "invalid_cause")
        flags(record, ("streamLease", "webSocketClosed", "resourcesReleased"))
        charged = 0
        for direction in ("client", "gateway"):
            side = record[direction]
            fields(side, {"sealed", "eofEmitted", "chargedBytes"})
            flags(side, ("sealed", "eofEmitted"))
            charged += integer(side["chargedBytes"], 0, 1048576)
            require(not side["eofEmitted"] or (side["sealed"] and side["chargedBytes"] == 0), "premature_eof_effect")
        integer(record["chargedFrames"], 0, 64)
        require(charged <= 1048576, "stream_byte_ceiling")
        require((charged == 0) == (record["chargedFrames"] == 0) and record["chargedFrames"] <= charged,
                "invalid_frame_charge")
        require(not record["resourcesReleased"] or (record["webSocketClosed"] and not record["streamLease"] and charged == 0),
                "unreleased_stream_resources")
        if record["phase"] == "complete":
            require(record["cause"] is None and record["resourcesReleased"] and
                    all(record[d]["sealed"] and record[d]["eofEmitted"] for d in ("client", "gateway")), "false_completion")
        totals["streamLeases"] += record["streamLease"]
        totals["chargedBytes"] += charged
    for ref, record in value["controls"].items():
        fields(record, {"phase", "cause", "sessionLease", "webSocketClosed", "resourcesReleased", "historyCount",
                        "streamLeases", "chargedBytes"})
        require(type(record["phase"]) is str and record["phase"] in CONTROL_PHASES, "invalid_control_snapshot")
        require(record["cause"] is None or (type(record["cause"]) is str and record["cause"] in CAUSES), "invalid_cause")
        flags(record, ("sessionLease", "webSocketClosed", "resourcesReleased"))
        integer(record["historyCount"], 0, 4096)
        integer(record["streamLeases"], 0, 64)
        integer(record["chargedBytes"], 0, 4194304)
        children = [s for s in value["streams"].values() if s["control"] == ref]
        require(record["streamLeases"] == sum(s["streamLease"] for s in children), "control_slot_mismatch")
        require(record["chargedBytes"] == sum(s[d]["chargedBytes"] for s in children for d in ("client", "gateway")),
                "control_byte_mismatch")
        require(not record["resourcesReleased"] or record["webSocketClosed"], "unclosed_control_resources")
        require(record["sessionLease"] or (record["historyCount"] == 0 and record["streamLeases"] == 0 and record["chargedBytes"] == 0),
                "premature_session_release")
        totals["sessionLeases"] += record["sessionLease"]
    for name, ceiling in (("sessionLeases", pool["maxSessions"]), ("streamLeases", pool["maxStreams"]),
                          ("chargedBytes", pool["maxBytes"])):
        integer(value["pool"][name], 0, ceiling)
        require(value["pool"][name] == totals[name], "pool_accounting_mismatch")


OPS = {
    "create_control": {"control"}, "control_text": {"control", "direction", "input"},
    "control_activity": {"control", "direction"},
    "allocate_stream": {"control", "stream", "deviceId", "sessionHeader"},
    "stream_text": {"stream", "direction", "input"}, "binary": {"stream", "direction", "input"},
    "peek": {"stream", "direction", "count"}, "drain": {"stream", "direction", "count"}, "snapshot": set(),
}


def lifecycle_case(case):
    fields(case, {"id", "pool", "initialClock", "controls", "steps"})
    fields(case["pool"], {"maxSessions", "maxStreams", "maxBytes"})
    for key, maximum in (("maxSessions", 16), ("maxStreams", 256), ("maxBytes", 16777216)):
        integer(case["pool"][key], 1, maximum)
    clock(case["initialClock"])
    require(type(case["controls"]) is dict and len(case["controls"]) > 0, "missing_control_definitions")
    for ref, value in case["controls"].items():
        named(ref, r"[a-z][a-z0-9-]{0,39}")
        fields(value, {"deviceId", "desktopId", "supportedCapabilities"})
        for key in ("deviceId", "desktopId"):
            named(value[key], r"[A-Za-z0-9_-]{1,128}")
        caps = value["supportedCapabilities"]
        require(type(caps) is list and len(caps) <= 16, "invalid_supported_capabilities")
        for cap in caps:
            named(cap, r"[a-z][a-z0-9-]{0,31}")
        require(len(set(caps)) == len(caps), "duplicate_supported_capability")
    require(type(case["steps"]) is list and 1 <= len(case["steps"]) <= 2048, "step_count_limit")
    controls, streams, previous = set(), set(), None
    for step in case["steps"]:
        require(type(step) is dict and type(step.get("op")) is str, "invalid_operation")
        op = step["op"]
        if op in ("local_cancel", "tick", "ws_closed", "resources_closed"):
            target = set(step) & {"control", "stream"}
            require(len(target) == 1, "ambiguous_operation_target")
            operation_fields = target | ({"closeCode"} if op == "ws_closed" else set())
        else:
            require(op in OPS, "unknown_operation")
            operation_fields = OPS[op]
        fields(step, {"op", "expect"} | operation_fields | ({"clock"} if "clock" in step else set()))
        require(op != "snapshot" or "clock" not in step, "snapshot_has_clock")
        if "clock" in step:
            clock(step["clock"])
        outcome = step["expect"]
        outcome_fields = {"code", "effects", "snapshot"}
        require(type(outcome) is dict and type(outcome.get("code")) is str, "invalid_operation_outcome")
        if op == "peek" and outcome["code"] == "ok":
            outcome_fields.add("peekHex")
            input_length({"wireHex": outcome.get("peekHex")})
        fields(outcome, outcome_fields)
        require(outcome["code"] in CAUSES | {"ok", "backpressure", "message_too_large"}, "unknown_outcome_code")
        if "control" in step:
            ref = step["control"]
            require(type(ref) is str and ref in case["controls"], "unknown_control_ref")
            if op == "create_control":
                require(ref not in controls, "reused_control_ref")
                controls.add(ref)
            else:
                require(ref in controls, "uncreated_control_ref")
        if "stream" in step:
            ref = step["stream"]
            named(ref, r"[a-z][a-z0-9-]{0,39}")
            if op == "allocate_stream":
                require(ref not in streams, "reused_stream_ref")
                if outcome["code"] == "ok":
                    streams.add(ref)
            else:
                require(ref in streams, "unallocated_stream_ref")
        if "direction" in step:
            named(step["direction"], r"[A-Za-z_-]{1,16}")
        if "input" in step:
            input_length(step["input"])
        if "count" in step:
            integer(step["count"], -1, 16777217)
        if "closeCode" in step:
            integer(step["closeCode"], 1000, 4999)
        if op == "allocate_stream":
            named(step["deviceId"], r"[A-Za-z0-9_-]{1,128}")
            require(type(step["sessionHeader"]) is str and len(step["sessionHeader"]) <= 128, "invalid_fixture_header")
        snapshot(outcome["snapshot"], controls, streams, case["pool"])
        effects = outcome["effects"]
        require(type(effects) is list and len(effects) <= 512, "effect_count_limit")
        keys = []
        for effect in effects:
            fields(effect, {"type", "stream", "direction"})
            require(effect["type"] == "write_eof" and type(effect["stream"]) is str and effect["stream"] in streams and
                    effect["direction"] in ("client", "gateway"), "invalid_eof_effect")
            current = outcome["snapshot"]["streams"][effect["stream"]]
            require(current[effect["direction"]]["eofEmitted"] and current["phase"] not in ("failed", "cancelled", "complete"),
                    "invalid_eof_effect_state")
            require(previous is None or not previous["streams"].get(effect["stream"], {}).get(effect["direction"], {}).get("eofEmitted", False),
                    "repeated_eof_effect")
            keys.append((effect["stream"], effect["direction"]))
        require(keys == sorted(set(keys)), "unordered_or_duplicate_effects")
        previous = outcome["snapshot"]


def validate(directory):
    digest, values = hashlib.sha256(), {}
    for filename in FILES:
        encoded, value = read_file(Path(directory) / filename)
        digest.update(filename.encode() + b"\0" + encoded + b"\0")
        values[filename] = value
    for kind in ("manifest", "codec", "lifecycle"):
        value = values[kind + ".json"]
        fields(value, {"format", "revision", "kind"} | ({"codecIds", "lifecycleIds"} if kind == "manifest" else {"cases"}))
        require(value["format"] == FORMAT and value["revision"] == REVISION and value["kind"] == kind, "invalid_envelope")
    manifest = values["manifest.json"]
    for key in ("codecIds", "lifecycleIds"):
        ordered_ids(manifest[key])
    require(not set(manifest["codecIds"]) & set(manifest["lifecycleIds"]), "overlapping_case_ids")
    for kind, id_field in (("codec", "codecIds"), ("lifecycle", "lifecycleIds")):
        cases = values[kind + ".json"]["cases"]
        require(type(cases) is list and all(type(case) is dict for case in cases), "invalid_case_array")
        require([case.get("id") for case in cases] == manifest[id_field], "case_manifest_mismatch")
        for case in cases:
            if kind == "lifecycle":
                lifecycle_case(case)
                continue
            fields(case, {"id", "channel", "input", "expect"})
            require(case["channel"] in ("control", "stream"), "invalid_codec_channel")
            input_length(case["input"])
            outcome = case["expect"]
            require(type(outcome) is dict, "invalid_codec_expectation")
            if outcome.get("code") == "ok":
                fields(outcome, {"code", "message"})
                require(type(outcome["message"]) is dict, "invalid_normalized_message")
            else:
                fields(outcome, {"code"})
                require(type(outcome["code"]) is str and outcome["code"] in
                        ("invalid_message", "message_too_large", "unsupported_version"), "invalid_codec_code")
    return {"format": FORMAT, "revision": REVISION, "corpusSha256": digest.hexdigest(),
            "codecCases": len(manifest["codecIds"]), "lifecycleCases": len(manifest["lifecycleIds"]),
            "lifecycleSteps": sum(len(case["steps"]) for case in values["lifecycle.json"]["cases"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate(args.corpus)
    except InvalidCorpus as problem:
        print(f"Protocol corpus validation failed: {problem}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
