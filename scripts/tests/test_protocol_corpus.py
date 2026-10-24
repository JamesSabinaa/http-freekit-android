"""Negative bounds/shape checks for the independent conformance data."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "check-protocol-corpus.py"
SPEC = importlib.util.spec_from_file_location("protocol_corpus", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
REAL = SCRIPT.parents[1] / "protocol/fixtures/a19-draft-0.3"


def fixture():
    control = dict(phase="awaiting_hello", cause=None, sessionLease=False, webSocketClosed=False,
                   resourcesReleased=False, historyCount=0, streamLeases=0, chargedBytes=0)
    snap = dict(pool=dict(sessionLeases=0, streamLeases=0, chargedBytes=0), controls={"a": control}, streams={})
    common = dict(format=guard.FORMAT, revision=guard.REVISION)
    return {
        "manifest": dict(**common, kind="manifest", codecIds=["codec-basic"], lifecycleIds=["life-basic"]),
        "codec": dict(**common, kind="codec", cases=[dict(id="codec-basic", channel="control",
            input={"wireHex": "00"}, expect={"code": "invalid_message"})]),
        "lifecycle": dict(**common, kind="lifecycle", cases=[dict(id="life-basic",
            pool=dict(maxSessions=1, maxStreams=2, maxBytes=64),
            initialClock=dict(utcMillis=1792843200000, monotonicMillis=0),
            controls={"a": dict(deviceId="device-a", desktopId="desk-a", supportedCapabilities=["tcp-http"])},
            steps=[dict(op="create_control", control="a", expect=dict(code="ok", effects=[], snapshot=snap))])]),
    }


class ProtocolCorpusTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freekit-corpus-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def write(self, data):
        for kind, value in data.items():
            (self.directory / (kind + ".json")).write_text(json.dumps(value), encoding="utf-8")

    def reject(self, data):
        self.write(data)
        with self.assertRaises(guard.InvalidCorpus):
            guard.validate(self.directory)

    def test_minimal_and_actual_committed_corpus_validate(self):
        self.write(fixture())
        result = guard.validate(self.directory)
        self.assertEqual((result["codecCases"], result["lifecycleCases"], result["lifecycleSteps"]), (1, 1, 1))
        result = guard.validate(REAL)
        self.assertEqual(result["codecCases"], len(json.loads((REAL / "codec.json").read_text())["cases"]))

    def test_repeat_descriptor_is_bounded_before_any_payload_allocation(self):
        self.assertEqual(guard.input_length(dict(prefixHex="", repeatHex="ff", repeatCount=65537, suffixHex="")), 65537)
        for descriptor in (
            dict(prefixHex="00", repeatHex="ff", repeatCount=65537, suffixHex=""),
            dict(prefixHex="", repeatHex="ff", repeatCount=65538, suffixHex=""),
            {"wireHex": "00" * 65538},
        ):
            with self.subTest(descriptor_size=len(str(descriptor))):
                with self.assertRaises(guard.InvalidCorpus): guard.input_length(descriptor)

    def test_invalid_byte_descriptors_cannot_be_executable_or_ambiguous(self):
        for value in ({"wireHex": "0"}, {"wireHex": "FF"}, {"wireHex": "00\n"}, {"wireHex": False},
                      {"file": "DO_NOT_PRINT_PRIVATE"}, {"wireHex": "00", "repeatCount": 1},
                      dict(prefixHex="", repeatHex="0000", repeatCount=1, suffixHex="")):
            with self.subTest(value=value):
                with self.assertRaises(guard.InvalidCorpus): guard.input_length(value)
        for count in (-1, True, 1.0, 9007199254740992):
            with self.assertRaises(guard.InvalidCorpus):
                guard.input_length(dict(prefixHex="", repeatHex="00", repeatCount=count, suffixHex=""))

    def test_duplicate_json_keys_and_noninteger_constants_are_rejected(self):
        self.write(fixture())
        for text in ('{"kind":1,"k\\u0069nd":2}', '{"value":NaN}', '{"value":Infinity}', '{"value":1.0}'):
            (self.directory / "manifest.json").write_text(text)
            with self.assertRaises(guard.InvalidCorpus): guard.validate(self.directory)

    def test_file_utf8_size_and_missing_file_guards(self):
        for content in (b"\xff", b"\xef\xbb\xbf{}", b" " * (guard.MAX_FILE_BYTES + 1)):
            self.write(fixture())
            (self.directory / "manifest.json").write_bytes(content)
            with self.assertRaises(guard.InvalidCorpus): guard.validate(self.directory)
        (self.directory / "manifest.json").unlink()
        with self.assertRaises(guard.InvalidCorpus): guard.validate(self.directory)

    def test_depth_guard_runs_before_recursive_json_parser(self):
        target = self.directory / "deep.json"
        target.write_text("[" * 33 + "0" + "]" * 33)
        with patch.object(guard.json, "loads", side_effect=AssertionError("Parser must not run")) as parser:
            with self.assertRaises(guard.InvalidCorpus): guard.read_file(target)
            parser.assert_not_called()
        target.write_text(json.dumps({"quoted": '[{\\"' * 40}))
        _, value = guard.read_file(target)
        self.assertEqual(value["quoted"], '[{\\"' * 40)

    def test_manifest_is_unique_ordered_and_exact(self):
        for change in ("missing", "duplicate", "extra", "overlap", "unknown"):
            data = fixture()
            if change == "missing": data["manifest"]["codecIds"] = []
            elif change == "duplicate": data["manifest"]["codecIds"] *= 2
            elif change == "extra": data["manifest"]["codecIds"].append("codec-extra")
            elif change == "overlap": data["manifest"]["lifecycleIds"] = ["codec-basic"]
            else: data["manifest"]["unknown"] = 1
            self.reject(data)
        data = fixture(); data["manifest"]["codecIds"] = ["codec-z", "codec-a"]; self.reject(data)

    def test_case_and_step_limits_are_enforced_before_execution(self):
        data = fixture(); data["manifest"]["codecIds"] = [f"codec-{n:03}" for n in range(257)]; self.reject(data)
        data = fixture(); case = data["lifecycle"]["cases"][0]; case["steps"] *= 2049; self.reject(data)

    def test_operation_fields_and_references_are_not_a_generic_language(self):
        for edit in (lambda s: s.update(op="eval"), lambda s: s.update(script="DO_NOT_PRINT_PRIVATE"),
                     lambda s: s.update(control="missing"), lambda s: s.update(op="tick", stream="missing")):
            data = fixture(); edit(data["lifecycle"]["cases"][0]["steps"][0]); self.reject(data)
        data = fixture(); steps = data["lifecycle"]["cases"][0]["steps"]; steps.append(copy.deepcopy(steps[0])); self.reject(data)

    def test_clock_and_boolean_number_substitutions_are_rejected(self):
        for invalid in (False, 1.0, -1, 9007199254740992):
            data = fixture(); data["lifecycle"]["cases"][0]["initialClock"]["monotonicMillis"] = invalid; self.reject(data)
        data = fixture(); data["lifecycle"]["cases"][0]["steps"][0]["expect"]["snapshot"]["pool"]["chargedBytes"] = False
        self.reject(data)

    def test_snapshot_accounting_and_early_release_contradictions_are_rejected(self):
        real = json.loads((REAL / "lifecycle.json").read_text())
        case = next(c for c in real["cases"] if c["id"] == "life-cancel-retains-bytes-and-stops-forwarding")
        for mode in ("pool", "release", "completion", "cause-type"):
            data = fixture(); changed = copy.deepcopy(case); changed["id"] = "life-basic"
            data["lifecycle"]["cases"] = [changed]
            step = next(s for s in changed["steps"] if s["op"] == "binary")
            state = step["expect"]["snapshot"]
            if mode == "pool": state["pool"]["chargedBytes"] = 0
            elif mode == "release": state["streams"]["s"]["resourcesReleased"] = True
            elif mode == "completion": state["streams"]["s"]["phase"] = "complete"
            else: state["streams"]["s"]["cause"] = []
            self.reject(data)

    def test_eof_effects_cannot_repeat_or_precede_drained_bytes(self):
        real = json.loads((REAL / "lifecycle.json").read_text())
        case = next(c for c in real["cases"] if c["id"] == "life-cross-frame-prefix-and-partial-drain")
        for mode in ("duplicate", "premature"):
            data = fixture(); changed = copy.deepcopy(case); changed["id"] = "life-basic"
            data["lifecycle"]["cases"] = [changed]
            step = next(s for s in changed["steps"] if s["expect"]["effects"])
            if mode == "duplicate": step["expect"]["effects"] *= 2
            else: step["expect"]["snapshot"]["streams"]["s"]["gateway"]["chargedBytes"] = 1
            self.reject(data)

    def test_snapshot_is_inert_and_cannot_supply_a_clock(self):
        data = fixture(); step = copy.deepcopy(data["lifecycle"]["cases"][0]["steps"][0])
        step.pop("control"); step["op"] = "snapshot"; step["clock"] = data["lifecycle"]["cases"][0]["initialClock"]
        data["lifecycle"]["cases"][0]["steps"].append(step); self.reject(data)

    def test_cli_errors_are_fixed_and_do_not_dump_input_or_paths(self):
        self.write(fixture()); (self.directory / "codec.json").write_text('{"DO_NOT_PRINT_PRIVATE":')
        result = subprocess.run([sys.executable, str(SCRIPT), "--corpus", str(self.directory)],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("DO_NOT_PRINT_PRIVATE", result.stderr)
        self.assertNotIn(str(self.directory), result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_oversized_lifecycle_text_can_store_the_local_size_cause(self):
        data = fixture()
        case = data["lifecycle"]["cases"][0]
        state = copy.deepcopy(case["steps"][0]["expect"]["snapshot"])
        state["controls"]["a"].update(phase="failed", cause="message_too_large")
        case["steps"].append(dict(op="control_text", control="a", direction="client",
            input=dict(prefixHex="", repeatHex="ff", repeatCount=65537, suffixHex=""),
            expect=dict(code="message_too_large", effects=[], snapshot=state)))
        self.write(data)
        self.assertEqual(guard.validate(self.directory)["lifecycleSteps"], 2)

    def test_huge_json_integer_and_unhashable_codec_codes_have_safe_cli_errors(self):
        bad_inputs = ['{"DO_NOT_PRINT_PRIVATE":' + "9" * 5000 + '}']
        for code in ({"DO_NOT_PRINT_PRIVATE": 1}, ["DO_NOT_PRINT_PRIVATE"]):
            data = fixture()
            data["codec"]["cases"][0]["expect"]["code"] = code
            bad_inputs.append(json.dumps(data["codec"]))
        for content in bad_inputs:
            self.write(fixture())
            (self.directory / "codec.json").write_text(content)
            result = subprocess.run([sys.executable, str(SCRIPT), "--corpus", str(self.directory)],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertNotIn("DO_NOT_PRINT_PRIVATE", result.stderr)
            self.assertNotIn(str(self.directory), result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
