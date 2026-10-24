"""Reject partial, stale or jointly wrong cross-language protocol evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "compare-protocol-conformance.py"
SPEC = importlib.util.spec_from_file_location("protocol_comparison", SCRIPT)
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)


def envelope(kind, **values):
    return {"format": "http-freekit-a19", "revision": "0.3", "kind": kind, **values}


class ProtocolComparisonTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="freekit-conformance-")
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.corpus = self.directory / "corpus"
        self.corpus.mkdir()
        self.codec = envelope("codec", cases=[
            {"id": "hello", "channel": "control", "input": {"wireHex": "7b7d"},
             "expect": {"code": "ok", "message": {"protocolVersion": 1, "type": "hello",
                         "capabilities": ["tcp-http"], "requiredCapabilities": []}}},
            {"id": "bad-utf8", "channel": "control", "input": {"wireHex": "ff"},
             "expect": {"code": "invalid_message"}},
        ])
        self.lifecycle = envelope("lifecycle", cases=[
            {"id": "retained-cancellation", "steps": [
                {"op": "cancel", "expect": {"code": "ok", "effects": [],
                 "snapshot": {"phase": "cancelled", "chargedBytes": 3, "streamLease": True}}},
                {"op": "resources_closed", "expect": {"code": "ok", "effects": [],
                 "snapshot": {"phase": "cancelled", "chargedBytes": 0, "streamLease": False}}},
            ]},
            {"id": "empty-peek", "steps": [
                {"op": "peek", "expect": {"code": "ok", "effects": [], "peekHex": "", "snapshot": {}}},
            ]},
        ])
        self.manifest = envelope("manifest", codecIds=["hello", "bad-utf8"],
                                 lifecycleIds=["retained-cancellation", "empty-peek"])
        for name, value in (("codec.json", self.codec), ("lifecycle.json", self.lifecycle),
                            ("manifest.json", self.manifest)):
            self.write(self.corpus / name, value)
        # Independent framing/expectation builder: do not ask the comparator to invent evidence.
        digest = hashlib.sha256()
        for name in ("codec.json", "lifecycle.json", "manifest.json"):
            digest.update(name.encode() + b"\0" + (self.corpus / name).read_bytes() + b"\0")
        self.digest = digest.hexdigest()
        self.reports = {}
        for implementation in ("kotlin", "node"):
            self.reports[implementation] = envelope("results", implementation=implementation,
                corpusSha256=self.digest,
                codec=[{"id": row["id"], "actual": copy.deepcopy(row["expect"])} for row in self.codec["cases"]],
                lifecycle=[{"id": row["id"], "steps": [copy.deepcopy(step["expect"]) for step in row["steps"]]}
                           for row in self.lifecycle["cases"]])
        self.save_reports()

    def write(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def save_reports(self):
        for name, value in self.reports.items():
            self.write(self.directory / f"{name}.json", value)

    def verify(self):
        return comparison.compare(self.corpus, self.directory / "kotlin.json", self.directory / "node.json")

    def reject(self):
        self.save_reports()
        with self.assertRaises(comparison.InvalidConformance):
            self.verify()

    def test_complete_actual_reports_match_independent_manifest_and_digest(self):
        result = self.verify()
        self.assertEqual(result["corpusSha256"], self.digest)
        self.assertEqual((result["codecCases"], result["lifecycleCases"], result["lifecycleSteps"]), (2, 2, 3))
        self.assertEqual(result["implementations"], ["kotlin", "node"])

    def test_both_implementations_agreeing_on_wrong_outcomes_cannot_pass(self):
        for report in self.reports.values():
            report["codec"][1]["actual"] = {"code": "ok"}
            report["lifecycle"][0]["steps"][0]["snapshot"]["chargedBytes"] = 0
        self.reject()

    def test_one_language_wrong_cleanup_or_missing_step_is_rejected(self):
        original = copy.deepcopy(self.reports)
        for change in ("early-release", "missing-step", "extra-step"):
            with self.subTest(change=change):
                self.reports = copy.deepcopy(original)
                steps = self.reports["node"]["lifecycle"][0]["steps"]
                if change == "early-release":
                    steps[0]["snapshot"]["streamLease"] = False
                elif change == "missing-step":
                    steps.pop()
                else:
                    steps.append(copy.deepcopy(steps[-1]))
                self.reject()

    def test_missing_duplicate_unexpected_and_reordered_ids_cannot_pass(self):
        original = copy.deepcopy(self.reports)
        for kind in ("codec", "lifecycle"):
            for change in ("missing", "duplicate", "unexpected", "reordered"):
                with self.subTest(kind=kind, change=change):
                    self.reports = copy.deepcopy(original)
                    rows = self.reports["kotlin"][kind]
                    if change == "missing":
                        rows.pop()
                    elif change == "duplicate":
                        rows.append(copy.deepcopy(rows[0]))
                    elif change == "unexpected":
                        rows[0]["id"] = "unlisted-case"
                    else:
                        rows.reverse()
                    self.reject()

    def test_stale_digest_and_wrong_implementation_or_envelope_are_rejected(self):
        original = copy.deepcopy(self.reports)
        for field, value in (("corpusSha256", "0" * 64), ("implementation", "node"),
                             ("format", "other"), ("kind", "codec"), ("revision", "0.2")):
            with self.subTest(field=field):
                self.reports = copy.deepcopy(original)
                self.reports["kotlin"][field] = value
                self.reject()

    def test_exact_file_bytes_and_filename_framing_are_part_of_corpus_identity(self):
        path = self.corpus / "codec.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaises(comparison.InvalidConformance):
            self.verify()

    def test_boolean_float_and_integer_substitutions_cannot_compare_equal(self):
        original = copy.deepcopy(self.reports)
        for value in (False, 0.0):
            with self.subTest(value=repr(value)):
                self.reports = copy.deepcopy(original)
                self.reports["node"]["lifecycle"][0]["steps"][1]["snapshot"]["chargedBytes"] = value
                self.reject()

    def test_extra_result_fields_and_missing_actual_values_cannot_hide_a_subset(self):
        original = copy.deepcopy(self.reports)
        for mode in ("extra-envelope", "extra-row", "missing-actual"):
            with self.subTest(mode=mode):
                self.reports = copy.deepcopy(original)
                report = self.reports["kotlin"]
                if mode == "extra-envelope":
                    report["ignored"] = "DO_NOT_PRINT"
                elif mode == "extra-row":
                    report["codec"][0]["expected"] = report["codec"][0]["actual"]
                else:
                    del report["codec"][0]["actual"]
                self.reject()

    def test_corpus_manifest_or_missing_independent_expectations_cannot_pass(self):
        for name, value in (("manifest.json", {**self.manifest, "codecIds": ["hello", "hello"]}),
                            ("codec.json", {**self.codec, "cases": [{"id": "hello"}, {"id": "bad-utf8"}]}),
                            ("lifecycle.json", {**self.lifecycle, "cases": [{"id": "retained-cancellation", "steps": []},
                                                                           self.lifecycle["cases"][1]]})):
            with self.subTest(name=name):
                self.write(self.corpus / name, value)
                with self.assertRaises(comparison.InvalidConformance):
                    self.verify()
                original = {"manifest.json": self.manifest, "codec.json": self.codec, "lifecycle.json": self.lifecycle}[name]
                self.write(self.corpus / name, original)

    def test_missing_invalid_duplicate_member_and_nonfinite_reports_are_rejected(self):
        path = self.directory / "node.json"
        for data in (None, b"", b"<not-json>", b"\xff", b'{"kind":"results","kind":"results"}', b'{"bad":NaN}'):
            with self.subTest(data=data):
                if data is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(data)
                with self.assertRaises(comparison.InvalidConformance):
                    self.verify()

    def test_report_and_corpus_reads_are_bounded(self):
        with tempfile.NamedTemporaryFile(dir=self.directory, delete=False) as source:
            source.write(b" " * (comparison.MAX_REPORT_BYTES + 1))
            path = Path(source.name)
        with self.assertRaises(comparison.InvalidConformance):
            comparison.read_json(path, comparison.MAX_REPORT_BYTES)
        with self.assertRaises(comparison.InvalidConformance):
            comparison.read_json(path, comparison.MAX_CORPUS_BYTES)

    def test_cli_emits_only_safe_summary_and_fixed_diagnostics(self):
        command = [sys.executable, str(SCRIPT), "--corpus", str(self.corpus),
                   "--kotlin", str(self.directory / "kotlin.json"), "--node", str(self.directory / "node.json")]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["codecCases"], 2)
        self.reports["node"]["codec"][0]["actual"] = {"code": "DO_NOT_PRINT_PRIVATE_DETAIL"}
        self.save_reports()
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("DO_NOT_PRINT_PRIVATE_DETAIL", result.stderr)
        self.assertNotIn(str(self.directory), result.stderr)


if __name__ == "__main__":
    unittest.main()
