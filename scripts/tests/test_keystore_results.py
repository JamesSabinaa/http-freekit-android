"""Exercise complete and interrupted AGP-style Keystore reports."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).resolve().parents[1] / "verify-keystore-results.py"
spec = importlib.util.spec_from_file_location("keystore_results", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def passing_report():
    root = ET.Element("testsuites", tests="12", failures="0", errors="0", skipped="0")
    for name, methods in verifier.EXPECTED_METHODS.items():
        suite = ET.SubElement(root, "testsuite", name=name, tests=str(len(methods)), failures="0", errors="0", skipped="0")
        properties = ET.SubElement(suite, "properties")
        ET.SubElement(properties, "property", name="device", value="fixture-emulator")
        for method in sorted(methods):
            ET.SubElement(suite, "testcase", classname=name, name=method, time="0.001")
    return root


def update_counts(root):
    for suite in root.findall("testsuite"):
        suite.set("tests", str(len(suite.findall("testcase"))))
    root.set("tests", str(sum(int(suite.get("tests")) for suite in root)))


class KeystoreResultsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="freekit-keystore-results-")
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def write(self, root, name="TEST-device.xml"):
        target = self.directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        ET.ElementTree(root).write(target, encoding="utf-8", xml_declaration=True)
        return target

    def reject(self, root):
        self.write(root)
        with self.assertRaises(verifier.InvalidResults):
            verifier.verify_results(self.directory)

    def test_complete_agp_report_requires_twelve_cases_in_three_suites(self):
        self.write(passing_report(), "debug/TEST-device.xml")
        self.assertEqual(verifier.verify_results(self.directory),
                         {"reports": 1, "suites": 3, "tests": 12, "failures": 0, "errors": 0, "skipped": 0})

    def test_separate_suite_files_are_counted_once(self):
        for index, suite in enumerate(passing_report()):
            self.write(suite, f"TEST-class-{index}.xml")
        result = verifier.verify_results(self.directory)
        self.assertEqual((result["reports"], result["tests"]), (3, 12))

    def test_missing_directory_or_reports_cannot_pass(self):
        for directory in (self.directory, self.directory / "missing"):
            with self.subTest(directory=directory):
                with self.assertRaises(verifier.InvalidResults):
                    verifier.verify_results(directory)

    def test_missing_method_is_rejected_even_with_consistent_counters(self):
        root = passing_report()
        root[0].remove(root[0].find("testcase"))
        update_counts(root)
        self.reject(root)

    def test_duplicate_method_is_rejected_even_with_consistent_counters(self):
        root = passing_report()
        root[0].append(copy.deepcopy(root[0].find("testcase")))
        update_counts(root)
        self.reject(root)

    def test_unexpected_method_or_wrong_class_cannot_replace_an_expected_case(self):
        for attribute, value in (("name", "unexpectedMethod"), ("classname", "unexpected.Test")):
            with self.subTest(attribute=attribute):
                root = passing_report()
                root[0].find("testcase").set(attribute, value)
                self.reject(root)

    def test_extra_duplicate_and_empty_suites_are_rejected(self):
        for mode in ("extra", "duplicate", "empty", "missing"):
            with self.subTest(mode=mode):
                root = passing_report()
                if mode == "extra":
                    ET.SubElement(root, "testsuite", name="unexpected.Test", tests="0", failures="0", errors="0", skipped="0")
                elif mode == "duplicate":
                    root.append(copy.deepcopy(root[0]))
                elif mode == "empty":
                    for case in root[0].findall("testcase"):
                        root[0].remove(case)
                else:
                    root.remove(root[0])
                update_counts(root)
                self.reject(root)

    def test_second_copy_of_a_complete_report_cannot_pass(self):
        self.write(passing_report())
        self.write(passing_report(), "other/TEST-copy.xml")
        with self.assertRaises(verifier.InvalidResults):
            verifier.verify_results(self.directory)

    def test_failure_skip_and_crash_elements_are_rejected_even_with_zero_counters(self):
        for tag in ("failure", "error", "skipped"):
            for location in ("case", "suite"):
                with self.subTest(tag=tag, location=location):
                    root = passing_report()
                    target = root[0].find("testcase") if location == "case" else root[0]
                    ET.SubElement(target, tag, message="DO_NOT_PRINT_PRIVATE_DETAIL")
                    self.reject(root)

    def test_suite_and_aggregate_counters_must_agree_with_observed_cases(self):
        for target in ("suite", "aggregate"):
            for field, value in (("tests", "13"), ("failures", "1"), ("errors", "1"), ("skipped", "1")):
                with self.subTest(target=target, field=field):
                    root = passing_report()
                    (root[0] if target == "suite" else root).set(field, value)
                    self.reject(root)

    def test_missing_or_invalid_counters_do_not_default_to_zero(self):
        for target in ("suite", "aggregate"):
            for field in verifier.COUNTERS:
                for invalid in (None, "", "-1", "1.0", " 0", "unknown", "9" * 100):
                    with self.subTest(target=target, field=field, invalid=invalid):
                        root = passing_report()
                        element = root[0] if target == "suite" else root
                        if invalid is None:
                            del element.attrib[field]
                        else:
                            element.set(field, invalid)
                        self.reject(root)

    def test_empty_partial_malformed_and_oversized_xml_are_rejected(self):
        for content in (b"", b"<testsuites>", b"<testsuite", b"not XML", b" " * (verifier.MAX_REPORT_BYTES + 1)):
            with self.subTest(length=len(content)):
                (self.directory / "TEST-device.xml").write_bytes(content)
                with self.assertRaises(verifier.InvalidResults):
                    verifier.verify_results(self.directory)

    def test_unexpected_empty_or_nested_report_structures_are_rejected(self):
        for root in (ET.Element("report"), ET.Element("testsuites"), passing_report()):
            if root.tag == "testsuites" and len(root):
                ET.SubElement(root[0], "testsuite", name="nested")
            self.reject(root)

    def test_extra_cases_or_suites_hidden_in_metadata_are_rejected(self):
        for tag in ("testcase", "testsuite"):
            root = passing_report()
            ET.SubElement(root[0].find("properties"), tag, name="hidden")
            self.reject(root)

    def test_cli_returns_success_only_for_the_exact_contract_without_dumping_report_text(self):
        root = passing_report()
        self.write(root)
        command = [sys.executable, str(SCRIPT), "--results", str(self.directory), "--api", "26"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["tests"], 12)
        self.assertEqual(json.loads(result.stdout)["api"], 26)
        ET.SubElement(root[0].find("testcase"), "error", message="DO_NOT_PRINT_PRIVATE_DETAIL")
        self.write(root)
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("DO_NOT_PRINT_PRIVATE_DETAIL", result.stderr)


if __name__ == "__main__":
    unittest.main()
