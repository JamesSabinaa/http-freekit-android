"""Require the complete, passing Android Keystore instrumentation contract."""
import argparse
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


EXPECTED_METHODS = {
    "com.httpfreekit.security.AndroidDeviceIdentityStoreTest": frozenset((
        "nonexportableIdentitySurvivesReopenSignsAndCanBeForgotten",
        "creationNeverSilentlyReplacesAnExistingComputerKey",
        "concurrentStoreInstancesCannotReplaceTheWinningKey",
        "freshIdentityAuthorizesPrehashedTlsSigningWithoutExportingItsKey",
        "legacySha256OnlyIdentityRequiresPairingAgainWithoutReplacement",
    )),
    "com.httpfreekit.security.AndroidDeviceClientCredentialTest": frozenset((
        "nonexportableKeyAuthenticatesWithIssuedChainWithoutReplacingItsKeystoreCertificate",
        "deletedOrRecreatedAliasCannotBeSelectedByTheOldCredential",
    )),
    "com.httpfreekit.security.AndroidEnrolledCredentialStoreTest": frozenset((
        "reopenedPublicRecordUsesTheOriginalNonexportableKeyWithoutReplacingItsCertificate",
        "missingReplacedAndLegacyKeysCannotReopenOrPreventForget",
        "interruptedAndCorruptRecordsNeverGenerateOrReplaceTheExistingKey",
        "failedMetadataCleanupLeavesTheDeletedKeyUnusableAndCanBeRetried",
        "separateStoreInstancesSerializePublicationAndForgetWithTheIdentityMonitor",
    )),
    "com.httpfreekit.security.AndroidOriginalDeviceEvidenceTest": frozenset((
        "originalPublicEvidenceSurvivesReopenAndCopiesCannotMutateIt",
        "absentAndDeletedIdentityEvidenceNeverCreatesOrReplacesAKey",
        "evidenceRemainsBoundToTheRequestedComputer",
    )),
}
EXPECTED_CASES = frozenset((name, method) for name, methods in EXPECTED_METHODS.items() for method in methods)
COUNTERS = ("tests", "failures", "errors", "skipped")
MAX_REPORT_BYTES = 2 * 1024 * 1024


class InvalidResults(ValueError):
    """A static diagnostic; never include report contents or exception messages."""


def counters(element):
    values = {}
    for field in COUNTERS:
        value = element.get(field, "")
        if len(value) > 10 or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
            raise InvalidResults("Missing or invalid JUnit counters")
        values[field] = int(value)
    return values


def verify_results(directory):
    directory = Path(directory)
    if not directory.is_dir():
        raise InvalidResults("Instrumentation result directory is missing")
    reports = sorted(directory.rglob("*.xml"))
    if not reports:
        raise InvalidResults("No instrumentation XML reports were produced")
    seen_cases, seen_suites = set(), set()
    for report in reports:
        try:
            with report.open("rb") as stream:
                content = stream.read(MAX_REPORT_BYTES + 1)
            if len(content) > MAX_REPORT_BYTES:
                raise InvalidResults("Instrumentation XML report exceeds the size limit")
            root = ET.fromstring(content)
        except (OSError, ET.ParseError):
            raise InvalidResults("Instrumentation XML report is unreadable or malformed") from None
        if root.tag == "testsuite":
            suites = [root]
        elif root.tag == "testsuites" and len(root) and all(child.tag == "testsuite" for child in root):
            suites = list(root)
        else:
            raise InvalidResults("Unexpected or empty JUnit report structure")
        report_totals = dict.fromkeys(COUNTERS, 0)
        for suite in suites:
            name = suite.get("name")
            if name not in EXPECTED_METHODS or name in seen_suites:
                raise InvalidResults("Unexpected or duplicate Keystore test suite")
            seen_suites.add(name)
            if any(child.tag not in ("properties", "testcase", "system-out", "system-err") for child in suite):
                raise InvalidResults("Unexpected JUnit suite result or structure")
            if any(element.tag in ("failure", "error", "skipped") for element in suite.iter()):
                raise InvalidResults("A Keystore testcase failed, crashed, or was skipped")
            cases = suite.findall("testcase")
            if suite.findall(".//testsuite") or len(list(suite.iter("testcase"))) != len(cases):
                raise InvalidResults("Unexpected nested JUnit suite or testcase")
            if not cases:
                raise InvalidResults("A Keystore test suite is empty")
            declared = counters(suite)
            actual = {"tests": len(cases), "failures": 0, "errors": 0, "skipped": 0}
            if declared != actual:
                raise InvalidResults("JUnit suite counters disagree with passing testcases")
            for case in cases:
                identity = (case.get("classname"), case.get("name"))
                if identity[0] != name or identity not in EXPECTED_CASES or identity in seen_cases:
                    raise InvalidResults("Missing, unexpected, or duplicate Keystore testcase identity")
                if any(child.tag not in ("system-out", "system-err") for child in case):
                    raise InvalidResults("Unexpected JUnit testcase result or structure")
                seen_cases.add(identity)
            for field in COUNTERS:
                report_totals[field] += declared[field]
        if root.tag == "testsuites" and counters(root) != report_totals:
            raise InvalidResults("JUnit aggregate counters disagree with its suites")
    if seen_cases != EXPECTED_CASES or seen_suites != set(EXPECTED_METHODS):
        raise InvalidResults("The exact fifteen Keystore testcases did not execute")
    return {"reports": len(reports), "suites": len(seen_suites), "tests": len(seen_cases),
            "failures": 0, "errors": 0, "skipped": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--api", required=True, type=int, choices=(26, 37))
    args = parser.parse_args()
    try:
        summary = verify_results(args.results)
    except InvalidResults as failure:
        print(f"Keystore result verification failed: {failure}", file=sys.stderr)
        return 1
    print(json.dumps({"api": args.api, **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
