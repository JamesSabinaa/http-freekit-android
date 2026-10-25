import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-capture-runtime.py'
SPEC = importlib.util.spec_from_file_location('capture_verifier', SCRIPT)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
SOURCE = 'a' * 40


def snapshot():
    return dict(dict.fromkeys(V.SNAPSHOT - {'closed'}, 0), closed=False)


def fixture(api=26):
    definitions = ([V.PERMISSION] if api == 37 else []) + V.CASES
    runtime = dict(format='http-freekit-capture-runtime', revision=1, source=dict(commit=SOURCE, trackedDirty=False), api=api,
                   clock=dict(deviceEpochSeconds=1700000000, hostBeforeMillis=1700000000000, hostAfterMillis=1700000000010, roundTripMillis=10, lowerBoundMillis=-10, upperBoundMillis=999),
                   permissionSetup=dict(required=api == 37, mode='owned_ci_grant' if api == 37 else 'not_required', hostGrantExitCode=0 if api == 37 else None, trafficGrantExitCode=0 if api == 37 else None),
                   methods=[], cleanup={}, problems=[], accepted=True)
    previous = snapshot()
    for definition in definitions:
        before, after = dict(previous), dict(previous)
        if definition != V.PERMISSION:
            counts = [dict(interceptedHttp=1, interceptedOpaque=1, directHttp=1, directOpaque=1, tcpConnections=4), dict(directTcp=1, udp=1, dns=1, udp443=1, tcpConnections=1, udpDatagrams=3), dict(interceptedIpv6=1, tcpConnections=1), dict(heldRequestsClosed=1, interceptedHttp=1, tcpConnections=2), {}][V.CASES.index(definition)]
            for key, count in counts.items():
                after[key] += count
        invocation = dict(method=definition[0], state='passed', actualStarted=1, actualCompleted=1, terminalCount=1, terminalCode=-1,
                          observation=V.facts(definition, api, 'true'), failure=None,
                          command=dict(exitCode=0, signal=None, closeObserved=True, processGroupClosed=True, reason=None), problems=[])
        runtime['methods'].append(dict(invocation=invocation, receiversBefore=before, receiversAfter=after)); previous = after
    runtime['cleanup'] = dict(forceStopExitCodes=[0] * 4, uninstallExitCodes=[0] * 4, packagesAbsent=True, ownedCommandsClosed=True, ownedCommandGroupsClosed=True, receivers=dict(previous, closed=True))
    host = dict(format='http-freekit-capture-host-cleanup', revision=1, sourceCommit=SOURCE, api=api, driverExitCode=0, emulatorStarted=True, stopAttempted=True, stopExitCode=0, terminationObserved=True, joinObserved=True, emulatorExitCode=0)
    return runtime, host


def render(runtime):
    root = ET.Element('testsuite', dict(name='capture-research', tests=str(len(runtime['methods'])), failures='0', errors='0', skipped='0'))
    props = ET.SubElement(root, 'properties')
    for name, value in dict(sourceCommit=SOURCE, sourceDirty='false', api=str(runtime['api'])).items():
        ET.SubElement(props, 'property', dict(name=name, value=value))
    for entry in runtime['methods']:
        invocation = entry['invocation']
        case = ET.SubElement(root, 'testcase', dict(classname=V.CLASS, name=invocation['method'], time='0'))
        props = ET.SubElement(case, 'properties')
        for name, value in dict(actualStarted='1', actualCompleted='1', **invocation['observation']).items():
            ET.SubElement(props, 'property', dict(name=name, value=value))
    return ET.tostring(root, encoding='utf-8')


class CaptureRuntimeTests(unittest.TestCase):
    def rejects(self, runtime, host, xml=None):
        with self.assertRaises((V.InvalidCapture, ET.ParseError)):
            V.verify(runtime, host, render(runtime) if xml is None else xml, SOURCE, runtime['api'])

    def test_independent_complete_five_and_six_method_shapes(self):
        for api in [26, 37]:
            runtime, host = fixture(api)
            self.assertEqual(V.verify(runtime, host, render(runtime), SOURCE, api), 5 if api == 26 else 6)

    def test_bool_cannot_substitute_numbers_or_actual_join_flags(self):
        mutations = [lambda r, h: r['methods'][0]['invocation'].__setitem__('actualStarted', True),
                     lambda r, h: r['methods'][0]['receiversAfter'].__setitem__('tcpConnections', True),
                     lambda r, h: r['clock'].__setitem__('roundTripMillis', True),
                     lambda r, h: h.__setitem__('joinObserved', 1)]
        for change in mutations:
            runtime, host = fixture(); change(runtime, host); self.rejects(runtime, host)

    def test_missing_reordered_or_duplicate_invocations_do_not_pass(self):
        for change in [lambda r: r['methods'].pop(), lambda r: r['methods'].reverse(), lambda r: r['methods'].__setitem__(1, copy.deepcopy(r['methods'][0])), lambda r: r['methods'][0]['invocation'].__setitem__('terminalCount', 0)]:
            runtime, host = fixture(); change(runtime); self.rejects(runtime, host)

    def test_wrong_paths_resets_and_no_connect_counters_reject(self):
        for index, name in [(0, 'dns'), (1, 'interceptedHttp'), (4, 'tcpConnections'), (1, 'udpDatagrams')]:
            runtime, host = fixture(); runtime['methods'][index]['receiversAfter'][name] += 1; self.rejects(runtime, host)
        runtime, host = fixture(); runtime['methods'][1]['receiversBefore']['directHttp'] = 0; self.rejects(runtime, host)

    def test_denial_case_is_required_and_cannot_create_factory_or_tun(self):
        for key, value in [('captureFactoryCalls', '1'), ('captureTunEstablished', 'true'), ('captureCaptureOwnerAbsent', 'false')]:
            runtime, host = fixture(37); runtime['methods'][0]['invocation']['observation'][key] = value; self.rejects(runtime, host)
        runtime, host = fixture(37); runtime['permissionSetup']['hostGrantExitCode'] = 1; self.rejects(runtime, host)

    def test_clock_source_permission_and_cleanup_cannot_be_asserted_by_summary(self):
        changes = [lambda r, h: r['source'].__setitem__('trackedDirty', True), lambda r, h: r['clock'].__setitem__('upperBoundMillis', 2001),
                   lambda r, h: r['cleanup']['uninstallExitCodes'].__setitem__(2, 124), lambda r, h: r['cleanup']['receivers'].__setitem__('pendingCallbacks', 1),
                   lambda r, h: h.__setitem__('terminationObserved', False), lambda r, h: h.__setitem__('emulatorExitCode', 127)]
        for change in changes:
            runtime, host = fixture(); change(runtime, host); self.rejects(runtime, host)

    def test_unknown_fields_payload_canaries_and_xml_identity_fail(self):
        for target in ['root', 'observation', 'command', 'receiver']:
            runtime, host = fixture()
            selected = {'root': runtime, 'observation': runtime['methods'][0]['invocation']['observation'], 'command': runtime['methods'][0]['invocation']['command'], 'receiver': runtime['cleanup']['receivers']}[target]
            selected['CANARY'] = 'private'; self.rejects(runtime, host)
        runtime, host = fixture(); xml = render(runtime)
        self.rejects(runtime, host, xml.replace(V.CLASS.encode(), b'foreign.Class'))
        self.rejects(runtime, host, b'<!DOCTYPE x [<!ENTITY material SYSTEM "file:///private">]>' + xml)

    def test_actual_file_bounds_freshness_and_link_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'; path.write_bytes(b'{}'); now = int(time.time())
            self.assertEqual(V.read_file(path, 32, now), b'{}')
            with self.assertRaises(V.InvalidCapture): V.read_file(path, 1, now)
            os.utime(path, (now - 60, now - 60))
            with self.assertRaises(V.InvalidCapture): V.read_file(path, 32, now)
            if os.name != 'nt':
                link = Path(directory) / 'link.json'; link.symlink_to(path)
                with self.assertRaises(V.InvalidCapture): V.read_file(link, 32, now - 120)

    def test_duplicate_nonfinite_huge_integer_json_and_actual_cli_are_redacted(self):
        for data in [b'{"CANARY":1,"CANARY":2}', b'{"x":NaN}', ('{"x":' + '9' * 5000 + '}').encode(), b'\xff']:
            with self.assertRaises(V.InvalidCapture) as error: V.load_json(data)
            self.assertNotIn('CANARY', str(error.exception))
        result = subprocess.run([sys.executable, str(SCRIPT), '--source', 'CANARY_private', '--api', '26', '--started', '1'], capture_output=True, timeout=5, text=True)
        self.assertEqual(result.returncode, 1); self.assertNotIn('CANARY', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
