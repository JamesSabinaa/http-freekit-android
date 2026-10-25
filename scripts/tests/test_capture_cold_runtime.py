import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-capture-cold-runtime.py'
SPEC = importlib.util.spec_from_file_location('cold_verifier', SCRIPT)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
SOURCE = 'a' * 40


def fixture():
    before = dict.fromkeys(V.CUMULATIVE + V.OWNED, 0); before.update(listeners=7, closed=False)
    after = dict(before, directHttp=1, tcpConnections=1, uploadBytes=16528, downloadBytes=32787)
    observation = dict(coldVersion='1', coldScenario='cold-http', coldOwnerAbsentBefore='true', coldOwnerAbsentAfter='true',
        coldRouteObserved='true', coldHttpAttempts='1', coldTrafficCommand='10', coldTrafficStatus='0', coldTrafficBytes='32787',
        coldTrafficSha256='05dfd86ee3ecc0267ceb6234e1955c1e8c80e34b6323b2b1c87c7d1d84042255',
        coldFailurePhase='none', coldFailureCode='none', coldCleanupJoined='true')
    invocation = dict(method='coldUnboundHttpRequiresStrictEof', state='passed', actualStarted=1, actualCompleted=1,
        terminalCount=1, terminalCode=-1, observation=observation, failure=None,
        command=dict(exitCode=0, signal=None, closeObserved=True, processGroupClosed=True, reason=None), problems=[])
    runtime = dict(format='http-freekit-capture-cold-tcp', revision=1, source=dict(commit=SOURCE, trackedDirty=False), api=26,
        clock=dict(deviceEpochSeconds=1700000000, hostBeforeMillis=1700000000000, hostAfterMillis=1700000000010,
                   roundTripMillis=10, lowerBoundMillis=-10, upperBoundMillis=999),
        method=dict(invocation=invocation, receiversBefore=before, receiversAfter=after),
        cleanup=dict(forceStopExitCodes=[0,0,0], uninstallExitCodes=[0,0,0], packagesAbsent=True,
                     ownedCommandsClosed=True, ownedCommandGroupsClosed=True, receivers=dict(after, listeners=0, closed=True)),
        problems=[], accepted=True)
    host = dict(format='http-freekit-capture-cold-host-cleanup', revision=1, sourceCommit=SOURCE, api=26,
        driverExitCode=0, emulatorStarted=True, stopAttempted=True, stopExitCode=0,
        terminationObserved=True, joinObserved=True, emulatorExitCode=0)
    return runtime, host


def render(runtime):
    root = ET.Element('testsuite', dict(name='capture-cold-tcp', tests='1', failures='0', errors='0', skipped='0'))
    props = ET.SubElement(root, 'properties')
    for name, value in dict(sourceCommit=SOURCE, sourceDirty='false', api='26').items():
        ET.SubElement(props, 'property', dict(name=name, value=value))
    invocation = runtime['method']['invocation']
    case = ET.SubElement(root, 'testcase', dict(classname=V.CLASS, name=invocation['method'], time='0'))
    props = ET.SubElement(case, 'properties')
    for name, value in dict(actualStarted='1', actualCompleted='1', **invocation['observation']).items():
        ET.SubElement(props, 'property', dict(name=name, value=value))
    return ET.tostring(root, encoding='utf-8')


class ColdRuntimeTests(unittest.TestCase):
    def rejects(self, runtime, host, xml=None):
        with self.assertRaises((V.InvalidCapture, ET.ParseError)):
            V.verify(runtime, host, render(runtime) if xml is None else xml, SOURCE)

    def test_exact_one_cold_transaction_with_independent_full_byte_vector(self):
        runtime, host = fixture()
        self.assertEqual(V.verify(runtime, host, render(runtime), SOURCE), 1)

    def test_full_host_reply_never_turns_eof_reset_into_a_pass(self):
        runtime, host = fixture(); invocation = runtime['method']['invocation']
        invocation['observation'].update(coldTrafficStatus='3', coldTrafficBytes='0', coldTrafficSha256='none',
                                        coldFailurePhase='http', coldFailureCode='traffic_tcp_eof_reset')
        self.rejects(runtime, host)
        invocation.update(state='failed', failure=dict(phase='http', code='traffic_tcp_eof_reset'), problems=['instrumentation_failed'])
        runtime['accepted'] = False
        self.rejects(runtime, host)

    def test_actual_pair_terminal_command_and_failure_truth_are_mandatory(self):
        changes = [lambda i: i.update(method='selectedTcpUsesTunAndNonselectedUidBypasses'),
                   lambda i: i.update(actualStarted=0), lambda i: i.update(actualCompleted=2),
                   lambda i: i.update(terminalCount=0), lambda i: i.update(terminalCode=0),
                   lambda i: i.update(failure=dict(phase='http', code='cold_tcp_reply')),
                   lambda i: i['command'].update(closeObserved=False),
                   lambda i: i['command'].update(processGroupClosed=False),
                   lambda i: i['command'].update(reason='owned_command_failed')]
        for change in changes:
            runtime, host = fixture(); change(runtime['method']['invocation']); self.rejects(runtime, host)

    def test_every_counter_and_before_after_cleanup_vector_is_exact(self):
        for field in V.CUMULATIVE + V.OWNED:
            for scope in ['before', 'after', 'cleanup']:
                runtime, host = fixture()
                target = runtime['cleanup']['receivers'] if scope == 'cleanup' else runtime['method']['receiversBefore' if scope == 'before' else 'receiversAfter']
                target[field] += 1; self.rejects(runtime, host)
        runtime, host = fixture()
        runtime['method']['receiversAfter']['tcpResetErrors'] = 1
        self.rejects(runtime, host)

    def test_boolean_numeric_substitutions_and_unknown_material_reject(self):
        for change in [lambda r,h: r.update(api=True), lambda r,h: r['method']['invocation'].update(actualStarted=True),
                       lambda r,h: r['method']['receiversAfter'].update(directHttp=True),
                       lambda r,h: r['cleanup']['uninstallExitCodes'].__setitem__(0, False),
                       lambda r,h: h.update(joinObserved=1)]:
            runtime, host = fixture(); change(runtime, host); self.rejects(runtime, host)
        for target in ['root','observation','receiver','command','cleanup','host']:
            runtime, host = fixture()
            scopes = dict(root=runtime, observation=runtime['method']['invocation']['observation'], receiver=runtime['method']['receiversAfter'],
                          command=runtime['method']['invocation']['command'], cleanup=runtime['cleanup'], host=host)
            scopes[target]['CANARY'] = 'private'; self.rejects(runtime, host)

    def test_no_owner_route_or_client_cleanup_claim_can_be_omitted(self):
        for field in ['coldOwnerAbsentBefore','coldOwnerAbsentAfter','coldRouteObserved','coldCleanupJoined']:
            runtime, host = fixture(); runtime['method']['invocation']['observation'][field]='false'; self.rejects(runtime, host)
        for field,value in [('coldHttpAttempts','2'),('coldTrafficCommand','18'),('coldTrafficBytes','32786'),('coldTrafficSha256','none')]:
            runtime, host = fixture(); runtime['method']['invocation']['observation'][field]=value; self.rejects(runtime, host)

    def test_source_clock_quantization_and_api_are_independently_bound(self):
        for change in [lambda r: r['source'].update(trackedDirty=True), lambda r: r['source'].update(commit='b'*40),
                       lambda r: r.update(api=37), lambda r: r['clock'].update(upperBoundMillis=2001),
                       lambda r: r['clock'].update(lowerBoundMillis=-2001), lambda r: r['clock'].update(roundTripMillis=11),
                       lambda r: r['clock'].update(deviceEpochSeconds=1700000002)]:
            runtime, host = fixture(); change(runtime); self.rejects(runtime, host)

    def test_package_process_and_emulator_joins_require_actual_success(self):
        for change in [lambda r,h: r['cleanup'].update(packagesAbsent=False), lambda r,h: r['cleanup'].update(forceStopExitCodes=[0,0]),
                       lambda r,h: r['cleanup']['uninstallExitCodes'].__setitem__(2,124),
                       lambda r,h: r['cleanup'].update(ownedCommandsClosed=False), lambda r,h: r['cleanup'].update(ownedCommandGroupsClosed=False),
                       lambda r,h: h.update(driverExitCode=None), lambda r,h: h.update(stopExitCode=9),
                       lambda r,h: h.update(emulatorExitCode=137), lambda r,h: h.update(terminationObserved=False)]:
            runtime, host = fixture(); change(runtime, host); self.rejects(runtime, host)

    def test_xml_cannot_add_foreign_identity_properties_text_or_entities(self):
        runtime, host = fixture(); xml=render(runtime)
        for altered in [xml.replace(V.CLASS.encode(),b'foreign.Class'), xml.replace(b'tests="1"',b'tests="2"'),
                        xml.replace(b'<properties>',b'<properties>CANARY',1),
                        xml.replace(b'</testcase>',b'<skipped /></testcase>'),
                        b'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///private">]>'+xml]:
            self.rejects(runtime, host, altered)
        document=ET.fromstring(xml); document[1][0].append(copy.deepcopy(document[1][0][0]))
        self.rejects(runtime, host, ET.tostring(document))

    def test_real_file_bounds_freshness_and_links_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report'; path.write_bytes(b'{}'); now=int(time.time())
            self.assertEqual(V.read_file(path,2,now),b'{}')
            with self.assertRaises(V.InvalidCapture): V.read_file(path,1,now)
            os.utime(path,(now-60,now-60))
            with self.assertRaises(V.InvalidCapture): V.read_file(path,2,now)
            if os.name!='nt':
                link=Path(directory)/'link'; link.symlink_to(path)
                with self.assertRaises(V.InvalidCapture): V.read_file(link,2,now-120)

    def test_duplicate_nonfinite_huge_numbers_and_cli_errors_are_redacted(self):
        for data in [b'{"CANARY":1,"CANARY":2}', b'{"x":NaN}', b'\xff', ('{"x":'+'9'*5000+'}').encode()]:
            with self.assertRaises(V.InvalidCapture) as error: V.load_json(data)
            self.assertNotIn('CANARY',str(error.exception))
        result=subprocess.run([sys.executable,str(SCRIPT),'--source','CANARY_private','--api','37','--started','1'],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(result.returncode,0); self.assertNotIn('CANARY',result.stdout+result.stderr)

    def test_actual_cli_accepts_only_fresh_exact_three_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); scripts=root/'scripts'; scripts.mkdir(); script=scripts/SCRIPT.name; shutil.copyfile(SCRIPT,script)
            reports=root/'build/reports/capture-cold-tcp'; reports.mkdir(parents=True)
            runtime,host=fixture()
            for name,value in [('runtime.json',runtime),('host-cleanup.json',host)]: (reports/name).write_text(json.dumps(value))
            (reports/'TEST-capture-cold-tcp.xml').write_bytes(render(runtime))
            args=[sys.executable,str(script),'--source',SOURCE,'--api','26','--started',str(int(time.time()))]
            good=subprocess.run(args,capture_output=True,text=True,timeout=5)
            self.assertEqual(good.returncode,0,good.stdout+good.stderr)
            (reports/'extra.log').write_text('CANARY_private')
            extra=subprocess.run(args,capture_output=True,text=True,timeout=5)
            self.assertEqual(extra.returncode,1); self.assertNotIn('CANARY',extra.stdout+extra.stderr)
            (reports/'extra.log').unlink()
            runtime['method']['invocation']['observation']['coldFailureCode']='traffic_tcp_eof_reset'
            (reports/'runtime.json').write_text(json.dumps(runtime))
            bad=subprocess.run(args,capture_output=True,text=True,timeout=5)
            self.assertEqual(bad.returncode,1); self.assertEqual(bad.stdout.strip(),'Cold TCP comparison verification failed.')


if __name__ == '__main__':
    unittest.main()
