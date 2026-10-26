"""Synthetic report replay only: these tests are not Android/device evidence."""
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

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-reference-tun-runtime.py'
SPEC = importlib.util.spec_from_file_location('reference_verifier', SCRIPT)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
SOURCE = 'a' * 40
CLASS = 'com.httpfreekit.interop.DraftReferenceTunInteropTest'
METHODS = ['selectedUidHttpReachesReferenceOriginThroughTun', 'selectedUidH1HttpsReachesReferenceOriginThroughTun']
PHASES = ['input-consumed', 'strict-csr-reserved', 'awaiting-host-approval', 'credential-saved-reloaded',
          'authenticated-ca-fetched', 'vpn-consent-granted', 'tun-native-active', 'selected-uid-route-observed',
          'traffic-command-started', 'traffic-response-validated', 'local-stream-drained', 'gateway-complete-acknowledged',
          'capture-stop-joined', 'non-vpn-route-observed', 'traffic-worker-joined', 'owned-state-forgotten']


def fixture(api=26, epoch=None):
    epoch = int(time.time()) if epoch is None else epoch
    def command():
        return dict(exitCode=0, signal=None, reason=None, closeObserved=True, processGroupClosed=True)
    methods = []
    for index, method in enumerate(METHODS):
        https = index == 1
        facts = dict(version=1, credentialSavedReloaded=True, keyNonexportable=True, originalCredentialUnchanged=True,
                     authenticatedCaFetched=True, separateTrafficUid=True, vpnConsentGranted=True, selectedUidVpnObserved=True,
                     tunAndNativeObserved=True, foregroundNotificationObserved=True, requestBodyValidated=True,
                     responseBodyValidated=True, outputHalfClosed=True, strictResponseEof=True, socketClosed=True,
                     localStreamsDrained=True, hostCompleteAcknowledged=True, captureStopped=True, tunClosed=True,
                     nativeStopJoined=True, configurationAbsent=True, lifecycleJoined=True, factoryClosed=True,
                     nonVpnRouteObserved=True, trafficWorkerJoined=True, consentUiDestroyed=True, ownedStateAbsent=True,
                     sessionLease=False, directTcpFlows=0, udpTargets=0, udp443Drops=0, protectFailures=0, bindFailures=0,
                     activeFlows=0, ownedSockets=0, pendingOpens=0, liveWorkers=0, factoryPendingOpens=0,
                     factoryPendingCalls=0, retainedTransports=0, factoryLiveWorkers=0, streamLeases=0, chargedBytes=0,
                     pendingIngressBytes=0, backendOutputBytes=0, backendIncomingBytes=0, trafficAttempts=1,
                     selectedPackageCount=1, interceptedTcpFlows=1, protectAttempts=2, protectSuccesses=2,
                     bindAttempts=2, bindSuccesses=2, responseBodyBytes=81, tlsUsed=https, tlsPeerVerified=https)
        completion = dict(phase='complete', streamResourcesReleased=True, clientEofEmitted=True, gatewayEofEmitted=True,
                          webSocketClosed=True, close1000Acknowledged=True, streamLease=False, sessionLease=True,
                          requestMatched=True, responseMatched=True, originModeMatched=True, chargedBytes=0,
                          controlChargedBytes=0, chargedFrames=0, streamLeases=0, pendingIngressBytes=0,
                          activeOwners=0, activeSockets=0, activeRequests=0, ownersCreated=1, ownersClosed=1,
                          upstreamDials=1, interceptedHttpRequests=int(not https), interceptedHttpsRequests=int(https),
                          upstreamHttpRequests=int(not https), upstreamHttpsRequests=int(https),
                          interceptionTlsHandshakes=int(https), upstreamTlsHandshakes=int(https),
                          rejectedPrefaces=0, requestBytes=4096, responseBytes=81)
        invocation = dict(method=method, state='passed', actualStarted=1, actualCompleted=1, terminalCount=1,
                          terminalCode=-1, phases=PHASES.copy(), command=command(), problems=[], failureType=None,
                          frames=[], observation=facts, failure=None)
        resources = dict(gateway=dict(admissionClosed=True, listenersClosed=True, storeClosed=True, issuerChildrenJoined=True,
                                      activeSockets=0, pendingCallbacks=0, pendingTimers=0, issuerJobs=0, signerGroups=0, workers=0),
                         process=dict(closeObserved=True, exitCode=0, signal=None, processGroupJoined=True, stdoutJoined=True,
                                      stderrJoined=True, stdinJoined=True, pendingWrites=0, pendingRequests=0, forced=False, failure=None),
                         reverseCommands=[command() for _ in range(3)], ownedReversesAbsent=True, privateDirectoryRemoved=True,
                         gatewayJoined=True, backendJoined=True, assetsJoined=True, ownedCommandsClosed=True, ownedCommandGroupsClosed=True)
        methods.append(dict(invocation=invocation,
                            input=dict(byteCount=1024, inputBytes=1024, inputFinished=True, inputClosed=True,
                                       command=command(), inputAbsentAfterMethod=True),
                            approval=dict(registered=True, livePhaseObserved=True, requested=True, completed=True),
                            host=dict(completion=completion, livePhaseObserved=True, completeObservedBeforeAck=True, androidAckPhaseObserved=True),
                            ack=dict(byteCount=34, inputBytes=34, inputFinished=True, inputClosed=True,
                                     command=command(), published=True, absentAfterMethod=True), resources=resources))
    runtime = dict(format='http-freekit-reference-tun-runtime', revision=1, source=dict(commit=SOURCE, trackedDirty=False), api=api,
                   clock=dict(deviceEpochSeconds=epoch, hostBeforeMillis=epoch*1000, hostAfterMillis=epoch*1000+10,
                              lowerBoundMillis=-10, upperBoundMillis=999, roundTripMillis=10), methods=methods,
                   apkSetup=dict(sameSigner=True, controlTrafficGranted=True,
                                 packages=[dict(package=name, initiallyAbsent=True, installAttempted=True, installed=True,
                                                uninstallConfirmed=True, absentAfterCleanup=True, installCommand=command(),
                                                forceStopCommand=command(), uninstallCommand=command()) for name in
                                           ['com.httpfreekit.capturetest', 'com.httpfreekit.capturetraffic']],
                                 permissions=dict(mode='not_required' if api == 26 else 'owned_ci_grant',
                                                  **{key: None if api == 26 else command() for key in
                                                     ['interopLocalNetwork', 'trafficLocalNetwork', 'interopNotification']})),
                   cleanup=dict(forceStopCommand=command(), uninstallCommand=command(), uninstallConfirmed=True,
                                packageAbsentAfterCleanup=True, ownedCommandsClosed=True, ownedCommandGroupsClosed=True), problems=[])
    host = dict(format='http-freekit-reference-tun-host-cleanup', revision=1, sourceCommit=SOURCE, api=api,
                driverExitCode=0, emulatorStarted=True, stopAttempted=True, stopExitCode=0,
                terminationObserved=True, joinObserved=True, emulatorExitCode=0)
    return runtime, host


def render(runtime):
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += f'<testsuite name="{CLASS}" tests="2" failures="0" errors="0" skipped="0">\n'
    xml += '\n'.join(f'<testcase classname="{CLASS}" name="{method}" time="0"></testcase>' for method in METHODS)
    xml += '\n</testsuite>\n'
    text = json.dumps(runtime, indent=2)
    for before, after in [('&', '&amp;'), ('<', '&lt;'), ('>', '&gt;'), ('"', '&quot;'), ("'", '&apos;')]:
        text = text.replace(before, after)
    html = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Reference TUN research</title><body><pre>'
    html += text + '</pre></body></html>\n'
    return xml.encode(), html.encode()


def leaves(value, path=()):
    if type(value) is dict:
        for key, child in value.items():
            yield from leaves(child, path + (key,))
    elif type(value) is list:
        for key, child in enumerate(value):
            yield from leaves(child, path + (key,))
    else:
        yield path, value


def replace(value, path, replacement):
    for part in path[:-1]:
        value = value[part]
    value[path[-1]] = replacement


class ReferenceTunTests(unittest.TestCase):
    def check(self, runtime, host, xml=None, html=None, **options):
        original_xml, original_html = render(runtime)
        return V.verify(runtime, host, original_xml if xml is None else xml, original_html if html is None else html,
                        SOURCE, runtime['api'], runtime['clock']['hostBeforeMillis']//1000, **options)

    def rejects(self, runtime, host, **options):
        with self.assertRaises((V.InvalidEvidence, ValueError, TypeError, KeyError)):
            self.check(runtime, host, **options)

    def test_two_exact_ordered_methods_api26_and37(self):
        for api in (26, 37):
            runtime, host = fixture(api)
            self.assertEqual(self.check(runtime, host), 2)
            self.assertEqual(len(runtime['methods'][0]['invocation']['observation']), 56)
            for item in runtime['methods']:
                for key in ['protectAttempts', 'protectSuccesses', 'bindAttempts', 'bindSuccesses']:
                    item['invocation']['observation'][key] = 3
            self.assertEqual(self.check(runtime, host), 2)

    def test_each_serialized_runtime_leaf_is_independently_required(self):
        good, host = fixture()
        for path, original in leaves(good):
            with self.subTest(path=path):
                runtime = copy.deepcopy(good)
                changed = not original if type(original) is bool else original + 1 if type(original) is int else 'CANARY_PRIVATE'
                replace(runtime, path, changed)
                self.rejects(runtime, host)

    def test_every_host_complete_fact_mutation_missing_extra_and_type_reject(self):
        for index in (0, 1):
            runtime, host = fixture()
            completion = runtime['methods'][index]['host']['completion']
            for key, original in completion.items():
                for replacement in [None, 'CANARY_PROVIDER', 1 if type(original) is bool else True]:
                    changed = copy.deepcopy(runtime)
                    changed['methods'][index]['host']['completion'][key] = replacement
                    self.rejects(changed, host)
            for key in completion:
                changed = copy.deepcopy(runtime); del changed['methods'][index]['host']['completion'][key]
                self.rejects(changed, host)
        runtime, host = fixture(); runtime['methods'][0]['host']['completion']['gatewaySessionLeases'] = 1
        self.rejects(runtime, host)

    def test_missing_extra_keys_at_every_object_reject(self):
        good, host = fixture()
        def objects(value, path=()):
            if type(value) is dict:
                yield path, value
                for key, child in value.items():
                    yield from objects(child, path + (key,))
            elif type(value) is list:
                for key, child in enumerate(value):
                    yield from objects(child, path + (key,))
        for path, obj in objects(good):
            for mode in ('missing', 'extra'):
                changed = copy.deepcopy(good); target = changed
                for part in path:
                    target = target[part]
                if mode == 'missing':
                    del target[next(iter(obj))]
                else:
                    target['CANARY_IDENTITY'] = 'private'
                self.rejects(changed, host)

    def test_types_empty_collections_method_order_phases_and_cross_method_reject(self):
        runtime, host = fixture()
        for path, value in leaves(runtime):
            if type(value) in (bool, int):
                changed = copy.deepcopy(runtime)
                replace(changed, path, int(value) if type(value) is bool else bool(value))
                self.rejects(changed, host)
        for mutate in [lambda r: r['methods'].reverse(),
                       lambda r: r['methods'][0]['invocation']['phases'].reverse(),
                       lambda r: r['methods'][0]['invocation']['phases'].pop(),
                       lambda r: r['methods'][0]['invocation']['phases'].append('owned-state-forgotten'),
                       lambda r: r['methods'][0]['invocation']['problems'].append('instrumentation_command_failed'),
                       lambda r: r['methods'][0]['invocation']['frames'].append({}),
                       lambda r: r['problems'].append('enrollment_cleanup_failed'),
                       lambda r: r['methods'][0].update(host=r['methods'][1]['host']),
                       lambda r: r['methods'][0]['invocation'].update(observation=r['methods'][1]['invocation']['observation']),
                       lambda r: r['methods'][0]['resources']['reverseCommands'].pop()]:
            changed = copy.deepcopy(runtime); mutate(changed); self.rejects(changed, host)

    def test_host_cleanup_schema_source_and_join_are_exact(self):
        runtime, good = fixture()
        for path, original in leaves(good):
            host = copy.deepcopy(good)
            replace(host, path, None)
            self.rejects(runtime, host)
            host = copy.deepcopy(good); del host[path[0]]; self.rejects(runtime, host)
        for changes in [dict(sourceCommit='b'*40), dict(api=37), dict(driverExitCode=1), dict(emulatorExitCode=127),
                        dict(stopExitCode=-1), dict(stopExitCode=True), dict(emulatorExitCode=256),
                        dict(joinObserved=1), dict(extra='CANARY')]:
            self.rejects(runtime, dict(good, **changes))
        # The workflow can fall back to kill/wait after adb emu kill fails.
        self.assertEqual(self.check(runtime, dict(good, stopExitCode=124, emulatorExitCode=143)), 2)

    def test_clock_source_age_bounds_and_quantization(self):
        runtime, host = fixture(epoch=1700000000)
        self.assertEqual(self.check(runtime, host, now=1700000001), 2)
        with self.assertRaises(V.InvalidEvidence):
            V.verify(runtime, host, *render(runtime), SOURCE, 26, 1700000100, now=1700000101)
        with self.assertRaises(V.InvalidEvidence):
            V.verify(runtime, host, *render(runtime), SOURCE, 26, 1700000000, now=1699999990)
        for mutate in [lambda r: r['source'].update(commit='b'*40), lambda r: r['source'].update(trackedDirty=True),
                       lambda r: r['clock'].update(roundTripMillis=2001), lambda r: r['clock'].update(lowerBoundMillis=-2001),
                       lambda r: r['clock'].update(upperBoundMillis=2001), lambda r: r['clock'].update(deviceEpochSeconds=1700000002)]:
            changed = copy.deepcopy(runtime); mutate(changed); self.rejects(changed, host, now=1700000001)

    def test_strict_bounded_duplicate_rejecting_json(self):
        invalid = [b'', b'\xff', b'\xef\xbb\xbf{}', b'{"x":1,"x":2}', b'{"x":{},"x":{}}',
                   b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.0}', b'{"x":1e0}', b'{"x":99999999999999999}',
                   b'['*2000+b']'*2000, b'{} trailing', b'\0{}', b' '*131073]
        for data in invalid:
            with self.subTest(data=data[:40]), self.assertRaises(V.InvalidEvidence):
                V.load_json(data)
        self.assertEqual(V.load_json(b'{"x":0}'), {'x': 0})

    def test_xml_guards_and_html_exact_cross_artifact_replay(self):
        runtime, host = fixture(); xml, html = render(runtime)
        for altered in [xml.replace(b'tests="2"', b'tests="3"'), xml.replace(METHODS[0].encode(), METHODS[1].encode()),
                        xml.replace(b'</testcase>', b'<skipped/></testcase>', 1),
                        b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///CANARY">]>'+xml,
                        xml.replace(b'</testsuite>', b'<testcase/></testsuite>'), xml+b'<!--CANARY-->',
                        xml.replace(b'encoding="UTF-8"', b'encoding="UTF-16"'), b'x'*131073]:
            self.rejects(runtime, host, xml=altered)
        different = copy.deepcopy(runtime); different['source']['commit'] = 'b'*40
        for altered in [render(different)[1], html.replace(b'<pre>', b'<pre><script>CANARY</script>'),
                        html.replace(b'&quot;revision&quot;: 1', b'&quot;revision&quot;: true'),
                        html.replace(b'&quot;revision&quot;: 1', b'&quot;revision&quot;: 1, &quot;revision&quot;: 1'),
                        html.replace(b'&quot;', b'&#34;', 1), html+b'<script>CANARY</script>', b'x'*131073]:
            self.rejects(runtime, host, html=altered)

    def test_files_bound_fresh_regular_no_symlinks_or_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); path = base/'report'; path.write_bytes(b'{}'); started = int(time.time())
            self.assertEqual(V.read_file(path, 2, started), b'{}')
            for cap in (0, 1):
                with self.assertRaises(V.InvalidEvidence): V.read_file(path, cap, started)
            for stamp in (started-60, started+60):
                os.utime(path, (stamp, stamp))
                with self.assertRaises(V.InvalidEvidence): V.read_file(path, 2, started)
            path.unlink(); path.symlink_to(base/'absent')
            with self.assertRaises(OSError): V.read_file(path, 2, started)
            path.unlink(); path.write_bytes(b'{}')
            link = base/'link'; link.symlink_to(base, target_is_directory=True)
            with self.assertRaises(OSError): V.read_file(link/'report', 2, started)
            fifo = base/'fifo'; os.mkfifo(fifo)
            with self.assertRaises(V.InvalidEvidence): V.read_file(fifo, 2, started)
            with self.assertRaises(V.InvalidEvidence): V.read_file(base, 2, started)
            with self.assertRaises(V.InvalidEvidence): V.read_file(Path('report'), 2, started)

    def cli(self, args):
        return subprocess.run([sys.executable, '-I', str(SCRIPT), *args], cwd=SCRIPT.parent.parent,
                              capture_output=True, timeout=10)

    def test_actual_cli_original_four_files_pass_and_fail_without_payload_leak(self):
        for api in (26, 37):
            runtime, host = fixture(api); xml, html = render(runtime); started = int(time.time())
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                # Poison Python imports in the untrusted artifact directory. Never execute there.
                (base/'json.py').write_text('raise RuntimeError("CANARY_IMPORT")')
                files = dict(runtime=json.dumps(runtime).encode(), host=json.dumps(host).encode(), xml=xml, html=html)
                args = ['--source', SOURCE, '--api', str(api), '--started', str(started)]
                for name, data in files.items():
                    path = base/name; path.write_bytes(data); args.extend(['--'+name, str(path)])
                result = self.cli(args)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertIn(b'2 actual methods', result.stdout)
                for name, invalid in [('runtime', b'{"CANARY_IDENTITY":"private","x":1,"x":2}'),
                                      ('host', b'{"CANARY_PROVIDER":"private"}'), ('xml', b'<CANARY/>'), ('html', b'<script>CANARY</script>')]:
                    path = base/name; original = path.read_bytes(); path.write_bytes(invalid)
                    result = self.cli(args)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, b'Reference TUN verification failed.\n'); self.assertEqual(result.stderr, b'')
                    path.write_bytes(original)
                for name in files:
                    path = base/name; os.utime(path, (started-60, started-60))
                    self.assertEqual(self.cli(args).returncode, 1)
                    os.utime(path, None)
                (base/'host').unlink()
                self.assertEqual(self.cli(args).returncode, 1)
        for args in [['--CANARY_PROVIDER'], ['--source', 'CANARY'],
                     ['--source', SOURCE, '--api', 'CANARY', '--started', '1']]:
            result = self.cli(args)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'CANARY', result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
