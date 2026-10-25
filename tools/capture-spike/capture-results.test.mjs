import test from 'node:test';
import assert from 'node:assert/strict';
import { captureCases, capturePermissionCase, captureClass, captureFactExpectations, parseCaptureInvocation, captureReportAccepted, captureXml } from './capture-results.mjs';

const command = { code: 0, signal: null, closeObserved: true, processGroupClosed: true, reason: null };
const identity = method => `INSTRUMENTATION_STATUS: class=${captureClass}\nINSTRUMENTATION_STATUS: test=${method}\n`;
const facts = (method, values = captureFactExpectations(method, 'true')) => Object.entries(values).map(([key, value]) => `INSTRUMENTATION_STATUS: ${key}=${value}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 2\n';
const output = method => identity(method) + 'INSTRUMENTATION_STATUS_CODE: 1\n' + facts(method) + identity(method) + 'INSTRUMENTATION_STATUS_CODE: 0\nINSTRUMENTATION_CODE: -1\n';
const snap = () => Object.fromEntries(['directHttp', 'directOpaque', 'directTcp', 'udp', 'dns', 'udp443', 'interceptedHttp', 'interceptedOpaque', 'interceptedIpv6', 'uploadBytes', 'downloadBytes', 'invalidRequests', 'heldRequestsClosed', 'tcpConnections', 'udpDatagrams', 'activeSockets', 'pendingCallbacks', 'timers', 'listeners', 'heldConnections'].map(key => [key, 0]).concat([['closed', false]]));
const report = () => {
  let previous = snap();
  const result = { format: 'http-freekit-capture-runtime', revision: 1, source: { commit: 'a'.repeat(40), trackedDirty: false }, api: 26,
  permissionSetup: { required: false, mode: 'not_required', hostGrantExitCode: null, trafficGrantExitCode: null },
  clock: { deviceEpochSeconds: 1700000000, hostBeforeMillis: 1700000000000, hostAfterMillis: 1700000000010, lowerBoundMillis: -10, upperBoundMillis: 999, roundTripMillis: 10 },
  methods: captureCases.map((item, index) => {
    const before = { ...previous }, after = { ...before };
    for (const key of [ ['interceptedHttp', 'interceptedOpaque', 'directHttp', 'directOpaque'], ['directTcp', 'udp', 'dns', 'udp443'], ['interceptedIpv6'], ['heldRequestsClosed', 'interceptedHttp'], [] ][index]) after[key]++;
    after.tcpConnections += [4, 1, 1, 2, 0][index]; after.udpDatagrams += index === 1 ? 3 : 0;
    previous = after;
    return { invocation: parseCaptureInvocation(output(item.method), item.method, command), receiversBefore: before, receiversAfter: after };
  }),
  cleanup: { ownedCommandsClosed: true, ownedCommandGroupsClosed: true, packagesAbsent: true, forceStopExitCodes: [0, 0, 0, 0], uninstallExitCodes: [0, 0, 0, 0], receivers: null }, problems: [] };
  result.cleanup.receivers = { ...previous, closed: true };
  return result;
};

test('all five exact methods require paired actual identities, final facts and terminal success', () => {
  for (const item of captureCases) {
    const actual = parseCaptureInvocation(output(item.method), item.method, command);
    assert.equal(actual.state, 'passed'); assert.equal(actual.actualStarted, 1); assert.equal(actual.actualCompleted, 1);
  }
  assert.equal(captureReportAccepted(report()), true);
});
test('summary text, missing start, duplicate completion and foreign method/class cannot prove execution', () => {
  const method = captureCases[0].method, valid = output(method);
  for (const text of ['OK (1 test)\nINSTRUMENTATION_CODE: -1\n', valid.replace('INSTRUMENTATION_STATUS_CODE: 1\n', ''),
    valid.replace('INSTRUMENTATION_CODE: -1', identity(method) + 'INSTRUMENTATION_STATUS_CODE: 0\nINSTRUMENTATION_CODE: -1'),
    valid.replaceAll(captureClass, 'foreign.Class'), valid.replaceAll(method, captureCases[1].method)]) assert.notEqual(parseCaptureInvocation(text, method, command).state, 'passed');
});
test('early, duplicate or missing terminal records cannot accept otherwise successful facts', () => {
  const method = captureCases[0].method, valid = output(method);
  for (const text of ['INSTRUMENTATION_CODE: -1\n' + valid.replace('INSTRUMENTATION_CODE: -1\n', ''), valid + 'INSTRUMENTATION_CODE: -1\n', valid.replace('INSTRUMENTATION_CODE: -1\n', '')]) assert.notEqual(parseCaptureInvocation(text, method, command).state, 'passed');
});
test('facts are exact, unique, active-method-only and cannot substitute unknown keys or an unjoined Stop', () => {
  const method = captureCases[0].method, valid = output(method);
  for (const text of [valid.replace('captureAllStopsJoined=true', 'captureAllStopsJoined=false'), valid.replace('captureVersion=1', 'captureVersion=1\nINSTRUMENTATION_STATUS: captureExtra=CANARY'),
    valid.replace('captureVersion=1', 'captureVersion=1\nINSTRUMENTATION_STATUS: captureVersion=1'), valid.replace(facts(method), ''), facts(method) + valid.replace(facts(method), '')]) assert.notEqual(parseCaptureInvocation(text, method, command).state, 'passed');
});
test('actual owned command failure, signal and missing process-group join always fail acceptance', () => {
  const method = captureCases[0].method;
  for (const changed of [{ code: 1 }, { signal: 'SIGTERM' }, { closeObserved: false }, { processGroupClosed: false }, { reason: 'deadline' }]) assert.notEqual(parseCaptureInvocation(output(method), method, { ...command, ...changed }).state, 'passed');
});
test('only finite failure phase/type survives provider messages, causes and foreign suffixes', () => {
  const method = captureCases[0].method;
  const failed = identity(method) + 'INSTRUMENTATION_STATUS_CODE: 1\n' + identity(method) + 'INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: Capture research uid failed at selected-traffic (IOException); cleanup=true.\nCaused by: private.CANARY: secret\nINSTRUMENTATION_STATUS_CODE: -2\nINSTRUMENTATION_CODE: -1\n';
  const actual = parseCaptureInvocation(failed, method, command);
  assert.deepEqual(actual.failure, { phase: 'selected-traffic', type: 'IOException', cleanupCompleted: true, frames: [], diagnostic: null });
  assert.equal(JSON.stringify(actual).includes('CANARY'), false);
  assert.equal(parseCaptureInvocation(failed.replace('cleanup=true.', 'cleanup=true. CANARY'), method, command).failure, null);
});
test('output bytes, line length, invalid UTF8 and metadata count have finite rejecting bounds', () => {
  const method = captureCases[0].method;
  for (const value of [Buffer.alloc(262145), Buffer.from([0xff]), 'a'.repeat(8193), identity(method) + Array.from({ length: 49 }, (_, i) => `INSTRUMENTATION_STATUS: field${i}=x\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 1\n']) assert.notEqual(parseCaptureInvocation(value, method, command).state, 'passed');
});
test('independent host path counters cannot be replaced by positive Android facts', () => {
  for (const [index, field] of [[0, 'directHttp'], [1, 'udp443'], [2, 'interceptedIpv6'], [3, 'heldRequestsClosed'], [4, 'directTcp']]) {
    const value = report(); value.methods[index].receiversAfter[field]++;
    assert.equal(captureReportAccepted(value), false);
  }
});
test('clock quantization, dirty source, absent consent and incomplete cleanup remain rejecting', () => {
  for (const change of [r => { r.clock.upperBoundMillis = 2001; }, r => { r.source.trackedDirty = true; },
    r => { r.methods[0].invocation.observation.captureConsentDialogObserved = 'false'; }, r => { r.cleanup.ownedCommandGroupsClosed = false; },
    r => { r.cleanup.uninstallExitCodes[2] = 1; }, r => { r.cleanup.receivers.pendingCallbacks = 1; }]) {
    const value = report(); change(value); assert.equal(captureReportAccepted(value), false);
  }
});
test('later host cleanup failure preserves the five actual method outcomes in bounded XML', () => {
  const value = report(); value.accepted = false; value.problems = ['cleanup_incomplete'];
  const rendered = captureXml(value);
  assert.equal((rendered.match(/<testcase /g) ?? []).length, 5); assert.match(rendered, /failures="0" errors="1"/);
  assert.equal(rendered.includes('CANARY'), false);
});

test('API37 requires the denied-permission no-TUN invocation before the owned grant and five real policy methods', () => {
  const value = report(); value.api = 37;
  value.permissionSetup = { required: true, mode: 'owned_ci_grant', hostGrantExitCode: 0, trafficGrantExitCode: 0 };
  for (const item of value.methods) item.invocation.observation.captureLocalNetworkPermission = 'granted';
  const method = capturePermissionCase.method;
  value.methods.unshift({ invocation: parseCaptureInvocation(output(method), method, command), receiversBefore: snap(), receiversAfter: snap() });
  assert.equal(captureReportAccepted(value), true);
  assert.match(captureXml({ ...value, accepted: true }), /tests="6"/);
  value.methods[0].invocation.observation.captureFactoryCalls = '1';
  assert.equal(captureReportAccepted(value), false);
});

test('counter resets, traffic between methods and positive method failure facts cannot be hidden', () => {
  for (const change of [r => { r.methods[1].receiversBefore.directHttp = 0; r.methods[1].receiversAfter.directHttp = 0; },
    r => { r.cleanup.receivers.dns++; }, r => { r.methods[0].invocation.failure = { phase: 'selected-traffic', type: 'IOException', cleanupCompleted: true }; }]) {
    const value = report(); change(value); assert.equal(captureReportAccepted(value), false);
  }
});

test('boolean counters and recognized failure followed by a passing terminal cannot substitute actual outcomes', () => {
  const value = report(); value.methods[0].receiversAfter.directHttp = true;
  assert.equal(captureReportAccepted(value), false);
  const method = captureCases[0].method;
  const contradictory = output(method).replace('INSTRUMENTATION_CODE: -1', 'java.lang.AssertionError: Capture research uid failed at selected-traffic (IOException); cleanup=true.\nINSTRUMENTATION_CODE: -1');
  assert.equal(parseCaptureInvocation(contradictory, method, command).state, 'failed');
});

function failureFacts(scenario, phase) {
  const value = { Version: '1', Scenario: scenario, Phase: phase, Type: 'IllegalStateException', Check: 'tcp_bytes', TrafficCommand: '16', TrafficStatus: '3', TrafficBytes: '0',
    ServicePresent: 'false', ServiceState: 'absent', ServiceFailureCode: 'null', TunEstablished: 'null', SelectedPackageCount: 'null', UnderlyingNetworkPresent: 'null', LifecycleThreadAlive: 'null',
    CapturePresent: 'false', Started: 'null', AdmissionClosed: 'null', NativeRunning: 'null', NativeStopJoined: 'null', TunClosed: 'null', ConfigurationPresent: 'null', ActiveFlows: 'null', OwnedSockets: 'null',
    LiveWorkers: 'null', PendingOpens: 'null', InterceptedTcpFlows: 'null', DirectTcpFlows: 'null', UdpTargets: 'null', Udp443Drops: 'null', ProtectFailures: 'null', BindFailures: 'null', Failed: 'null',
    GuardProtects: 'null', GuardBinds: 'null', GuardRejected: 'null', GuardRejectedSocketsClosed: 'null', CaptureRequestCalls: 'null', InterceptedFactoryClosed: 'null' };
  return Object.fromEntries(Object.entries(value).map(([key, item]) => ['captureFailure' + key, item]));
}
const status = (value, code) => Object.entries(value).map(([key, item]) => `INSTRUMENTATION_STATUS: ${key}=${item}\n`).join('') + `INSTRUMENTATION_STATUS_CODE: ${code}\n`;
function failedOutput(method, scenario, phase, observation, frames = '') {
  return identity(method) + 'INSTRUMENTATION_STATUS_CODE: 1\n' + status(observation, 3) + identity(method) +
    `INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: Capture research ${scenario} failed at ${phase} (IllegalStateException); cleanup=true.\n` + frames +
    'INSTRUMENTATION_STATUS_CODE: -2\nINSTRUMENTATION_CODE: -1\n';
}

test('digit-containing failure scenarios/phases retain only finite typed facts and own-source sites', () => {
  for (const [index, scenario, phase] of [[2, 'ipv6', 'selected-ipv6'], [1, 'direct', 'udp443-positive-control']]) {
    const method = captureCases[index].method;
    const text = failedOutput(method, scenario, phase, failureFacts(scenario, phase), '    at com.httpfreekit.capturetest.CapturePolicyInteropTest.selectedIpv6UsesTun(CapturePolicyInteropTest.kt:123)\nCaused by: private.CANARY\n    at foreign.CANARY.private(CapturePolicyInteropTest.kt:7)\n');
    const result = parseCaptureInvocation(text, method, command);
    assert.equal(result.state, 'failed'); assert.equal(result.failure.phase, phase); assert.equal(result.failure.diagnostic.trafficStatus, 3);
    assert.deepEqual(result.failure.frames, [{ file: 'CapturePolicyInteropTest.kt', line: 123 }]); assert.equal(JSON.stringify(result).includes('CANARY'), false);
  }
});

test('unknown/duplicate/mismatched/nonprimitive failure bundles cannot become retained observations', () => {
  const method = captureCases[2].method;
  for (const change of [v => { v.captureFailureExtra = 'CANARY'; }, v => { v.captureFailureScenario = 'uid'; }, v => { v.captureFailureActiveFlows = 'true'; },
    v => { v.captureFailureCheck = 'CANARY'; }, v => { v.captureFailureCapturePresent = 'true'; }, v => { v.captureFailureTrafficStatus = '-2'; }]) {
    const values = failureFacts('ipv6', 'selected-ipv6'); change(values);
    const result = parseCaptureInvocation(failedOutput(method, 'ipv6', 'selected-ipv6', values), method, command);
    assert.equal(result.failure.diagnostic, null); assert.equal(JSON.stringify(result).includes('CANARY'), false);
  }
  const value = failureFacts('ipv6', 'selected-ipv6');
  const duplicate = failedOutput(method, 'ipv6', 'selected-ipv6', value).replace(identity(method) + 'INSTRUMENTATION_STATUS: stack=', status(value, 3) + identity(method) + 'INSTRUMENTATION_STATUS: stack=');
  assert.ok(parseCaptureInvocation(duplicate, method, command).problems.includes('invalid_capture_facts'));
});

test('failure facts always prevent passing acceptance and source frames remain capped at16', () => {
  const method = captureCases[2].method, values = failureFacts('ipv6', 'selected-ipv6');
  const text = output(method).replace(facts(method), status(values, 3) + facts(method));
  assert.equal(parseCaptureInvocation(text, method, command).state, 'failed');
  const frames = Array.from({ length: 24 }, (_, i) => `    at com.httpfreekit.capturetest.CapturePolicyInteropTest.selectedIpv6UsesTun(CapturePolicyInteropTest.kt:${i + 1})\n`).join('');
  assert.equal(parseCaptureInvocation(failedOutput(method, 'ipv6', 'selected-ipv6', values, frames), method, command).failure.frames.length, 16);
});
