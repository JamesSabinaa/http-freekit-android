import test from 'node:test';
import assert from 'node:assert/strict';
import { captureCases, captureClass, captureFactExpectations, parseCaptureInvocation, captureReportAccepted, captureXml } from './capture-results.mjs';

const command = { code: 0, signal: null, closeObserved: true, processGroupClosed: true, reason: null };
const identity = method => `INSTRUMENTATION_STATUS: class=${captureClass}\nINSTRUMENTATION_STATUS: test=${method}\n`;
const facts = (method, values = captureFactExpectations(method, 'true')) => Object.entries(values).map(([key, value]) => `INSTRUMENTATION_STATUS: ${key}=${value}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 2\n';
const output = method => identity(method) + 'INSTRUMENTATION_STATUS_CODE: 1\n' + facts(method) + identity(method) + 'INSTRUMENTATION_STATUS_CODE: 0\nINSTRUMENTATION_CODE: -1\n';
const snap = () => Object.fromEntries(['directHttp', 'directOpaque', 'directTcp', 'udp', 'dns', 'udp443', 'interceptedHttp', 'interceptedOpaque', 'interceptedIpv6', 'uploadBytes', 'downloadBytes', 'invalidRequests', 'heldRequestsClosed', 'activeSockets', 'pendingCallbacks', 'timers', 'listeners', 'heldConnections'].map(key => [key, 0]).concat([['closed', false]]));
const report = () => ({ format: 'http-freekit-capture-runtime', revision: 1, source: { commit: 'a'.repeat(40), trackedDirty: false }, api: 26,
  clock: { deviceEpochSeconds: 1700000000, hostBeforeMillis: 1700000000000, hostAfterMillis: 1700000000010, lowerBoundMillis: -10, upperBoundMillis: 999, roundTripMillis: 10 },
  methods: captureCases.map((item, index) => {
    const before = snap(), after = snap();
    for (const key of [ ['interceptedHttp', 'interceptedOpaque', 'directHttp', 'directOpaque'], ['directTcp', 'udp', 'dns', 'udp443'], ['interceptedIpv6'], ['heldRequestsClosed', 'interceptedHttp'], [] ][index]) after[key] = 1;
    return { invocation: parseCaptureInvocation(output(item.method), item.method, command), receiversBefore: before, receiversAfter: after };
  }),
  cleanup: { ownedCommandsClosed: true, ownedCommandGroupsClosed: true, packagesAbsent: true, forceStopExitCodes: [0, 0, 0, 0], uninstallExitCodes: [0, 0, 0, 0], receivers: { ...snap(), closed: true } }, problems: [] });

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
  assert.deepEqual(actual.failure, { phase: 'selected-traffic', type: 'IOException', cleanupCompleted: true });
  assert.equal(JSON.stringify(actual).includes('CANARY'), false);
  assert.equal(parseCaptureInvocation(failed.replace('cleanup=true.', 'cleanup=true. CANARY'), method, command).failure, null);
});
test('output bytes, line length, invalid UTF8 and metadata count have finite rejecting bounds', () => {
  const method = captureCases[0].method;
  for (const value of [Buffer.alloc(262145), Buffer.from([0xff]), 'a'.repeat(8193), identity(method) + Array.from({ length: 33 }, (_, i) => `INSTRUMENTATION_STATUS: field${i}=x\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 1\n']) assert.notEqual(parseCaptureInvocation(value, method, command).state, 'passed');
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
