import test from 'node:test';
import assert from 'node:assert/strict';
import { createEnrolledTunInvocationParser, parseEnrolledTunInvocation, enrolledTunClass, enrolledTunMethod,
  enrolledTunPhases, enrolledTunObservationSuffixes } from './enrolled-tun-results.mjs';
import { enrollmentRuntimeValidation as V, EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { enrolledTunFailureCategory } from './enrolled-tun-observation.mjs';
import { command, status, phase, facts, observation, prefix, transcript } from './enrolled-tun-test-fixtures.mjs';
const parse = (value, result = command()) => parseEnrolledTunInvocation(value, result);

test('C5 requires one exact method, fifteen live phases, fifty source facts and actual command closure', () => {
  assert.equal(enrolledTunObservationSuffixes.length, 50); assert.equal(Object.keys(facts()).length, 50);
  const seen = [], parser = createEnrolledTunInvocationParser({ onPhase: value => { seen.push(value); } });
  for (const byte of Buffer.from(transcript())) parser.push(Buffer.of(byte));
  const result = parser.finish(command());
  assert.equal(result.state, 'passed'); assert.deepEqual(seen, enrolledTunPhases);
  assert.equal(result.actualStarted, 1); assert.equal(result.actualCompleted, 1); assert.equal(result.terminalCode, -1);
  assert.equal(result.observation.sessionLease, false); assert.equal(result.observation.interceptedTcpFlows, 1);
  assert.equal(result.observation.responseBodyBytes, 32787); assert.equal(result.failure, null);
  V.validateInvocation(result, enrolledTunMethod, 'c5');
});

test('every C5 positive fact is independently necessary; unknown, missing and noncanonical facts fail', () => {
  for (const [key, value] of Object.entries(facts())) {
    const changed = facts(); changed[key] = value === 'true' ? 'false' : value === 'false' ? 'true' : key.endsWith('Sha256') ? '0'.repeat(64) : String(Number(value) + 1);
    assert.notEqual(parse(transcript(changed)).state, 'passed', key);
    const missing = facts(); delete missing[key]; assert.notEqual(parse(transcript(missing)).state, 'passed', key);
  }
  const unknown = facts(); unknown.draftTunRequestBodyBytes = '16421'; assert.notEqual(parse(transcript(unknown)).state, 'passed');
  for (const value of ['-0', '00', '2.0', '2\r0', '131073', '9007199254740992', 'CANARY']) {
    const changed = facts(); changed.draftTunProtectAttempts = value; assert.notEqual(parse(transcript(changed)).state, 'passed');
  }
  const duplicate = transcript().replace('INSTRUMENTATION_STATUS: draftTunProtectAttempts=2\n', 'INSTRUMENTATION_STATUS: draftTunProtectAttempts=2\nINSTRUMENTATION_STATUS: draftTunProtectAttempts=2\n');
  assert.notEqual(parse(duplicate).state, 'passed');
  assert.notEqual(parse(prefix(13) + observation(facts()) + enrolledTunPhases.slice(13).map(phase).join('') + status(0) + 'INSTRUMENTATION_CODE: -1\n').state, 'passed');
});

test('command EOF cannot authorize approval, response release or COMPLETE acknowledgment from an unterminated status line', () => {
  for (const target of ['awaiting-host-approval', 'http-command-started', 'local-stream-drained']) {
    const seen = [], parser = createEnrolledTunInvocationParser({ onPhase: value => { seen.push(value); } });
    parser.push(Buffer.from(prefix(enrolledTunPhases.indexOf(target)) + phase(target).trimEnd()));
    assert(!seen.includes(target)); const result = parser.finish(command());
    assert(!seen.includes(target)); assert(result.problems.includes('phase_after_command_close')); assert.notEqual(result.state, 'passed');
  }
});

test('C5 preserves only finite failure phase/type/category/cleanup and exact project frames', () => {
  const stack = 'java.lang.AssertionError: Enrolled TUN research failed at http-command-started (IOException); category=traffic_tcp_eof_reset; cleanup=false.\n' +
    ' at com.httpfreekit.capturetest.TrafficClient.call(TrafficClient.kt:42)\n' +
    ' at com.httpfreekit.interop.DraftEnrolledTunInteropTest.selectedUidHttpReachesEnrolledDesktopThroughTun(DraftEnrolledTunInteropTest.kt:123)\n' +
    ' at com.provider.CANARY.secret(CANARY.kt:1)\nCaused by: provider.CANARY invitation-secret\nSuppressed: CANARY';
  const result = parse(prefix(8) + status(-2, stack) + 'INSTRUMENTATION_CODE: -1\n');
  assert.equal(result.state, 'failed'); assert.deepEqual(result.failure, { phase: 'http-command-started', type: 'IOException', category: 'traffic_tcp_eof_reset', cleanup: false });
  assert.equal(result.frames.length, 2); assert(!JSON.stringify(result).includes('CANARY')); assert(!JSON.stringify(result).includes('invitation-secret'));
  V.validateInvocation(result, enrolledTunMethod, 'c5');
  for (const stage of ['connect', 'write', 'shutdown', 'reply', 'eof', 'close']) for (const category of ['timeout', 'io', 'protocol', 'other', 'reset', 'aborted', 'bad_fd', 'not_connected', 'closed']) {
    assert(enrolledTunFailureCategory(`traffic_tcp_${stage}_${category}`));
  }
  for (const invalid of ['traffic_tcp_eof_CANARY', 'none\n', 'none\r', 'traffic_tcp_eof_reset\n']) assert(!enrolledTunFailureCategory(invalid));
});

test('known or malformed C5 failure wrappers cannot coexist with an otherwise successful transcript', () => {
  for (const category of ['none', 'traffic_close_io', 'traffic_command_failed', 'traffic_tcp_reply_protocol', 'CANARY']) {
    const result = parse(transcript().replace('INSTRUMENTATION_CODE: -1', `Enrolled TUN research failed at http-command-started (IOException); category=${category}; cleanup=false.\nINSTRUMENTATION_CODE: -1`));
    assert.notEqual(result.state, 'passed'); assert(result.problems.includes('instrumentation_failure')); assert(!JSON.stringify(result).includes('CANARY'));
  }
});

test('foreign identities, duplicate invocation, skipped methods and incomplete command ownership never pass C5', () => {
  assert.notEqual(parse(transcript().replaceAll(enrolledTunClass, 'com.httpfreekit.interop.DraftCaptureFactoryInteropTest')).state, 'passed');
  assert.notEqual(parse(transcript().replaceAll(enrolledTunMethod, 'otherMethod')).state, 'passed');
  assert.notEqual(parse(status(1) + transcript()).state, 'passed');
  assert.notEqual(parse(prefix(14) + observation(facts()) + phase(enrolledTunPhases[14]) + status(-3) + 'INSTRUMENTATION_CODE: -1\n').state, 'passed');
  for (const change of [{ code: 1 }, { closeObserved: false }, { processGroupClosed: false }, { reason: 'owned_child_timeout' }]) assert.notEqual(parse(transcript(), { ...command(), ...change }).state, 'passed');
});

test('C5 rejects malformed UTF8 and bounded line/output excess without retaining raw output', () => {
  for (const bytes of [Buffer.from([0xc3]), Buffer.from('\uFEFF' + transcript()), Buffer.alloc(8193, 65), Buffer.alloc(262145, 65)]) {
    const result = parse(bytes); assert.notEqual(result.state, 'passed');
    assert(result.problems.some(code => ['invalid_instrumentation_utf8', 'instrumentation_line_limit', 'instrumentation_output_limit'].includes(code)));
  }
  assert.throws(() => V.validateInvocation({ ...parse(transcript()), failure: { phase: 'http-command-started', type: 'IOException', category: 'none', cleanup: false } }, enrolledTunMethod, 'c5'), EnrollmentRuntimeError);
});
