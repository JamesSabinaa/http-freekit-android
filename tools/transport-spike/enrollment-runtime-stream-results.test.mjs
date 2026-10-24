import test from 'node:test';
import assert from 'node:assert/strict';
import { EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { enrolledStreamingCases, enrolledObservationSuffixes, enrolledStreamingReportPaths,
  projectEnrolledHostSnapshot, createEnrolledHostSnapshot } from './enrollment-runtime-stream-results.mjs';
const now = 1792852701000;
const window = { callStartedNanos: 1000000, callReceivedNanos: 2000000 };
function inspection() {
  return { revision: 1, found: true, available: true, credentialExpiresUtcMillis: now + 60000,
    gatewayExpiresUtcMillis: now + 3600000, sessionPolicyMillis: 15000, grantValid: true, invalidationCause: null,
    revalidations: 5, controlsAdmitted: 1, applicationWriteAdmissions: 7, writesAfterInvalidation: 0,
    terminalNotification: { attempted: false, completed: false, aborted: false },
    probe: { revision: 1, scenario: 'cancel', streamOrdinal: 1,
      control: { phase: 'active', cause: null, sessionLease: true, webSocketClosed: false, resourcesReleased: false,
        historyCount: 1, streamLeases: 1, chargedBytes: 8192 },
      stream: { phase: 'open', cause: null, streamLease: true, webSocketClosed: false, resourcesReleased: false, chargedFrames: 2,
        client: { sealed: false, eofEmitted: false, chargedBytes: 8192 }, gateway: { sealed: false, eofEmitted: false, chargedBytes: 0 } },
      pool: { sessionLeases: 1, streamLeases: 1, chargedBytes: 8192 },
      fixture: { proxyReadPaused: true, uploadBytesRead: 0, uploadPrefixSeen: false, uploadEof: false, uploadVerified: false,
        uploadSha256: null, responseBytesWritten: 0, responsePrefixWritten: false, responseTailReleased: true, responseEof: false, responseSha256: null },
      io: { proxyWriteEntries: 7, proxyWriteCompletions: 6, proxyWritePending: true, wsWriteEntries: 1, wsWriteCompletions: 1,
        wsWritePending: false, pendingIngressBytes: 4096, backpressureCount: 1, resumedPendingCount: 0,
        retainedBytesAtAbort: 0, retainedFramesAtAbort: 0, retainedStreamLeasesAtAbort: 0 },
      cleanup: { controlClosed: false, streamClosed: false, proxyClosed: false, fixtureClosed: false, workers: 4,
        timers: 1, pendingCallbacks: 1, complete: false },
      timing: { readyUtcMillis: now, expiresUtcMillis: now + 15000, terminalUtcMillis: null, terminalElapsedMillis: null } } };
}
const project = value => projectEnrolledHostSnapshot(value, window);
function invalid(value) {
  assert.throws(() => project(value), error => error instanceof EnrollmentRuntimeError && error.message === 'invalid_enrolled_host_observation');
}

test('finite descriptor fixes all three ordered methods, twelve phases and thirty-five observation keys', () => {
  assert.deepEqual(enrolledStreamingCases.map(value => value.inputScenario), [1, 2, 3]);
  assert.deepEqual(enrolledStreamingCases.map(value => value.sessionLifetimeMillis), [120000, 120000, 15000]);
  for (const value of enrolledStreamingCases) {
    assert.equal(value.phases.length, 12); assert.equal(new Set(value.phases).size, 12);
    assert.equal(value.credentialLifetimeSeconds, 60); assert.ok(Object.isFrozen(value.phases));
  }
  assert.equal(enrolledObservationSuffixes.length, 35); assert.equal(new Set(enrolledObservationSuffixes).size, 35);
  assert.equal(Object.values(enrolledStreamingReportPaths).length, 4);
});

test('projection copies and freezes only original-owner primitives and exact call window', () => {
  const input = inspection(), result = project(input);
  assert.equal(result.proxyWriteEntries, 7); assert.equal(result.chargedBytes, 8192);
  assert.equal(result.callStartedNanos, window.callStartedNanos); assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.terminalNotification)); assert.ok(!Object.hasOwn(result, 'probe'));
  input.terminalNotification.attempted = true; input.probe.io.proxyWriteEntries = 99;
  assert.equal(result.terminalNotification.attempted, false); assert.equal(result.proxyWriteEntries, 7);
  assert.deepEqual(createEnrolledHostSnapshot(result), result);
});

test('released original-owner evidence cannot inherit new control global pool charges', () => {
  const input = inspection(); input.controlsAdmitted = 2;
  Object.assign(input.probe.control, { phase: 'failed', cause: 'session_expired', sessionLease: false, resourcesReleased: true, streamLeases: 0, chargedBytes: 0 });
  Object.assign(input.probe.stream, { phase: 'failed', cause: 'network_unreachable', resourcesReleased: true, chargedFrames: 0 });
  Object.assign(input.probe.cleanup, { complete: true, workers: 0, timers: 0, pendingCallbacks: 0 });
  Object.assign(input.probe.timing, { terminalUtcMillis: now + 15000, terminalElapsedMillis: 15000 });
  const result = project(input);
  assert.equal(input.probe.pool.sessionLeases, 1); assert.equal(result.sessionLease, false); assert.equal(result.streamLeases, 0);
  assert.equal(result.chargedBytes, 0); assert.equal(result.ownerResourcesReleased, true); assert.equal(result.controlsAdmitted, 2);
});

test('missing or not-yet-created owner returns null rather than fabricated ready evidence', () => {
  const input = inspection(); Object.assign(input, { found: false, credentialExpiresUtcMillis: null, grantValid: false,
    revalidations: 0, controlsAdmitted: 0, applicationWriteAdmissions: 0, writesAfterInvalidation: 0, probe: null });
  assert.equal(project(input), null);
  input.grantValid = true; invalid(input);
  input.grantValid = false; input.found = true; input.credentialExpiresUtcMillis = now + 60000;
  assert.equal(project(input), null);
});

test('unknown private fields and mismatched public fields fail with a static redacted error', () => {
  for (const mutate of [value => { value.enrollmentId = 'PRIVATE_CANARY'; },
    value => { value.probe.control.deviceId = 'PRIVATE_CANARY'; }, value => { value.probe.pool.charge = 1; },
    value => { value.probe.fixture.uploadSha256 = 'PRIVATE_CANARY'; }, value => { value.probe.scenario = 'PRIVATE_CANARY'; }]) {
    const input = inspection(); mutate(input); invalid(input);
  }
});

test('bounds, completion order, terminal pair and notification consistency are enforced', () => {
  for (const mutate of [value => { value.probe.io.proxyWriteCompletions = 8; },
    value => { value.writesAfterInvalidation = 8; }, value => { value.probe.io.pendingIngressBytes = 4097; },
    value => { value.probe.control.chargedBytes = 16385; }, value => { value.controlsAdmitted = 9; },
    value => { value.probe.cleanup.workers = 65; }, value => { value.probe.timing.terminalElapsedMillis = 10; },
    value => { value.terminalNotification.completed = true; },
    value => { value.terminalNotification = { attempted: true, completed: true, aborted: true }; },
    value => { value.probe.control.sessionLease = 1; }, value => { value.probe.stream.chargedFrames = -0; }]) {
    const input = inspection(); mutate(input); invalid(input);
  }
  for (const times of [{ callStartedNanos: 3, callReceivedNanos: 2 }, { callStartedNanos: -0, callReceivedNanos: 2 },
    { callStartedNanos: 0, callReceivedNanos: 3600000000001 }]) assert.throws(() => projectEnrolledHostSnapshot(inspection(), times), EnrollmentRuntimeError);
});
