import test from 'node:test';
import assert from 'node:assert/strict';
import { EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { enrolledStreamingCases, enrolledObservationSuffixes, enrolledStreamingReportPaths,
  projectEnrolledHostSnapshot, createEnrolledHostSnapshot, createEnrolledStreamingInvocationParser, parseEnrolledStreamingInvocation,
  createEnrolledStreamingReport, verifyEnrolledStreamingReport, enrolledStreamingRuntimeXml, enrolledStreamingRuntimeHtml, decodeEnrolledStreamingReport } from './enrollment-runtime-stream-results.mjs';
import { transcript, phase, status, bundle, observation, commandResult, runtime, source } from './enrollment-runtime-stream-test-fixtures.mjs';
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

test('three real-method shapes require exact phases and a single canonical positive observation', () => {
  for (const [index, item] of enrolledStreamingCases.entries()) {
    const result = parseEnrolledStreamingInvocation(transcript(index), { method: item.method, ...commandResult() });
    assert.equal(result.state, 'passed'); assert.deepEqual(result.observation, observation(index)); assert.deepEqual(result.phases, item.phases);
  }
  assert.equal(verifyEnrolledStreamingReport(runtime(), { source, api: 26 }).methods, 3);
});

test('byte-split phases remain live-only and finish never authorizes an unterminated revocation phase', () => {
  const method = enrolledStreamingCases[0].method, calls = [], parser = createEnrolledStreamingInvocationParser(method, { onPhase: value => { calls.push(value); } });
  const text = status(0, 1) + enrolledStreamingCases[0].phases.slice(0, 8).map(phase).join('').slice(0, -1);
  for (const byte of Buffer.from(text)) parser.push(Buffer.from([byte]));
  assert.equal(calls.length, 7); const result = parser.finish(commandResult());
  assert.equal(calls.length, 7); assert.ok(result.problems.includes('phase_after_command_close')); assert.notEqual(result.state, 'passed');
});

test('missing, duplicate, early, late and foreign-scenario observation bundles cannot pass', () => {
  const method = enrolledStreamingCases[0].method, valid = transcript(0), facts = bundle(observation());
  for (const text of [valid.replace(facts, ''), valid.replace(facts, facts + facts), facts + valid,
    valid.replace(facts, '').replace('INSTRUMENTATION_CODE: -1\n', facts + 'INSTRUMENTATION_CODE: -1\n'),
    valid.replace(facts, bundle(observation(1))), valid.replace(facts, facts.replace('Version=1', 'Version=01')),
    valid.replace(facts, facts.replace('SocketsClosed=true', 'SocketsClosed=1')),
    valid.replace(facts, facts.replace('PrefixBytes=4096', 'PrefixBytes=4095'))]) {
    const result = parseEnrolledStreamingInvocation(text, { method, ...commandResult() }); assert.notEqual(result.state, 'passed');
  }
});

test('finish cannot retain an unterminated positive observation after actual command closure', () => {
  const parser = createEnrolledStreamingInvocationParser(enrolledStreamingCases[0].method);
  parser.push(Buffer.from(status(0, 1) + enrolledStreamingCases[0].phases.slice(0, 10).map(phase).join('') + bundle(observation()).slice(0, -1)));
  const result = parser.finish(commandResult());
  assert.equal(result.observation, null); assert.ok(result.problems.includes('observation_after_command_close')); assert.notEqual(result.state, 'passed');
});

test('observation metadata cap and exact key set reject private or oversized instrumentation fields', () => {
  const method = enrolledStreamingCases[0].method;
  for (const extras of [1, 6]) {
    const text = transcript(0).replace('INSTRUMENTATION_STATUS_CODE: 3',
      Array.from({ length: extras }, (_, index) => `INSTRUMENTATION_STATUS: private${index}=PRIVATE_CANARY\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 3');
    const result = parseEnrolledStreamingInvocation(text, { method, ...commandResult() });
    assert.notEqual(result.state, 'passed'); assert.ok(!JSON.stringify(result).includes('PRIVATE_CANARY'));
  }
});

test('failed B methods retain only exact committed streaming helper roots and never private messages', () => {
  const stack = 'java.lang.IllegalStateException: PRIVATE_CANARY\n' +
    '\tat com.httpfreekit.interop.DraftStreamingTls.close(DraftStreamingFixture.kt:20)\n' +
    '\tat com.httpfreekit.interop.DraftEnrolledStreamingObservation.values(DraftEnrolledStreamingObservation.kt:21)\n' +
    '\tat com.httpfreekit.interop.DraftOther.canary(DraftStreamingFixture.kt:22)';
  const text = transcript(0).replace(status(0, 0), status(0, -2, 'INSTRUMENTATION_STATUS: stack=' + stack + '\n'));
  const result = parseEnrolledStreamingInvocation(text, { method: enrolledStreamingCases[0].method, ...commandResult() });
  assert.equal(result.state, 'failed'); assert.equal(result.frames.length, 2); assert.ok(!JSON.stringify(result).includes('PRIVATE_CANARY'));
});

test('strict host gate rejects completion-gap pressure proof, new IDs and prematurely released resources', () => {
  for (const mutate of [value => { value.scenarios[0].host.blockedLast.callStartedNanos = 249000000; value.scenarios[0].host.blockedLast.callReceivedNanos = 1000000000; },
    value => { value.scenarios[0].host.blockedLast.proxyWriteEntries++; },
    value => { value.scenarios[0].host.blockedFirst.chargedBytes = 0; },
    value => { value.scenarios[0].host.terminal.ownerResourcesReleased = false; },
    value => { value.scenarios[0].host.terminal.writesAfterInvalidation = 1; },
    value => { value.scenarios[0].host.terminal.pendingCallbacks = 1; },
    value => { value.scenarios[0].host.terminal.controlsAdmitted = 2; }]) {
    const value = runtime(); mutate(value); assert.throws(() => verifyEnrolledStreamingReport(value, { source, api: 26 }), EnrollmentRuntimeError);
  }
});

test('expiry gate requires an actual first-owner UTC or monotonic proof and accepts truthful races', () => {
  const value = runtime(), expiry = value.scenarios[1]; expiry.invocation.observation.localCause = 'network_unreachable';
  assert.equal(verifyEnrolledStreamingReport(value, { source, api: 26 }).methods, 3);
  expiry.host.terminal.controlCause = 'network_unreachable';
  assert.throws(() => verifyEnrolledStreamingReport(value, { source, api: 26 }), /runtime_stream_deadline_failed/);
  expiry.host.terminal.controlCause = 'session_expired'; expiry.host.terminal.terminalUtcMillis--; expiry.host.terminal.terminalElapsedMillis--;
  assert.throws(() => verifyEnrolledStreamingReport(value, { source, api: 26 }), /runtime_stream_deadline_failed/);
});

test('credential expiry and session policy evidence cannot substitute cached validity or a new enrollment', () => {
  for (const mutate of [value => { value.scenarios[1].host.credentialStatusAfterMethod = false; },
    value => { value.scenarios[1].host.credentialStatusObservedUtcMillis = now + 59999; },
    value => { value.scenarios[2].host.terminal.controlsAdmitted = 1; },
    value => { value.scenarios[2].host.terminal.grantValid = false; },
    value => { value.scenarios[2].invocation.observation.sameCredential = false; },
    value => { value.scenarios[2].invocation.observation.sessionExpiresUtcMillis += 1000; },
    value => { value.scenarios[2].profile.anchorExpiresUtcMillis = now + 10000; }]) {
    const value = runtime(); mutate(value); assert.throws(() => verifyEnrolledStreamingReport(value, { source, api: 26 }), EnrollmentRuntimeError);
  }
});

test('expiry scenarios require the exact isolated limiter, destructive closure and settled terminal writes', () => {
  for (const mutate of [value => { value.scenarios[1].host.terminal.streamPhase = 'complete'; },
    value => { value.scenarios[1].host.terminal.terminalNotification = { attempted: true, completed: false, aborted: false }; },
    ...[1, 2].map(index => value => {
      const item = value.scenarios[index], early = now + (index === 1 ? 50000 : 5000);
      for (const snapshot of [item.host.blockedFirst, item.host.blockedLast, item.host.terminal]) snapshot.expiresUtcMillis = early;
      Object.assign(item.host.terminal, { terminalUtcMillis: early, terminalElapsedMillis: early - now });
      Object.assign(item.invocation.observation, { sessionExpiresUtcMillis: early, terminalObservedUtcMillis: early, terminalObservedElapsedMillis: early - now });
      if (index === 2) item.invocation.observation.newControlObservedUtcMillis = early + 1000;
    })]) {
    const value = runtime(); mutate(value); assert.throws(() => verifyEnrolledStreamingReport(value, { source, api: 26 }), EnrollmentRuntimeError);
  }
});

test('source, clock, private input, actual deliveries and all owned cleanup remain required', () => {
  for (const mutate of [value => { value.source.trackedDirty = true; }, value => { value.clock.lowerBoundMillis = 0; },
    value => { value.scenarios[0].input.inputClosed = false; }, value => { value.scenarios[0].approval.actualApprovedResponseDrops = 1; },
    value => { value.scenarios[0].cleanup.reverseRemovalExitCodes.pop(); }, value => { value.scenarios[0].cleanup.workerClosed.workers = 1; },
    value => { value.scenarios[0].cleanup.workerCommand.processGroupClosed = false; }, value => { value.cleanup.uninstallConfirmed = false; }]) {
    const value = runtime(); mutate(value); assert.throws(() => verifyEnrolledStreamingReport(value, { source, api: 26 }), EnrollmentRuntimeError);
  }
});

test('exact report schema, strict JSON and truthful projections never retain unknown raw material', () => {
  const input = runtime(), report = createEnrolledStreamingReport(input); input.scenarios[0].approval.completed = false;
  assert.equal(report.scenarios[0].approval.completed, true);
  const xml = enrolledStreamingRuntimeXml(report); assert.equal((xml.match(/<testcase /g) ?? []).length, 3); assert.match(xml, /errors="0"/);
  assert.deepEqual(decodeEnrolledStreamingReport(Buffer.from(JSON.stringify(report))), report);
  for (const bytes of [Buffer.from('{"format":1,"format":2}'), Buffer.from('\uFEFF' + JSON.stringify(report)), Buffer.alloc(65537)]) assert.throws(() => decodeEnrolledStreamingReport(bytes), EnrollmentRuntimeError);
  const unknown = runtime(); unknown.scenarios[0].host.secret = 'PRIVATE_CANARY';
  assert.throws(() => enrolledStreamingRuntimeHtml(unknown), /invalid_runtime_report/);
  const failed = runtime(); failed.problems = ['enrollment_cleanup_failed'];
  assert.match(enrolledStreamingRuntimeXml(failed), /errors="0"/); assert.throws(() => verifyEnrolledStreamingReport(failed, { source, api: 26 }));
  failed.scenarios[0].invocation = parseEnrolledStreamingInvocation('', { method: enrolledStreamingCases[0].method, ...commandResult() });
  assert.match(enrolledStreamingRuntimeXml(failed), /errors="1"/);
});
