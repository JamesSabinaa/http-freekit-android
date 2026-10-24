import test from 'node:test';
import assert from 'node:assert/strict';
import { MAX_INSTRUMENTATION_BYTES } from './instrumentation-results.mjs';
import { draftSetupCode, draftStreamingClass as clazz, expectedDraftStreamingTests as names,
  parseDraftStreamingInstrumentation as parse, draftStreamingXml as xml, draftStreamingHtml as html,
  measureDraftStreamingClock as clock } from './draft-stream-results.mjs';

const bundle = (name, status, extra = '', ordinal = names.indexOf(name) + 1) =>
  `INSTRUMENTATION_STATUS: class=${clazz}\nINSTRUMENTATION_STATUS: test=${name}\nINSTRUMENTATION_STATUS: numtests=7\nINSTRUMENTATION_STATUS: current=${ordinal}\n${extra}INSTRUMENTATION_STATUS_CODE: ${status}\n`;
const expiry = {
  draftExpiryVersion: '1', draftExpiryReadyUtcMillis: '1800000000000', draftExpiryExpiresUtcMillis: '1800000030000',
  draftExpiryObservedUtcMillis: '1800000030010', draftExpiryElapsedMillis: '30010', draftExpiryRemainingAtReadyMillis: '30000',
  draftExpiryInitialDeviceRemainingMillis: '29990', draftExpiryLocalTicks: '1200', draftExpiryLocalExpiryTicks: '1',
  draftExpiryLocalExpired: 'true', draftExpiryPeerExpired: 'true', draftExpiryPeerReadyUtcMillis: '1800000000000',
  draftExpiryPeerTerminalUtcMillis: '1800000030000', draftExpiryPeerTerminalElapsedMillis: '30000',
};
const progress = (values = expiry) => Object.entries(values).map(([name, value]) => `INSTRUMENTATION_STATUS: ${name}=${value}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 2\n';
const pair = (name, index) => bundle(name, 1, '', index + 1) + (name === names[3] ? progress() : '') + bundle(name, 0, '', index + 1);
const terminal = 'INSTRUMENTATION_RESULT: stream=\nOK (7 tests)\nINSTRUMENTATION_CODE: -1\n';
const success = names.map(pair).join('') + terminal;
const pressure = {
  draftPressureVersion: '1', draftPressureWaitStartUtcMillis: '1800000012000', draftPressureWaitStartElapsedMillis: '12000',
  draftPressureFailureUtcMillis: '1800000032010', draftPressureFailureElapsedMillis: '32010', draftPressureExpiresUtcMillis: '1800000030000',
  draftPressureControlPhase: 'failed', draftPressureControlCause: 'session_expired', draftPressureStreamPhase: 'failed',
  draftPressureStreamCause: 'session_expired', draftPressureWriteEntered: '750', draftPressureWriteCompleted: '749',
  draftPressureWriteInFlight: '0', draftPressureChargedBytes: '8192', draftPressureChargedFrames: '2', draftPressurePendingClientBytes: '4096',
  draftPressureApplicationWritten: '3200117', draftPressureProducerFinished: 'false', draftPressureOwnedStopping: 'true',
  draftPressureWorkerFailed: 'false', draftPressureLocalTicks: '1200', draftPressureLocalExpiryTicks: '1',
  draftPressureLongestCandidateMillis: '200', draftPressureSeenPredicateMask: '7',
};
const pressureBundle = (values = pressure) => Object.entries(values).map(([key, value]) => `INSTRUMENTATION_STATUS: ${key}=${value}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 3\n';
const pressureFailure = (diagnostic = pressureBundle()) => names.map((name, index) => name === names[3]
  ? bundle(name, 1) + diagnostic + bundle(name, -2) : pair(name, index)).join('') + terminal;

test('seven actual exact pairs and terminal success are required and reported', () => {
  const result = parse(success);
  assert.equal(result.ok, true); assert.equal(result.started, 7); assert.equal(result.completed, 7);
  assert.match(xml(result), /tests="7" failures="0" errors="0" skipped="0"/);
  assert.equal((xml(result).match(/<testcase /g) ?? []).length, 7);
});
test('a summary alone cannot fabricate any start or completion', () => {
  const result = parse(terminal);
  assert.equal(result.ok, false); assert.equal(result.started, 0); assert.equal(result.completed, 0);
  assert.match(xml(result), /errors="7"/);
});
test('expiry success requires one canonical typed observation within its actual running case', () => {
  assert.match(xml(parse(success)), /name="draftExpiryElapsedMillis" value="30010"/);
  for (const output of [success.replace(progress(), ''), success.replace(progress(), progress() + progress()),
    progress() + success, success.replace(progress(), '') + progress(),
    success.replace(progress(), progress({ ...expiry, PRIVATE_VALUE: 'SECRET' }))]) {
    const result = parse(output); assert.equal(result.ok, false); assert.doesNotMatch(xml(result), /PRIVATE_VALUE|SECRET/);
  }
});
test('expiry observations reject invented timing, malformed types and a deadline that never occurred', () => {
  for (const replacement of [{ draftExpiryVersion: '2' }, { draftExpiryElapsedMillis: '30010.0' },
    { draftExpiryElapsedMillis: '030010' }, { draftExpiryLocalExpired: 'yes' }, { draftExpiryReadyUtcMillis: 'SECRET' },
    { draftExpiryLocalTicks: '0' }, { draftExpiryLocalExpiryTicks: '1201' }, { draftExpiryLocalExpired: 'false', draftExpiryPeerExpired: 'false' },
    { draftExpiryObservedUtcMillis: '1800000027000' }, { draftExpiryElapsedMillis: '27000' },
    { draftExpiryRemainingAtReadyMillis: '31000' }, { draftExpiryPeerReadyUtcMillis: '1800000005000' },
    { draftExpiryPeerTerminalUtcMillis: 'null' }, { draftExpiryPeerTerminalUtcMillis: 'null', draftExpiryPeerTerminalElapsedMillis: 'null' },
    { draftExpiryObservedUtcMillis: '1800000029900', draftExpiryElapsedMillis: '29900' },
    { draftExpiryPeerTerminalUtcMillis: '1800000029900', draftExpiryPeerTerminalElapsedMillis: '29900' }]) {
    const result = parse(success.replace(progress(), progress({ ...expiry, ...replacement })));
    assert.equal(result.ok, false); assert.doesNotMatch(xml(result), /SECRET/);
  }
});
test('either actual deadline owner can win with bounded skew and retained public evidence', () => {
  for (const replacement of [
    { draftExpiryLocalExpired: 'false', draftExpiryLocalExpiryTicks: '0', draftExpiryObservedUtcMillis: '1800000028000', draftExpiryElapsedMillis: '28000' },
    { draftExpiryPeerExpired: 'false', draftExpiryPeerTerminalUtcMillis: 'null', draftExpiryPeerTerminalElapsedMillis: 'null' },
    { draftExpiryObservedUtcMillis: '1800000029000', draftExpiryPeerTerminalUtcMillis: '1800000029000' },
  ]) {
    assert.equal(parse(success.replace(progress(), progress({ ...expiry, ...replacement }))).ok, true);
  }
});
test('failure-only pressure facts survive reports without proving successful expiry', () => {
  const result = parse(pressureFailure());
  assert.equal(result.ok, false); assert.equal(result.started, 7); assert.equal(result.completed, 7);
  assert.equal(result.cases[3].state, 'failed'); assert.equal(Object.keys(result.observations).length, 24);
  assert.match(xml(result), /name="draftPressureFailureElapsedMillis" value="32010"/);
  assert.match(html(result), /draftPressureWriteInFlight/);
  assert.ok(result.problems.includes('missing_or_duplicate_expiry_observation'));
});
test('pressure facts require their exact active case, unique bundle and a failed completion', () => {
  for (const output of [pressureBundle() + pressureFailure(''), pressureFailure('') + pressureBundle(),
    pressureFailure(pressureBundle() + pressureBundle()), success.replace(progress(), pressureBundle() + progress())]) {
    assert.equal(parse(output).ok, false);
  }
  const passed = parse(success.replace(progress(), pressureBundle() + progress()));
  assert.ok(passed.problems.includes('failure_pressure_observation_on_passing_case'));
});
test('pressure facts reject noncanonical, out-of-bound or inconsistent data without retaining secrets', () => {
  for (const values of [{ ...pressure, PRIVATE_VALUE: 'SECRET' }, { ...pressure, draftPressureControlCause: 'SECRET' },
    { ...pressure, draftPressureStreamPhase: 'SECRET' }, { ...pressure, draftPressureWorkerFailed: 'yes' },
    { ...pressure, draftPressureWriteEntered: '0750' }, { ...pressure, draftPressureWriteEntered: '750.0' },
    { ...pressure, draftPressureWriteCompleted: '751' }, { ...pressure, draftPressureWriteInFlight: '751' },
    { ...pressure, draftPressureChargedBytes: '8193' }, { ...pressure, draftPressureChargedFrames: '5' },
    { ...pressure, draftPressurePendingClientBytes: '4097' }, { ...pressure, draftPressureApplicationWritten: '33562625' },
    { ...pressure, draftPressureSeenPredicateMask: '8' }, { ...pressure, draftPressureLocalExpiryTicks: '1201' },
    { ...pressure, draftPressureFailureElapsedMillis: '11999' }, { ...pressure, draftPressureFailureUtcMillis: '0' }]) {
    const result = parse(pressureFailure(pressureBundle(values)));
    assert.ok(result.problems.includes('invalid_pressure_observation'));
    assert.equal(Object.keys(result.observations).length, 0);
    assert.doesNotMatch(xml(result) + html(result), /PRIVATE_VALUE|SECRET/);
  }
});
test('pressure facts preserve active/exhausted/partial-predicate states without assuming a cause', () => {
  for (const values of [{ ...pressure, draftPressureControlPhase: 'active', draftPressureControlCause: 'null', draftPressureStreamPhase: 'half_closed',
    draftPressureStreamCause: 'null', draftPressureWriteCompleted: '750', draftPressureChargedBytes: '0', draftPressureChargedFrames: '0',
    draftPressurePendingClientBytes: '0', draftPressureApplicationWritten: '33554549', draftPressureProducerFinished: 'true',
    draftPressureOwnedStopping: 'false', draftPressureLocalExpiryTicks: '0', draftPressureLongestCandidateMillis: '0', draftPressureSeenPredicateMask: '1' },
    { ...pressure, draftPressureControlCause: 'network_unreachable', draftPressureStreamCause: 'network_unreachable', draftPressureLocalExpiryTicks: '0' }]) {
    const result = parse(pressureFailure(pressureBundle(values)));
    assert.equal(result.ok, false); assert.equal(Object.keys(result.observations).length, 24);
    assert.ok(!result.problems.includes('invalid_pressure_observation'));
  }
});
test('all seven can execute in another JUnit order without changing the report contract', () => {
  const result = parse([...names].reverse().map(pair).join('') + terminal);
  assert.equal(result.ok, true); assert.deepEqual(result.cases.map(value => value.name), names);
});
test('missing, duplicate, foreign and overlapping case identities cannot pass', () => {
  for (const output of [success.replace(pair(names[0], 0), ''), pair(names[0], 0) + success,
    success.replace(clazz, 'com.other.Test'), success.replace(names[0], 'otherMethod'),
    bundle(names[0], 1) + bundle(names[1], 1) + names.map(pair).join('') + terminal]) {
    assert.equal(parse(output).ok, false);
  }
});
test('completion without its exact active start and repeated completions fail', () => {
  for (const output of [bundle(names[0], 0) + success, success.replace(bundle(names[0], 0), bundle(names[1], 0)),
    success.replace(terminal, bundle(names[6], 0) + terminal)]) assert.equal(parse(output).ok, false);
});
test('incomplete starts and a process crash remain unexecuted errors', () => {
  const result = parse(bundle(names[0], 1) + 'INSTRUMENTATION_RESULT: shortMsg=Process crashed SECRET\nINSTRUMENTATION_CODE: 0\n');
  assert.equal(result.started, 1); assert.equal(result.completed, 0); assert.equal(result.ok, false);
  assert.match(xml(result), /errors="7"/); assert.doesNotMatch(xml(result) + html(result), /SECRET/);
});
test('skips, assumptions, unknown statuses and error fields cannot look successful', () => {
  for (const status of [-1, -2, -3, -4, -99]) {
    const output = bundle(names[0], 1) + bundle(names[0], status) + names.slice(1).map((name, index) => pair(name, index + 1)).join('') + terminal;
    assert.equal(parse(output).ok, false); assert.match(xml(parse(output)), /failures="1"/);
  }
  assert.equal(parse(success.replace('current=1', 'Error=SECRET\nINSTRUMENTATION_STATUS: current=1')).ok, false);
});
test('missing, duplicate or failed terminal results and late status cannot pass', () => {
  for (const output of [success.replace(terminal, ''), success.replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0'),
    success + 'INSTRUMENTATION_CODE: -1\n', success + bundle(names[0], 1),
    success.replace(terminal, 'INSTRUMENTATION_RESULT: stream=FAILURES!!!\nINSTRUMENTATION_CODE: -1\n')]) assert.equal(parse(output).ok, false);
});
test('wrong declared counts, ordinals, repeated fields and incomplete bundles fail', () => {
  for (const output of [success.replace('numtests=7', 'numtests=6'), success.replace('numtests=7\n', ''),
    success.replace('current=1', 'current=7'), success.replace('test=', 'test=duplicate\nINSTRUMENTATION_STATUS: test='),
    success + 'INSTRUMENTATION_STATUS: class=unfinished\n']) assert.equal(parse(output).ok, false);
});
test('process failure and capture limits override apparently successful case text', () => {
  for (const options of [{ exitCode: 1 }, { signal: 'SIGTERM' }, { transportError: 'owned_child_timeout' }]) {
    const result = parse(success, options); assert.equal(result.ok, false); assert.match(xml(result), /errors="1"/);
  }
  const large = parse('x'.repeat(MAX_INSTRUMENTATION_BYTES + 1));
  assert.equal(large.started, 0); assert.ok(large.problems.includes('instrumentation_output_limit'));
});
test('redacts failure messages and paths but retains permitted call sites and types', () => {
  const detail = 'INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: DO_NOT_RETAIN\n' +
    '\tat com.httpfreekit.interop.DraftStreamingOwner.write(DraftStreamingOwner.kt:12)\n' +
    'Caused by: javax.net.ssl.SSLException: DO_NOT_RETAIN /private/key\n';
  const output = bundle(names[0], 1) + bundle(names[0], -2, detail) + names.slice(1).map((name, index) => pair(name, index + 1)).join('') + terminal;
  const reports = xml(parse(output)) + html(parse(output));
  assert.match(reports, /DraftStreamingOwner.kt:12/); assert.match(reports, /javax.net.ssl.SSLException/);
  assert.doesNotMatch(reports, /DO_NOT_RETAIN|private\/key/);
});
test('only exact fixed research phases for the actual scenario survive wrapped failure redaction', () => {
  const reports = message => {
    const detail = `INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: ${message}\n`;
    const output = bundle(names[0], 1) + bundle(names[0], -2, detail) + names.slice(1).map((name, index) => pair(name, index + 1)).join('') + terminal;
    return xml(parse(output)) + html(parse(output));
  };
  assert.match(reports('Draft streaming gated failed at gated-upload-prefix (IllegalStateException)'), /Research phase: gated\/gated-upload-prefix \(IllegalStateException\)/);
  for (const message of ['Draft streaming gated failed at PRIVATE_VALUE (IllegalStateException)',
    'Draft streaming cancel failed at cancel-independent-control (IOException)',
    'Draft streaming gated failed at gated-upload-prefix (IOException) PRIVATE_VALUE']) {
    assert.doesNotMatch(reports(message), /Research phase:|PRIVATE_VALUE/);
  }
  const unknownType = reports('Draft streaming gated failed at gated-upload-prefix (PRIVATEException)');
  assert.match(unknownType, /other_exception/); assert.doesNotMatch(unknownType, /PRIVATE/);
});
test('pressure failures retain distinct proxy and Android stages plus bounded original project call sites', () => {
  for (const [name, scenario] of [[names[2], 'cancel'], [names[3], 'expiry']]) {
    for (const side of ['proxy', 'android']) {
      const stack = `INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: Draft streaming ${scenario} failed at ${scenario}-${side}-actual-write (IllegalStateException)\n` +
        '\tat com.httpfreekit.interop.DraftStreamingFixtureKt.draftAwait(DraftStreamingFixture.kt:231)\n' +
        '\tat com.httpfreekit.interop.DraftStreamingOwner$Stream.observedBlockedWriter(DraftStreamingOwner.kt:411)\n' +
        'Caused by: java.lang.IllegalStateException: PRIVATE_VALUE /private/path\n';
      const output = names.map((testName, index) => testName === name
        ? bundle(name, 1) + bundle(name, -2, stack) : pair(testName, index)).join('') + terminal;
      const report = xml(parse(output)) + html(parse(output));
      assert.match(report, new RegExp(`Research phase: ${scenario}/${scenario}-${side}-actual-write`));
      assert.match(report, /DraftStreamingFixture.kt:231/); assert.match(report, /DraftStreamingOwner.kt:411/);
      assert.doesNotMatch(report, /PRIVATE_VALUE|private\/path/);
    }
  }
});
test('success with a failure stack and excessive status metadata fails closed', () => {
  assert.equal(parse(success.replace('current=1\n', 'current=1\nINSTRUMENTATION_STATUS: stack=SECRET\n')).ok, false);
  const fields = Array.from({ length: 35 }, (_, index) => `INSTRUMENTATION_STATUS: field${index}=SECRET\n`).join('');
  const result = parse(success.replace('current=1\n', 'current=1\n' + fields));
  assert.equal(result.ok, false); assert.doesNotMatch(xml(result), /SECRET/);
});
test('unknown host failures are static and reports cannot narrow or rename the gate', () => {
  assert.equal(draftSetupCode('/private/secret'), 'host_setup_failed');
  assert.doesNotMatch(xml(parse(success, { transportError: 'DO_NOT_RETAIN' })), /DO_NOT_RETAIN/);
  const result = parse(success); result.cases.pop();
  assert.throws(() => xml(result), /^Error: invalid_result_contract$/);
});

test('real clock preflight uses stricter two-second bounds without rebasing time', () => {
  const epoch = 1800000000000;
  assert.equal(clock('1800000001', epoch, epoch).draftClockStatus, 'within_bound');
  assert.equal(clock('1800000002', epoch, epoch).draftClockStatus, 'skew_exceeds_bound');
  assert.equal(clock('1800000000', epoch + 2000, epoch + 2000).draftClockStatus, 'within_bound');
  assert.equal(clock('1800000003', epoch, epoch).draftClockStatus, 'skew_exceeds_bound');
  assert.equal(clock('1800000000', epoch + 3000, epoch + 3000).draftClockStatus, 'skew_exceeds_bound');
  const bounded = clock('1800000001', epoch, epoch + 2000);
  assert.equal(bounded.draftClockStatus, 'within_bound');
  assert.equal(bounded.fixtureClockSkewMillis, 0);
  assert.equal(bounded.fixtureHostBeforeProbeEpochMillis, epoch);
  assert.equal(bounded.fixtureClockSkewLowerBoundMillis, -1000);
  assert.equal(bounded.fixtureClockSkewUpperBoundMillis, 1999);
  assert.equal(clock('1800000001', epoch, epoch + 2001).draftClockStatus, 'probe_budget_exceeded');
});
test('the entire second-resolution and round-trip uncertainty interval must fit the skew bound', () => {
  const epoch = 1800000000000;
  const ahead = clock('1800000002', epoch, epoch);
  assert.equal(ahead.fixtureClockSkewMillis, 2000);
  assert.equal(ahead.fixtureClockSkewLowerBoundMillis, 2000);
  assert.equal(ahead.fixtureClockSkewUpperBoundMillis, 2999);
  assert.equal(ahead.draftClockStatus, 'skew_exceeds_bound');
  const behind = clock('1800000000', epoch + 1500, epoch + 2500);
  assert.equal(behind.fixtureClockSkewMillis, -2000);
  assert.equal(behind.fixtureClockSkewLowerBoundMillis, -2500);
  assert.equal(behind.draftClockStatus, 'skew_exceeds_bound');
  const edge = clock('1800000002', epoch + 999, epoch + 999);
  assert.equal(edge.fixtureClockSkewUpperBoundMillis, 2000);
  assert.equal(edge.draftClockStatus, 'within_bound');
});
test('malformed, backward or invalid clock probes fail with no supplied data', () => {
  const epoch = 1800000000000;
  for (const args of [['SECRET', epoch, epoch], ['1800000000\n', epoch, epoch],
    ['1800000000', epoch, epoch - 1], ['1800000000', Number.NaN, epoch]]) {
    assert.throws(() => clock(...args), /^Error: draft_clock_probe_invalid$/);
  }
});
