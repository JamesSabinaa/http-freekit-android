import test from 'node:test';
import assert from 'node:assert/strict';
import { captureColdClass, captureColdMethod, captureColdSnapshotKeys, captureColdCleanupKeys,
  captureColdProblem, parseCaptureColdInvocation, captureColdReportAccepted, captureColdXml } from './capture-cold-results.mjs';

const command = { code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true };
const facts = () => ({ coldVersion: '1', coldScenario: 'cold-http', coldOwnerAbsentBefore: 'true', coldOwnerAbsentAfter: 'true',
  coldRouteObserved: 'true', coldHttpAttempts: '1', coldTrafficCommand: '10', coldTrafficStatus: '0', coldTrafficBytes: '32787',
  coldTrafficSha256: '05dfd86ee3ecc0267ceb6234e1955c1e8c80e34b6323b2b1c87c7d1d84042255',
  coldFailurePhase: 'none', coldFailureCode: 'none', coldCleanupJoined: 'true' });
const negative = () => ({ ...facts(), coldTrafficStatus: '3', coldTrafficBytes: '0', coldTrafficSha256: 'none',
  coldFailurePhase: 'http', coldFailureCode: 'traffic_tcp_eof_reset' });
const identity = () => `INSTRUMENTATION_STATUS: class=${captureColdClass}\nINSTRUMENTATION_STATUS: test=${captureColdMethod}\n`;
const bundle = (value, code) => Object.entries(value).map(([key, item]) => `INSTRUMENTATION_STATUS: ${key}=${item}\n`).join('') + `INSTRUMENTATION_STATUS_CODE: ${code}\n`;
const output = (value = facts(), code = 2) => identity() + 'INSTRUMENTATION_STATUS_CODE: 1\n' + bundle(value, code) + identity() +
  (code === 3 ? 'INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: Cold TCP comparison failed.\nCaused by: private.CANARY\n' : '') +
  `INSTRUMENTATION_STATUS_CODE: ${code === 3 ? -2 : 0}\nINSTRUMENTATION_CODE: -1\n`;
const snapshot = (after = false, closed = false) => Object.fromEntries(captureColdSnapshotKeys.map(key => [key,
  key === 'closed' ? closed : key === 'listeners' ? closed ? 0 : 7 : after ? ({ directHttp: 1, tcpConnections: 1, uploadBytes: 16528, downloadBytes: 32787 }[key] ?? 0) : 0]));
const report = () => ({ format: 'http-freekit-capture-cold-tcp', revision: 1, source: { commit: 'a'.repeat(40), trackedDirty: false }, api: 26,
  clock: { deviceEpochSeconds: 1792890000, hostBeforeMillis: 1792890000200, hostAfterMillis: 1792890000220,
    roundTripMillis: 20, lowerBoundMillis: -220, upperBoundMillis: 799 },
  method: { invocation: parseCaptureColdInvocation(output(), command), receiversBefore: snapshot(), receiversAfter: snapshot(true) },
  cleanup: { forceStopExitCodes: [0, 0, 0], uninstallExitCodes: [0, 0, 0], packagesAbsent: true,
    ownedCommandsClosed: true, ownedCommandGroupsClosed: true, receivers: snapshot(true, true) }, problems: [], accepted: false });
const clone = value => structuredClone(value);

test('frozen exports distinguish receiver fields from the six report cleanup fields', () => {
  assert.equal(captureColdSnapshotKeys.length, 25); assert.equal(new Set(captureColdSnapshotKeys).size, 25);
  assert.deepEqual(captureColdCleanupKeys, ['forceStopExitCodes', 'ownedCommandGroupsClosed', 'ownedCommandsClosed', 'packagesAbsent', 'receivers', 'uninstallExitCodes']);
  assert.throws(() => captureColdSnapshotKeys.push('CANARY'), TypeError);
  assert.throws(() => captureColdCleanupKeys.pop(), TypeError);
  assert.equal(captureColdProblem('research_cancelled'), 'research_cancelled');
  for (const value of ['CANARY', null, {}, 'instrumentation_failed']) assert.equal(captureColdProblem(value), 'host_setup_failed');
});

test('one exact standalone invocation preserves thirteen actual string facts and joined command evidence', () => {
  const actual = parseCaptureColdInvocation(Buffer.from(output()), command);
  assert.equal(actual.state, 'passed'); assert.equal(actual.actualStarted, 1); assert.equal(actual.actualCompleted, 1);
  assert.equal(actual.terminalCount, 1); assert.equal(actual.terminalCode, -1);
  assert.deepEqual(actual.observation, facts()); assert.equal(actual.failure, null); assert.deepEqual(actual.problems, []);
  assert.throws(() => { actual.observation.coldTrafficBytes = '0'; }, TypeError);
});

test('failed EOF retains the negative observation and cannot become accepted after a complete host reply', () => {
  const actual = parseCaptureColdInvocation(output(negative(), 3), command);
  assert.equal(actual.state, 'failed'); assert.deepEqual(actual.failure, { phase: 'http', code: 'traffic_tcp_eof_reset' });
  assert.deepEqual(actual.observation, negative()); assert.equal(actual.actualStarted, 1); assert.equal(actual.actualCompleted, 1);
  assert.equal(JSON.stringify(actual).includes('CANARY'), false);
  const value = report(); value.method.invocation = actual; value.accepted = true;
  assert.equal(captureColdReportAccepted(value), false);
  assert.match(captureColdXml(value), /failures="1" errors="1" skipped="0"/);
});

test('finite negative facts survive later cleanup or owner changes without extra sequencing rules', () => {
  const value = { ...negative(), coldOwnerAbsentAfter: 'false', coldCleanupJoined: 'false', coldTrafficCommand: '18', coldHttpAttempts: '1' };
  const actual = parseCaptureColdInvocation(output(value, 3), command);
  assert.equal(actual.state, 'failed'); assert.deepEqual(actual.observation, value);
  assert.equal(actual.failure.code, 'traffic_tcp_eof_reset');
});

test('every supported finite failure category is preserved while foreign codes and arbitrary text are discarded', () => {
  for (const code of ['traffic_tcp_connect_timeout', 'traffic_tcp_eof_not_connected', 'traffic_route_nonvpn_timeout_p1_i1_v0',
    'traffic_route_unavailable', 'traffic_command_failed', 'traffic_close_io', 'cold_setup', 'cold_route_reply', 'cold_tcp_reply', 'cold_client_cleanup', 'cold_owner_present']) {
    const actual = parseCaptureColdInvocation(output({ ...negative(), coldFailureCode: code }, 3), command);
    assert.equal(actual.failure.code, code); assert.equal(actual.state, 'failed');
  }
  for (const code of ['CANARY_PRIVATE', 'traffic_datagram_io', 'traffic_route_vpn_timeout_p1_i1_v1', 'traffic_tcp_eof_\rreset']) {
    const actual = parseCaptureColdInvocation(output({ ...negative(), coldFailureCode: code }, 3), command);
    assert.equal(actual.observation, null); assert.ok(actual.problems.includes('invalid_cold_facts'));
    assert.equal(JSON.stringify(actual).includes('CANARY'), false);
  }
});

test('status-three always latches failure despite later positive facts or a success completion', () => {
  const text = identity() + 'INSTRUMENTATION_STATUS_CODE: 1\n' + bundle(negative(), 3) + bundle(facts(), 2) + identity() + 'INSTRUMENTATION_STATUS_CODE: 0\nINSTRUMENTATION_CODE: -1\n';
  const actual = parseCaptureColdInvocation(text, command);
  assert.equal(actual.state, 'failed'); assert.equal(actual.failure.code, 'traffic_tcp_eof_reset');
  assert.deepEqual(actual.observation, negative()); assert.ok(actual.problems.includes('invalid_cold_facts'));
  const invalid = parseCaptureColdInvocation(output(facts(), 3), command);
  assert.equal(invalid.state, 'failed'); assert.ok(invalid.problems.includes('instrumentation_failed'));
});

test('positive facts reject changed owners, route, attempt, tuple, hash and failure state', () => {
  const changes = { coldOwnerAbsentBefore: 'false', coldOwnerAbsentAfter: 'false', coldRouteObserved: 'false', coldCleanupJoined: 'false',
    coldHttpAttempts: '0', coldTrafficCommand: '18', coldTrafficStatus: '3', coldTrafficBytes: '32786',
    coldTrafficSha256: 'b'.repeat(64), coldFailurePhase: 'http', coldFailureCode: 'cold_tcp_reply' };
  for (const [key, value] of Object.entries(changes)) {
    const actual = parseCaptureColdInvocation(output({ ...facts(), [key]: value }), command);
    assert.notEqual(actual.state, 'passed', key); assert.equal(actual.observation, null, key);
  }
});

test('unknown missing duplicate and noncanonical observation values never substitute facts', () => {
  const mutations = [v => { v.CANARY = 'private'; }, v => { delete v.coldVersion; }, v => { v.coldTrafficBytes = '032787'; },
    v => { v.coldTrafficBytes = '+32787'; }, v => { v.coldTrafficBytes = '1e2'; }, v => { v.coldTrafficBytes = '65508'; },
    v => { v.coldTrafficSha256 = 'A'.repeat(64); }, v => { v.coldCleanupJoined = '1'; }, v => { v.coldHttpAttempts = '2'; },
    v => { v.coldTrafficStatus = '-0'; }, v => { v.coldTrafficCommand = '010'; }, v => { v.coldScenario = 'cold-\rhttp'; }];
  for (const mutate of mutations) {
    const value = facts(); mutate(value); const actual = parseCaptureColdInvocation(output(value), command);
    assert.notEqual(actual.state, 'passed'); assert.equal(actual.observation, null);
    assert.equal(JSON.stringify(actual).includes('CANARY'), false);
  }
  const duplicate = output().replace('INSTRUMENTATION_STATUS: coldVersion=1\n', 'INSTRUMENTATION_STATUS: coldVersion=1\nINSTRUMENTATION_STATUS: coldVersion=1\n');
  assert.notEqual(parseCaptureColdInvocation(duplicate, command).state, 'passed');
});

test('foreign identities missing starts skips repeated cases and malformed terminals remain rejecting', () => {
  for (const text of [output().replaceAll(captureColdClass, 'foreign.CANARY'), output().replaceAll(captureColdMethod, 'foreignMethod'),
    output().replace(identity() + 'INSTRUMENTATION_STATUS_CODE: 1\n', ''), output() + output(),
    output().replace('INSTRUMENTATION_STATUS_CODE: 0', 'INSTRUMENTATION_STATUS_CODE: -3'),
    output().replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: -01'),
    output().replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: -1\nINSTRUMENTATION_CODE: -1'),
    'INSTRUMENTATION_CODE: -1\n' + output(), output().replace('INSTRUMENTATION_STATUS_CODE: 0', 'INSTRUMENTATION_STATUS_CODE: 0\nINSTRUMENTATION_STATUS: CANARY=x')]) {
    const actual = parseCaptureColdInvocation(text, command); assert.notEqual(actual.state, 'passed');
    assert.equal(JSON.stringify(actual).includes('CANARY'), false);
  }
});

test('a failure stack or instrumentation abort cannot coexist with a passing result', () => {
  for (const text of [output().replace(identity() + 'INSTRUMENTATION_STATUS_CODE: 0', identity() + 'INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: CANARY\nINSTRUMENTATION_STATUS_CODE: 0'),
    output() + 'INSTRUMENTATION_ABORTED: CANARY\n', output() + 'INSTRUMENTATION_RESULT: shortMsg=CANARY\n']) {
    const actual = parseCaptureColdInvocation(text, command); assert.equal(actual.state, 'failed');
    assert.equal(JSON.stringify(actual).includes('CANARY'), false);
  }
});

test('byte line UTF8 and status-bundle bounds reject before retaining attacker text', () => {
  for (const value of [Buffer.alloc(262145), '\u00e9'.repeat(131073), Buffer.from([0xff]), 'a'.repeat(8193),
    identity() + Array.from({ length: 49 }, (_, i) => `INSTRUMENTATION_STATUS: field${i}=x\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 1\n']) {
    assert.notEqual(parseCaptureColdInvocation(value, command).state, 'passed');
  }
});

test('owned command failures signals missing closes and unknown reasons cannot prove execution', () => {
  for (const change of [{ code: 124 }, { signal: 'SIGTERM' }, { signal: 'CANARY' }, { reason: 'CANARY' }, { reason: 0 },
    { closeObserved: false }, { processGroupClosed: false }, { code: false }]) {
    const actual = parseCaptureColdInvocation(output(), { ...command, ...change });
    assert.equal(actual.state, 'failed'); assert.equal(JSON.stringify(actual).includes('CANARY'), false);
  }
});

test('the independent report gate accepts the exact cold vector before assigning its accepted output', () => {
  const value = report(); assert.equal(captureColdReportAccepted(value), true); assert.equal(value.accepted, false);
  value.accepted = true; assert.equal(captureColdReportAccepted(value), true);
  assert.deepEqual(value.method.receiversBefore, snapshot());
});

test('extra traffic resets timeouts and leftover resources reject even when Android facts pass', () => {
  for (const key of captureColdSnapshotKeys.filter(key => key !== 'closed')) {
    const value = report(); value.method.receiversAfter[key]++;
    assert.equal(captureColdReportAccepted(value), false, key);
  }
  for (const location of ['receiversBefore', 'receiversAfter']) {
    for (const key of ['closed', 'tcpErrorEvents', 'listeners']) {
      const value = report(); value.method[location][key] = key === 'closed' ? true : false;
      assert.equal(captureColdReportAccepted(value), false);
    }
  }
  const reset = report(); reset.method.receiversAfter.tcpResetErrors = 1;
  assert.equal(captureColdReportAccepted(reset), false);
});

test('dirty source bad clock missing joins and post-transaction counter changes reject', () => {
  const mutations = [v => { v.source.trackedDirty = true; }, v => { v.source.commit += '\n'; }, v => { v.api = 37; },
    v => { v.clock.lowerBoundMillis = -2001; }, v => { v.clock.roundTripMillis++; }, v => { v.clock.extra = 1; },
    v => { v.cleanup.receivers.uploadBytes++; }, v => { v.cleanup.receivers.timers = 1; }, v => { v.cleanup.receivers.closed = false; },
    v => { v.cleanup.forceStopExitCodes = [0, 0]; }, v => { v.cleanup.uninstallExitCodes[2] = 1; },
    v => { v.cleanup.packagesAbsent = false; }, v => { v.cleanup.ownedCommandsClosed = false; }, v => { v.cleanup.ownedCommandGroupsClosed = false; },
    v => { v.method.invocation.command.closeObserved = false; }, v => { v.method.invocation.terminalCount = 0; },
    v => { v.method.invocation.observation.coldCleanupJoined = 'false'; }, v => { v.problems = ['CANARY']; }];
  for (const mutate of mutations) { const value = clone(report()); mutate(value); value.accepted = true; assert.equal(captureColdReportAccepted(value), false); }
});

test('strict report schemas reject unknown fields at every nested boundary', () => {
  for (const select of [v => v, v => v.source, v => v.clock, v => v.method, v => v.method.invocation,
    v => v.method.invocation.command, v => v.method.invocation.observation, v => v.method.receiversBefore, v => v.method.receiversAfter,
    v => v.cleanup, v => v.cleanup.receivers]) {
    const value = clone(report()); select(value).CANARY = 'private'; assert.equal(captureColdReportAccepted(value), false);
  }
});

test('accepted XML has exact fixed identities source properties and fifteen testcase properties', () => {
  const value = report(); value.accepted = captureColdReportAccepted(value); const text = captureColdXml(value);
  assert.match(text, /name="capture-cold-tcp" tests="1" failures="0" errors="0" skipped="0"/);
  assert.match(text, new RegExp(`classname="${captureColdClass}" name="${captureColdMethod}" time="0"`));
  assert.equal((text.match(/<property /g) ?? []).length, 18); assert.equal(Buffer.byteLength(text) < 65536, true);
  assert.equal(text.includes('<failure'), false);
});

test('XML recomputes contradictory gates and never prints raw report exception or provider values', () => {
  const value = report(); value.accepted = true; value.cleanup.packagesAbsent = false;
  assert.match(captureColdXml(value), /errors="1"/);
  value.source.commit = 'CANARY_PRIVATE'; value.method.invocation.observation = { CANARY: 'secret' };
  value.method.invocation.problems = ['CANARY']; value.method.invocation.failure = { phase: 'CANARY', code: 'secret' };
  const text = captureColdXml(value); assert.equal(text.includes('CANARY'), false); assert.equal(text.includes('secret'), false);
  assert.match(text, /failures="1" errors="1"/);
});
