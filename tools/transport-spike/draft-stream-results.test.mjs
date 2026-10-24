import test from 'node:test';
import assert from 'node:assert/strict';
import { MAX_INSTRUMENTATION_BYTES } from './instrumentation-results.mjs';
import { draftSetupCode, draftStreamingClass as clazz, expectedDraftStreamingTests as names,
  parseDraftStreamingInstrumentation as parse, draftStreamingXml as xml, draftStreamingHtml as html,
  measureDraftStreamingClock as clock } from './draft-stream-results.mjs';

const bundle = (name, status, extra = '', ordinal = names.indexOf(name) + 1) =>
  `INSTRUMENTATION_STATUS: class=${clazz}\nINSTRUMENTATION_STATUS: test=${name}\nINSTRUMENTATION_STATUS: numtests=7\nINSTRUMENTATION_STATUS: current=${ordinal}\n${extra}INSTRUMENTATION_STATUS_CODE: ${status}\n`;
const pair = (name, index) => bundle(name, 1, '', index + 1) + bundle(name, 0, '', index + 1);
const terminal = 'INSTRUMENTATION_RESULT: stream=\nOK (7 tests)\nINSTRUMENTATION_CODE: -1\n';
const success = names.map(pair).join('') + terminal;

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
  assert.equal(clock('1800000002', epoch, epoch).draftClockStatus, 'within_bound');
  assert.equal(clock('1800000000', epoch + 2000, epoch + 2000).draftClockStatus, 'within_bound');
  assert.equal(clock('1800000003', epoch, epoch).draftClockStatus, 'skew_exceeds_bound');
  assert.equal(clock('1800000000', epoch + 3000, epoch + 3000).draftClockStatus, 'skew_exceeds_bound');
  const bounded = clock('1800000001', epoch, epoch + 2000);
  assert.equal(bounded.draftClockStatus, 'within_bound');
  assert.equal(bounded.fixtureClockSkewMillis, 0);
  assert.equal(bounded.fixtureHostBeforeProbeEpochMillis, epoch);
  assert.equal(clock('1800000001', epoch, epoch + 2001).draftClockStatus, 'probe_budget_exceeded');
});
test('malformed, backward or invalid clock probes fail with no supplied data', () => {
  const epoch = 1800000000000;
  for (const args of [['SECRET', epoch, epoch], ['1800000000\n', epoch, epoch],
    ['1800000000', epoch, epoch - 1], ['1800000000', Number.NaN, epoch]]) {
    assert.throws(() => clock(...args), /^Error: draft_clock_probe_invalid$/);
  }
});
