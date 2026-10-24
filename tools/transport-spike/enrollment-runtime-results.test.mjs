import test from 'node:test';
import assert from 'node:assert/strict';
import { createEnrollmentInvocationParser, parseEnrollmentInvocation, enrollmentPhases, expectedEnrollmentMethods,
  createEnrollmentRuntimeReport, verifyEnrollmentRuntime, enrollmentRuntimeXml, enrollmentRuntimeHtml,
  EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { transcript, status, phase, commandResult, runtime, clone, source } from './enrollment-runtime-test-fixtures.mjs';
const method = expectedEnrollmentMethods[0];
const parse = (text, overrides = {}) => parseEnrollmentInvocation(text, { method, ...commandResult(), ...overrides });

test('both exact methods require all paired phases, command close and terminal success', () => {
  for (const name of expectedEnrollmentMethods) {
    const result = parseEnrollmentInvocation(transcript(name), { method: name, ...commandResult() });
    assert.equal(result.state, 'passed'); assert.equal(result.actualStarted, 1); assert.equal(result.actualCompleted, 1);
    assert.deepEqual(result.phases, enrollmentPhases[name]); assert.deepEqual(result.problems, []);
    assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.phases));
  }
});
test('every byte boundary is incremental and incomplete phase cannot authorize approval', () => {
  const observed = [], parser = createEnrollmentInvocationParser(method, { onPhase: value => { observed.push(value); } });
  const text = transcript(method), trigger = text.indexOf('INSTRUMENTATION_STATUS_CODE: 2\n') + 'INSTRUMENTATION_STATUS_CODE: 2'.length;
  for (const byte of Buffer.from(text.slice(0, trigger))) parser.push(Buffer.from([byte]));
  assert.deepEqual(observed, []);
  for (const byte of Buffer.from(text.slice(trigger))) parser.push(Buffer.from([byte]));
  assert.deepEqual(observed, enrollmentPhases[method]); assert.equal(parser.finish(commandResult()).state, 'passed');
});
test('split UTF8 is accepted but malformed UTF8, BOM, NUL and truncated sequences fail closed', () => {
  const parser = createEnrollmentInvocationParser(method);
  for (const byte of Buffer.from('INSTRUMENTATION_RESULT: stream=\u{1f642}\n' + transcript(method))) parser.push(Buffer.from([byte]));
  assert.equal(parser.finish(commandResult()).state, 'passed');
  for (const bytes of [Buffer.from([0xc0, 0xaf]), Buffer.from('\uFEFF'), Buffer.from([0]), Buffer.from([0xe2])]) {
    const p = createEnrollmentInvocationParser(method);
    try { p.push(bytes); } catch (error) { assert.ok(error instanceof EnrollmentRuntimeError); }
    assert.notEqual(p.finish(commandResult()).state, 'passed');
  }
});
test('phase before start, foreign active method and malformed or reordered phases never call observer', () => {
  const variants = [phase('input-consumed'), status(expectedEnrollmentMethods[1], 1) + phase('input-consumed'),
    status(method, 1) + phase('strict-csr-reserved'), status(method, 1) + phase('input-consumed').replace('Version=1', 'Version=2'),
    status(method, 1) + phase('input-consumed').replace('INSTRUMENTATION_STATUS_CODE:', 'INSTRUMENTATION_STATUS: secret=DO_NOT_RETAIN\nINSTRUMENTATION_STATUS_CODE:')];
  for (const text of variants) {
    let calls = 0; const parser = createEnrollmentInvocationParser(method, { onPhase: () => { calls++; } });
    assert.throws(() => parser.push(Buffer.from(text)), EnrollmentRuntimeError);
    assert.equal(calls, 0); assert.notEqual(parser.finish(commandResult()).state, 'passed');
  }
});
test('duplicate phase or metadata, skipped phase and status after terminal cannot pass', () => {
  const valid = transcript(method), first = phase('input-consumed');
  const variants = [valid.replace(first, first + first), valid.replace(first, ''),
    valid.replace('INSTRUMENTATION_STATUS: numtests=1', 'INSTRUMENTATION_STATUS: numtests=1\nINSTRUMENTATION_STATUS: numtests=1'),
    valid + first];
  for (const text of variants) assert.notEqual(parse(text).state, 'passed');
});
test('callback exceptions and promises abort observer with static error and retain only actual phases', async () => {
  for (const callback of [() => { throw Error('PRIVATE_CANARY'); }, () => Promise.reject(Error('PRIVATE_CANARY')), () => 1]) {
    const parser = createEnrollmentInvocationParser(method, { onPhase: callback });
    assert.throws(() => parser.push(Buffer.from(status(method, 1) + phase('input-consumed'))), /phase_callback_failed/);
    const result = parser.finish({ ...commandResult(), reason: 'owned_child_observer_failed' });
    assert.deepEqual(result.phases, ['input-consumed']); assert.ok(!JSON.stringify(result).includes('PRIVATE_CANARY'));
    assert.notEqual(result.state, 'passed');
  }
  await new Promise(resolve => setImmediate(resolve));
});
test('bounded output, line, stack and metadata collections fail without retaining excess bytes', () => {
  const texts = ['x'.repeat(8193), ('x\n').repeat(131073), status(method, 1) + 'INSTRUMENTATION_STATUS: stack=' + 'x'.repeat(8180) + '\nx'.repeat(100),
    Array.from({ length: 17 }, (_, index) => `INSTRUMENTATION_STATUS: key${index}=x\n`).join('')];
  for (const text of texts) {
    const result = parse(text); assert.notEqual(result.state, 'passed');
    assert.ok(Buffer.byteLength(JSON.stringify(result)) < 4096);
  }
});
test('missing, repeated, failed terminal and incomplete or skipped JUnit execution never pass', () => {
  const valid = transcript(method);
  for (const text of [valid.replace('INSTRUMENTATION_CODE: -1\n', ''), valid + 'INSTRUMENTATION_CODE: -1\n',
    valid.replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0'), valid.replace(status(method, 0), ''),
    valid.replace(status(method, 0), status(method, -3)), valid.replace('numtests=1', 'numtests=2'),
    valid.replace(status(method, 1), status(method, 1) + status(method, 1)),
    valid.replace(status(method, 1), ''), valid + 'INSTRUMENTATION_RESULT: shortMsg=PRIVATE_CANARY\n']) assert.notEqual(parse(text).state, 'passed');
});
test('foreign method cannot increment actual starts or authorize approval', () => {
  const result = parse(transcript(expectedEnrollmentMethods[1]));
  assert.equal(result.actualStarted, 0); assert.equal(result.actualCompleted, 0); assert.equal(result.state, 'not_started');
});
test('nonzero command, signal, timeout and unjoined process cannot be accepted', () => {
  for (const overrides of [{ code: 1 }, { code: null, signal: 'SIGKILL' }, { reason: 'owned_child_timeout' },
    { closeObserved: false }, { processGroupClosed: false }]) assert.notEqual(parse(transcript(method), overrides).state, 'passed');
});
test('failed stack retains bounded own call sites and finite type, never messages, causes or foreign paths', () => {
  const stack = 'java.lang.AssertionError: PRIVATE_CANARY\n' +
    '\tat com.httpfreekit.interop.DraftEnrollmentInteropTest.prepareApprovedCredentialForRestart(DraftEnrollmentInteropTest.kt:25)\n' +
    '\tat com.vendor.Private.userId(Secret.kt:1)\nCaused by: java.io.IOException: PRIVATE_CAUSE\n' +
    '\tat com.httpfreekit.interop.DraftEnrollmentClient.work(Foreign.kt:1)\n' +
    '\tat com.httpfreekit.interop.DraftEnrollmentClient.work(DraftEnrollmentClient.kt:30)';
  const result = parse(transcript(method).replace(status(method, 0), status(method, -2, 'INSTRUMENTATION_STATUS: stack=' + stack + '\n')));
  assert.equal(result.state, 'failed'); assert.equal(result.failureType, 'AssertionError'); assert.equal(result.frames.length, 2);
  for (const canary of ['PRIVATE_CANARY', 'PRIVATE_CAUSE', 'Secret.kt', 'Foreign.kt', 'com.vendor']) assert.ok(!JSON.stringify(result).includes(canary));
  const many = stack + '\n' + '\tat com.httpfreekit.interop.DraftEnrollmentClient.work(DraftEnrollmentClient.kt:1)\n'.repeat(30);
  assert.equal(parse(transcript(method).replace(status(method, 0), status(method, -2, 'INSTRUMENTATION_STATUS: stack=' + many + '\n'))).frames.length, 16);
});
test('successful status with failure stack and unknown status cannot become green', () => {
  const valid = transcript(method);
  for (const text of [valid.replace(status(method, 0), status(method, 0, 'INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: SECRET\n')),
    valid.replace(status(method, 0), status(method, 12)), valid.replace('INSTRUMENTATION_STATUS_CODE: 1', 'INSTRUMENTATION_STATUS_CODE: 01')]) assert.notEqual(parse(text).state, 'passed');
});
test('finished or broken parser is single use and report copies do not expose mutable observations', () => {
  const parser = createEnrollmentInvocationParser(method); parser.push(Buffer.from(transcript(method))); parser.finish(commandResult());
  assert.throws(() => parser.finish(commandResult()), /parser_closed/); assert.throws(() => parser.push(Buffer.from('x')), /parser_closed/);
  const input = runtime(), report = createEnrollmentRuntimeReport(input); input.approval.completed = false;
  assert.equal(report.approval.completed, true); assert.ok(Object.isFrozen(report.approval));
});
test('truthful XML projects missing methods as errors and host failure never fabricates an Android assertion', () => {
  const report = runtime(); report.problems = ['enrollment_cleanup_failed'];
  const xml = enrollmentRuntimeXml(report);
  assert.match(xml, /tests="2" failures="0" errors="0" skipped="0"/);
  assert.equal((xml.match(/<testcase /g) ?? []).length, 2);
  assert.throws(() => verifyEnrollmentRuntime(report, { source, api: 26 }), /runtime_invocation_failed/);
  report.invocations[1] = parseEnrollmentInvocation('', { method: expectedEnrollmentMethods[1], ...commandResult() });
  assert.match(enrollmentRuntimeXml(report), /errors="1"/); assert.match(enrollmentRuntimeHtml(report), /not_started/);
  const privateReport = clone(report); privateReport.secret = 'PRIVATE_CANARY';
  assert.throws(() => enrollmentRuntimeHtml(privateReport), /invalid_runtime_report/);
});
