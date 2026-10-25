import test from 'node:test';
import assert from 'node:assert/strict';
import { interceptionCaRuntimeClass as className, interceptionCaRuntimeMethod as method,
  interceptionCaRuntimePhases as phases, interceptionCaRuntimeObservationSuffixes as suffixes } from './interception-ca-runtime-descriptor.mjs';
import { interceptionCaObservationKeys, decodeInterceptionCaObservation, validateInterceptionCaObservation } from './interception-ca-runtime-observation.mjs';
import { createEnrollmentSuiteInvocationParser, createEnrollmentInvocationParser, expectedEnrollmentMethods,
  enrollmentRuntimeValidation as V } from './enrollment-runtime-results.mjs';
import { transcript as oldTranscript } from './enrollment-runtime-test-fixtures.mjs';

const command = () => ({ code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
const expected = () => ({ version: 1, fetchAttempts: 1, caBytes: 767, savedApprovalValidated: true, originalKeyUnchanged: true,
  privateKeyNonexportable: true, recoveryUnchanged: true, approvedCaHashMatched: true, credentialLeafUnchanged: true,
  freshLookupAfterFetch: true, closed: true, activeCall: false, rawSocketOwned: false, tlsSocketOwned: false,
  deadlineAlive: false, tlsCloserAlive: false, cleanupFailed: false });
const raw = () => ({ draftCaVersion: '1', draftCaFetchAttempts: '1', draftCaCaBytes: '767', draftCaSavedApprovalValidated: 'true',
  draftCaOriginalKeyUnchanged: 'true', draftCaPrivateKeyNonexportable: 'true', draftCaRecoveryUnchanged: 'true',
  draftCaApprovedCaHashMatched: 'true', draftCaCredentialLeafUnchanged: 'true', draftCaFreshLookupAfterFetch: 'true',
  draftCaClosed: 'true', draftCaActiveCall: 'false', draftCaRawSocketOwned: 'false', draftCaTlsSocketOwned: 'false',
  draftCaDeadlineAlive: 'false', draftCaTlsCloserAlive: 'false', draftCaCleanupFailed: 'false' });
const bundle = (value, code) => Object.entries(value).map(([key, field]) => `INSTRUMENTATION_STATUS: ${key}=${field}\n`).join('') + `INSTRUMENTATION_STATUS_CODE: ${code}\n`;
const phase = value => bundle({ draftCaVersion: '1', draftCaPhase: value }, 2);
const status = (code, extra = {}) => bundle({ class: className, test: method, numtests: '1', current: '1', ...extra }, code);
const observation = value => bundle(value ?? raw(), 3);
const prefix = count => status(1) + phases.slice(0, count).map(phase).join('');
const wire = () => prefix(3) + observation() + status(0) + 'INSTRUMENTATION_CODE: -1\n';
function parse(text, overrides = {}) {
  const parser = createEnrollmentSuiteInvocationParser(method, { suite: 'a23' });
  try { parser.push(Buffer.from(text)); } catch { /* The finite parser records its actual failure before closing. */ }
  return parser.finish({ ...command(), ...overrides });
}

test('A23 exact seventeen-field observation decodes only the descriptor method and real byte bounds', () => {
  assert.equal(suffixes.length, 17); assert.deepEqual(interceptionCaObservationKeys, Object.keys(expected()));
  assert.deepEqual(decodeInterceptionCaObservation(raw(), method), expected());
  assert(Object.isFrozen(interceptionCaObservationKeys)); assert(Object.isFrozen(decodeInterceptionCaObservation(raw(), method)));
  for (const bytes of [1, 4096]) {
    const input = raw(); input.draftCaCaBytes = String(bytes);
    assert.equal(decodeInterceptionCaObservation(input, method).caBytes, bytes);
  }
  for (const wrong of [undefined, '', expectedEnrollmentMethods[0], 'retrieveSavedApprovedCaAfterRestart ']) {
    assert.throws(() => decodeInterceptionCaObservation(raw(), wrong)); assert.throws(() => validateInterceptionCaObservation(expected(), wrong));
  }
});

test('every missing, renamed or unknown raw/typed field rejects without calling foreign getters', () => {
  for (const key of Object.keys(raw())) { const input = raw(); delete input[key]; assert.throws(() => decodeInterceptionCaObservation(input, method)); }
  for (const key of interceptionCaObservationKeys) { const input = expected(); delete input[key]; assert.throws(() => validateInterceptionCaObservation(input, method)); }
  for (const input of [null, [], 'PRIVATE_CANARY', { ...raw(), private: 'PRIVATE_CANARY' }, { ...raw(), draftCaCaBytes: 767 }]) assert.throws(() => decodeInterceptionCaObservation(input, method));
  const foreign = raw(); foreign.draftFactoryVersion = foreign.draftCaVersion; delete foreign.draftCaVersion;
  assert.throws(() => decodeInterceptionCaObservation(foreign, method));
  let called = false; const accessor = raw(); Object.defineProperty(accessor, 'draftCaCaBytes', { get() { called = true; return '767'; } });
  assert.throws(() => decodeInterceptionCaObservation(accessor, method)); assert.equal(called, false);
  const symbol = raw(); symbol[Symbol('PRIVATE_CANARY')] = 'x'; assert.throws(() => decodeInterceptionCaObservation(symbol, method));
});

test('canonical numbers, single fetch and positive bounded actual bytes are mandatory', () => {
  for (const key of ['draftCaVersion', 'draftCaFetchAttempts', 'draftCaCaBytes']) for (const value of ['01', '+1', '-0', '1.0', '1e0', 'NaN', 'Infinity', ' 1', '1 ', '10000', 'PRIVATE_CANARY']) {
    assert.throws(() => decodeInterceptionCaObservation({ ...raw(), [key]: value }, method));
  }
  for (const key of ['version', 'fetchAttempts']) for (const value of [0, 2, -1, -0, true, '1', null, NaN]) assert.throws(() => validateInterceptionCaObservation({ ...expected(), [key]: value }, method));
  for (const value of [0, -1, 4097, 1.5, Number.MAX_SAFE_INTEGER, '767', true, null]) assert.throws(() => validateInterceptionCaObservation({ ...expected(), caBytes: value }, method));
});

test('all seven binding facts and Closed must be true and every actual owner/failure flag false', () => {
  for (const [key, value] of Object.entries(expected())) if (typeof value === 'boolean') {
    for (const item of [!value, String(value), 0, 1, null]) assert.throws(() => validateInterceptionCaObservation({ ...expected(), [key]: item }, method), undefined, key);
    const field = 'draftCa' + key[0].toUpperCase() + key.slice(1);
    for (const item of [String(!value), String(value).toUpperCase(), '0', '1', ' true', 'false ']) assert.throws(() => decodeInterceptionCaObservation({ ...raw(), [field]: item }, method), undefined, field);
  }
});

test('actual A23 invocation accepts exactly three phases followed by one final observation, incrementally', () => {
  const seen = [], parser = createEnrollmentSuiteInvocationParser(method, { suite: 'a23', onPhase: value => { seen.push(value); } });
  for (const byte of Buffer.from(wire())) parser.push(Buffer.of(byte));
  const result = parser.finish(command());
  assert.equal(result.state, 'passed'); assert.equal(result.actualStarted, 1); assert.equal(result.actualCompleted, 1);
  assert.deepEqual(result.phases, phases); assert.deepEqual(seen, phases); assert.deepEqual(result.observation, expected());
  assert.deepEqual(result.problems, []); assert.equal(result.failureType, null); assert.deepEqual(result.frames, []);
  assert.equal(Object.hasOwn(result, 'failure'), false); assert(Object.isFrozen(result) && Object.isFrozen(result.observation));
  assert.doesNotThrow(() => V.validateInvocation(result, method, 'a23'));
});

test('each missing phase, order change or duplicate phase and malformed phase bundle remains failed', () => {
  for (const value of phases) assert.notEqual(parse(wire().replace(phase(value), '')).state, 'passed');
  for (const text of [wire().replace(phase(phases[0]), phase(phases[1])), wire().replace(phase(phases[0]), phase(phases[0]) + phase(phases[0])),
    wire().replace('draftCaVersion=1', 'draftCaVersion=2'), wire().replace(phase(phases[1]), phase(phases[1]).replace('INSTRUMENTATION_STATUS_CODE:', 'INSTRUMENTATION_STATUS: private=PRIVATE_CANARY\nINSTRUMENTATION_STATUS_CODE:'))]) assert.notEqual(parse(text).state, 'passed');
});

test('observation cannot precede the third phase, follow JUnit end or terminal, repeat or disappear', () => {
  const inputs = [prefix(2) + observation() + phase(phases[2]) + status(0) + 'INSTRUMENTATION_CODE: -1\n',
    prefix(3) + status(0) + observation() + 'INSTRUMENTATION_CODE: -1\n', prefix(3) + status(0) + 'INSTRUMENTATION_CODE: -1\n' + observation(),
    wire().replace(observation(), observation() + observation()), wire().replace(observation(), '')];
  for (const text of inputs) { const result = parse(text); assert.notEqual(result.state, 'passed'); assert(!JSON.stringify(result).includes('PRIVATE_CANARY')); }
});

test('duplicate, unknown, partial or failed-owner final status cannot be repaired by successful JUnit/command', () => {
  const variants = [observation().replace('INSTRUMENTATION_STATUS: draftCaVersion=1', 'INSTRUMENTATION_STATUS: draftCaVersion=1\nINSTRUMENTATION_STATUS: draftCaVersion=1'),
    observation().replace('draftCaVersion=1', 'private=PRIVATE_CANARY'), observation({ ...raw(), draftCaActiveCall: 'true' }), observation({ ...raw(), draftCaCleanupFailed: 'true' }),
    observation().replace('INSTRUMENTATION_STATUS_CODE: 3\n', '')];
  for (const value of variants) assert.notEqual(parse(wire().replace(observation(), value)).state, 'passed');
});

test('only the new class/method can start A23 and it never changes the two old A22 parsers', () => {
  for (const text of [wire().replaceAll(className, 'com.httpfreekit.interop.DraftEnrollmentInteropTest'), wire().replaceAll(method, expectedEnrollmentMethods[0])]) {
    const result = parse(text); assert.equal(result.actualStarted, 0); assert.notEqual(result.state, 'passed');
  }
  for (const old of expectedEnrollmentMethods) {
    assert.throws(() => createEnrollmentSuiteInvocationParser(old, { suite: 'a23' }));
    const parser = createEnrollmentInvocationParser(old); parser.push(Buffer.from(oldTranscript(old)));
    const result = parser.finish(command()); assert.equal(result.state, 'passed'); assert.equal(Object.hasOwn(result, 'observation'), false);
  }
  assert.throws(() => createEnrollmentInvocationParser(method));
});

test('source-only CA failure frames are finite, capped and never preserve messages, fingerprints or foreign paths', () => {
  const stack = 'java.lang.AssertionError: Interception CA research failed at ca-fetched-and-bound (RESPONSE); cleanup=false. PRIVATE_CANARY\n' +
    '\tat com.httpfreekit.interop.DraftInterceptionCaInteropTest.retrieveSavedApprovedCaAfterRestart(DraftInterceptionCaInteropTest.kt:99)\n' +
    '\tat com.httpfreekit.interop.DraftInterceptionCaClient.fetch(DraftInterceptionCaClient.kt:100000)\n' +
    '\tat com.httpfreekit.interop.DraftInterceptionCaClient.fetch(DraftInterceptionCaClient.kt:100001)\n' +
    '\tat com.httpfreekit.interop.DraftInterceptionCaClient.<<private>>(DraftInterceptionCaClient.kt:8)\n' +
    '\tat com.httpfreekit.interop.DraftEnrollmentInteropTest.work(DraftEnrollmentInteropTest.kt:10)\n' +
    '\tat com.vendor.Private.identity(Secret.kt:1)\nCaused by: javax.net.ssl.SSLException: PRIVATE_CAUSE\n' +
    '\tat com.httpfreekit.interop.DraftInterceptionCaDer.parse(DraftInterceptionCaDer.kt:12)';
  const result = parse(prefix(2) + status(-2, { stack }) + 'INSTRUMENTATION_CODE: -1\n');
  assert.equal(result.state, 'failed'); assert.equal(result.failureType, 'AssertionError'); assert.equal(result.frames.length, 3);
  for (const canary of ['PRIVATE_CANARY', 'PRIVATE_CAUSE', 'com.vendor', 'Secret.kt', '100001', '<<private>>', 'DraftEnrollmentInteropTest.kt']) assert(!JSON.stringify(result).includes(canary));
  V.validateInvocation(result, method, 'a23');
  const repeated = result.frames[0]; const many = prefix(2) + status(-2, { stack: 'java.lang.AssertionError: PRIVATE_CANARY\n' +
    `\tat ${repeated.className}.${repeated.method}(${repeated.file}:${repeated.line})\n`.repeat(40) }) + 'INSTRUMENTATION_CODE: -1\n';
  assert.equal(parse(many).frames.length, 16);
});

test('unknown failure types remain finite and successful statuses cannot retain a failure stack', () => {
  const unknown = parse(prefix(1) + status(-2, { stack: 'PrivateProviderException: PRIVATE_CANARY' }) + 'INSTRUMENTATION_CODE: -1\n');
  assert.equal(unknown.failureType, 'other_exception'); assert(!JSON.stringify(unknown).includes('PRIVATE_CANARY'));
  assert.notEqual(parse(wire().replace(status(0), status(0, { stack: 'java.lang.AssertionError: PRIVATE_CANARY' }))).state, 'passed');
});

test('terminal, actual test counters, command success and real command/group closes remain mandatory', () => {
  for (const text of [wire().replace('INSTRUMENTATION_CODE: -1\n', ''), wire() + 'INSTRUMENTATION_CODE: -1\n', wire().replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0'),
    wire().replace(status(1), ''), wire().replace(status(0), ''), wire().replace(status(1), status(1) + status(1)), wire().replace(status(0), status(-3)), wire().replace(status(0), status(-4)),
    wire().replace('numtests=1', 'numtests=2')]) assert.notEqual(parse(text).state, 'passed');
  for (const override of [{ code: 1 }, { code: null, signal: 'SIGKILL' }, { reason: 'owned_child_timeout' }, { closeObserved: false }, { processGroupClosed: false }]) assert.notEqual(parse(wire(), override).state, 'passed');
});

test('late residual observations cannot authorize a callback after actual command close', () => {
  const parser = createEnrollmentSuiteInvocationParser(method, { suite: 'a23' });
  parser.push(Buffer.from(prefix(3) + observation().trimEnd()));
  const result = parser.finish(command()); assert(result.problems.includes('observation_after_command_close'));
  assert.equal(result.observation, null); assert.notEqual(result.state, 'passed');
});

test('bounded malformed UTF8, output, lines and pending collections fail with only fixed categories', () => {
  for (const bytes of [Buffer.from([255]), Buffer.alloc(8193, 65), Buffer.alloc(262145, 65),
    Buffer.from(Array.from({ length: 25 }, (_, index) => `INSTRUMENTATION_STATUS: unknown${index}=PRIVATE_CANARY\n`).join(''))]) {
    const parser = createEnrollmentSuiteInvocationParser(method, { suite: 'a23' }); assert.throws(() => parser.push(bytes));
    const result = parser.finish(command()); assert.notEqual(result.state, 'passed'); assert(!JSON.stringify(result).includes('PRIVATE_CANARY')); assert(JSON.stringify(result).length < 4096);
  }
});
