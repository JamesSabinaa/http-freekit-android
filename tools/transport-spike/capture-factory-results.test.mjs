import test from 'node:test';
import assert from 'node:assert/strict';
import { createCaptureFactoryInvocationParser, parseCaptureFactoryInvocation, captureFactoryClass, captureFactoryMethod,
  captureFactoryPhases, captureFactoryObservationSuffixes, captureFactoryPayload } from './capture-factory-results.mjs';
import { enrollmentRuntimeValidation as V, EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';

const command = () => ({ code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
const status = (code, stack) => `INSTRUMENTATION_STATUS: class=${captureFactoryClass}\nINSTRUMENTATION_STATUS: test=${captureFactoryMethod}\nINSTRUMENTATION_STATUS: numtests=1\n` +
  (stack ? `INSTRUMENTATION_STATUS: stack=${stack}\n` : '') + `INSTRUMENTATION_STATUS_CODE: ${code}\n`;
const phase = value => `INSTRUMENTATION_STATUS: draftFactoryVersion=1\nINSTRUMENTATION_STATUS: draftFactoryPhase=${value}\nINSTRUMENTATION_STATUS_CODE: 2\n`;
function facts() {
  const booleans = new Set(('CredentialSavedReloaded KeyNonexportable OriginalCredentialUnchanged VpnConsentGranted NoTunEstablished ' +
    'ApplicationOutputHalfClosed StrictResponseEof FactoryClosed RelayJoined ServiceObserverJoined ServiceDestroyed OwnedStateAbsent').split(' '));
  return Object.fromEntries(captureFactoryObservationSuffixes.map(suffix => ['draftFactory' + suffix, booleans.has(suffix) ? 'true' :
    suffix === 'SessionLease' ? 'false' : ['ProtectAttempts', 'ProtectSuccesses', 'BindAttempts', 'BindSuccesses'].includes(suffix) ? '2' :
    suffix === 'Version' ? '1' : suffix === 'RequestBodyBytes' ? '16421' : suffix === 'ResponseBodyBytes' ? '32787' :
    suffix === 'ResponseBodySha256' ? captureFactoryPayload.responseBodySha256 : '0']));
}
const observation = value => Object.entries(value).map(([key, field]) => `INSTRUMENTATION_STATUS: ${key}=${field}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 3\n';
const prefix = count => status(1) + captureFactoryPhases.slice(0, count).map(phase).join('');
const transcript = value => prefix(9) + observation(value ?? facts()) + phase(captureFactoryPhases[9]) + status(0) + 'INSTRUMENTATION_CODE: -1\n';
const parse = value => parseCaptureFactoryInvocation(value, command());

test('one exact C2 method requires ten live phases, thirty actual facts and actual command closure', () => {
  const observed = [], parser = createCaptureFactoryInvocationParser({ onPhase: value => { observed.push(value); } });
  for (const byte of Buffer.from(transcript())) parser.push(Buffer.of(byte));
  const result = parser.finish(command());
  assert.equal(result.state, 'passed'); assert.deepEqual(observed, captureFactoryPhases); assert.equal(result.actualStarted, 1); assert.equal(result.actualCompleted, 1);
  assert.equal(result.observation.responseBodyBytes, 32787); assert.equal(result.observation.sessionLease, false); assert.equal(result.failure, null);
  V.validateInvocation(result, captureFactoryMethod, 'c2');
  for (const override of [{ code: 1 }, { closeObserved: false }, { processGroupClosed: false }]) {
    assert.notEqual(parseCaptureFactoryInvocation(transcript(), { ...command(), ...override }).state, 'passed');
  }
});

test('every positive source fact is necessary and canonical; extras, missing, duplicates and wrong position fail', () => {
  for (const [key, value] of Object.entries(facts())) {
    const changed = facts(); changed[key] = value === 'true' ? 'false' : value === 'false' ? 'true' : key.endsWith('Sha256') ? '0'.repeat(64) : String(Number(value) + 1);
    assert.notEqual(parse(transcript(changed)).state, 'passed', key);
  }
  for (const raw of ['-0', '00', '2\r0', '2.0', '131073', '9007199254740992', 'CANARY']) {
    const changed = facts(); changed.draftFactoryProtectAttempts = raw; assert.notEqual(parse(transcript(changed)).state, 'passed');
  }
  const missing = facts(); delete missing.draftFactoryFactoryClosed;
  const variants = [transcript(missing), transcript({ ...facts(), secret: 'CANARY' }),
    transcript().replace('INSTRUMENTATION_STATUS_CODE: 3', 'INSTRUMENTATION_STATUS: draftFactoryVersion=1\nINSTRUMENTATION_STATUS_CODE: 3'),
    prefix(8) + observation(facts()), transcript().replace(observation(facts()), '')];
  for (const text of variants) assert.notEqual(parse(text).state, 'passed');
});

test('command EOF cannot authorize approval or tail release from an incomplete live phase', () => {
  for (const count of [3, 7]) {
    const observed = [], parser = createCaptureFactoryInvocationParser({ onPhase: value => { observed.push(value); } });
    parser.push(Buffer.from(prefix(count).slice(0, -1)));
    assert.equal(observed.length, count - 1);
    const result = parser.finish(command()); assert.equal(observed.length, count - 1);
    assert(result.problems.includes('phase_after_command_close')); assert.notEqual(result.state, 'passed');
  }
});

test('finite original failure phase/type/cleanup and exact project frames survive while provider/cause data do not', () => {
  const stack = 'java.lang.AssertionError: Capture factory research failed at factory-opened (IOException); cleanup=false.\n' +
    ' at com.httpfreekit.interop.DraftCaptureFactoryInteropTest.run(DraftCaptureFactoryInteropTest.kt:123)\n' +
    ' at com.httpfreekit.capture.transport.EnrolledCaptureTcpFactory$Connection.read(EnrolledCaptureTcpFactory.kt:99)\n' +
    ' at com.httpfreekit.capture.transport.EnrolledCaptureTcpFactory.read(EnrolledCaptureTcpFactory.kt:100001)\n' +
    ' at com.provider.CANARY_private.run(EnrolledCaptureTcpFactory.kt:1)\nCaused by: java.io.IOException: CANARY_private';
  const result = parse(prefix(5) + status(-2, stack) + 'INSTRUMENTATION_CODE: -1\n');
  assert.equal(result.state, 'failed'); assert.deepEqual(result.failure, { phase: 'factory-opened', type: 'IOException', cleanup: false });
  assert.equal(result.frames.length, 2); assert.equal(result.failureType, 'AssertionError'); assert(!JSON.stringify(result).includes('CANARY'));
  V.validateInvocation(result, captureFactoryMethod, 'c2');
});

test('recognized failure cannot coexist with a passing transcript, even outside a stack bundle', () => {
  const failure = 'Capture factory research failed at factory-opened (IllegalStateException); cleanup=true.';
  for (const text of [failure + '\n' + transcript(), transcript().replace(status(0), status(0, 'java.lang.AssertionError: ' + failure))]) {
    const result = parse(text); assert.notEqual(result.state, 'passed'); assert(result.failure); assert(result.problems.length > 0);
  }
});

test('foreign classes, repeated invocation, malformed UTF8 and excess status bounds cannot pass', () => {
  const variants = [transcript().replaceAll(captureFactoryClass, 'com.private.CANARY'), status(1) + transcript(),
    transcript() + phase(captureFactoryPhases[0]), Buffer.concat([Buffer.of(0xc0, 0xaf), Buffer.from(transcript())]),
    prefix(9) + Array.from({ length: 37 }, (_, i) => `INSTRUMENTATION_STATUS: extra${i}=CANARY\n`).join('')];
  for (const text of variants) { const result = parse(text); assert.notEqual(result.state, 'passed'); assert(!JSON.stringify(result).includes('CANARY')); }
  const parser = createCaptureFactoryInvocationParser({ onPhase: () => Promise.reject(Error('CANARY')) });
  assert.throws(() => parser.push(Buffer.from(prefix(1))), EnrollmentRuntimeError);
  assert(!JSON.stringify(parser.finish(command())).includes('CANARY'));
});
