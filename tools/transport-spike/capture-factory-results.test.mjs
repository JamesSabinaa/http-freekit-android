import test from 'node:test';
import assert from 'node:assert/strict';
import { createCaptureFactoryInvocationParser, parseCaptureFactoryInvocation, captureFactoryClass, captureFactoryMethod,
  captureFactoryPhases, captureFactoryObservationSuffixes, captureFactoryPayload } from './capture-factory-results.mjs';
import { enrollmentRuntimeValidation as V, EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { createCaptureFactoryReport, decodeCaptureFactoryReport, verifyCaptureFactoryReport, captureFactoryRuntimeXml, captureFactoryRuntimeHtml } from './capture-factory-results.mjs';
import { runtime as legacyRuntime, worker as workerClosed, command as commandObservation } from './enrollment-runtime-test-fixtures.mjs';

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
const source = 'a'.repeat(40), desktopCommit = 'b'.repeat(40);
function report() {
  return { format: 'http-freekit-capture-factory-runtime', revision: 1, source: { commit: source, trackedDirty: false }, api: 26,
    clock: legacyRuntime().clock, invocation: parse(transcript()),
    input: { byteCount: 100, inputBytes: 100, inputFinished: true, inputClosed: true, command: commandObservation(), inputAbsentAfterMethod: true },
    approval: { livePhaseObserved: true, requested: true, completed: true, approvedResponsesDelivered: 1, actualApprovedResponseDrops: 0, issuerCommandsBefore: 1, issuerCommandsAfter: 2, issuerJobsAfter: 0 },
    host: { desktopCommit, registered: true, liveReleasePhaseObserved: true, releaseRequested: true, releaseCompleted: true, gatewayStreamComplete: true,
      origin: { connections: 1, requests: 1, requestBodyBytes: 16421, requestBodySha256: captureFactoryPayload.requestBodySha256, requestVerified: true,
        responseBodyBytesWritten: 32787, responseBodySha256: captureFactoryPayload.responseBodySha256, responsePrefixWritten: true, responseEof: true,
        tailReleased: true, clientEndWriteApplied: true, originalDestinationMatched: true, captureMatched: true, tailReleaseRequested: true },
      backend: { closing: false, activeOwners: 0, admitted: 1, settled: 1, captures: 2, clientEndWrites: 1, proxyMode: 'http-origin-connect', negotiatedCapabilities: ['tcp-http-origin-connect'] } },
    resources: { workerClosed: workerClosed(), workerCommand: commandObservation(), reverseRemovalExitCodes: [0, 0, 0], ownedReversesAbsent: true,
      privateDirectoryRemoved: true, gatewayStreamComplete: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true },
    cleanup: { forceStopCommand: commandObservation(), uninstallCommand: commandObservation(), uninstallConfirmed: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true }, problems: [] };
}
const clone = value => JSON.parse(JSON.stringify(value));
const verify = value => verifyCaptureFactoryReport(value, { source, api: 26, desktopCommit });

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

test('host proof requires exact numeric-origin capture, body bytes, actual mode/caps and applied END_WRITE before release', () => {
  assert.equal(verify(report()).methods, 1);
  const mutations = [r => { r.host.registered = false; }, r => { r.host.liveReleasePhaseObserved = false; }, r => { r.host.releaseRequested = false; },
    r => { r.host.releaseCompleted = false; }, r => { r.host.gatewayStreamComplete = false; },
    r => { r.host.backend.negotiatedCapabilities = ['tcp-http']; }, r => { r.host.backend.negotiatedCapabilities.push('tcp-https-connect'); },
    r => { r.host.backend.proxyMode = null; }, r => { r.host.backend.activeOwners = 1; }, r => { r.host.backend.admitted = 2; }, r => { r.host.backend.settled = 0; },
    r => { r.host.backend.captures = 0; }, r => { r.host.backend.clientEndWrites = 0; }];
  for (const key of ['requestVerified', 'responsePrefixWritten', 'responseEof', 'tailReleased', 'clientEndWriteApplied', 'originalDestinationMatched', 'captureMatched', 'tailReleaseRequested']) {
    mutations.push(r => { r.host.origin[key] = false; });
  }
  for (const key of ['connections', 'requests', 'requestBodyBytes', 'responseBodyBytesWritten']) mutations.push(r => { r.host.origin[key]++; });
  for (const key of ['requestBodySha256', 'responseBodySha256']) mutations.push(r => { r.host.origin[key] = '0'.repeat(64); });
  for (const mutate of mutations) { const value = report(); mutate(value); assert.throws(() => verify(value), EnrollmentRuntimeError); }
});

test('source/clock/live approval/input and every owned cleanup join remain independent mandatory gates', () => {
  const mutations = [r => { r.source.trackedDirty = true; }, r => { r.api = 37; }, r => { r.host.desktopCommit = 'c'.repeat(40); },
    r => { r.clock.upperBoundMillis = 3000; }, r => { r.input.inputBytes--; }, r => { r.input.inputAbsentAfterMethod = false; },
    r => { r.input.command.closeObserved = false; }, r => { r.approval.livePhaseObserved = false; }, r => { r.approval.completed = false; },
    r => { r.approval.approvedResponsesDelivered = 0; }, r => { r.approval.actualApprovedResponseDrops = 1; }, r => { r.approval.issuerCommandsAfter = null; },
    r => { r.approval.issuerJobsAfter = 1; }, r => { r.resources.reverseRemovalExitCodes.pop(); }, r => { r.resources.workerClosed.storeClosed = false; },
    r => { r.resources.workerCommand.processGroupClosed = false; }, r => { r.cleanup.uninstallCommand.exitCode = 1; }];
  for (const key of ['ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayStreamComplete', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']) mutations.push(r => { r.resources[key] = false; });
  for (const key of ['uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']) mutations.push(r => { r.cleanup[key] = false; });
  for (const mutate of mutations) { const value = report(); mutate(value); assert.throws(() => verify(value), EnrollmentRuntimeError); }
});

test('failed/unstarted methods and unknown host proof remain truthful in bounded projections', () => {
  const failed = report(); failed.invocation = parse(prefix(2) + status(-2, 'java.lang.AssertionError: Capture factory research failed at strict-csr-reserved (IOException); cleanup=false.') + 'INSTRUMENTATION_CODE: -1\n');
  failed.host = null; failed.resources = null; failed.approval.issuerCommandsAfter = null; failed.approval.issuerJobsAfter = null;
  createCaptureFactoryReport(failed); assert.throws(() => verify(failed));
  assert.match(captureFactoryRuntimeXml(failed), /failures="1"/); assert.match(captureFactoryRuntimeHtml(failed), /cleanup=false|&quot;cleanup&quot;: false/);
  const notStarted = clone(failed); notStarted.invocation = createCaptureFactoryInvocationParser().finish();
  assert.match(captureFactoryRuntimeXml(notStarted), /errors="1"/);
  const hostFailure = report(); hostFailure.problems.push('enrollment_cleanup_failed');
  assert.throws(() => verify(hostFailure)); assert.match(captureFactoryRuntimeXml(hostFailure), /failures="0" errors="0"/);
});

test('exact report JSON rejects duplicates/private extras and returns immutable copies without raw material', () => {
  const value = report(), copied = createCaptureFactoryReport(value); value.host.backend.negotiatedCapabilities.push('tcp-http');
  assert.deepEqual(copied.host.backend.negotiatedCapabilities, ['tcp-http-origin-connect']); assert(Object.isFrozen(copied.host.backend));
  const bytes = Buffer.from(JSON.stringify(copied)); assert.equal(decodeCaptureFactoryReport(bytes).invocation.state, 'passed');
  const poison = clone(copied); poison.host.origin.secret = 'CANARY_private';
  for (const raw of [JSON.stringify(poison), JSON.stringify(copied).replace('"revision":1', '"revision":1,"revision":1'), 'x'.repeat(65537)]) {
    assert.throws(() => decodeCaptureFactoryReport(Buffer.from(raw)), error => !String(error).includes('CANARY'));
  }
});
