import test from 'node:test'; import assert from 'node:assert/strict';
import { EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { enrollmentAdversarialCases, createEnrollmentAdversarialInvocationParser, parseEnrollmentAdversarialInvocation,
  createEnrollmentAdversarialReport, decodeEnrollmentAdversarialReport, verifyEnrollmentAdversarialReport,
  enrollmentAdversarialRuntimeXml, enrollmentAdversarialRuntimeHtml } from './enrollment-runtime-adversarial-results.mjs';
import { observation, phase, status, bundle, transcript, commandResult, runtime, source } from './enrollment-runtime-adversarial-test-fixtures.mjs';
const options = { source, api: 26 }, encode = value => Buffer.from(JSON.stringify(value));
const parse = (text, index = 0, command = {}) => parseEnrollmentAdversarialInvocation(text, { method: enrollmentAdversarialCases[index].method, ...commandResult(), ...command });
const reject = value => assert.throws(() => verifyEnrollmentAdversarialReport(value, options), EnrollmentRuntimeError);

test('four finite C cases require their exact phase and positive observation catalogues', () => {
  assert.deepEqual(enrollmentAdversarialCases.map(value => value.phases.length), [11, 7, 9, 11]);
  assert.deepEqual(enrollmentAdversarialCases.map(value => value.observationSuffixes.length), [19, 11, 13, 19]);
  for (const [index, descriptor] of enrollmentAdversarialCases.entries()) {
    const result = parse(transcript(index), index); assert.equal(result.state, 'passed'); assert.deepEqual(result.phases, descriptor.phases);
    assert.deepEqual(result.observation, observation(index)); assert.ok(Object.isFrozen(result.observation));
  }
  assert.equal(verifyEnrollmentAdversarialReport(runtime(), options).methods, 4);
});
test('byte-split live phases authorize only complete next lines and never EOF approval', () => {
  const index = 3, calls = [], parser = createEnrollmentAdversarialInvocationParser(enrollmentAdversarialCases[index].method, { onPhase: value => { calls.push(value); } });
  const text = status(index, 1) + enrollmentAdversarialCases[index].phases.slice(0, 4).map(phase).join('').slice(0, -1);
  for (const byte of Buffer.from(text)) parser.push(Buffer.from([byte])); assert.equal(calls.length, 3);
  const result = parser.finish(commandResult()); assert.equal(calls.length, 3); assert.ok(result.problems.includes('phase_after_command_close'));
});
test('finish cannot retain an unterminated C positive bundle after command closure', () => {
  const parser = createEnrollmentAdversarialInvocationParser(enrollmentAdversarialCases[0].method);
  parser.push(Buffer.from(status(0, 1) + enrollmentAdversarialCases[0].phases.slice(0, -1).map(phase).join('') + bundle(0).slice(0, -1)));
  const result = parser.finish(commandResult()); assert.equal(result.observation, null); assert.ok(result.problems.includes('observation_after_command_close'));
});
test('missing, duplicate, early, wrong-case and malformed observations cannot become passing cases', () => {
  const valid = transcript(0), facts = bundle(0);
  for (const text of [valid.replace(facts, ''), valid.replace(facts, facts + facts), facts + valid,
    valid.replace(facts, bundle(1)), valid.replace(facts, facts.replace('Version=1', 'Version=01')),
    valid.replace(facts, facts.replace('PurposeHttp=403', 'PurposeHttp=400')),
    valid.replace(facts, facts.replace('PurposeCode=authentication_failed', 'PurposeCode=pairing_limit')),
    valid.replace(facts, facts.replace('OriginalKeyUnchanged=true', 'OriginalKeyUnchanged=1'))]) assert.notEqual(parse(text).state, 'passed');
});
test('unknown or oversized metadata and private messages cannot enter retained reports', () => {
  for (const count of [1, 6]) {
    const text = transcript(0).replace('INSTRUMENTATION_STATUS_CODE: 3', Array.from({ length: count }, (_, i) => `INSTRUMENTATION_STATUS: key${i}=PRIVATE_CANARY\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 3');
    const result = parse(text); assert.notEqual(result.state, 'passed'); assert.ok(!JSON.stringify(result).includes('PRIVATE_CANARY'));
  }
  const stack = 'java.lang.IllegalStateException: PRIVATE_CANARY\n' +
    '\tat com.httpfreekit.interop.DraftStreamingConnectorKt.draftStreamingConnect(DraftStreamingConnector.kt:20)\n' +
    '\tat com.vendor.Private.ID(Secret.kt:10)';
  const result = parse(transcript(0).replace(status(0, 0), status(0, -2, 'INSTRUMENTATION_STATUS: stack=' + stack + '\n')));
  assert.equal(result.frames.length, 1); assert.ok(!JSON.stringify(result).includes('PRIVATE_CANARY')); assert.ok(!JSON.stringify(result).includes('Secret.kt'));
});
test('all paired starts/completions, terminal success and actual owned command joins remain required', () => {
  for (const text of [transcript(0).replace(status(0, 1), ''), transcript(0).replace(status(0, 0), ''), transcript(0).replace(status(0, 0), status(0, -3)),
    transcript(0).replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0'), transcript(0) + 'INSTRUMENTATION_CODE: -1\n', transcript(1)]) assert.notEqual(parse(text).state, 'passed');
  for (const command of [{ code: 1 }, { processGroupClosed: false }, { closeObserved: false }, { signal: 'SIGKILL' }]) assert.notEqual(parse(transcript(0), 0, command).state, 'passed');
});
test('unapproved C cases require current pending/cancelled state and no additional actual issuer commands', () => {
  for (const mutate of [value => { value.scenarios[0].host.issuerCommandsAfter++; }, value => { value.scenarios[0].host.result = 'cancelled'; },
    value => { value.scenarios[0].host.registered = false; }, value => { value.scenarios[0].host.resultAfterMethod = false; },
    value => { value.scenarios[0].host.issuerJobsAfter = 1; }, value => { value.scenarios[0].host.dispatchesAfter = 0; },
    value => { value.scenarios[0].approval = value.scenarios[3].approval; }]) { const value = runtime(); mutate(value); reject(value); }
});
test('wrong TLS requires actual alternate accepts/rejections, no HTTP/secure callback and joined child commands', () => {
  for (const [key, item] of [['accepted', 0], ['rejected', 0], ['httpDispatches', 1], ['secureConnections', 1], ['childrenClosed', 1], ['childGroupsClosed', 1]]) {
    const value = runtime(); value.scenarios[1].host.alternateTls[key] = item; reject(value);
  }
  const value = runtime(); value.scenarios[1].invocation.observation.tlsFailureType = 'ConnectException'; reject(value);
});
test('late approval requires the real failed attempt and a cancelled read AFTER that completion', () => {
  for (const mutate of [value => { value.scenarios[2].host.lateApproval.requested = false; }, value => { value.scenarios[2].host.lateApproval.completed = false; },
    value => { value.scenarios[2].host.lateApproval.error = null; }, value => { value.scenarios[2].host.lateApproval.resultAfterAttempt = null; },
    value => { value.scenarios[2].host.result = 'pending'; }, value => { value.scenarios[2].host.issuerCommandsAfter++; }]) { const value = runtime(); mutate(value); reject(value); }
});
test('published cancellation binds successful mTLS, exact saved expiry and no issuance after its sole approval', () => {
  for (const mutate of [value => { value.scenarios[3].approval.liveAwaitingPhaseObserved = false; }, value => { value.scenarios[3].approval.approvedResponsesDelivered = 0; },
    value => { value.scenarios[3].approval.issuerCommandsAfterApproval = 4; }, value => { value.scenarios[3].approval.credentialExpiresUtcMillis++; },
    value => { value.scenarios[3].invocation.observation.beforeMtlsHttp = 403; }, value => { value.scenarios[3].invocation.observation.afterMtlsHttp = 200; },
    value => { value.scenarios[3].invocation.observation.refusalObservedUtcMillis = value.scenarios[3].invocation.observation.credentialExpiresUtcMillis; },
    value => { value.scenarios[3].invocation.observation.keyManagerUsableAtRefusal = false; }]) { const value = runtime(); mutate(value); reject(value); }
});
test('partial post-method counters stay null and truthful failed/unstarted records cannot pass', () => {
  const value = runtime(); value.scenarios[0].host.dispatchesAfter = null; value.scenarios[0].host.issuerCommandsAfter = null; value.scenarios[0].host.issuerJobsAfter = null;
  assert.ok(createEnrollmentAdversarialReport(value)); reject(value);
  value.scenarios[0].invocation = parse('', 0); assert.match(enrollmentAdversarialRuntimeXml(value), /errors="1"/);
});
test('source, clock, private input and all two/three reverses and worker/package cleanup remain strict', () => {
  for (const mutate of [value => { value.source.trackedDirty = true; }, value => { value.clock.upperBoundMillis--; }, value => { value.scenarios[0].input.inputClosed = false; },
    value => { value.scenarios[1].cleanup.reverseRemovalExitCodes.pop(); }, value => { value.scenarios[0].cleanup.reverseRemovalExitCodes.push(0); },
    value => { value.scenarios[1].cleanup.workerClosed.activeSockets = 1; }, value => { value.cleanup.uninstallCommand.processGroupClosed = false; }]) { const value = runtime(); mutate(value); reject(value); }
});
test('C reports are exact bounded JSON and immutable copies; projections retain truthful Android outcomes', () => {
  const input = runtime(), report = createEnrollmentAdversarialReport(input); input.scenarios[0].host.registered = false; assert.equal(report.scenarios[0].host.registered, true);
  assert.deepEqual(decodeEnrollmentAdversarialReport(encode(report)), report); assert.equal((enrollmentAdversarialRuntimeXml(report).match(/<testcase /g) ?? []).length, 4);
  for (const bytes of [Buffer.from('{"format":1,"format":2}'), Buffer.from('\uFEFF' + JSON.stringify(report)), Buffer.alloc(65537)]) assert.throws(() => decodeEnrollmentAdversarialReport(bytes), EnrollmentRuntimeError);
  const extra = runtime(); extra.scenarios[0].host.secret = 'PRIVATE_CANARY'; assert.throws(() => enrollmentAdversarialRuntimeHtml(extra), /invalid_runtime_report/);
  const failed = runtime(); failed.problems = ['enrollment_cleanup_failed']; assert.match(enrollmentAdversarialRuntimeXml(failed), /errors="0"/); reject(failed);
});
