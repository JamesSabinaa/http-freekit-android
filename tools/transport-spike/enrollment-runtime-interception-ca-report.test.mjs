import test from 'node:test';
import assert from 'node:assert/strict';
import { runtime, clone, source } from './enrollment-runtime-test-fixtures.mjs';
import { interceptionCaRuntimeMethod, interceptionCaRuntimePhases, interceptionCaRuntimeReportPaths } from './interception-ca-runtime-descriptor.mjs';
import { interceptionCaObservationKeys } from './interception-ca-runtime-observation.mjs';
import { createInterceptionCaRuntimeReport, decodeInterceptionCaRuntimeReport, verifyInterceptionCaRuntimeReport,
  interceptionCaRuntimeXml, interceptionCaRuntimeHtml } from './interception-ca-runtime-results.mjs';
import { decodeEnrollmentHostCleanup, verifyEnrollmentHostCleanup } from './enrollment-runtime-results.mjs';
import { host } from './enrollment-runtime-test-fixtures.mjs';

const goodCommand = () => ({ exitCode: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
const observation = Object.fromEntries(interceptionCaObservationKeys.map(key => [key, ['version', 'fetchAttempts'].includes(key) ? 1 : key === 'caBytes' ? 1256 :
  ['activeCall', 'rawSocketOwned', 'tlsSocketOwned', 'deadlineAlive', 'tlsCloserAlive', 'cleanupFailed'].includes(key) ? false : true]));
export function caRuntime(api = 26) {
  const report = clone(runtime()); report.format = 'http-freekit-a23-runtime'; report.api = api;
  report.invocations.splice(1, 0, { method: interceptionCaRuntimeMethod, state: 'passed', actualStarted: 1, actualCompleted: 1,
    terminalCount: 1, terminalCode: -1, phases: [...interceptionCaRuntimePhases], command: goodCommand(), problems: [], failureType: null, frames: [], observation: { ...observation } });
  report.permission = api === 26 ? { mode: 'not_required', declared: false, grantCommand: null, readbackCommand: null, readbackGranted: false }
    : { mode: 'owned_ci_grant', declared: true, grantCommand: goodCommand(), readbackCommand: goodCommand(), readbackGranted: true };
  report.ca = { beforeBytes: 1256, afterBytes: 1256, beforeMatchesApproval: true, afterMatchesApproval: true,
    beforeMatchesMetadata: true, afterMatchesMetadata: true, digestUnchanged: true, bytesUnchanged: true };
  return report;
}
const verify = value => verifyInterceptionCaRuntimeReport(value, { source, api: value.api });
const reject = value => assert.throws(() => verify(value), /^(?:EnrollmentRuntimeError: )?(?:invalid_runtime_report|runtime_[a-z_]+)$/);

test('three exact ordered same-run invocations retain original A22 gates and finite CA proof', () => {
  for (const api of [26, 37]) {
    const report = caRuntime(api), decoded = decodeInterceptionCaRuntimeReport(Buffer.from(JSON.stringify(report)));
    assert.deepEqual(verify(decoded), { methods: 3, actualStarted: 3, actualCompleted: 3, api, source });
    assert.match(interceptionCaRuntimeXml(report), /tests="3"/);
    assert.match(interceptionCaRuntimeHtml(report), /A23 method/);
    assert.equal(JSON.stringify(report).includes('certificateSha256'), false);
  }
  assert.equal(interceptionCaRuntimeReportPaths.host, 'build/reports/interception-ca-runtime/host-cleanup.json');
  const cleanup = host(); cleanup.format = 'http-freekit-a23-host-cleanup';
  assert.deepEqual(verifyEnrollmentHostCleanup(decodeEnrollmentHostCleanup(Buffer.from(JSON.stringify(cleanup)), { suite: 'a23' }), { source, api: 26, suite: 'a23' }), { emulatorJoined: true });
});
test('CA facts, actual bytes, digest continuity and explicit permission ownership fail closed', () => {
  for (const field of ['beforeMatchesApproval', 'afterMatchesApproval', 'beforeMatchesMetadata', 'afterMatchesMetadata', 'digestUnchanged', 'bytesUnchanged']) {
    const value = caRuntime(); value.ca[field] = false; reject(value);
  }
  for (const field of ['beforeBytes', 'afterBytes']) for (const count of [0, 4097, 1255]) {
    const value = caRuntime(); value.ca[field] = count; reject(value);
  }
  for (const mutation of [value => { value.permission.declared = false; }, value => { value.permission.readbackGranted = false; },
    value => { value.permission.grantCommand.exitCode = 1; }, value => { value.permission.readbackCommand.processGroupClosed = false; },
    value => { value.permission.mode = 'not_required'; }]) { const value = caRuntime(37); mutation(value); reject(value); }
  const api26 = caRuntime(); api26.permission.grantCommand = goodCommand(); reject(api26);
  const unknown = caRuntime(); unknown.ca.certificateSha256 = 'secret'; reject(unknown);
});
test('missing, swapped, duplicate and failed CA method cannot be replaced by passing A22 methods', () => {
  for (const mutation of [value => { value.invocations.splice(1, 1); }, value => { value.invocations.reverse(); },
    value => { value.invocations[1] = clone(value.invocations[0]); }, value => { value.invocations[1].actualStarted = 0; },
    value => { value.invocations[1].phases.pop(); }, value => { value.invocations[1].observation = null; },
    value => { value.invocations[1].observation.closed = false; }, value => { value.invocations[2].state = 'failed'; },
    value => { value.restart.continuity.approvedResultSha256After = 'f'.repeat(64); },
    value => { value.cleanup.ownedCommandsClosed = false; }]) { const value = caRuntime(); mutation(value); reject(value); }
});
test('strict decoder rejects duplicate keys, private fields and oversized records', () => {
  const original = JSON.stringify(caRuntime());
  for (const bad of [original.replace('"ca":', '"privateDigest":"secret","ca":'),
    original.replace('"revision":1', '"revision":1,"revision":1'), Buffer.alloc(65537)]) {
    assert.throws(() => decodeInterceptionCaRuntimeReport(Buffer.from(bad)));
  }
});
