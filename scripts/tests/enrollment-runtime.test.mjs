import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decodeEnrollmentRuntime, decodeEnrollmentHostCleanup, verifyEnrollmentRuntime, verifyEnrollmentHostCleanup,
  createEnrollmentRuntimeReport, enrollmentRuntimeXml, enrollmentRuntimeHtml, EnrollmentRuntimeError } from '../../tools/transport-spike/enrollment-runtime-results.mjs';
import { verifyEnrollmentRuntimeFiles } from '../verify-enrollment-runtime.mjs';
import { runtime, host, source, clone } from '../../tools/transport-spike/enrollment-runtime-test-fixtures.mjs';
const options = { source, api: 26 };
const encode = value => Buffer.from(JSON.stringify(value));
const invalid = value => assert.throws(() => verifyEnrollmentRuntime(value, options), EnrollmentRuntimeError);

test('independent final gate accepts only complete two-method runtime and joined emulator records', () => {
  assert.deepEqual(verifyEnrollmentRuntime(decodeEnrollmentRuntime(encode(runtime())), options), { methods: 2, actualStarted: 2, actualCompleted: 2, api: 26, source });
  assert.deepEqual(verifyEnrollmentHostCleanup(decodeEnrollmentHostCleanup(encode(host())), options), { emulatorJoined: true });
});
test('strict JSON rejects duplicate keys, floats, boolean-number substitutions, BOM and excessive files', () => {
  const base = JSON.stringify(runtime());
  for (const text of [base.replace('"revision":1', '"revision":1,"revision":1'), base.replace('"revision":1', '"revision":1.0'),
    base.replace('"api":26', '"api":true'), base.replace('"trackedDirty":false', '"trackedDirty":0'), '\uFEFF' + base,
    base.replace('"revision":1', '"revision":NaN'), base.slice(0, -1)]) assert.throws(() => decodeEnrollmentRuntime(Buffer.from(text)), EnrollmentRuntimeError);
  assert.throws(() => decodeEnrollmentRuntime(Buffer.alloc(65537)), /runtime_report_limit/);
  assert.throws(() => decodeEnrollmentHostCleanup(Buffer.alloc(16385)), /host_report_limit/);
});
test('every report group has exact bounded schemas and unavailable evidence never passes', () => {
  for (const key of ['source', 'api', 'clock', 'input', 'approval', 'stop', 'restart', 'cleanup']) {
    const value = runtime(); value[key] = null; invalid(value);
  }
  const extra = runtime(); extra.input.secret = 'DO_NOT_RETAIN'; invalid(extra);
  const missing = runtime(); delete missing.cleanup.ownedCommandsClosed; invalid(missing);
  for (const path of ['approval.actualApprovedResponseDrops', 'cleanup.finalWorkerClosed.workers', 'clock.deviceEpochSeconds']) {
    const value = runtime(), [group, key, nested] = path.split('.');
    if (nested) value[group][key][nested] = Number.MAX_SAFE_INTEGER + 1; else value[group][key] = Number.MAX_SAFE_INTEGER + 1;
    invalid(value);
  }
});
test('source/API binding refuses wrong, dirty, uppercase or missing implementation identity', () => {
  for (const mutate of [value => { value.source.commit = 'b'.repeat(40); }, value => { value.source.trackedDirty = true; },
    value => { value.source.commit = 'A'.repeat(40); }, value => { value.api = 37; }, value => { value.source.commit = null; }]) {
    const value = runtime(); mutate(value); invalid(value);
  }
});
test('fixed source/hash/frame tokens consume the whole string including trailing LF or CRLF negatives', () => {
  for (const suffix of ['\n', '\r\n']) {
    const report = runtime(); report.source.commit += suffix; invalid(report);
    const fingerprint = runtime(); fingerprint.restart.continuity.gatewayCertificateSha256Before += suffix; invalid(fingerprint);
    const frame = clone(runtime()); frame.invocations[0].state = 'failed'; frame.invocations[0].frames = [{
      className: 'com.httpfreekit.interop.DraftEnrollmentInteropTest', method: 'work' + suffix, file: 'DraftEnrollmentInteropTest.kt', line: 1 }];
    invalid(frame);
  }
});
test('clock gate derives full second-quantization interval and round trip rather than trusting fields', () => {
  for (const mutate of [value => { value.lowerBoundMillis++; }, value => { value.upperBoundMillis--; }, value => { value.roundTripMillis++; },
    value => { value.hostAfterMillis = value.hostBeforeMillis + 2001; value.lowerBoundMillis = value.deviceEpochSeconds * 1000 - value.hostAfterMillis; value.roundTripMillis = 2001; },
    value => { value.deviceEpochSeconds += 2; value.lowerBoundMillis += 2000; value.upperBoundMillis += 2000; },
    value => { value.deviceEpochSeconds -= 3; value.lowerBoundMillis -= 3000; value.upperBoundMillis -= 3000; }]) {
    const report = runtime(); mutate(report.clock); invalid(report);
  }
});
test('matched starts/completions, all required phases and method identity cannot be replaced by passing summary', () => {
  for (const mutate of [value => { value.actualStarted = 0; }, value => { value.actualCompleted = 0; }, value => { value.terminalCount = 2; },
    value => { value.terminalCode = 0; }, value => { value.method = 'anotherMethod'; }, value => { value.phases.pop(); },
    value => { value.problems = ['instrumentation_failure']; }, value => { value.frames = [{ className: 'Secret', file: 'Secret.kt', method: 'x', line: 1 }]; },
    value => { value.command.closeObserved = false; }]) {
    const report = clone(runtime()); mutate(report.invocations[0]); invalid(report);
  }
  const report = runtime(); report.invocations.reverse(); invalid(report);
});
test('private input requires actual written bytes, input finish and close, unlink and successful owned command', () => {
  for (const key of ['inputFinished', 'inputClosed', 'inputAbsentAfterPrepare']) { const value = runtime(); value.input[key] = false; invalid(value); }
  for (const mutate of [value => { value.inputBytes--; }, value => { value.byteCount = 16385; }, value => { value.command.exitCode = 1; }, value => { value.command.processGroupClosed = false; }]) {
    const value = runtime(); mutate(value.input); invalid(value);
  }
});
test('approval arm is distinct from one actual approved response drop and later delivery', () => {
  for (const key of ['liveAwaitingPhaseObserved', 'dropArmAcknowledged', 'requestedAfterArm', 'completed']) { const value = runtime(); value.approval[key] = false; invalid(value); }
  for (const [key, counter] of [['actualApprovedResponseDrops', 0], ['actualApprovedResponseDrops', 2], ['approvedResponsesAfterDrop', 0], ['approvedResponsesAfterDrop', 33], ['reopenedApprovedResponses', 0]]) {
    const value = runtime(); value.approval[key] = counter; invalid(value);
  }
});
test('force-stop requires selected-device continuity plus successful explicit process-absence query', () => {
  for (const mutate of [value => { value.deviceBefore = 'offline'; }, value => { value.deviceAfter = 'unavailable'; }, value => { value.presenceBefore = 'unknown'; },
    value => { value.presenceAfter = 'present'; }, value => { value.absenceQueryExitCode = 1; }, value => { value.absenceMarkerVerified = false; }, value => { value.forceStopCommand.exitCode = 1; }]) {
    const value = runtime(); mutate(value.stop); invalid(value);
  }
  const naturalExit = runtime(); naturalExit.stop.presenceBefore = 'absent'; assert.equal(verifyEnrollmentRuntime(naturalExit, options).methods, 2);
});
test('graceful worker restart proves actual joins plus exact identity, result and port continuity', () => {
  for (const key of ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined']) { const value = runtime(); value.restart.initialWorkerClosed[key] = false; invalid(value); }
  for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']) { const value = runtime(); value.restart.initialWorkerClosed[key] = 1; invalid(value); }
  for (const key of ['setupPortAfter', 'credentialPortAfter', 'gatewayCertificateSha256After', 'enrollmentAuthoritySha256After', 'approvedResultSha256After']) {
    const value = runtime(); value.restart.continuity[key] = key.includes('Port') ? 40000 : 'f'.repeat(64); invalid(value);
  }
  for (const mutate of [value => { value.opened = false; }, value => { value.initialWorkerCommand.processGroupClosed = false; },
    value => { value.continuity.credentialPortBefore = value.continuity.setupPortBefore; value.continuity.credentialPortAfter = value.continuity.setupPortAfter; }]) {
    const value = runtime(); mutate(value.restart); invalid(value);
  }
});
test('final selective cleanup requires both owned reverses, uninstallation, private directory removal and all resource joins', () => {
  for (const key of ['uninstallConfirmed', 'ownedReversesAbsent', 'ownedCommandsClosed', 'ownedCommandGroupsClosed', 'privateDirectoryRemoved']) { const value = runtime(); value.cleanup[key] = false; invalid(value); }
  for (const codes of [[], [0], [0, 1], [0, 0, 0], [false, 0]]) { const value = runtime(); value.cleanup.reverseRemovalExitCodes = codes; invalid(value); }
  for (const key of ['forceStopCommand', 'uninstallCommand', 'finalWorkerCommand']) { const value = runtime(); value.cleanup[key].closeObserved = false; invalid(value); }
  const value = runtime(); value.cleanup.finalWorkerClosed.signerGroups = 1; invalid(value);
});
test('emulator evidence preserves actual stop/termination/join and original driver failure', () => {
  for (const key of ['emulatorStarted', 'stopAttempted', 'terminationObserved', 'joinObserved']) {
    const value = host(); value[key] = false; assert.throws(() => verifyEnrollmentHostCleanup(value, options), /host_cleanup_failed/);
  }
  for (const mutate of [value => { value.driverExitCode = 1; }, value => { value.emulatorExitCode = null; }, value => { value.sourceCommit = 'b'.repeat(40); }, value => { value.api = 37; }]) {
    const value = host(); mutate(value); assert.throws(() => verifyEnrollmentHostCleanup(value, options), /host_cleanup_failed/);
  }
  const fallback = host(); fallback.stopExitCode = 124; fallback.emulatorExitCode = 143;
  assert.equal(verifyEnrollmentHostCleanup(fallback, options).emulatorJoined, true);
});
test('CLI independently reads bounded fresh files and emits only fixed errors for malformed/stale/private inputs', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-enrollment-gate-'));
  const runtimePath = path.join(directory, 'runtime.json'), hostPath = path.join(directory, 'host.json');
  const xml = path.join(directory, 'results.xml'), html = path.join(directory, 'index.html');
  const cli = fileURLToPath(new URL('../verify-enrollment-runtime.mjs', import.meta.url));
  const started = Math.floor(Date.now() / 1000) - 1;
  try {
    fs.writeFileSync(runtimePath, encode(runtime())); fs.writeFileSync(hostPath, encode(host()));
    fs.writeFileSync(xml, enrollmentRuntimeXml(runtime())); fs.writeFileSync(html, enrollmentRuntimeHtml(runtime()));
    assert.equal(verifyEnrollmentRuntimeFiles({ runtime: runtimePath, host: hostPath, xml, html, source, api: 26, started }).methods, 2);
    const args = ['--runtime', runtimePath, '--host', hostPath, '--xml', xml, '--html', html, '--source', source, '--api', '26', '--started', String(started)];
    const good = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' }); assert.equal(good.status, 0); assert.match(good.stdout, /2 exact methods/);
    fs.utimesSync(runtimePath, started - 1, started - 1);
    const stale = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' }); assert.equal(stale.status, 1); assert.match(stale.stderr, /runtime_file_unavailable_or_stale/);
    for (const badArgs of [['--PRIVATE_CANARY', 'secret'], ['--source', source, '--api', '26', '--started', '1e9'], [...args, '--source', 'PRIVATE_CANARY']]) {
      const result = spawnSync(process.execPath, [cli, ...badArgs], { encoding: 'utf8' }); assert.equal(result.status, 1);
      assert.ok(!result.stderr.includes('PRIVATE_CANARY')); assert.ok(!result.stderr.includes(directory)); assert.ok(!result.stderr.includes('Error:'));
    }
    fs.writeFileSync(runtimePath, '{"PRIVATE_CANARY":');
    const malformed = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' }); assert.equal(malformed.status, 1); assert.ok(!malformed.stderr.includes('PRIVATE_CANARY'));
    fs.writeFileSync(runtimePath, Buffer.alloc(65537));
    assert.throws(() => verifyEnrollmentRuntimeFiles({ runtime: runtimePath, host: hostPath, source, api: 26, started }), /runtime_file_unavailable_or_stale/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test('fresh XML and HTML must be exact sanitized projections, with no missing or appended material', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-enrollment-projections-'));
  const files = { runtime: path.join(directory, 'runtime.json'), host: path.join(directory, 'host.json'), xml: path.join(directory, 'results.xml'), html: path.join(directory, 'index.html') };
  const started = Math.floor(Date.now() / 1000) - 1;
  try {
    fs.writeFileSync(files.runtime, encode(runtime())); fs.writeFileSync(files.host, encode(host()));
    fs.writeFileSync(files.xml, enrollmentRuntimeXml(runtime())); fs.writeFileSync(files.html, enrollmentRuntimeHtml(runtime()));
    for (const field of ['xml', 'html']) {
      const bytes = fs.readFileSync(files[field]);
      fs.appendFileSync(files[field], 'PRIVATE_PROJECTION_CANARY');
      assert.throws(() => verifyEnrollmentRuntimeFiles({ ...files, ...options, started }), /runtime_projection_mismatch/);
      fs.writeFileSync(files[field], bytes); fs.utimesSync(files[field], started - 1, started - 1);
      assert.throws(() => verifyEnrollmentRuntimeFiles({ ...files, ...options, started }), /runtime_file_unavailable_or_stale/);
      fs.unlinkSync(files[field]); assert.throws(() => verifyEnrollmentRuntimeFiles({ ...files, ...options, started }), /runtime_file_unavailable_or_stale/);
      fs.writeFileSync(files[field], bytes);
    }
    assert.equal(verifyEnrollmentRuntimeFiles({ ...files, ...options, started }).methods, 2);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test('failed setup can retain truthful null/unstarted evidence without producing a passing result', () => {
  const report = clone(runtime()); report.problems = ['host_setup_failed'];
  for (const key of ['source', 'api', 'clock', 'input', 'approval', 'stop', 'restart', 'cleanup']) report[key] = null;
  assert.ok(createEnrollmentRuntimeReport(report)); invalid(report);
});
