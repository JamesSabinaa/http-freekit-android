import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import test from 'node:test';
import { enrollmentRuntimeOptions, registerEnrollmentReverses, enrollmentOwnedReversesAbsent } from './run-enrollment-runtime.mjs';
import { decodeEnrollmentRuntime, expectedEnrollmentMethods, enrollmentReportPaths } from './enrollment-runtime-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const successful = output => ({ code: 0, signal: null, reason: null, closeObserved: true,
  processGroupClosed: true, stderrBytes: 0, output });

test('an exit0 reverse registration is owned before late cleanup/response validation failures', async () => {
  for (const result of [{ ...successful(''), reason: 'research_run_cancelled' }, successful('unexpected')]) {
    const owned = [];
    await assert.rejects(registerEnrollmentReverses(async () => result, { setupPort: 32101, credentialPort: 32102 }, owned),
      /^Error: enrollment_fixture_failed$/);
    assert.deepEqual(owned, [{ devicePort: 32101, hostPort: 32101 }]);
  }
  const owned = [];
  await assert.rejects(registerEnrollmentReverses(async () => ({ ...successful(''), code: 1 }),
    { setupPort: 32101, credentialPort: 32102 }, owned), /^Error: enrollment_fixture_failed$/);
  assert.equal(owned.length, 0);
});

test('invalid reverse endpoints cause no registration and known complete rows alone prove absence', async () => {
  let called = false;
  await assert.rejects(registerEnrollmentReverses(async () => { called = true; }, { setupPort: 1, credentialPort: 1 }, []));
  assert.equal(called, false);
  const owned = [{ devicePort: 32101, hostPort: 32101 }];
  for (const output of ['garbage', String.fromCharCode(0xfeff), String.fromCharCode(11), 'host tcp:bad tcp:333', 'host tcp:1', 'host tcp:1 tcp:2 extra',
    'host tcp:65536 tcp:2', 'host tcp:0 tcp:2', 'host tcp:32101 tcp:32101']) {
    assert.equal(enrollmentOwnedReversesAbsent(successful(output), owned), false);
  }
  assert.equal(enrollmentOwnedReversesAbsent(successful(''), owned), true);
  assert.equal(enrollmentOwnedReversesAbsent(successful('host-1 tcp:32000 tcp:32000\n'), owned), true);
  assert.equal(enrollmentOwnedReversesAbsent(successful('tcp:32000 tcp:32000\n'), owned), true);
  assert.equal(enrollmentOwnedReversesAbsent({ ...successful(''), stderrBytes: 1 }, owned), false);
  assert.equal(enrollmentOwnedReversesAbsent({ ...successful(''), code: 1 }, owned), false);
});

test('driver requires one explicit serial and rejects duplicate/malformed executable arguments', () => {
  assert.throws(() => enrollmentRuntimeOptions([]), /^Error: explicit_enrollment_serial_required$/);
  for (const args of [['--serial', 'test', '--serial', 'other'], ['--serial', 'test\n'],
    ['--serial', 'test', '--adb'], ['--serial', 'test', '--shell', 'value']]) {
    assert.throws(() => enrollmentRuntimeOptions(args), /^Error: invalid_enrollment_arguments$/);
  }
  assert.equal(enrollmentRuntimeOptions(['--serial', 'emulator-5554']).serial, 'emulator-5554');
});

test('an actual failed preflight retains truthful unstarted methods and enforces its earliest current-state gate', () => {
  const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: ROOT, encoding: 'utf8' }).trim() !== '';
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('./run-enrollment-runtime.mjs', import.meta.url)),
    '--serial', 'PRIVATE_SERIAL_CANARY', '--adb', process.execPath], {
    cwd: ROOT, timeout: 15000, maxBuffer: 32768, encoding: 'utf8', windowsHide: true,
  });
  assert.equal(result.status, 1);
  const report = decodeEnrollmentRuntime(fs.readFileSync(path.join(ROOT, enrollmentReportPaths.runtime)));
  assert.deepEqual(report.invocations.map(value => value.method), expectedEnrollmentMethods);
  assert.equal(report.invocations.every(value => value.state === 'not_started' && value.actualStarted === 0 && value.actualCompleted === 0), true);
  assert.equal(report.source.trackedDirty, dirty);
  assert.equal(report.problems.includes(dirty ? 'source_not_clean' : 'selected_device_unavailable'), true);
  assert.equal(report.api, null);
  assert.equal(report.input, null);
  assert.equal(report.approval, null);
  const exported = result.stdout + result.stderr + JSON.stringify(report) +
    fs.readFileSync(path.join(ROOT, enrollmentReportPaths.xml), 'utf8') +
    fs.readFileSync(path.join(ROOT, enrollmentReportPaths.html), 'utf8');
  assert.doesNotMatch(exported, /PRIVATE_SERIAL_CANARY|PRIVATE_IPC|invitationSecret|clientCertificateDer/);
});
