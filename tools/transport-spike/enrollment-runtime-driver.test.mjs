import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import test from 'node:test';
import { enrollmentRuntimeOptions } from './run-enrollment-runtime.mjs';
import { decodeEnrollmentRuntime, expectedEnrollmentMethods, enrollmentReportPaths } from './enrollment-runtime-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
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
