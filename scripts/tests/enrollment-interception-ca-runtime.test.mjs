import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyEnrollmentRuntimeFiles } from '../verify-enrollment-runtime.mjs';
import { enrollmentRuntimeOptions } from '../../tools/transport-spike/run-enrollment-runtime.mjs';
import { decodeInterceptionCaRuntimeReport, interceptionCaRuntimeXml, interceptionCaRuntimeHtml } from '../../tools/transport-spike/interception-ca-runtime-results.mjs';
import { interceptionCaRuntimeMethod, interceptionCaRuntimeReportPaths } from '../../tools/transport-spike/interception-ca-runtime-descriptor.mjs';
import { caRuntime } from '../../tools/transport-spike/enrollment-runtime-interception-ca-report.test.mjs';
import { host, source } from '../../tools/transport-spike/enrollment-runtime-test-fixtures.mjs';
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const cli = fileURLToPath(new URL('../verify-enrollment-runtime.mjs', import.meta.url));
const driver = fileURLToPath(new URL('../../tools/transport-spike/run-enrollment-runtime.mjs', import.meta.url));

test('a23 selection is explicit, old default remains a22a and desktop inputs are refused', () => {
  assert.equal(enrollmentRuntimeOptions(['--serial', 'emulator-5554']).suite, 'a22a');
  assert.equal(enrollmentRuntimeOptions(['--serial', 'emulator-5554', '--suite', 'a23']).suite, 'a23');
  for (const args of [['--desktop-root', ROOT], ['--desktop-commit', 'a'.repeat(40)]])
    assert.throws(() => enrollmentRuntimeOptions(['--serial', 'emulator-5554', '--suite', 'a23', ...args]), /invalid_enrollment_arguments/);
});
test('independent a23 CLI requires current fresh JSON/XML/HTML and joined host without desktop identity', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-ca-verifier-'));
  const files = Object.fromEntries(['runtime', 'host', 'xml', 'html'].map(name => [name, path.join(directory, name)]));
  const report = caRuntime(), cleanup = host(); cleanup.format = 'http-freekit-a23-host-cleanup';
  const started = Math.floor(Date.now() / 1000) - 1;
  const opts = { ...files, suite: 'a23', source, api: 26, started };
  try {
    fs.writeFileSync(files.runtime, JSON.stringify(report)); fs.writeFileSync(files.host, JSON.stringify(cleanup));
    fs.writeFileSync(files.xml, interceptionCaRuntimeXml(report)); fs.writeFileSync(files.html, interceptionCaRuntimeHtml(report));
    assert.equal(verifyEnrollmentRuntimeFiles(opts).methods, 3);
    const args = ['--suite', 'a23', '--source', source, '--api', '26', '--started', String(started),
      ...Object.entries(files).flatMap(([name, file]) => ['--' + name, file])];
    assert.equal(spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' }).status, 0);
    assert.throws(() => verifyEnrollmentRuntimeFiles({ ...opts, desktopSource: 'a'.repeat(40) }), /invalid_runtime_arguments/);
    fs.appendFileSync(files.xml, 'private canary');
    assert.throws(() => verifyEnrollmentRuntimeFiles(opts), /runtime_projection_mismatch/);
    fs.writeFileSync(files.xml, interceptionCaRuntimeXml(report));
    cleanup.driverExitCode = 1; fs.writeFileSync(files.host, JSON.stringify(cleanup));
    assert.throws(() => verifyEnrollmentRuntimeFiles(opts), /host_cleanup_failed/);
    fs.writeFileSync(files.host, JSON.stringify(host()));
    assert.throws(() => verifyEnrollmentRuntimeFiles(opts), /invalid_host_report/);
    fs.utimesSync(files.runtime, started - 2, started - 2);
    assert.throws(() => verifyEnrollmentRuntimeFiles(opts), /runtime_file_unavailable_or_stale/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test('actual unavailable-device CLI exits one with three truthful zero-start observations and no private identifiers', () => {
  const result = spawnSync(process.execPath, [driver, '--serial', 'PRIVATE_A23_SERIAL', '--suite', 'a23', '--adb', process.execPath],
    { cwd: ROOT, timeout: 20000, maxBuffer: 32768, encoding: 'utf8' });
  assert.equal(result.status, 1);
  const report = decodeInterceptionCaRuntimeReport(fs.readFileSync(path.join(ROOT, interceptionCaRuntimeReportPaths.runtime)));
  assert.deepEqual(report.invocations.map(item => item.method), ['prepareApprovedCredentialForRestart', interceptionCaRuntimeMethod, 'reopenApprovedCredentialAfterRestart']);
  assert.deepEqual(report.invocations.map(item => [item.actualStarted, item.actualCompleted]), [[0, 0], [0, 0], [0, 0]]);
  assert.equal(report.problems.includes(report.source?.trackedDirty ? 'source_not_clean' : 'selected_device_unavailable'), true);
  assert.equal(report.ca, null);
  assert.doesNotMatch(result.stdout + result.stderr + JSON.stringify(report), /PRIVATE_A23_SERIAL/);
});
