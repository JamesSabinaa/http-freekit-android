import test from 'node:test'; import assert from 'node:assert/strict';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { fileURLToPath } from 'node:url'; import { spawnSync } from 'node:child_process';
import { verifyEnrollmentRuntimeFiles } from '../verify-enrollment-runtime.mjs';
import { enrollmentAdversarialReportPaths, enrollmentAdversarialRuntimeXml, enrollmentAdversarialRuntimeHtml,
  parseEnrollmentAdversarialInvocation, createEnrollmentAdversarialReport } from '../../tools/transport-spike/enrollment-runtime-adversarial-results.mjs';
import { runtime, source, commandResult } from '../../tools/transport-spike/enrollment-runtime-adversarial-test-fixtures.mjs';
import { host } from '../../tools/transport-spike/enrollment-runtime-test-fixtures.mjs';
const cli = fileURLToPath(new URL('../verify-enrollment-runtime.mjs', import.meta.url)), started = Math.floor(Date.now() / 1000) - 1;
const args = ['--source', source, '--api', '26', '--started', String(started), '--suite', 'a22c'];
function temporary(action) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-a22c-gate-'));
  try { action(directory); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function setup(directory) {
  const report = runtime(), cleanup = { ...host(), format: 'http-freekit-a22c-host-cleanup' };
  const files = Object.fromEntries(Object.entries(enrollmentAdversarialReportPaths).map(([key, value]) => [key, path.join(directory, value)]));
  for (const file of Object.values(files)) fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(files.runtime, JSON.stringify(report)); fs.writeFileSync(files.host, JSON.stringify(cleanup));
  fs.writeFileSync(files.xml, enrollmentAdversarialRuntimeXml(report)); fs.writeFileSync(files.html, enrollmentAdversarialRuntimeHtml(report));
  return { files, cleanup };
}
test('C CLI independently accepts only its four exact default projections and joined cleanup', () => temporary(directory => {
  const { files } = setup(directory); assert.equal(verifyEnrollmentRuntimeFiles({ ...files, source, api: 26, started, suite: 'a22c' }).methods, 4);
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 0); assert.match(result.stdout, /A22c verified: 4 exact methods, 4 starts, 4 completions/);
}));
test('C cannot mix A/B formats, stale projections or extra appended material', () => temporary(directory => {
  const { files, cleanup } = setup(directory), options = { ...files, source, api: 26, started, suite: 'a22c' };
  assert.throws(() => verifyEnrollmentRuntimeFiles({ ...options, suite: 'a22b' }), /invalid_runtime_report/);
  fs.writeFileSync(files.host, JSON.stringify({ ...cleanup, format: 'http-freekit-a22a-host-cleanup' }));
  assert.throws(() => verifyEnrollmentRuntimeFiles(options), /invalid_host_report/); setup(directory);
  for (const key of ['xml', 'html']) {
    const bytes = fs.readFileSync(files[key]); fs.appendFileSync(files[key], 'PRIVATE_CANARY');
    assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_projection_mismatch/); fs.writeFileSync(files[key], bytes);
  }
  fs.utimesSync(files.runtime, started - 1, started - 1); assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_file_unavailable_or_stale/);
}));
test('C requires actual emulator termination/join even after four method outcomes pass', () => temporary(directory => {
  const { files, cleanup } = setup(directory);
  for (const mutation of [{ joinObserved: false }, { terminationObserved: false }, { driverExitCode: 1 }, { emulatorExitCode: null }]) {
    fs.writeFileSync(files.host, JSON.stringify({ ...cleanup, ...mutation }));
    assert.throws(() => verifyEnrollmentRuntimeFiles({ ...files, source, api: 26, started, suite: 'a22c' }), /host_cleanup_failed/);
  }
}));
test('C CLI malformed arguments/reports emit fixed errors without private paths or material', () => temporary(directory => {
  const { files } = setup(directory);
  for (const bad of [[...args, '--suite', 'PRIVATE_CANARY'], args.map(value => value === 'a22c' ? '__proto__' : value), ['--PRIVATE_CANARY', directory]]) {
    const result = spawnSync(process.execPath, [cli, ...bad], { cwd: directory, encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 1); assert.doesNotMatch(result.stderr, /PRIVATE_CANARY|__proto__|Error:/); assert.ok(!result.stderr.includes(directory));
  }
  fs.writeFileSync(files.runtime, '{"PRIVATE_CANARY":');
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1); assert.doesNotMatch(result.stderr, /PRIVATE_CANARY|Error:/);
}));
test('C early setup failure retains four unstarted methods without fake host cases', () => {
  const report = runtime(); report.source = null; report.api = null; report.clock = null; report.cleanup = null; report.problems = ['host_setup_failed'];
  for (const item of report.scenarios) {
    item.invocation = parseEnrollmentAdversarialInvocation('', { method: item.method, ...commandResult() });
    for (const key of ['input', 'approval', 'host', 'cleanup']) item[key] = null;
  }
  assert.ok(createEnrollmentAdversarialReport(report)); assert.match(enrollmentAdversarialRuntimeXml(report), /tests="4" failures="0" errors="4"/);
});
