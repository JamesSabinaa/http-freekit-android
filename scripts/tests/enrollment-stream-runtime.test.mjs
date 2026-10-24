import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { verifyEnrollmentRuntimeFiles } from '../verify-enrollment-runtime.mjs';
import { enrolledStreamingReportPaths, enrolledStreamingRuntimeXml, enrolledStreamingRuntimeHtml,
  createEnrolledStreamingReport, parseEnrolledStreamingInvocation } from '../../tools/transport-spike/enrollment-runtime-stream-results.mjs';
import { runtime, source, commandResult } from '../../tools/transport-spike/enrollment-runtime-stream-test-fixtures.mjs';
import { host } from '../../tools/transport-spike/enrollment-runtime-test-fixtures.mjs';
import { enrollmentAdversarialReportPaths } from '../../tools/transport-spike/enrollment-runtime-adversarial-descriptor.mjs';
const cli = fileURLToPath(new URL('../verify-enrollment-runtime.mjs', import.meta.url));
const started = Math.floor(Date.now() / 1000) - 1;
function setup(directory) {
  const report = runtime(), cleanup = { ...host(), format: 'http-freekit-a22b-host-cleanup' };
  const files = Object.fromEntries(Object.entries(enrolledStreamingReportPaths).map(([key, value]) => [key, path.join(directory, value)]));
  for (const file of Object.values(files)) fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(files.runtime, JSON.stringify(report)); fs.writeFileSync(files.host, JSON.stringify(cleanup));
  fs.writeFileSync(files.xml, enrolledStreamingRuntimeXml(report)); fs.writeFileSync(files.html, enrolledStreamingRuntimeHtml(report));
  return { files, report, cleanup };
}
function temporary(action) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-a22b-gate-'));
  try { action(directory); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
const args = ['--source', source, '--api', '26', '--started', String(started), '--suite', 'a22b'];

test('B CLI selects its four default sanitized files and independently verifies all three methods', () => temporary(directory => {
  const { files } = setup(directory);
  assert.equal(verifyEnrollmentRuntimeFiles({ ...files, source, api: 26, started, suite: 'a22b' }).methods, 3);
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 0); assert.match(result.stdout, /A22b verified: 3 exact methods, 3 starts, 3 completions/);
}));

test('suite and cleanup formats cannot mix even when method and source summaries are valid', () => temporary(directory => {
  const { files, cleanup } = setup(directory);
  assert.throws(() => verifyEnrollmentRuntimeFiles({ ...files, source, api: 26, started }), /invalid_runtime_report/);
  fs.writeFileSync(files.host, JSON.stringify({ ...cleanup, format: 'http-freekit-a22a-host-cleanup' }));
  assert.throws(() => verifyEnrollmentRuntimeFiles({ ...files, source, api: 26, started, suite: 'a22b' }), /invalid_host_report/);
}));

test('B CLI preserves fresh byte-exact projections and refuses stale, extra or unjoined evidence', () => temporary(directory => {
  const { files, cleanup } = setup(directory), options = { ...files, source, api: 26, started, suite: 'a22b' };
  for (const key of ['xml', 'html']) {
    const bytes = fs.readFileSync(files[key]); fs.appendFileSync(files[key], 'PRIVATE_CANARY');
    assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_projection_mismatch/); fs.writeFileSync(files[key], bytes);
  }
  fs.utimesSync(files.runtime, started - 1, started - 1);
  assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_file_unavailable_or_stale/);
  setup(directory); fs.writeFileSync(files.host, JSON.stringify({ ...cleanup, joinObserved: false }));
  assert.throws(() => verifyEnrollmentRuntimeFiles(options), /host_cleanup_failed/);
}));

test('B argument and malformed-report errors remain fixed and never print paths or private values', () => temporary(directory => {
  const { files } = setup(directory);
  for (const bad of [[...args, '--suite', 'PRIVATE_CANARY'], args.map(value => value === 'a22b' ? 'PRIVATE_CANARY' : value), ['--PRIVATE_CANARY', directory]]) {
    const result = spawnSync(process.execPath, [cli, ...bad], { cwd: directory, encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 1); assert.doesNotMatch(result.stderr, /PRIVATE_CANARY|Error:/); assert.ok(!result.stderr.includes(directory));
  }
  fs.writeFileSync(files.runtime, '{"PRIVATE_CANARY":');
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1); assert.doesNotMatch(result.stderr, /PRIVATE_CANARY|Error:/);
}));

test('failed B setup keeps three truthful unstarted methods and cannot produce a successful gate', () => {
  const value = runtime(); value.problems = ['host_setup_failed']; value.source = null; value.api = null; value.clock = null; value.cleanup = null;
  for (const item of value.scenarios) {
    item.invocation = parseEnrolledStreamingInvocation('', { method: item.method, ...commandResult() });
    for (const key of ['input', 'approval', 'profile', 'host', 'cleanup']) item[key] = null;
  }
  assert.ok(createEnrolledStreamingReport(value)); assert.match(enrolledStreamingRuntimeXml(value), /errors="3"/);
});

const workflow = fs.readFileSync(new URL('../../.github/workflows/enrollment-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const selection = /id: suite\n        run: \|\n([\s\S]*?)      - name: Require Linux KVM/.exec(workflow)?.[1].replace(/^ {10}/gm, '');
assert.ok(selection);
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
for (const suite of ['a22a', 'a22b', 'a22c']) test(`actual workflow ${suite} selection exposes only the four fixed selected paths`, () => temporary(directory => {
  const paths = ['tools/transport-spike/run-enrollment-runtime.mjs', 'tools/transport-spike/companion-enrollment-worker.mjs',
    'tools/transport-spike/enrollment-runtime-results.mjs', 'scripts/verify-enrollment-runtime.mjs',
    ...(suite === 'a22b' ? ['tools/transport-spike/enrollment-runtime-stream-results.mjs', 'tools/transport-spike/run-enrolled-stream-runtime.mjs',
      'tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftEnrolledStreamingInteropTest.kt'] :
      suite === 'a22c' ? ['tools/transport-spike/enrollment-runtime-adversarial-results.mjs', 'tools/transport-spike/run-enrollment-adversarial-runtime.mjs',
        'tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftEnrollmentAdversarialInteropTest.kt'] :
      ['tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftEnrollmentInteropTest.kt'])];
  for (const file of paths) { const absolute = path.join(directory, file); fs.mkdirSync(path.dirname(absolute), { recursive: true }); fs.writeFileSync(absolute, ''); }
  const output = path.join(directory, 'output');
  const result = spawnSync(bash, ['-c', 'set -euo pipefail\n' + selection], { cwd: directory, encoding: 'utf8', timeout: 5000, env: { ...process.env, A22_SUITE: suite, GITHUB_OUTPUT: output } });
  assert.equal(result.status, 0, result.stderr);
  const lines = fs.readFileSync(output, 'utf8').trim().split('\n'); assert.equal(lines.length, 4);
  if (suite === 'a22b') assert.deepEqual(Object.fromEntries(lines.map(line => line.split('='))), enrolledStreamingReportPaths);
  else if (suite === 'a22c') assert.deepEqual(Object.fromEntries(lines.map(line => line.split('='))), enrollmentAdversarialReportPaths);
  else assert.ok(lines.every(line => line.includes('enrollment-runtime')));
}));
