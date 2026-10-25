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
import { interceptionCaRuntimeReportPaths } from '../../tools/transport-spike/interception-ca-runtime-descriptor.mjs';
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
const selection = /id: suite\n        run: \|\n([\s\S]*?)(?=      - name:)/.exec(workflow)?.[1].replace(/^ {10}/gm, '');
assert.ok(selection);
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
for (const suite of ['a22a', 'a22b', 'a22c', 'a23', 'c2']) test(`actual workflow ${suite} selection exposes only the four fixed selected paths`, () => temporary(directory => {
  const paths = ['tools/transport-spike/run-enrollment-runtime.mjs', 'tools/transport-spike/companion-enrollment-worker.mjs',
    'tools/transport-spike/enrollment-runtime-results.mjs', 'scripts/verify-enrollment-runtime.mjs',
    ...(suite === 'a22b' ? ['tools/transport-spike/enrollment-runtime-stream-results.mjs', 'tools/transport-spike/run-enrolled-stream-runtime.mjs',
      'tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftEnrolledStreamingInteropTest.kt'] :
      suite === 'a22c' ? ['tools/transport-spike/enrollment-runtime-adversarial-results.mjs', 'tools/transport-spike/run-enrollment-adversarial-runtime.mjs',
        'tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftEnrollmentAdversarialInteropTest.kt'] :
      suite === 'a23' ? ['tools/transport-spike/interception-ca-runtime-descriptor.mjs',
        'tools/transport-spike/interception-ca-runtime-results.mjs', 'tools/transport-spike/run-interception-ca-runtime.mjs',
        'tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftInterceptionCaInteropTest.kt'] :
      suite === 'c2' ? ['tools/transport-spike/capture-factory-results.mjs', 'tools/transport-spike/run-capture-factory-runtime.mjs',
        'tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftCaptureFactoryInteropTest.kt'] :
      ['tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftEnrollmentInteropTest.kt'])];
  for (const file of paths) { const absolute = path.join(directory, file); fs.mkdirSync(path.dirname(absolute), { recursive: true }); fs.writeFileSync(absolute, ''); }
  const output = path.join(directory, 'output');
  const result = spawnSync(bash, ['-c', 'set -euo pipefail\n' + selection], { cwd: directory, encoding: 'utf8', timeout: 5000, env: { ...process.env, A22_SUITE: suite, GITHUB_OUTPUT: output } });
  assert.equal(result.status, 0, result.stderr);
  const lines = fs.readFileSync(output, 'utf8').trim().split('\n'); assert.equal(lines.length, 4);
  if (suite === 'a22b') assert.deepEqual(Object.fromEntries(lines.map(line => line.split('='))), enrolledStreamingReportPaths);
  else if (suite === 'a22c') assert.deepEqual(Object.fromEntries(lines.map(line => line.split('='))), enrollmentAdversarialReportPaths);
  else if (suite === 'a23') assert.deepEqual(Object.fromEntries(lines.map(line => line.split('='))), interceptionCaRuntimeReportPaths);
  else if (suite === 'c2') assert.deepEqual(Object.fromEntries(lines.map(line => line.split('='))), {
    runtime: 'tools/transport-spike/android/build/outputs/androidTest-results/capture-factory/debug/runtime.json',
    xml: 'tools/transport-spike/android/build/outputs/androidTest-results/capture-factory/debug/TEST-capture-factory-research.xml',
    html: 'tools/transport-spike/android/build/reports/androidTests/capture-factory/debug/index.html', host: 'build/reports/capture-factory/host-cleanup.json',
  });
  else assert.ok(lines.every(line => line.includes('enrollment-runtime')));
}));

test('actual A23 invocation keeps desktop arguments and setup out of the owned permission profile', () => {
  assert.match(workflow, /          - a23\n/);
  assert.match(workflow, /if: inputs\.suite == 'c2' \|\| inputs\.suite == 'c5'/);
  for (const name of ['Check out reviewed desktop dependency for C2', 'Check out reviewed desktop dependency for C5']) {
    const step = workflow.slice(workflow.indexOf('      - name: ' + name));
    assert.match(step.slice(0, step.indexOf('      - name:', 1)), /if: inputs\.suite == 'c[25]'/);
  }
  assert.match(workflow, /API 37 ACCESS_LOCAL_NETWORK\n          # declaration\/grant\/exact-package readback; API 26 records not_required/);
  const invocation = /          driver_args=\(--serial emulator-5554 --suite "\$A22_SUITE"\)\n([\s\S]*?)          if node tools\/transport-spike\/run-enrollment-runtime\.mjs/.exec(workflow)?.[0];
  assert.ok(invocation);
  const script = invocation.slice(0, invocation.lastIndexOf('          if node')).replace(/^ {10}/gm, '') +
    'printf "driver=%s\\n" "${driver_args[*]}"\nprintf "verify=%s\\n" "${verify_args[*]}"\n';
  const result = spawnSync(bash, ['-c', 'set -euo pipefail\n' + script], { encoding: 'utf8', timeout: 5000,
    env: { ...process.env, A22_SUITE: 'a23', GITHUB_SHA: source, API_LEVEL: '37', started: '123' } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `driver=--serial emulator-5554 --suite a23\nverify=--source ${source} --api 37 --started 123 --suite a23\n`);
});
