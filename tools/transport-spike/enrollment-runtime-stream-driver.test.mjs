import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { enrollmentRuntimeOptions } from './run-enrollment-runtime.mjs';
import { decodeEnrolledStreamingReport, enrolledStreamingReportPaths, verifyEnrolledStreamingReport } from './enrollment-runtime-stream-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

test('driver selection is finite, defaults to the unchanged A22a suite and rejects duplicate selectors', () => {
  assert.equal(enrollmentRuntimeOptions(['--serial', 'device']).suite, 'a22a');
  assert.equal(enrollmentRuntimeOptions(['--serial', 'device', '--suite', 'a22b']).suite, 'a22b');
  for (const args of [['--suite', 'other'], ['--suite', 'a22b\n'], ['--suite', 'a22b', '--suite', 'a22a']]) {
    assert.throws(() => enrollmentRuntimeOptions(['--serial', 'device', ...args]), /^Error: invalid_enrollment_arguments$/);
  }
});

test('actual A22b preflight failure keeps all three methods unstarted and emits only the selected bounded reports', () => {
  const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: ROOT, encoding: 'utf8' }).trim() !== '';
  const started = Date.now();
  const result = spawnSync(process.execPath, ['tools/transport-spike/run-enrollment-runtime.mjs', '--serial',
    'enrolled-PRIVATE-unavailable-device', '--suite', 'a22b'], { cwd: ROOT, encoding: 'utf8', timeout: 20000, windowsHide: true });
  assert.equal(result.error, undefined); assert.equal(result.status, 1);
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE|invitation|BEGIN.*PRIVATE KEY/);
  assert.match(result.stdout, /0 started, 0 completed; failed/);
  const filename = path.join(ROOT, enrolledStreamingReportPaths.runtime);
  assert.ok(fs.statSync(filename).mtimeMs >= started - 1000);
  const report = decodeEnrolledStreamingReport(fs.readFileSync(filename));
  assert.deepEqual(report.problems, [dirty ? 'source_not_clean' : 'selected_device_unavailable']);
  assert.equal(report.scenarios.length, 3);
  for (const item of report.scenarios) {
    assert.equal(item.invocation.state, 'not_started'); assert.equal(item.invocation.actualStarted, 0);
    assert.equal(item.invocation.actualCompleted, 0); assert.equal(item.invocation.observation, null);
    assert.equal(item.input, null); assert.equal(item.approval, null); assert.equal(item.cleanup, null);
  }
  assert.equal(report.cleanup.ownedCommandsClosed, true); assert.equal(report.cleanup.ownedCommandGroupsClosed, true);
  assert.throws(() => verifyEnrolledStreamingReport(report, { source: report.source.commit, api: 26 }));
  const xml = fs.readFileSync(path.join(ROOT, enrolledStreamingReportPaths.xml), 'utf8');
  assert.match(xml, /tests="3" failures="0" errors="3" skipped="0"/);
});
