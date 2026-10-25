import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { enrollmentRuntimeOptions } from './run-enrollment-runtime.mjs';
import { captureFactoryReportPaths, decodeCaptureFactoryReport } from './capture-factory-results.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const entry = fileURLToPath(new URL('./run-enrollment-runtime.mjs', import.meta.url));
const options = ['--serial', 'device', '--suite', 'c2', '--desktop-root', ROOT, '--desktop-commit', 'b'.repeat(40)];
test('C2 alone requires explicit canonical desktop source without changing legacy defaults', () => {
  assert.equal(enrollmentRuntimeOptions(['--serial', 'device']).suite, 'a22a');
  assert.equal(enrollmentRuntimeOptions(options).desktopRoot, ROOT);
  for (const args of [options.slice(0, 4), options.map(value => value === ROOT ? '.' : value),
    options.map(value => value === 'b'.repeat(40) ? value + '\n' : value), options.map(value => value === 'c2' ? 'a22a' : value),
    [...options, '--desktop-commit', 'b'.repeat(40)]]) assert.throws(() => enrollmentRuntimeOptions(args), /^Error: invalid_enrollment_arguments$/);
});
test('actual invalid C2 CLI arguments reject supplied material without starting a fixture', async () => {
  const result = await runDraftCommand(process.execPath, [entry, '--serial', 'CANARY_private', '--suite', 'c2'], { cwd: ROOT, timeoutMillis: 5000 });
  assert.equal(result.code, 1); assert(result.closeObserved && result.processGroupClosed);
  assert(!String(result.output + result.stderr).includes('CANARY'));
});
test('actual earliest preflight preserves unstarted C2 truth and sanitized artifacts without claiming device execution', async () => {
  const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: ROOT, encoding: 'utf8', windowsHide: true }).trim() !== '';
  const result = await runDraftCommand(process.execPath, [entry, ...options.map(value => value === 'device' ? 'CANARY_unavailable' : value), '--adb', process.execPath],
    { cwd: ROOT, timeoutMillis: 15000, maxOutputBytes: 32768 });
  assert.equal(result.code, 1); assert(result.closeObserved && result.processGroupClosed);
  assert(!String(result.output + result.stderr).includes('CANARY'));
  const report = decodeCaptureFactoryReport(fs.readFileSync(path.join(ROOT, captureFactoryReportPaths.runtime)));
  assert.deepEqual(report.problems, [dirty ? 'source_not_clean' : 'selected_device_unavailable']);
  assert.equal(report.invocation.state, 'not_started'); assert.equal(report.invocation.actualStarted + report.invocation.actualCompleted, 0);
  for (const key of ['host', 'input', 'approval', 'resources']) assert.equal(report[key], null);
  const all = [captureFactoryReportPaths.runtime, captureFactoryReportPaths.xml, captureFactoryReportPaths.html].map(name => fs.readFileSync(path.join(ROOT, name), 'utf8')).join('');
  assert(!/CANARY|invitationSecret|clientCertificateDer|PRIVATE KEY/.test(all));
});
