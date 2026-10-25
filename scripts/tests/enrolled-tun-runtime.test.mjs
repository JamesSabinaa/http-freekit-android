import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { verifyEnrollmentRuntimeFiles } from '../verify-enrollment-runtime.mjs';
import { report, source, desktopCommit } from '../../tools/transport-spike/enrolled-tun-test-fixtures.mjs';
import { enrolledTunRuntimeXml, enrolledTunRuntimeHtml } from '../../tools/transport-spike/enrolled-tun-results.mjs';
import { host as hostFixture } from '../../tools/transport-spike/enrollment-runtime-test-fixtures.mjs';
const cli = fileURLToPath(new URL('../verify-enrollment-runtime.mjs', import.meta.url));

function files(action, api = 26) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-tun-gate-'));
  const paths = Object.fromEntries(['runtime', 'host', 'xml', 'html'].map(key => [key, path.join(directory, key + (key === 'runtime' || key === 'host' ? '.json' : '.' + key))]));
  const value = report(api), host = { ...hostFixture(), format: 'http-freekit-c5-host-cleanup', api };
  const options = { ...paths, source, api, desktopSource: desktopCommit, started: Math.floor(Date.now() / 1000) - 1, suite: 'c5' };
  const write = () => { fs.writeFileSync(paths.runtime, JSON.stringify(value)); fs.writeFileSync(paths.host, JSON.stringify(host));
    fs.writeFileSync(paths.xml, enrolledTunRuntimeXml(value)); fs.writeFileSync(paths.html, enrolledTunRuntimeHtml(value)); };
  try { write(); action({ value, host, paths, options, write }); }
  finally { assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir())); assert.match(path.basename(directory), /^freekit-tun-gate-/); fs.rmSync(directory, { recursive: true, force: true }); }
}
test('C5 final CLI independently binds all four fresh files and exact Android/API/desktop source on both APIs', () => {
  for (const api of [26, 37]) files(({ options }) => {
    assert.equal(verifyEnrollmentRuntimeFiles(options).methods, 1);
    const args = Object.entries(options).flatMap(([key, value]) => ['--' + (key === 'desktopSource' ? 'desktop-source' : key), String(value)]);
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /C5 verified: 1 exact methods, 1 starts, 1 completions/);
  }, api);
});
test('C5 final gate rejects wrong source, dirty source, old desktop pin, missing desktop input and independent emulator failures', () => {
  files(({ value, host, options, write }) => {
    for (const changed of [{ desktopSource: 'b'.repeat(40) }, { desktopSource: undefined }, { source: 'b'.repeat(40) }, { api: 37 }]) assert.throws(() => verifyEnrollmentRuntimeFiles({ ...options, ...changed }));
    value.source.trackedDirty = true; write(); assert.throws(() => verifyEnrollmentRuntimeFiles(options)); value.source.trackedDirty = false;
    for (const [key, replacement] of [['driverExitCode', 1], ['joinObserved', false], ['terminationObserved', false], ['emulatorExitCode', null], ['sourceCommit', 'b'.repeat(40)]]) {
      const before = host[key]; host[key] = replacement; write(); assert.throws(() => verifyEnrollmentRuntimeFiles(options)); host[key] = before;
    }
  });
});
test('C5 final gate rejects stale, truncated, missing, appended and foreign-key files without logging their contents', () => {
  files(({ paths, options, write }) => {
    for (const name of ['runtime', 'host', 'xml', 'html']) {
      write(); fs.utimesSync(paths[name], options.started - 1, options.started - 1); assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_file_unavailable_or_stale/);
      write(); fs.unlinkSync(paths[name]); assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_file_unavailable_or_stale/);
    }
    for (const name of ['xml', 'html']) { write(); fs.appendFileSync(paths[name], 'CANARY_PROVIDER'); assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_projection_mismatch/); }
    for (const name of ['runtime', 'host']) { write(); fs.writeFileSync(paths[name], '{"CANARY_PROVIDER":'); assert.throws(() => verifyEnrollmentRuntimeFiles(options)); }
    write(); fs.writeFileSync(paths.runtime, Buffer.alloc(65537, 32)); assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_file_unavailable_or_stale/);
    const result = spawnSync(process.execPath, [cli, '--runtime', paths.runtime, '--source', source, '--api', '26', '--started', String(options.started), '--suite', 'c5', '--desktop-source', desktopCommit], { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 1); assert(!result.stderr.includes('CANARY')); assert(!result.stderr.includes(paths.runtime)); assert(!result.stderr.includes('Error:'));
  });
});
test('C5 cannot borrow passing host cleanup or XML to repair an incomplete/failed method or host-origin contradiction', () => {
  files(({ value, options, write }) => {
    value.host.origin.requestBodyBytes--; write(); assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_enrolled_tun_host_failed/);
    value.host.origin.requestBodyBytes++; value.invocation = { ...value.invocation, state: 'failed', problems: ['instrumentation_failure'] }; write();
    assert.throws(() => verifyEnrollmentRuntimeFiles(options), /runtime_invocation_failed/);
  });
});
