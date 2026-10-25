import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyEnrollmentRuntimeFiles } from '../verify-enrollment-runtime.mjs';
import { report, source, desktopCommit } from '../../tools/transport-spike/capture-factory-test-fixtures.mjs';
import { captureFactoryRuntimeXml, captureFactoryRuntimeHtml } from '../../tools/transport-spike/capture-factory-results.mjs';
import { host } from '../../tools/transport-spike/enrollment-runtime-test-fixtures.mjs';
import { runDraftCommand } from '../../tools/transport-spike/draft-stream-command.mjs';

function files(t) {
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-capture-verifier-'));
  t.after(() => { assert.equal(path.dirname(directory), root); assert(path.basename(directory).startsWith('freekit-capture-verifier-')); fs.rmSync(directory, { recursive: true, force: true }); });
  const value = report(), cleanup = { ...host(), format: 'http-freekit-c2-host-cleanup' };
  const result = { suite: 'c2', source, desktopSource: desktopCommit, api: 26, started: Math.floor(Date.now() / 1000) - 1 };
  for (const [name, body] of [['runtime', JSON.stringify(value)], ['host', JSON.stringify(cleanup)], ['xml', captureFactoryRuntimeXml(value)], ['html', captureFactoryRuntimeHtml(value)]]) {
    result[name] = path.join(directory, name); fs.writeFileSync(result[name], body);
  }
  return result;
}
test('four fresh exact C2 projections bind both source commits and actual emulator cleanup', t => {
  assert.equal(verifyEnrollmentRuntimeFiles(files(t)).methods, 1);
});
test('C2 requires its explicit desktop source and other suites cannot silently accept that input', t => {
  const value = files(t);
  for (const extra of [{ desktopSource: undefined }, { desktopSource: '0'.repeat(40) }, { desktopSource: desktopCommit + '\n' }, { suite: 'a22a' }]) {
    assert.throws(() => verifyEnrollmentRuntimeFiles({ ...value, ...extra }));
  }
});
test('tampered, stale, missing and material-bearing projections cannot pass', t => {
  for (const kind of ['xml', 'html', 'host', 'runtime']) {
    const value = files(t); fs.appendFileSync(value[kind], 'CANARY_private');
    assert.throws(() => verifyEnrollmentRuntimeFiles(value), error => !String(error).includes('CANARY'));
  }
  const value = files(t); fs.utimesSync(value.runtime, new Date(0), new Date(0)); assert.throws(() => verifyEnrollmentRuntimeFiles(value));
  const missing = files(t); fs.rmSync(missing.host); assert.throws(() => verifyEnrollmentRuntimeFiles(missing));
});
test('independent host/emulator failures remain fatal with an otherwise passing Android method', t => {
  for (const key of ['terminationObserved', 'joinObserved']) {
    const value = files(t), cleanup = JSON.parse(fs.readFileSync(value.host)); cleanup[key] = false; fs.writeFileSync(value.host, JSON.stringify(cleanup));
    assert.throws(() => verifyEnrollmentRuntimeFiles(value));
  }
});
test('actual CLI preserves exact C2 binding and emits only fixed summary text', async t => {
  const value = files(t), args = [fileURLToPath(new URL('../verify-enrollment-runtime.mjs', import.meta.url))];
  for (const [key, item] of Object.entries(value)) args.push('--' + (key === 'desktopSource' ? 'desktop-source' : key), String(item));
  const result = await runDraftCommand(process.execPath, args, { timeoutMillis: 5000 });
  assert.equal(result.code, 0); assert(result.closeObserved && result.processGroupClosed); assert.equal(result.stderrBytes, 0); assert.match(result.output, /^C2 verified: 1 exact methods, 1 starts, 1 completions;/);
});
