import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { captureColdOptions, runCaptureColdRuntime } from './run-capture-cold-runtime.mjs';
import { runDraftCommand } from '../transport-spike/draft-stream-command.mjs';

test('finite cold TCP options and actual CLI errors never echo supplied values or accept another suite', { timeout: 10000 }, async () => {
  for (const args of [[], ['--serial'], ['--serial', 'x', '--suite', 'a22a'], ['--serial', 'x', '--serial', 'y'], ['--serial', 'CANARY\nprivate']]) assert.throws(() => captureColdOptions(args));
  assert.deepEqual(captureColdOptions(['--serial', 'emulator-5554'], { ANDROID_HOME: '/sdk' }).serial, 'emulator-5554');
  const command = await runDraftCommand(process.execPath, [fileURLToPath(new URL('./run-capture-cold-runtime.mjs', import.meta.url)), '--serial', 'CANARY\nprivate'], { timeoutMillis: 5000 });
  assert.equal(command.code, 1); assert.equal(command.closeObserved, true); assert.equal(command.processGroupClosed, true);
  assert.equal((command.output + command.stderr).includes('CANARY'), false);
});

test('real unavailable-device child leaves one truthful unstarted case and joined host commands', { timeout: 15000 }, async () => {
  // Node rejects adb's -s flag: this exercises an actual bounded failed child, without starting ADB or an emulator.
  const report = await runCaptureColdRuntime({ serial: 'CANARY_private_serial', adb: process.execPath });
  assert.equal(report.accepted, false); assert.deepEqual(report.problems, ['device_unavailable']);
  assert.equal(report.api, 0);
  for (const item of [report.method]) {
    assert.equal(item.invocation.actualStarted, 0); assert.equal(item.invocation.actualCompleted, 0);
    assert.equal(item.invocation.state, 'incomplete'); assert.equal(item.invocation.observation, null);
  }
  assert.equal(report.cleanup.ownedCommandsClosed, true); assert.equal(report.cleanup.ownedCommandGroupsClosed, true);
  assert.equal(JSON.stringify(report).includes('CANARY'), false);
});
