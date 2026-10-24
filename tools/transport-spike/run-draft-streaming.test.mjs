import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { containsOwnedMappings, draftStreamingOptions } from './run-draft-streaming.mjs';

test('driver requires an explicit validated serial and rejects duplicate or malformed arguments', () => {
  for (const args of [[], ['--serial', ''], ['--serial', 'private value'], ['--serial', 'emulator-5554', '--serial', 'other'],
    ['--serial', 'emulator-5554', '--unknown', 'value'], ['--serial', 'emulator-5554', '--adb'],
    ['--serial', 'emulator-5554', '--openssl', 'PRIVATE\nVALUE']]) {
    assert.throws(() => draftStreamingOptions(args, {}), /^Error: (?:explicit_research_serial_required|invalid_research_arguments)$/);
  }
  const options = draftStreamingOptions(['--serial', 'emulator-5554', '--adb', 'custom adb', '--openssl', 'custom openssl'], {});
  assert.deepEqual(options, { serial: 'emulator-5554', adb: 'custom adb', openssl: 'custom openssl' });
  assert.equal(Object.isFrozen(options), true);
});

test('reverse liveness requires both exact owned pairs and ignores unrelated mappings', () => {
  const owned = [{ devicePort: '1234', hostPort: '1234' }, { devicePort: '2345', hostPort: '2345' }];
  assert.equal(containsOwnedMappings('host tcp:1234 tcp:1234\r\nhost tcp:2345 tcp:2345\nhost tcp:9999 tcp:9999', owned), true);
  assert.equal(containsOwnedMappings('host tcp:1234 tcp:1234\nhost tcp:2345 tcp:7777', owned), false);
  assert.equal(containsOwnedMappings('host tcp:1234 tcp:1234', owned), false);
  assert.equal(containsOwnedMappings('', []), false);
});

test('a real unavailable-device run writes seven incomplete cases after cleanup without exposing command arguments', () => {
  let failure;
  try { execFileSync(process.execPath, ['tools/transport-spike/run-draft-streaming.mjs', '--serial', 'PRIVATE_SERIAL_CANARY',
    '--adb', 'PRIVATE_ADB_CANARY_does_not_exist'], { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); }
  catch (value) { failure = value; }
  assert.equal(failure?.status, 1);
  const output = String(failure.stdout) + String(failure.stderr);
  assert.doesNotMatch(output, /PRIVATE_/);
  assert.match(output, /selected_device_unavailable/);
  const xml = fs.readFileSync('tools/transport-spike/android/build/outputs/androidTest-results/draft-streaming/debug/TEST-draft-stream-research.xml', 'utf8');
  assert.match(xml, /tests="7" failures="0" errors="7" skipped="0"/);
  assert.match(xml, /name="actualStarted" value="0"/);
  assert.match(xml, /name="cleanupStatus" value="complete"/);
  assert.doesNotMatch(xml, /PRIVATE_/);
});
