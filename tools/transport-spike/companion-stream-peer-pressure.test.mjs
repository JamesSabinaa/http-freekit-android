import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runPressureProbe, pressureProfiles } from './companion-stream-peer-pressure.mjs';

const javaHome = process.env.PRESSURE_JAVA_HOME || process.env.JAVA_HOME;
const executable = name => javaHome ? path.join(javaHome, 'bin', `${name}${process.platform === 'win32' ? '.exe' : ''}`) : name;
for (const profile of pressureProfiles) {
  test(`software JSSE pressure: ${profile.requestedBufferBytes} bytes, ${profile.packetization} writes, localPair=${profile.localPair === true}`, { timeout: 35000 }, async () => {
    const result = await runPressureProbe({ ...profile, java: executable('java'), javac: executable('javac') });
    assert.equal(result.observationBudgetMillis, 15000);
    assert.ok(result.samples > 0 && result.samples <= 128);
    assert.ok(result.maxCompletedBytes <= 32 * 1024 * 1024 + 8192);
    assert.equal(result.shutdown.writerJoined, true); assert.equal(result.shutdown.processJoined, true);
    assert.equal(result.shutdown.producerJoined, true);
    assert.equal(result.shutdown.writerActive, false); assert.equal(result.shutdown.producerActive, false);
    if (profile.localPair) assert.ok(result.java.producerBytesWritten > 0);
    else assert.equal(result.java.producerBytesWritten, 0);
    assert.deepEqual(result.cleanup, { complete: true, workers: 0, timers: 0, pendingCallbacks: 0, sessionLeases: 0, streamLeases: 0, chargedBytes: 0 });
    if (result.observedWithinBudget) {
      assert.equal(result.peer.proxyWritePending, true);
      assert.ok(result.peer.proxyWriteEntries > result.peer.proxyWriteCompletions);
      assert.ok(result.peer.pendingIngressBytes > 0 && result.peer.chargedBytes > 0);
    }
    if (result.javaWriterObserved) {
      assert.equal(result.java.writerActive, true); assert.ok(result.java.writeEntries > result.java.writeCompletions);
    }
    const rendered = JSON.stringify(result);
    assert.doesNotMatch(rendered, /sessionId|deviceId|BEGIN |certificate|X-FreeKit|fixture\.invalid/);
    console.log(`PRESSURE ${rendered}`);
  });
}
test('pressure CLI help and invalid input are bounded and never echo supplied values', () => {
  const cli = path.resolve('tools/transport-spike/companion-stream-peer-pressure.mjs');
  const help = spawnSync(process.execPath, [cli, '--help'], { timeout: 5000, encoding: 'utf8', maxBuffer: 4096 });
  assert.equal(help.status, 0); assert.match(help.stdout, /Usage:/);
  const invalid = spawnSync(process.execPath, [cli, 'PRIVATE_VALUE'], { timeout: 5000, encoding: 'utf8', maxBuffer: 4096 });
  assert.equal(invalid.status, 1); assert.equal(invalid.stdout, ''); assert.equal(invalid.stderr.trim(), 'pressure_probe_failed');
});
