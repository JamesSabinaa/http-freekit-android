import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { cleanupEnrollmentResources } from './enrollment-runtime-host.mjs';
import { enrollmentCommandObservation } from './enrollment-runtime-results.mjs';
import { encodeEnrolledStreamInput } from './enrollment-runtime-stream-input.mjs';
import { projectEnrolledHostSnapshot } from './enrollment-runtime-stream-results.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enroll, enrolledControl, enrolledStream, upgradeEnrolled } from './companion-enrollment-stream-client.mjs';
import { bounded } from './companion-stream-peer-io.mjs';

test('actual streaming worker IPC carries finite original-owner evidence and joins before private-state removal', { timeout: 30000 }, async () => {
  const temporary = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(temporary, 'freekit-enrollment-runtime-'));
  fs.chmodSync(directory, 0o700);
  const worker = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)) });
  const connections = [];
  try {
    const metadata = await worker.request('startStreaming', { directory, mode: 'create', openssl: process.env.OPENSSL_BIN ?? 'openssl',
      setupPort: 0, credentialPort: 0, streamPort: 0, credentialLifetimeSeconds: 60, sessionLifetimeMillis: 120000 }, { timeoutMillis: 60000 });
    const invitation = await worker.request('createInvitation');
    const input = encodeEnrolledStreamInput(metadata.material(), invitation.material(), 1);
    assert.equal(input[10], 1); input.fill(0);
    const fixture = { metadata: () => metadata, createInvitation: () => invitation,
      approve: enrollmentId => worker.request('approve', { enrollmentId }) };
    const credential = await enroll(fixture, createCryptoFixture());
    const control = await enrolledControl(fixture, credential); connections.push(control);
    const stream = await enrolledStream(fixture, credential, control); connections.push(stream);
    const origin = process.hrtime.bigint();
    async function sample() {
      const callStartedNanos = Number(process.hrtime.bigint() - origin);
      const value = (await worker.request('inspectEnrollment', { enrollmentId: credential.enrollmentId })).material();
      return projectEnrolledHostSnapshot(value, { callStartedNanos, callReceivedNanos: Number(process.hrtime.bigint() - origin) });
    }
    const active = await sample();
    assert.equal(active.controlPhase, 'active'); assert.equal(active.controlsAdmitted, 1);
    assert.equal(active.grantValid, true); assert.equal(active.sessionLease, true);
    assert.equal((await worker.request('revoke', { enrollmentId: credential.enrollmentId })).material().code, 'device_revoked');
    await bounded(Promise.all(connections.map(connection => connection.closed)), 5000);
    let terminal;
    const until = Date.now() + 5000;
    do {
      terminal = await sample();
      if (terminal.cleanupComplete) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    } while (Date.now() < until);
    assert.equal(terminal.controlCause, 'device_revoked'); assert.equal(terminal.cleanupComplete, true);
    assert.equal(terminal.ownerResourcesReleased, true); assert.equal(terminal.writesAfterInvalidation, 0);
    assert.equal((await upgradeEnrolled(fixture, credential, '/companion/v1/control')).status, 403);
  } finally {
    for (const connection of connections) { connection.socket.destroy(); await connection.closed; await connection.pump; }
    const cleanup = await cleanupEnrollmentResources({ commands: [], adb() { throw Error('Unexpected device operation in host test'); } },
      { workers: [worker], mappings: [], directory }, enrollmentCommandObservation);
    assert.equal(cleanup.failed, false); assert.equal(cleanup.workerClosed.storeClosed, true);
    assert.equal(cleanup.workerCommand.processGroupClosed, true); assert.equal(cleanup.privateDirectoryRemoved, true);
    assert.equal(fs.existsSync(directory), false);
  }
});
