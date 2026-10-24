import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';

test('invalid streaming IPC cannot initialize assets or consume the single legacy start', async () => {
  const root = fs.realpathSync(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(root, 'freekit-stream-ipc-'));
  fs.chmodSync(directory, 0o700);
  const worker = new EnrollmentRuntimeWorker({
    entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)),
    cwd: fileURLToPath(new URL('../../', import.meta.url)),
  });
  const args = { directory, mode: 'create', openssl: process.env.OPENSSL_BIN ?? 'openssl',
    setupPort: 0, credentialPort: 0, streamPort: 0, credentialLifetimeSeconds: 60, sessionLifetimeMillis: 120000 };
  try {
    const missingPort = { ...args }; delete missingPort.streamPort;
    const mutations = [
      { mode: 'open' }, { setupPort: 54321, streamPort: 54321 },
      { credentialLifetimeSeconds: 59 }, { sessionLifetimeMillis: 1800001 }, { extra: 'PRIVATE' },
    ];
    for (const candidate of [missingPort, ...mutations.map(mutation => ({ ...args, ...mutation }))]) {
      await assert.rejects(worker.request('startStreaming', candidate), e => e.code === 'invalid_message');
      assert.deepEqual(fs.readdirSync(directory), []);
    }
    const metadata = (await worker.request('start', { directory, mode: 'create', openssl: args.openssl,
      setupPort: 0, credentialPort: 0 }, { timeoutMillis: 60000 })).material();
    assert.ok(metadata.setupPort > 0 && metadata.credentialPort > 0);
    assert.equal(Object.hasOwn(metadata, 'webSocketPort'), false);
    await assert.rejects(worker.request('inspectEnrollment', { enrollmentId: 'enr_' + Buffer.alloc(32, 7).toString('base64url') }),
      e => e.code === 'pairing_unavailable');
    const closed = (await worker.close()).material();
    assert.equal(closed.closed, true); assert.equal(closed.storeClosed, true);
    assert.equal(worker.commandObservation().closeObserved, true);
  } finally {
    // A failed actual join must retain the private directory rather than deleting issuer state.
    await worker.close();
    assert.equal(path.dirname(directory), root);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('a never-started worker closes after configuration refusal and actually exits without claiming initialization', async () => {
  const worker = new EnrollmentRuntimeWorker({
    entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)),
    cwd: fileURLToPath(new URL('../../', import.meta.url)),
  });
  try {
    await assert.rejects(worker.request('startStreaming', {}), e => e.code === 'invalid_message');
    const closed = (await worker.close()).material();
    assert.equal(closed.initializationAttempted, false);
    for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']) assert.equal(closed[key], 0);
    assert.deepEqual(worker.commandObservation(), { code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
  } finally { await worker.close(); }
});
