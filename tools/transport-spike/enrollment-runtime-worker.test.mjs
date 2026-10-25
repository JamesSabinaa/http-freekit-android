import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import test from 'node:test';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';

const entry = fileURLToPath(new URL('./enrollment-runtime-worker-fixture.mjs', import.meta.url));
const worker = mode => new EnrollmentRuntimeWorker({ entry, args: mode ? [mode] : [] });

test('origin operations retain the same private worker and reject invalid source before initialization', async () => {
  const realEntry = fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url));
  for (const args of [ { desktopRoot: '.', desktopCommit: '0'.repeat(40), openssl: 'openssl' },
    { desktopRoot: process.cwd(), desktopCommit: '0'.repeat(40) + '\n', openssl: 'openssl' },
    { desktopRoot: process.cwd(), desktopCommit: '0'.repeat(40), openssl: 'openssl', extra: 'PRIVATE_CANARY' } ]) {
    const child = new EnrollmentRuntimeWorker({ entry: realEntry });
    try {
      await assert.rejects(child.request('releaseOriginTail'), error => error.code === 'pairing_unavailable');
      await assert.rejects(child.request('startOrigin', args), error => error.code === 'invalid_message');
    } finally { await child.close(); }
    assert.equal(child.closedSnapshot().material().initializationAttempted, false);
    assert.equal(child.commandObservation().code, 0);
    assert.equal(child.commandObservation().closeObserved, true);
  }
});

test('private actual IPC replies are copied/redacted and graceful close joins the real worker', async () => {
  const child = worker();
  try {
    const reply = await child.request('metadata');
    assert.equal(reply.material().value, 'PRIVATE_IPC_MATERIAL');
    const copy = reply.material(); copy.value = 'changed';
    assert.equal(reply.material().value, 'PRIVATE_IPC_MATERIAL');
    assert.doesNotMatch(JSON.stringify(reply) + inspect(reply) + inspect(child), /PRIVATE/);
  } finally { await child.close(); }
  assert.deepEqual(child.commandObservation(), { code: 0, signal: null, reason: null,
    closeObserved: true, processGroupClosed: true });
  assert.equal(child.closedSnapshot().material().storeClosed, true);
});

test('configuration, bounded payload and operation errors do not send private or executable material', async () => {
  const child = worker();
  try {
    await assert.rejects(child.request('shell', {}), e => e.code === 'worker_configuration_failed');
    await assert.rejects(child.request('metadata', { private: 'x'.repeat(16385) }), e => e.code === 'worker_protocol_failed');
    await assert.rejects(child.request('metadata', {}, { timeoutMillis: 0 }), e => e.code === 'worker_configuration_failed');
  } finally { await child.close(); }
});

test('a malformed actual reply fails closed while the private close command still joins resources', async () => {
  const child = worker('malformed');
  await assert.rejects(child.request('metadata'), e => e.code === 'worker_protocol_failed' && !inspect(e).includes('PRIVATE'));
  await assert.rejects(child.close(), e => e.code === 'worker_protocol_failed');
  assert.equal(child.commandObservation().closeObserved, true);
  assert.equal(child.commandObservation().processGroupClosed, true);
});

test('timed-out private calls retain ownership and allow a separate close instead of a forced restart', async () => {
  const child = worker('hang');
  await assert.rejects(child.request('metadata', {}, { timeoutMillis: 100 }), e => e.code === 'worker_timeout');
  assert.equal(child.commandObservation().closeObserved, false);
  await assert.rejects(child.close(), e => e.code === 'worker_timeout');
  assert.equal(child.commandObservation().closeObserved, true);
  assert.equal(child.commandObservation().processGroupClosed, true);
});

test('three outstanding business requests cannot prevent the reserved cleanup command', async () => {
  const child = worker('hang');
  const requests = [child.request('metadata'), child.request('metadata'), child.request('metadata')];
  const observed = Promise.allSettled(requests);
  await assert.rejects(child.request('createInvitation'), e => e.code === 'worker_command_limit');
  await child.close();
  assert.equal((await observed).every(result => result.status === 'rejected'), true);
  assert.equal(child.commandObservation().closeObserved, true);
  await assert.rejects(child.request('metadata'), e => e.code === 'worker_exited');
});
