// Mandatory explicit local dependency; intentionally outside ordinary hosted globs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';

const desktopRoot = process.env.FREEKIT_DESKTOP_ROOT;
if (!desktopRoot) throw Error('Explicit FREEKIT_DESKTOP_ROOT is required for the real desktop integration');
const desktopCommit = process.env.FREEKIT_DESKTOP_COMMIT ?? 'fd63f6940226c8e3401a165082dfa9325abaca69';
test('actual reused private worker owns origin startup, public metadata, rejection and every aggregate cleanup join', { timeout: 15000 }, async () => {
  const worker = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)) });
  try {
    const metadata = (await worker.request('startOrigin', { desktopRoot, desktopCommit, openssl: process.env.OPENSSL_BIN ?? 'openssl' })).material();
    assert.equal(new Set([metadata.setupPort, metadata.credentialPort, metadata.webSocketPort]).size, 3);
    const invitation = await worker.request('createInvitation');
    assert(!JSON.stringify(invitation).includes(invitation.material().invitationSecret));
    assert(!inspect(worker).includes(metadata.desktopId));
    await assert.rejects(worker.request('releaseOriginTail'), error => error.code === 'pairing_unavailable');
    const snapshot = (await worker.request('snapshot')).material();
    assert.equal(snapshot.origin.tailReleased, false); assert.equal(snapshot.origin.tailReleaseRequested, false);
  } finally { await worker.close(); }
  const closed = worker.closedSnapshot().material();
  assert(closed.admissionClosed && closed.listenersClosed && closed.storeClosed && closed.issuerChildrenJoined && closed.privateDirectoryRemoved);
  for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']) assert.equal(closed[key], 0);
  assert.equal(closed.gatewayStreamComplete, false);
  assert.deepEqual(worker.commandObservation(), { code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
});
