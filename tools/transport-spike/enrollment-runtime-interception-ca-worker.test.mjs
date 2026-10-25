import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { createHash, X509Certificate } from 'node:crypto';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enroll } from './companion-enrollment-stream-client.mjs';

const entry = fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url));
const root = fs.realpathSync(os.tmpdir());
const openssl = process.env.OPENSSL_BIN ?? 'openssl';
function directory() { const dir = fs.mkdtempSync(path.join(root, 'freekit-ca-evidence-')); fs.chmodSync(dir, 0o700); return dir; }
function remove(dir) { assert.equal(path.dirname(dir), root); fs.rmSync(dir, { recursive: true, force: true }); }
const start = (dir, mode = 'create', ports = {}) => ({ directory: dir, mode, openssl, setupPort: 0, credentialPort: 0, ...ports });
function expected(dir) {
  const der = new X509Certificate(fs.readFileSync(path.join(dir, 'interception.pem'))).raw;
  return { certificateBytes: der.length, certificateSha256: createHash('sha256').update(der).digest('base64url') };
}
function evidence(value, actual) {
  assert.deepEqual(Object.keys(value).sort(), ['certificateBytes', 'certificateSha256']);
  assert(Number.isInteger(value.certificateBytes) && value.certificateBytes > 0 && value.certificateBytes <= 4096);
  assert.match(value.certificateSha256, /^[A-Za-z0-9_-]{43}$/); assert.deepEqual(value, actual);
}
function joined(value) {
  for (const key of ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined']) assert.equal(value[key], true);
  for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']) assert.equal(value[key], 0);
}
function commandJoined(worker) {
  assert.deepEqual(worker.commandObservation(), { code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
}

test('plain HTTPS evidence is synchronous, fresh, approval-bound and copied; closing never publishes it', { timeout: 15000 }, async () => {
  const dir = directory(); let owner;
  try {
    owner = await startEnrollmentHttpsFixture(start(dir));
    const credential = await enroll(owner, createCryptoFixture()), actual = expected(dir), metadata = owner.metadata().material();
    assert.equal(actual.certificateSha256, credential.approved.interceptionCaCertificateSha256);
    const keys = Object.keys(owner.snapshot()), reply = owner.interceptionCaEvidence();
    assert.equal(reply instanceof Promise, false); evidence(reply.material(), actual);
    const copy = reply.material(); copy.certificateBytes = 0; copy.certificateSha256 = 'PRIVATE_CANARY'; evidence(reply.material(), actual);
    assert.doesNotMatch(inspect(reply) + JSON.stringify(reply), new RegExp(actual.certificateSha256));
    const filename = path.join(dir, 'interception.pem'), original = fs.readFileSync(filename);
    fs.writeFileSync(filename, 'corrupt', { mode: 0o600 });
    assert.throws(() => owner.interceptionCaEvidence(), error => error.code === 'pairing_unavailable');
    const now = Math.floor(Date.now() / 1000) * 1000;
    const other = new X509Certificate(createCryptoFixture({ utcMillis: now }).certificate({ ca: true, eku: null }));
    assert(other.ca && other.verify(other.publicKey) && other.subject === other.issuer);
    assert(Date.parse(other.validFrom) <= now && Date.parse(other.validTo) > now);
    assert.notEqual(createHash('sha256').update(other.raw).digest('base64url'), actual.certificateSha256);
    fs.writeFileSync(filename, other.toString(), { mode: 0o600 });
    assert.throws(() => owner.interceptionCaEvidence(), error => error.code === 'pairing_unavailable');
    fs.writeFileSync(filename, original, { mode: 0o600 }); evidence(owner.interceptionCaEvidence().material(), actual);
    assert.deepEqual(owner.metadata().material(), metadata); assert.deepEqual(Object.keys(owner.snapshot()), keys);
    const closing = owner.close(); assert.throws(() => owner.interceptionCaEvidence(), error => error.code === 'pairing_unavailable');
    joined(await closing); assert.throws(() => owner.interceptionCaEvidence(), error => error.code === 'pairing_unavailable');
  } finally { if (owner) joined(await owner.close()); remove(dir); }
});

test('actual private worker evidence survives reopen, rejects arguments and keeps reserved close/actual joins', { timeout: 15000 }, async () => {
  const dir = directory(); let child;
  try {
    child = new EnrollmentRuntimeWorker({ entry });
    await assert.rejects(child.request('interceptionCaEvidence'), error => error.code === 'pairing_unavailable');
    await assert.rejects(child.request('interceptionCaEvidence', { extra: true }), error => error.code === 'invalid_message');
    const metadata = (await child.request('start', start(dir), { timeoutMillis: 60000 })).material();
    const actual = expected(dir), reply = await child.request('interceptionCaEvidence'); evidence(reply.material(), actual);
    assert.equal(actual.certificateSha256, metadata.interceptionCaCertificateSha256);
    const copy = reply.material(); copy.certificateBytes = 0; evidence(reply.material(), actual);
    assert.doesNotMatch(inspect(reply) + JSON.stringify(reply), new RegExp(actual.certificateSha256));
    await assert.rejects(child.request('interceptionCaEvidence', { certificateBytes: 1 }), error => error.code === 'invalid_message');
    const filename = path.join(dir, 'interception.pem'), original = fs.readFileSync(filename);
    fs.writeFileSync(filename, 'corrupt', { mode: 0o600 });
    await assert.rejects(child.request('interceptionCaEvidence'), error => error.code === 'pairing_unavailable');
    fs.writeFileSync(filename, original, { mode: 0o600 }); evidence((await child.request('interceptionCaEvidence')).material(), actual);
    const invitation = (await child.request('createInvitation')).material();
    const waiting = [0, 1, 2].map(() => assert.rejects(child.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 }), error => error.code === 'pairing_unavailable'));
    await assert.rejects(child.request('interceptionCaEvidence'), error => error.code === 'worker_command_limit');
    joined((await child.close()).material()); await Promise.all(waiting); commandJoined(child);
    await assert.rejects(child.request('interceptionCaEvidence'), error => error.code === 'worker_exited');
    child = new EnrollmentRuntimeWorker({ entry });
    const reopened = (await child.request('start', start(dir, 'open', { setupPort: metadata.setupPort, credentialPort: metadata.credentialPort }))).material();
    assert.deepEqual(reopened, metadata); evidence((await child.request('interceptionCaEvidence')).material(), actual);
    joined((await child.close()).material()); commandJoined(child);
  } finally { if (child) { await child.close(); commandJoined(child); } remove(dir); }
});

test('real streaming mode refuses plain-HTTPS evidence and still closes every actual listener and issuer', { timeout: 10000 }, async () => {
  const dir = directory(), child = new EnrollmentRuntimeWorker({ entry });
  try {
    const metadata = (await child.request('startStreaming', { ...start(dir), streamPort: 0, credentialLifetimeSeconds: 60, sessionLifetimeMillis: 120000 }, { timeoutMillis: 60000 })).material();
    assert(metadata.webSocketPort > 0);
    await assert.rejects(child.request('interceptionCaEvidence'), error => error.code === 'pairing_unavailable');
    joined((await child.close()).material()); commandJoined(child);
  } finally { await child.close(); commandJoined(child); remove(dir); }
});

test('private IPC mode guard rejects origin, TUN and adversarial doubles even when they expose an evidence method', { timeout: 10000 }, async () => {
  // Dispatch-only TEMP doubles create no alias, issuer, desktop or network proof.
  // They deliberately expose the method so that an absent worker mode check fails.
  const dir = directory(), copiedEntry = path.join(dir, 'companion-enrollment-worker.mjs');
  fs.copyFileSync(entry, copiedEntry);
  const source = `const closed={admissionClosed:true,listenersClosed:true,storeClosed:true,issuerChildrenJoined:true,
    activeSockets:0,pendingCallbacks:0,pendingTimers:0,issuerJobs:0,signerGroups:0,workers:0};
    function owner(origin=false){return {metadata:()=>({material:()=>({})}),interceptionCaEvidence:()=>({material:()=>({certificateBytes:1,certificateSha256:'forbidden'})}),
      close:async()=>origin?{...closed,listenerClosed:true,privateDirectoryRemoved:true,gatewayStreamComplete:false,enrollment:closed,
        backend:{closing:true,activeOwners:0,admitted:0,settled:0}}:closed};}
    export async function startEnrollmentHttpsFixture(){return owner();}
    export async function startEnrollmentAdversarialFixture(){return owner();}
    export async function startOriginGatewayFixture(){return owner(true);}`;
  for (const name of ['companion-enrollment-https.mjs', 'companion-enrollment-adversarial.mjs', 'gateway-origin-fixture.mjs']) fs.writeFileSync(path.join(dir, name), source);
  try {
    for (const op of ['startOrigin', 'startTunOrigin', 'startAdversarial']) {
      const child = new EnrollmentRuntimeWorker({ entry: copiedEntry });
      try {
        const args = op === 'startAdversarial' ? start(dir) : { desktopRoot: dir, desktopCommit: '2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6', openssl };
        await child.request(op, args);
        await assert.rejects(child.request('interceptionCaEvidence'), error => error.code === 'pairing_unavailable');
        joined((await child.close()).material()); commandJoined(child);
      } finally { await child.close(); commandJoined(child); }
    }
  } finally { remove(dir); }
});
