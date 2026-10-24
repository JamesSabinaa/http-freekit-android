import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import { ServerResponse } from 'node:http';
import tls from 'node:tls';
import net from 'node:net';
import { createHash, randomBytes, sign, X509Certificate } from 'node:crypto';
import { inspect, isDeepStrictEqual } from 'node:util';
import { setTimeout as pause } from 'node:timers/promises';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { startEnrollmentIssuer } from './companion-enrollment-issuer.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enrollmentProofPayload, enrollmentMessage } from './companion-enrollment-codec.mjs';

const root = fs.realpathSync(os.tmpdir());
const fail = (code, work) => assert.throws(work, failure => failure.code === code);
const digest = value => createHash('sha256').update(value).digest('base64url');
const same = (left, right) => assert.equal(isDeepStrictEqual(left, right), true, 'Exact public fixture material continuity');
async function waitFor(condition) { const end = performance.now() + 3000; while (!condition()) { assert(performance.now() < end, 'bounded fixture observation'); await pause(5); } }
async function fixture(t) {
  const directory = fs.mkdtempSync(path.join(root, 'freekit-enrollment-https-')); fs.chmodSync(directory, 0o700);
  let owner = await startEnrollmentHttpsFixture({ directory, mode: 'create' });
  t.after(async () => { await owner.close(); assert(directory.startsWith(root + path.sep)); fs.rmSync(directory, { recursive: true, force: true }); });
  return { directory, get owner() { return owner; }, get metadata() { return owner.metadata().material(); },
    async reopen() { const metadata = owner.metadata().material(); await owner.close(); owner = await startEnrollmentHttpsFixture({ directory, mode: 'open', setupPort: metadata.setupPort, credentialPort: metadata.credentialPort }); return owner; } };
}
function connection(f, role = 'setup', extra = {}) {
  const m = f.metadata; return { host: '127.0.0.1', port: role === 'setup' ? m.setupPort : m.credentialPort,
    servername: m.logicalName, ca: new X509Certificate(Buffer.from(m.gatewayCertificateDer, 'base64url')).toString(), rejectUnauthorized: true, ...extra };
}
async function request(f, route, material, { role = 'setup', credentials, tlsOptions = {} } = {}) {
  const body = material === undefined ? undefined : Buffer.from(JSON.stringify(material)), c = connection(f, role, tlsOptions);
  if (credentials) { c.key = credentials.key.export({ type: 'pkcs8', format: 'pem' }); c.cert = new X509Certificate(Buffer.from(credentials.leaf, 'base64url')).toString(); }
  return new Promise((resolve, reject) => {
    let session, reused;
    const req = https.request({ ...c, hostname: c.host, agent: false, method: body ? 'POST' : 'GET', path: route,
      headers: { host: `${f.metadata.logicalName}:${c.port}`, connection: 'close', ...(body ? { 'content-type': 'application/json', 'content-length': String(body.length) } : {}) } }, reply => {
      const chunks = []; let size = 0; reply.on('data', bytes => { size += bytes.length; if (size > 16384) reply.destroy(); else chunks.push(bytes); });
      reply.on('error', reject); reply.on('end', () => {
        try {
          const bytes = Buffer.concat(chunks); assert.equal(reply.headers['content-type'], 'application/json'); assert.equal(reply.headers['content-length'], String(bytes.length)); assert.equal(reply.headers.connection, 'close'); assert.equal(reply.headers['transfer-encoding'], undefined);
          const names = reply.rawHeaders.filter((_, index) => index % 2 === 0).map(name => name.toLowerCase()); assert.equal(new Set(names).size, names.length);
          resolve({ status: reply.statusCode, material: JSON.parse(bytes), session, reused });
        } catch { reject(Error('Invalid bounded fixture response')); }
      });
    });
    req.on('socket', socket => { socket.on('session', value => { session = Buffer.from(value); }); socket.once('secureConnect', () => { reused = socket.isSessionReused(); session ??= socket.getSession(); }); });
    req.setTimeout(5000, () => req.destroy(Error('Bounded fixture client timeout'))); req.on('error', reject); req.end(body);
  });
}
function pair(f, device, invitation) {
  return { protocolVersion: 1, type: 'pair', desktopId: f.metadata.desktopId, invitationId: invitation.invitationId, invitationSecret: invitation.invitationSecret,
    csrDer: device.csr().toString('base64url'), deviceName: 'HTTPS software research', capabilities: ['tcp-http', 'tcp-https-connect'] };
}
async function challenge(f, registration, purpose = 'status') {
  const reply = await request(f, '/companion/v1/pair/status', { protocolVersion: 1, type: 'pair_challenge', desktopId: f.metadata.desktopId,
    invitationId: registration.invitationId, enrollmentId: registration.enrollmentId, purpose });
  assert.equal(reply.status, 200); assert.equal(reply.material.type, 'pair_challenge'); return reply.material;
}
function proof(f, device, registration, challenge) {
  const context = { desktopId: f.metadata.desktopId, gatewaySpkiSha256: f.metadata.gatewaySpkiSha256, invitationId: registration.invitationId,
    enrollmentId: registration.enrollmentId, deviceSpkiSha256: digest(device.deviceSpkiDer), purpose: challenge.purpose };
  const bytes = enrollmentProofPayload(context, enrollmentMessage('challenge_response', challenge));
  return { protocolVersion: 1, type: challenge.purpose === 'status' ? 'pair_status' : 'pair_cancel', desktopId: context.desktopId,
    invitationId: registration.invitationId, enrollmentId: registration.enrollmentId, challengeId: challenge.challengeId, signature: sign('sha256', bytes, device.device.privateKey).toString('base64url') };
}
async function raw(f, bytes) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(connection(f)); const chunks = []; let size = 0, done = false;
    const finish = () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } };
    socket.setTimeout(5000, () => { socket.destroy(); reject(Error('Bounded raw fixture timeout')); });
    socket.once('secureConnect', () => socket.write(bytes)); socket.on('data', data => { size += data.length; if (size > 32768) socket.destroy(); else chunks.push(data); });
    socket.once('error', () => finish()); socket.once('close', finish);
  });
}
async function emptyTlsResponse(f, material) {
  const body = Buffer.from(JSON.stringify(material)), c = connection(f);
  return new Promise((resolve, reject) => {
    const socket = tls.connect(c); let written = false, ended = false, failed = false;
    const deadline = setTimeout(() => { failed = true; socket.destroy(); reject(Error('Empty TLS response deadline')); }, 5000);
    socket.once('secureConnect', () => socket.write(Buffer.concat([Buffer.from(`POST /companion/v1/pair/status HTTP/1.1\r\nHost: ${f.metadata.logicalName}:${c.port}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]), error => { if (error) { failed = true; socket.destroy(); reject(Error('Request write did not complete')); } else written = true; }));
    socket.on('data', () => { failed = true; socket.destroy(); reject(Error('Suppressed response contained application bytes')); });
    socket.once('error', () => { failed = true; reject(Error('Suppressed response was a TLS error')); });
    socket.once('end', () => { ended = true; socket.end(); });
    socket.once('close', () => { clearTimeout(deadline); if (!failed) { assert(written && ended, 'Actual request callback and clean empty TLS EOF'); resolve(); } });
  });
}
async function resetDuringEnd(f, material, drop) {
  const c = connection(f), raw = net.connect({ host: c.host, port: c.port }), socket = tls.connect({ ...c, socket: raw });
  socket.on('error', () => {}); raw.on('error', () => {});
  const prototype = drop ? tls.TLSSocket.prototype : ServerResponse.prototype, original = prototype.end;
  let intercepted = false, bytes = 0, resolveAttempt;
  const attempted = new Promise(resolve => { resolveAttempt = resolve; });
  const closed = new Promise(resolve => socket.once('close', resolve));
  prototype.end = function (...args) {
    const transport = drop ? this : this.socket;
    if (!intercepted && transport?.localPort === c.port) {
      intercepted = true;
      // Delay only this real end invocation until a real peer RST has closed its
      // transport. No finish callback is fabricated; Node handles end-on-closed.
      transport.once('close', () => { try { original.apply(this, args); } catch {} resolveAttempt(); });
      raw.resetAndDestroy(); return this;
    }
    return original.apply(this, args);
  };
  let timer;
  try {
    socket.on('data', data => { bytes += data.length; });
    await new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', reject); });
    const body = Buffer.from(JSON.stringify(material));
    socket.write(Buffer.concat([Buffer.from(`POST /companion/v1/pair/status HTTP/1.1\r\nHost: ${f.metadata.logicalName}:${c.port}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]));
    await Promise.race([Promise.all([attempted, closed]), new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Actual reset/end observation deadline')), 5000); })]);
    assert(intercepted); assert.equal(bytes, 0);
  } finally { clearTimeout(timer); prototype.end = original; socket.destroy(); raw.destroy(); }
}

test('real pinned HTTPS approval/drop/fresh-proof recovery and same-port reopen preserve exact result and mTLS key', { timeout: 20000 }, async t => {
  const f = await fixture(t), device = createCryptoFixture(), invitation = f.owner.createInvitation().material();
  const registrationWait = f.owner.waitForRegistered(invitation.invitationId, { timeoutMillis: 5000 });
  const first = await request(f, '/companion/v1/pair', pair(f, device, invitation)); assert.equal(first.status, 200);
  same((await registrationWait).material(), first.material); const registration = first.material;
  same((await request(f, '/companion/v1/pair', pair(f, device, invitation))).material, registration);
  const pending = await challenge(f, registration);
  assert.equal((await request(f, '/companion/v1/pair/status', proof(f, device, registration, pending))).material.type, 'pair_pending');
  f.owner.dropNextApprovedStatus(); await f.owner.approve(registration.enrollmentId); await pause(1050);
  const lost = await challenge(f, registration), signed = proof(f, device, registration, lost);
  await emptyTlsResponse(f, signed);
  assert.equal((await request(f, '/companion/v1/pair/status', signed)).status, 403);
  await pause(1050); const approved = (await request(f, '/companion/v1/pair/status', proof(f, device, registration, await challenge(f, registration)))).material;
  assert.equal(approved.type, 'pair_approved'); assert.equal(f.owner.snapshot().droppedApprovedResponses, 1); assert.equal(f.owner.snapshot().approvedResponsesDeliveredAfterDrop, 1);
  const metadata = f.metadata, initialClose = await f.owner.close(); assert(initialClose.storeClosed && initialClose.issuerChildrenJoined && initialClose.listenersClosed);
  await f.reopen(); same(f.metadata, metadata); same(f.owner.readResult(registration.enrollmentId).material(), approved);
  assert.equal((await request(f, '/companion/v1/pair/status', signed)).status, 403);
  const reopened = await request(f, '/companion/v1/pair/status', proof(f, device, registration, await challenge(f, registration))); same(reopened.material, approved);
  const credential = { key: device.device.privateKey, leaf: approved.clientCertificateDer };
  const admitted = await request(f, '/research/enrollment/credential', undefined, { role: 'credential', credentials: credential });
  assert.equal(admitted.status, 200); assert.deepEqual(admitted.material, { type: 'credential_admitted' }); assert.equal(admitted.reused, false);
  assert.equal(f.owner.snapshot().droppedApprovedResponses, 0); assert.equal(f.owner.snapshot().approvedResponsesDelivered, 1);
});
test('mTLS rejects missing and CA-valid unpublished leaves, and exact grant revocation denies later admission', { timeout: 15000 }, async t => {
  const f = await fixture(t), device = createCryptoFixture(), invitation = f.owner.createInvitation().material();
  const registered = (await request(f, '/companion/v1/pair', pair(f, device, invitation))).material;
  await assert.rejects(request(f, '/research/enrollment/credential', undefined, { role: 'credential' }));
  const issuer = await startEnrollmentIssuer({ directory: f.directory, enrollmentAuthorityDer: f.metadata.enrollmentAuthorityDer });
  let orphan;
  try {
    const now = Math.floor(Date.now() / 1000) * 1000;
    orphan = await issuer.issue({ material: () => ({ desktopId: f.metadata.desktopId, invitationId: invitation.invitationId, enrollmentId: registered.enrollmentId,
      deviceId: 'dev_' + randomBytes(32).toString('base64url'), generation: 1, token: randomBytes(32).toString('base64url'), serial: '999',
      deviceSpkiDer: device.deviceSpkiDer.toString('base64url'), deviceSpkiSha256: digest(device.deviceSpkiDer), csrDer: device.csr().toString('base64url'), capabilities: ['tcp-http'],
      notBefore: new Date(now).toISOString().replace('.000Z', 'Z'), notAfter: new Date(now + 600000).toISOString().replace('.000Z', 'Z'), subject: 'CN=HTTP FreeKit device', profile: 'p256-client-auth-v1' }) });
  } finally { await issuer.close(); }
  const unknown = { key: device.device.privateKey, leaf: orphan.material().clientCertificateDer };
  assert.equal((await request(f, '/research/enrollment/credential', undefined, { role: 'credential', credentials: unknown })).status, 403);
  const approved = (await f.owner.approve(registered.enrollmentId)).material(), credentials = { key: device.device.privateKey, leaf: approved.clientCertificateDer };
  assert.equal((await request(f, '/research/enrollment/credential', undefined, { role: 'credential', credentials })).status, 200);
  assert.equal((await request(f, '/research/enrollment/credential', undefined, { role: 'credential', credentials: unknown })).status, 403);
  f.owner.revoke(registered.enrollmentId); assert.equal((await request(f, '/research/enrollment/credential', undefined, { role: 'credential', credentials })).status, 403);
});
test('TLS1.2 and TLS1.3 offered sessions are not resumed and every admitted probe presents the exact current leaf', { timeout: 15000 }, async t => {
  const f = await fixture(t), device = createCryptoFixture(), invitation = f.owner.createInvitation().material();
  const registered = (await request(f, '/companion/v1/pair', pair(f, device, invitation))).material, result = (await f.owner.approve(registered.enrollmentId)).material();
  const credentials = { key: device.device.privateKey, leaf: result.clientCertificateDer };
  for (const version of ['TLSv1.2', 'TLSv1.3']) {
    const tlsOptions = { minVersion: version, maxVersion: version };
    const first = await request(f, '/research/enrollment/credential', undefined, { role: 'credential', credentials, tlsOptions });
    assert.equal(first.status, 200); assert(first.session instanceof Uint8Array && first.session.length > 0);
    const second = await request(f, '/research/enrollment/credential', undefined, { role: 'credential', credentials, tlsOptions: { ...tlsOptions, session: first.session } });
    assert.equal(second.status, 200); assert.equal(second.reused, false);
  }
});
test('malformed or duplicate HTTP framing and browser headers never dispatch a first request', { timeout: 20000 }, async t => {
  const f = await fixture(t), host = `${f.metadata.logicalName}:${f.metadata.setupPort}`;
  for (const head of [
    `POST /companion/v1/pair HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 2`,
    `POST /companion/v1/pair?x=1 HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: 2`,
    `POST /companion/v1/pair HTTP/1.1\r\nHost: ${host}\r\nOrigin: null\r\nContent-Type: application/json\r\nContent-Length: 2`,
    `POST /companion/v1/pair HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked`,
    `POST /companion/v1/pair HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue`,
    `GET /companion/v1/pair HTTP/1.1\r\nHost: ${host}`,
    `POST https://${host}/companion/v1/pair HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: 2`,
    `POST /companion/v1/pair HTTP/1.1\r\nHost: ${f.metadata.logicalName}\r\nContent-Type: application/json\r\nContent-Length: 2`,
  ]) { const response = await raw(f, Buffer.from(head + '\r\nConnection: close\r\n\r\n{}')); assert(!response.toString('ascii').includes('200 OK')); assert.equal(f.owner.snapshot().dispatches, 0); }
  const oversized = await raw(f, Buffer.from(`POST /companion/v1/pair HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: 16385\r\nConnection: close\r\n\r\n`));
  assert(oversized.toString('ascii').includes('413')); assert.equal(f.owner.snapshot().dispatches, 0);
});
test('four body-reader admission and close join incomplete requests and bounded registration waiters', { timeout: 15000 }, async t => {
  const f = await fixture(t), sockets = [], host = `${f.metadata.logicalName}:${f.metadata.setupPort}`;
  t.after(() => sockets.forEach(socket => socket.destroy()));
  const invitation = f.owner.createInvitation().material(), waiting = f.owner.waitForRegistered(invitation.invitationId, { timeoutMillis: 10000 });
  const rejected = assert.rejects(waiting, failure => failure.code === 'pairing_unavailable');
  for (let index = 0; index < 4; index++) {
    const socket = tls.connect(connection(f)); socket.on('error', () => {}); sockets.push(socket);
    await new Promise((resolve, reject) => { socket.once('error', reject); socket.once('secureConnect', resolve); });
    socket.write(`POST /companion/v1/pair HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n`);
  }
  await waitFor(() => f.owner.snapshot().bodyReaders === 4);
  const fifth = await request(f, '/companion/v1/pair', { protocolVersion: 1, type: 'pair' }); assert.equal(fifth.status, 429);
  const closed = await f.owner.close(); await rejected;
  for (const name of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers', 'bodyReaders', 'registrationWaiters']) assert.equal(closed[name], 0);
  for (const name of ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined']) assert.equal(closed[name], true);
  assert.equal(closed.dispatches, 0);
});
test('setup errors obey semantic status mapping and duplicate fields never reserve a key', { timeout: 10000 }, async t => {
  const f = await fixture(t), device = createCryptoFixture(), invitation = f.owner.createInvitation().material(), material = pair(f, device, invitation);
  const duplicate = JSON.stringify(material).replace('"type":"pair"', '"type":"pair","type":"pair"');
  const rejected = await raw(f, Buffer.from(`POST /companion/v1/pair HTTP/1.1\r\nHost: ${f.metadata.logicalName}:${f.metadata.setupPort}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(duplicate)}\r\nConnection: close\r\n\r\n${duplicate}`));
  assert(rejected.toString('ascii').startsWith('HTTP/1.1 400'));
  assert.equal((await request(f, '/companion/v1/pair', { ...material, invitationSecret: randomBytes(32).toString('base64url') })).status, 403);
  const unsupported = await request(f, '/companion/v1/pair', { ...material, capabilities: ['unoffered'] }); assert.equal(unsupported.status, 400); assert.equal(unsupported.material.code, 'unsupported_capability');
  assert.equal((await request(f, '/companion/v1/pair', { protocolVersion: 2 })).status, 400);
  const accepted = await request(f, '/companion/v1/pair', material); assert.equal(accepted.status, 200);
  const other = createCryptoFixture(); assert.equal((await request(f, '/companion/v1/pair', { ...material, csrDer: other.csr().toString('base64url') })).status, 409);
});
test('missing/corrupt identities and wrong restart ports fail closed without regenerating software keys', { timeout: 10000 }, async t => {
  const f = await fixture(t), metadata = f.metadata; await f.owner.close();
  const keyFile = path.join(f.directory, 'gateway-key.pem'), before = digest(fs.readFileSync(keyFile));
  await assert.rejects(startEnrollmentHttpsFixture({ directory: f.directory, mode: 'create' }), failure => failure.code === 'pairing_unavailable');
  await assert.rejects(startEnrollmentHttpsFixture({ directory: f.directory, mode: 'open', setupPort: metadata.credentialPort, credentialPort: metadata.setupPort }), failure => failure.code === 'pairing_unavailable');
  fs.unlinkSync(path.join(f.directory, 'enrollment-authority.pem'));
  await assert.rejects(startEnrollmentHttpsFixture({ directory: f.directory, mode: 'open', setupPort: metadata.setupPort, credentialPort: metadata.credentialPort }), failure => failure.code === 'pairing_unavailable');
  assert.equal(digest(fs.readFileSync(keyFile)), before);
});
test('default fixture diagnostics disclose no paths, invitation secrets or certificate bytes', async t => {
  const f = await fixture(t), invitation = f.owner.createInvitation().material();
  for (const text of [String(f.owner), inspect(f.owner), JSON.stringify(f.owner), inspect(f.owner.metadata())]) {
    for (const value of [f.directory, invitation.invitationSecret, f.metadata.gatewayCertificateDer, f.metadata.enrollmentAuthorityDer]) assert(!text.includes(value));
  }
});
test('fixture close aborts an admitted signer before releasing Store and permits same-port intent recovery', { timeout: 15000 }, async t => {
  const f = await fixture(t), device = createCryptoFixture(), invitation = f.owner.createInvitation().material();
  const registered = (await request(f, '/companion/v1/pair', pair(f, device, invitation))).material;
  const approval = f.owner.approve(registered.enrollmentId), aborted = assert.rejects(approval, error => error.code === 'pairing_unavailable' && error.joined === true);
  assert.equal(f.owner.snapshot().issuerJobs, 1); assert.equal(f.owner.snapshot().issuer.activeJobs, 1);
  const closed = await f.owner.close(); await aborted; assert(closed.storeClosed && closed.issuerChildrenJoined); assert.equal(closed.issuerJobs, 0);
  await f.reopen(); assert.equal(f.owner.readResult(registered.enrollmentId).material().type, 'pair_pending');
  const approved = await f.owner.approve(registered.enrollmentId); assert.equal(approved.material().type, 'pair_approved');
});
test('global socket admission remains at sixteen across both actual listeners and closes every owner', { timeout: 10000 }, async t => {
  const f = await fixture(t), sockets = [];
  t.after(() => sockets.forEach(socket => socket.destroy()));
  for (let index = 0; index < 16; index++) {
    const socket = net.connect({ host: '127.0.0.1', port: index % 2 ? f.metadata.setupPort : f.metadata.credentialPort }); socket.on('error', () => {}); sockets.push(socket);
    await new Promise(resolve => socket.once('connect', resolve));
  }
  await waitFor(() => f.owner.snapshot().acceptedSockets === 16);
  const extra = net.connect({ host: '127.0.0.1', port: f.metadata.setupPort }); extra.on('error', () => {}); sockets.push(extra);
  await new Promise(resolve => extra.once('close', resolve)); assert.equal(f.owner.snapshot().acceptedSockets, 16);
  const closed = await f.owner.close(); assert.equal(closed.activeSockets, 0); assert.equal(closed.pendingTimers, 0); assert(closed.storeClosed);
});
test('real peer RST before response/drop completion cancels owners without claiming callback delivery or an approved drop', { timeout: 15000 }, async t => {
  const f = await fixture(t), device = createCryptoFixture(), invitation = f.owner.createInvitation().material();
  const registration = (await request(f, '/companion/v1/pair', pair(f, device, invitation))).material; await f.owner.approve(registration.enrollmentId);
  for (const drop of [false, true]) {
    if (drop) { await pause(1050); f.owner.dropNextApprovedStatus(); }
    const signed = proof(f, device, registration, await challenge(f, registration));
    await resetDuringEnd(f, signed, drop);
    await waitFor(() => f.owner.snapshot().pendingWriteCallbacks === 0 && f.owner.snapshot().requestTasks === 0);
    assert.equal((await request(f, '/companion/v1/pair/status', signed)).status, 403);
    assert.equal(f.owner.snapshot().droppedApprovedResponses, 0); assert.equal(f.owner.snapshot().approvedResponsesDelivered, 0);
  }
  // Providers may also deliver a real error callback during close. At least one
  // owner must exercise the actual-close path; both paths remain failed writes.
  assert(f.owner.snapshot().writeOwnersCancelledByClose >= 1);
  const closed = await f.owner.close(); assert.equal(closed.pendingCallbacks, 0); assert.equal(closed.workers, 0); assert.equal(closed.pendingTimers, 0); assert(closed.storeClosed);
});
