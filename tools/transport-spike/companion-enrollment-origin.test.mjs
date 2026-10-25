import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { Duplex } from 'node:stream';
import { inspect } from 'node:util';
import { startEnrollmentOriginFixture } from './companion-enrollment-origin.mjs';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { createCompanionStreamServer } from './companion-stream-peer.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enrollOriginCsr, enrollOrigin, originControl, originStream } from './companion-enrollment-origin-client.mjs';
import { upgradeEnrolled } from './companion-enrollment-stream-client.mjs';
import { nextApplication, until } from './companion-stream-peer-client.mjs';
import { observeClose, bounded, safeError } from './companion-stream-peer-io.mjs';
import { encodeStream } from './companion-protocol-codec.mjs';
import { HTTP_ORIGIN_CAPABILITY, HTTP_ORIGIN_PROXY_MODE } from './companion-http-origin.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
async function fixture(t, factory) {
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-origin-'));
  fs.chmodSync(directory, 0o700);
  const owner = await startEnrollmentOriginFixture({ directory, mode: 'create', trustedProxyFactory: factory }), clients = [];
  t.after(async () => {
    for (const c of clients) { await c.ws.cancel(); await c.pump; }
    const closed = await owner.close();
    assert(closed.storeClosed && closed.listenersClosed && closed.issuerChildrenJoined);
    assert.equal(closed.activeSockets + closed.pendingCallbacks + closed.pendingTimers + closed.workers, 0);
    assert.deepEqual(closed.stream, { sessionLeases: 0, streamLeases: 0, chargedBytes: 0, ownerRecords: 0, authenticatedSockets: 0,
      proxySockets: 0, listeners: 0, workers: 0, timers: 0, pendingCallbacks: 0, unavailable: false });
    assert(directory.startsWith(root + path.sep)); fs.rmSync(directory, { recursive: true, force: true });
  });
  return { owner, track(c) { clients.push(c); return c; } };
}
function heldOwner(context, { startHeld = false, joinHeld = false } = {}) {
  const start = deferred(), join = deferred();
  const transport = new Duplex({ allowHalfOpen: true, read() {}, write(_bytes, _encoding, done) { done(); } });
  transport.on('error', () => {});
  const actualClosed = observeClose(transport);
  const state = { sealed: false, started: false, settled: false, release() { start.resolve(); join.resolve(); } };
  const closed = Promise.all([actualClosed, joinHeld ? join.promise : Promise.resolve()]).then(() => { state.settled = true; });
  return { state, owner: Object.freeze({ transport, closed,
    async start() { state.started = true; if (startHeld) await start.promise; if (!context.admissionAllowed()) throw safeError('admission_closed'); },
    close() { state.sealed = true; transport.destroy(); start.resolve(); return closed; } }) };
}

test('trusted composition rejects partial/unscoped capability configuration before any listener', async () => {
  const base = { tls: {}, authorize: () => true }, authority = { authorizeCertificate() {}, gatewayExpiresAt: new Date(Date.now() + 60000).toISOString() };
  for (const extra of [ { trustedProxyFactory() {} }, { supportedCapabilities: [HTTP_ORIGIN_CAPABILITY] },
    { trustedProxyFactory() {}, supportedCapabilities: [HTTP_ORIGIN_CAPABILITY] },
    { trustedProxyFactory() {}, credentialAuthority: authority, supportedCapabilities: ['other-feature'] },
    { trustedProxyFactory() {}, credentialAuthority: authority, supportedCapabilities: [HTTP_ORIGIN_CAPABILITY, HTTP_ORIGIN_CAPABILITY] } ]) {
    await assert.rejects(createCompanionStreamServer({ ...base, ...extra }), error => error.code === 'stream_fixture_configuration');
  }
  const poison = []; Object.defineProperty(poison, 0, { get() { throw Error('SECRET'); } }); poison.length = 1;
  await assert.rejects(startEnrollmentHttpsFixture({ supportedCapabilities: poison }), error => !inspect(error).includes('SECRET') && error.joined === true);
});

test('origin enrollment advertises the actual intersection and rejects scenario/legacy paths before factory admission', { timeout: 15000 }, async t => {
  let calls = 0;
  const f = await fixture(t, context => { calls++; return heldOwner(context).owner; });
  const credential = await enrollOrigin(f.owner, createCryptoFixture());
  assert.deepEqual(credential.approved.capabilities, [HTTP_ORIGIN_CAPABILITY]);
  assert.equal((await upgradeEnrolled(f.owner, credential, '/companion/v1/control')).status, 400);
  const control = f.track(await originControl(f.owner, credential));
  assert.deepEqual(control.ready.capabilities, [HTTP_ORIGIN_CAPABILITY]);
  assert.equal(f.owner.snapshot().stream.listeners, 1); // No fixed-fixture proxy listener.
  const legacy = f.track(await upgradeEnrolled(f.owner, credential, '/companion/v1/streams', { token: control.token }));
  await legacy.ws.send('text', encodeStream({ protocolVersion: 1, type: 'open', streamId: 'legacy-not-implemented' }));
  await bounded(legacy.closed, 5000);
  assert.equal(calls, 0);
  const state = await until(() => f.owner.inspectEnrollment(credential.enrollmentId), s => s.probe.stream.resourcesReleased);
  assert.equal(state.probe.stream.cause, 'unsupported_capability');
  assert.equal(state.probe.control.historyCount, 0);
});

test('enrollment snapshots configured capabilities before asynchronous startup and publishes the requested intersection', { timeout: 10000 }, async t => {
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-origin-caps-'));
  fs.chmodSync(directory, 0o700);
  const capabilities = [HTTP_ORIGIN_CAPABILITY];
  const starting = startEnrollmentHttpsFixture({ directory, mode: 'create', supportedCapabilities: capabilities });
  capabilities[0] = 'tcp-http';
  const owner = await starting;
  t.after(async () => { await owner.close(); assert(directory.startsWith(root + path.sep)); fs.rmSync(directory, { recursive: true, force: true }); });
  const approved = (await enrollOriginCsr(owner, createCryptoFixture().csr())).material();
  assert.deepEqual(approved.capabilities, [HTTP_ORIGIN_CAPABILITY]);
});

test('cancel during injected startup seals immediately and retains the model lease until actual owner joins', { timeout: 15000 }, async t => {
  let admitted;
  t.after(() => admitted?.state.release());
  const f = await fixture(t, context => { admitted = { context, ...heldOwner(context, { startHeld: true, joinHeld: true }) }; return admitted.owner; });
  const credential = await enrollOrigin(f.owner, createCryptoFixture()), control = f.track(await originControl(f.owner, credential));
  const flow = f.track(await upgradeEnrolled(f.owner, credential, '/companion/v1/streams', { token: control.token }));
  await flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'open', streamId: 'pending-start', proxyMode: HTTP_ORIGIN_PROXY_MODE }));
  await until(() => admitted?.state.started, Boolean);
  assert(Object.isFrozen(admitted.context) && Object.isFrozen(admitted.context.negotiatedCapabilities));
  assert.deepEqual(admitted.context.negotiatedCapabilities, [HTTP_ORIGIN_CAPABILITY]);
  const grant = admitted.context.grant.material();
  assert.equal(Object.keys(grant).length, 6); grant.deviceId = 'changed';
  assert.notEqual(admitted.context.grant.material().deviceId, 'changed');
  assert(!inspect(admitted.context.grant).includes(credential.enrollmentId));
  await flow.ws.cancel();
  await until(() => admitted.state.sealed, Boolean);
  assert.equal(admitted.context.admissionAllowed(), false);
  assert.equal(admitted.state.settled, false);
  assert.equal(f.owner.inspectEnrollment(credential.enrollmentId).probe.stream.streamLease, true);
  admitted.state.release();
  await until(() => f.owner.inspectEnrollment(credential.enrollmentId).probe.stream.resourcesReleased, Boolean);
  assert.equal(admitted.state.settled, true);
});

test('injected start rejection still closes and joins the retained owner before releasing its lease', { timeout: 15000 }, async t => {
  let admitted;
  const f = await fixture(t, context => {
    admitted = heldOwner(context);
    return Object.freeze({ ...admitted.owner, async start() { throw safeError('backend_start_failed'); } });
  });
  const credential = await enrollOrigin(f.owner, createCryptoFixture()), control = f.track(await originControl(f.owner, credential));
  const flow = f.track(await upgradeEnrolled(f.owner, credential, '/companion/v1/streams', { token: control.token }));
  await flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'open', streamId: 'failed-start', proxyMode: HTTP_ORIGIN_PROXY_MODE }));
  await bounded(flow.closed, 5000);
  await until(() => f.owner.inspectEnrollment(credential.enrollmentId).probe.stream.resourcesReleased, Boolean);
  assert(admitted.state.sealed && admitted.state.settled);
  assert.equal(f.owner.inspectEnrollment(credential.enrollmentId).probe.pool.streamLeases, 0);
});

test('registry revocation interrupts the actual injected owner and fresh exact credential admission is denied', { timeout: 15000 }, async t => {
  let admitted;
  const f = await fixture(t, context => { admitted = { context, ...heldOwner(context) }; return admitted.owner; });
  const credential = await enrollOrigin(f.owner, createCryptoFixture()), control = f.track(await originControl(f.owner, credential));
  f.track(await originStream(f.owner, credential, control));
  assert.equal(admitted.context.admissionAllowed(), true);
  f.owner.revoke(credential.enrollmentId);
  await until(() => f.owner.inspectEnrollment(credential.enrollmentId).probe.cleanup.complete, Boolean);
  assert.equal(admitted.context.admissionAllowed(), false);
  assert(admitted.state.sealed && admitted.state.settled);
  assert.equal((await upgradeEnrolled(f.owner, credential, '/companion/v1/control', { scenario: null })).status, 403);
});

test('injected real TCP byte transport preserves request/reply and both END_WRITE boundaries without fixed-fixture bytes', { timeout: 15000 }, async t => {
  const request = Buffer.from(Array.from({ length: 9001 }, (_, i) => (i * 13 + 7) & 255));
  const response = Buffer.from(Array.from({ length: 5003 }, (_, i) => (i * 23 + 11) & 255));
  let upstreamRead = Buffer.alloc(0), upstreamEof = false;
  const upstreamSockets = new Set();
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    upstreamSockets.add(socket); socket.once('close', () => upstreamSockets.delete(socket)); socket.on('error', () => {});
    const chunks = []; let count = 0;
    socket.on('data', bytes => { count += bytes.length; assert(count <= request.length); chunks.push(bytes); });
    socket.on('end', () => { upstreamEof = true; upstreamRead = Buffer.concat(chunks); socket.end(response); });
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  t.after(async () => { for (const socket of upstreamSockets) socket.destroy(); await new Promise(done => server.close(done)); });
  const f = await fixture(t, context => {
    const transport = new net.Socket({ allowHalfOpen: true }), closed = observeClose(transport); transport.on('error', () => {});
    return Object.freeze({ transport, closed,
      start() { assert.equal(context.proxyMode, HTTP_ORIGIN_PROXY_MODE); assert.equal(context.admissionAllowed(), true);
        return new Promise((done, reject) => { transport.once('error', reject); transport.connect(server.address().port, '127.0.0.1', done); }); },
      close() { transport.destroy(); return closed; } });
  });
  const credential = await enrollOrigin(f.owner, createCryptoFixture()), control = f.track(await originControl(f.owner, credential));
  const flow = f.track(await originStream(f.owner, credential, control));
  for (let offset = 0; offset < request.length; offset += 4096) await flow.ws.send('binary', request.subarray(offset, offset + 4096));
  await flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: flow.id }));
  const chunks = []; let count = 0;
  while (true) {
    const event = await bounded(nextApplication(flow), 5000);
    try {
      if (event.kind === 'text') { assert.equal(JSON.parse(event.copyBytes()).type, 'end_write'); break; }
      assert.equal(event.kind, 'binary'); count += event.copyBytes().length; assert(count <= response.length); chunks.push(event.copyBytes());
    } finally { event.release(); }
  }
  assert(upstreamEof); assert.deepEqual(upstreamRead, request); assert.deepEqual(Buffer.concat(chunks), response);
  await flow.ws.send('close', Buffer.from([3, 232]));
  const close = await nextApplication(flow); try { assert.equal(close.kind, 'close'); assert.equal(close.closeCode, 1000); } finally { close.release(); }
  await flow.ws.finish();
  const state = await until(() => f.owner.inspectEnrollment(credential.enrollmentId), s => s.probe.stream.phase === 'complete');
  assert.equal(state.probe.fixture.uploadBytesRead, 0); assert.equal(state.probe.fixture.responseBytesWritten, 0);
  assert.equal(state.probe.control.chargedBytes, 0);
});
