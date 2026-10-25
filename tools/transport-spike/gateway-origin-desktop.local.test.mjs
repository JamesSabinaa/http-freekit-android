// Explicit local integration: FREEKIT_DESKTOP_ROOT is mandatory, never an optional skip.
// It intentionally is not part of the hosted globs while that desktop revision is unpublished.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import dns from 'node:dns';
import { createDesktopOriginBackend } from './gateway-origin-desktop.mjs';
import { startEnrollmentOriginFixture } from './companion-enrollment-origin.mjs';
import { enrollOrigin, originControl, originStream } from './companion-enrollment-origin-client.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { nextApplication, until } from './companion-stream-peer-client.mjs';
import { bounded } from './companion-stream-peer-io.mjs';
import { encodeStream } from './companion-protocol-codec.mjs';
import { encodeHttpOriginPreface, HttpOriginAcknowledgement } from './companion-http-origin.mjs';
import { captureFactoryPayload } from './capture-factory-descriptor.mjs';

const desktopRoot = process.env.FREEKIT_DESKTOP_ROOT;
const desktopCommit = process.env.FREEKIT_DESKTOP_COMMIT ?? 'fd63f6940226c8e3401a165082dfa9325abaca69';
if (!desktopRoot) throw Error('Explicit FREEKIT_DESKTOP_ROOT is required for the real desktop integration');
const logicalName = captureFactoryPayload.logicalHost;
async function fixture(t, { authorize = () => true, handler } = {}) {
  const observed = { captures: [], destinations: [], requests: 0, connections: 0, body: null }, upstream = new Set(), clients = [];
  const server = http.createServer((request, reply) => {
    observed.requests++;
    if (handler) return handler(request, reply, observed);
    const chunks = []; let count = 0;
    request.on('data', bytes => { count += bytes.length; assert(count <= 65536); chunks.push(bytes); });
    request.once('end', () => {
      observed.body = Buffer.concat(chunks); assert.equal(request.headers.host, logicalName);
      const bytes = Buffer.from(Array.from({ length: 32787 }, (_, i) => (i * 7) % 253));
      reply.writeHead(200, { 'content-length': bytes.length, connection: 'close' }); reply.end(bytes);
    });
  });
  server.on('connection', socket => { observed.connections++; upstream.add(socket); socket.on('error', () => {}); socket.once('close', () => upstream.delete(socket)); });
  // A collision is a failed setup. No existing listener is displaced.
  await new Promise((done, reject) => { server.once('error', reject); server.listen(80, '127.0.0.2', done); });
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-origin-desktop-'));
  fs.chmodSync(directory, 0o700);
  const backend = await createDesktopOriginBackend({ desktopRoot, desktopCommit,
    authorizeDestination: (destination, grant) => {
      observed.destinations.push(destination);
      assert(Object.isFrozen(destination)); assert.equal(Object.keys(grant.material()).length, 6);
      return destination.address === '127.0.0.2' && destination.port === 80 && destination.protocol === 'http:' && authorize(destination) === true;
    }, onCapture: capture => observed.captures.push(capture) });
  const owner = await startEnrollmentOriginFixture({ directory, mode: 'create', trustedProxyFactory: backend.factory });
  const lookup = dns.lookup;
  t.mock.method(dns, 'lookup', function (host, ...args) {
    assert.notEqual(host, logicalName, 'The HTTP logical Host must never become a DNS route');
    return lookup.call(this, host, ...args);
  });
  t.after(async () => {
    let closed;
    try {
      for (const client of clients) { await client.ws.cancel(); await client.pump; }
      closed = await owner.close();
      const desktop = await backend.close();
      assert(closed.storeClosed && closed.listenersClosed && closed.issuerChildrenJoined);
      assert.equal(closed.stream.sessionLeases + closed.stream.streamLeases + closed.stream.chargedBytes + closed.stream.workers + closed.stream.pendingCallbacks + closed.stream.listeners, 0);
      assert.equal(desktop.activeOwners, 0); assert.equal(desktop.admitted, desktop.settled);
    } catch (failure) {
      t.diagnostic(JSON.stringify({ desktop: backend.snapshot(), stream: owner.snapshot().stream })); throw failure;
    } finally {
      const results = await Promise.allSettled([backend.close(), (async () => {
        for (const socket of upstream) socket.destroy(); await new Promise(done => server.close(done));
      })()]);
      assert.equal(upstream.size, 0);
      if (closed?.storeClosed) { assert(directory.startsWith(root + path.sep)); fs.rmSync(directory, { recursive: true, force: true }); }
      assert(results.every(result => result.status === 'fulfilled'), 'Every independent teardown group must join');
    }
  });
  const credential = await enrollOrigin(owner, createCryptoFixture()), control = await originControl(owner, credential); clients.push(control);
  return { owner, backend, credential, control, observed, async stream() { const c = await originStream(owner, credential, control); clients.push(c); return c; } };
}
async function send(connection, bytes) { for (let offset = 0; offset < bytes.length; offset += 4096) await connection.ws.send('binary', bytes.subarray(offset, offset + 4096)); }
async function receive(connection) {
  const chunks = []; let count = 0;
  while (true) {
    const event = await bounded(nextApplication(connection), 5000);
    try {
      if (event.kind === 'text') { assert.equal(JSON.parse(event.copyBytes()).type, 'end_write'); break; }
      assert.equal(event.kind, 'binary'); count += event.copyBytes().length; assert(count <= 131072); chunks.push(event.copyBytes());
    } finally { event.release(); }
  }
  return Buffer.concat(chunks);
}

test('real desktop import requires explicit clean exact source and a synchronous destination policy', async () => {
  for (const extra of [{ desktopCommit: '0'.repeat(40) }, { desktopRoot: '.' }, { desktopCommit: desktopCommit + '\n' }, { authorizeDestination: null }]) {
    await assert.rejects(createDesktopOriginBackend({ desktopRoot, desktopCommit, authorizeDestination: () => true, ...extra }),
      error => error.code === 'desktop_origin_configuration');
  }
});

test('actual mode/capability snapshot is empty before admission and copied before asynchronous desktop startup', async () => {
  const backend = await createDesktopOriginBackend({ desktopRoot, desktopCommit, authorizeDestination: () => true });
  assert.equal(backend.snapshot().proxyMode, null); assert.deepEqual(backend.snapshot().negotiatedCapabilities, []);
  let active = true;
  const context = { proxyMode: 'http-origin-connect', negotiatedCapabilities: ['tcp-http-origin-connect'], grant: { material: () => ({}) }, admissionAllowed: () => active };
  const owner = backend.factory(context);
  try {
    context.proxyMode = 'CANARY'; context.negotiatedCapabilities.splice(0); context.admissionAllowed = () => true;
    await owner.start();
    assert.equal(backend.snapshot().proxyMode, 'http-origin-connect');
    assert.deepEqual(backend.snapshot().negotiatedCapabilities, ['tcp-http-origin-connect']);
    assert(Object.isFrozen(backend.snapshot().negotiatedCapabilities));
    active = false;
    owner.transport.write(encodeHttpOriginPreface(Uint8Array.of(127, 0, 0, 2)), () => {});
    await bounded(owner.closed, 5000); assert.equal(backend.snapshot().activeOwners, 0);
  } finally { await owner.close(); await backend.close(); }
});

test('real enrolled mTLS origin mode routes numeric80, preserves logical HTTP and capture, and completes END_WRITE', { timeout: 20000 }, async t => {
  const f = await fixture(t), flow = await f.stream();
  const body = Buffer.from(Array.from({ length: 16421 }, (_, i) => i % 251));
  const app = Buffer.concat([Buffer.from(`POST /factory-research HTTP/1.1\r\nHost: ${logicalName}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]);
  await send(flow, Buffer.concat([encodeHttpOriginPreface(Uint8Array.of(127, 0, 0, 2)), app]));
  await flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: flow.id }));
  const bytes = await receive(flow), acknowledgement = new HttpOriginAcknowledgement(), consumed = acknowledgement.accept(bytes);
  assert.equal(consumed, 39); assert(acknowledgement.complete);
  const response = bytes.subarray(consumed), headerEnd = response.indexOf('\r\n\r\n'); assert(headerEnd > 0);
  assert.match(response.subarray(0, headerEnd).toString('ascii'), /^HTTP\/1\.1 200 OK\r\n/);
  assert.deepEqual(response.subarray(headerEnd + 4), Buffer.from(Array.from({ length: 32787 }, (_, i) => (i * 7) % 253)));
  assert.deepEqual(f.observed.body, body); assert.equal(f.observed.requests, 1); assert.equal(f.observed.connections, 1);
  assert(f.observed.captures.some(capture => capture.url === `http://${logicalName}/factory-research`));
  assert.equal(f.backend.snapshot().captures, 1); // Updates of the same actual capture are not new requests.
  await flow.ws.send('close', Buffer.from([3, 232]));
  const close = await nextApplication(flow); try { assert.equal(close.kind, 'close'); assert.equal(close.closeCode, 1000); } finally { close.release(); }
  await flow.ws.finish();
  await until(() => f.owner.inspectEnrollment(f.credential.enrollmentId).probe.stream.phase, phase => phase === 'complete');
});

test('real desktop exact destination denial closes without an origin connection or capture', { timeout: 15000 }, async t => {
  const f = await fixture(t, { authorize: () => false }), flow = await f.stream();
  await send(flow, Buffer.concat([encodeHttpOriginPreface(Uint8Array.of(127, 0, 0, 2)), Buffer.from(`GET /denied HTTP/1.1\r\nHost: ${logicalName}\r\n\r\n`)]));
  try { await bounded(flow.closed, 5000); }
  catch (failure) { t.diagnostic(JSON.stringify({ desktop: f.backend.snapshot(), probe: f.owner.inspectEnrollment(f.credential.enrollmentId).probe })); throw failure; }
  assert.equal(f.observed.connections, 0); assert.equal(f.observed.requests, 0); assert.equal(f.observed.captures.length, 0);
  try { await until(() => f.owner.inspectEnrollment(f.credential.enrollmentId).probe.stream.resourcesReleased, Boolean); }
  catch (failure) { t.diagnostic(JSON.stringify({ desktop: f.backend.snapshot(), probe: f.owner.inspectEnrollment(f.credential.enrollmentId).probe })); throw failure; }
});

test('committed registry revocation closes a real desktop/origin request and joins before releasing the stream', { timeout: 15000 }, async t => {
  const f = await fixture(t, { handler(request) { request.resume(); } }), flow = await f.stream();
  await send(flow, Buffer.concat([encodeHttpOriginPreface(Uint8Array.of(127, 0, 0, 2)), Buffer.from(`GET /held HTTP/1.1\r\nHost: ${logicalName}\r\nConnection: close\r\n\r\n`)]));
  // Own the actual client reader as well: consume the acknowledgement instead of
  // leaving TLS readable bytes paused while trying to observe remote closure.
  const reading = receive(flow).then(() => false, () => true);
  await until(() => f.observed.requests, n => n === 1);
  f.owner.revoke(f.credential.enrollmentId);
  try { await bounded(flow.closed, 5000); }
  catch (failure) { t.diagnostic(JSON.stringify({ desktop: f.backend.snapshot(), probe: f.owner.inspectEnrollment(f.credential.enrollmentId).probe })); throw failure; }
  try { await until(() => f.owner.inspectEnrollment(f.credential.enrollmentId).probe.cleanup.complete, Boolean); }
  catch (failure) { t.diagnostic(JSON.stringify({ desktop: f.backend.snapshot(), probe: f.owner.inspectEnrollment(f.credential.enrollmentId).probe })); throw failure; }
  assert.equal(f.backend.snapshot().activeOwners, 0);
  assert.equal(await reading, true);
  assert.equal(f.owner.inspectEnrollment(f.credential.enrollmentId).writesAfterInvalidation, 0);
});
