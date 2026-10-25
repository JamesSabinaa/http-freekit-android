// Explicit pinned unpublished-desktop checks. This file is never an optional CI skip.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Duplex } from 'node:stream';
import tls from 'node:tls';
import dns from 'node:dns';
import { createHash, X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { startOriginGatewayFixture, c3Upgrade } from './gateway-origin-fixture.mjs';
import { C3_CAPABILITIES, C3_DESKTOP_COMMIT, C3_LOGICAL_HOST } from './gateway-origin-desktop.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enrollOrigin, originControl, originStream } from './companion-enrollment-origin-client.mjs';
import { nextApplication, until } from './companion-stream-peer-client.mjs';
import { encodeStream } from './companion-protocol-codec.mjs';
import { encodeHttpOriginPreface, HttpOriginAcknowledgement } from './companion-http-origin.mjs';
import { captureFactoryPayload as payload } from './capture-factory-descriptor.mjs';
import { bounded, exact, headers, observeClose, write, endWrite, writerState, safeError } from './companion-stream-peer-io.mjs';
import { ResearchWebSocket } from './research-websocket.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';

const desktopRoot = process.env.FREEKIT_DESKTOP_ROOT, desktopCommit = process.env.FREEKIT_DESKTOP_COMMIT;
assert(desktopRoot && desktopCommit && desktopCommit === C3_DESKTOP_COMMIT, 'Explicit reviewed C3 desktop source required');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const binary = () => Buffer.from(Array.from({ length: c3Upgrade.binaryBytes }, (_, i) => (i * 29 + 3) & 255));
function joined(snapshot) {
  assert(snapshot.admissionClosed && snapshot.listenerClosed && snapshot.privateDirectoryRemoved);
  assert.equal(snapshot.activeSockets + snapshot.pendingCallbacks + snapshot.pendingTimers + snapshot.workers, 0);
  assert.equal(snapshot.backend.activeOwners, 0); assert.equal(snapshot.backend.admitted, snapshot.backend.settled);
  assert(snapshot.enrollment.storeClosed && snapshot.enrollment.listenersClosed && snapshot.enrollment.issuerChildrenJoined);
  assert.equal(snapshot.enrollment.stream.sessionLeases + snapshot.enrollment.stream.streamLeases + snapshot.enrollment.stream.chargedBytes +
    snapshot.enrollment.stream.workers + snapshot.enrollment.stream.pendingCallbacks + snapshot.enrollment.stream.timers, 0);
}
async function fixture(t, profile, family) {
  const owner = await startOriginGatewayFixture({ desktopRoot, desktopCommit, profile, family });
  const clients = []; let control;
  t.after(async () => {
    const results = await Promise.allSettled(clients.map(c => c.close()));
    await control?.ws.cancel(); await control?.pump;
    joined(await owner.close()); assert(results.every(result => result.status === 'fulfilled'));
  });
  const ca = owner.interceptionCaCertificateDer(), metadata = owner.metadata().material();
  assert.equal(createHash('sha256').update(ca).digest('base64url'), metadata.interceptionCaCertificateSha256);
  assert.notEqual(ca.toString('base64url'), metadata.gatewayCertificateDer);
  assert.notEqual(ca.toString('base64url'), metadata.enrollmentAuthorityDer);
  const credential = await enrollOrigin(owner, createCryptoFixture(), C3_CAPABILITIES);
  assert.deepEqual(credential.approved.capabilities, C3_CAPABILITIES);
  assert.equal(credential.approved.interceptionCaCertificateSha256, metadata.interceptionCaCertificateSha256);
  control = await originControl(owner, credential, C3_CAPABILITIES);
  assert.deepEqual(control.ready.capabilities, C3_CAPABILITIES);
  const lookup = dns.lookup;
  t.mock.method(dns, 'lookup', (hostname, ...args) => { assert.notEqual(hostname, C3_LOGICAL_HOST, 'Logical identity must not become the physical route'); return lookup.call(dns, hostname, ...args); });
  return { owner, ca, async application(port) {
    const flow = await originStream(owner, credential, control, 'c3-flow', port === 80 ? 'http-origin-connect' : null);
    const address = family === 'ipv6' ? '0:0:0:0:0:0:0:1' : '127.0.0.2';
    const authority = family === 'ipv6' ? `[${address}]:443` : `${address}:443`;
    const preface = port === 80 ? encodeHttpOriginPreface(family === 'ipv6' ? Uint8Array.from([...Array(15).fill(0), 1]) : Uint8Array.of(127, 0, 0, 2)) :
      Buffer.from(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    await flow.ws.send('binary', preface);
    const ack = new HttpOriginAcknowledgement();
    while (!ack.complete) {
      const event = await bounded(nextApplication(flow), 5000);
      try { assert.equal(event.kind, 'binary'); const bytes = event.copyBytes(); assert.equal(ack.accept(bytes), bytes.length); }
      finally { event.release(); }
    }
    const client = applicationBytes(flow); clients.push(client); return client;
  } };
}

// One bounded test bridge carries actual authenticated binary/END_WRITE traffic;
// it implements no proxy, TLS policy, frame codec or production adapter.
function applicationBytes(flow) {
  let wakeRead, endTask, clientEnd = false, gatewayEnd = false, normalClose = false, failed = false;
  let phase = 'waiting', failureCode = null, receivedType = null, streamCode = null;
  const transport = new Duplex({ allowHalfOpen: true, readableHighWaterMark: 4096, writableHighWaterMark: 4096,
    read() { wakeRead?.(); wakeRead = null; },
    write(bytes, _encoding, done) {
      (async () => { for (let offset = 0; offset < bytes.length; offset += 4096) await flow.ws.send('binary', bytes.subarray(offset, offset + 4096)); })().then(() => done(), () => done(safeError('test_bridge_failed')));
    },
    final(done) {
      endTask = flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: flow.id })).then(() => { clientEnd = true; });
      endTask.then(() => done(), () => done(safeError('test_bridge_failed')));
    },
    destroy(error, done) { wakeRead?.(); wakeRead = null; done(error); },
  });
  transport.on('error', () => {});
  const pump = (async () => {
    while (true) {
      phase = 'outer_read';
      const event = await nextApplication(flow); let close = false;
      try {
        if (event.kind === 'binary') {
          phase = 'gateway_binary';
          if (gatewayEnd || transport.destroyed) throw safeError('test_bridge_failed');
          const reading = new Promise(resolve => { wakeRead = resolve; });
          if (!transport.push(event.copyBytes())) await reading; else wakeRead = null;
        } else if (event.kind === 'text') {
          phase = 'gateway_text';
          const message = JSON.parse(event.copyBytes());
          receivedType = ['end_write', 'error'].includes(message.type) ? message.type : 'other';
          streamCode = ['network_unreachable', 'session_expired', 'device_revoked', 'proxy_unavailable', 'invalid_message'].includes(message.code) ? message.code : null;
          assert.equal(message.type, 'end_write'); assert.equal(gatewayEnd, false);
          gatewayEnd = true; transport.push(null);
        } else if (event.kind === 'close') {
          phase = 'gateway_close';
          if (!clientEnd && endTask) await endTask;
          assert(clientEnd && gatewayEnd); assert.equal(event.closeCode, 1000);
          phase = 'client_close_reply'; await flow.ws.send('close', Buffer.from([3, 232])); normalClose = true; close = true;
        } else throw safeError('test_bridge_failed');
      } finally { event.release(); }
      if (close) { phase = 'outer_finish'; await flow.ws.finish(); phase = 'complete'; return; }
    }
  })().catch(error => { failed = true; failureCode = ['ERR_ASSERTION', 'connection_closed', 'network_error', 'invalid_close_state', 'cancelled'].includes(error?.code) ? error.code : 'bridge_failed'; transport.destroy(safeError('test_bridge_failed')); });
  const snapshot = () => ({ phase, failureCode, receivedType, streamCode, clientEnd, gatewayEnd, normalClose, failed, transportDestroyed: transport.destroyed, outer: flow.ws.snapshot() });
  return { transport, snapshot, async finish() { if (!transport.writableEnded) await endWrite(transport); await bounded(pump, 5000); assert(normalClose && !failed, JSON.stringify(snapshot())); },
    async close() { transport.destroy(); await flow.ws.cancel(); await pump; } };
}
async function innerTls(client, ca) {
  const socket = tls.connect({ socket: client.transport, servername: C3_LOGICAL_HOST, ca: new X509Certificate(ca).toString(),
    rejectUnauthorized: true, ALPNProtocols: ['http/1.1'], minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', allowHalfOpen: true });
  socket.on('error', () => {});
  await bounded(new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', () => reject(safeError('inner_tls_failed'))); }), 5000);
  assert(socket.authorized); assert.equal(socket.alpnProtocol, 'http/1.1'); return socket;
}
async function bytesThroughEof(socket) {
  const chunks = []; let count = 0;
  while (true) {
    const bytes = socket.read(Math.min(4096, socket.readableLength || 4096));
    if (bytes !== null) { count += bytes.length; assert(count <= 131072); chunks.push(bytes); continue; }
    if (socket.readableEnded) return Buffer.concat(chunks);
    if (socket.destroyed) throw safeError('application_eof_failed');
    await bounded(new Promise((resolve, reject) => {
      const clean = () => { socket.removeListener('readable', ready); socket.removeListener('end', ready); socket.removeListener('error', bad); socket.removeListener('close', ready); };
      const ready = () => { clean(); resolve(); }, bad = () => { clean(); reject(safeError('application_eof_failed')); };
      socket.once('readable', ready); socket.once('end', ready); socket.once('error', bad); socket.once('close', ready);
    }), 5000);
  }
}

test('actual enrolled HTTP80 keeps both capabilities and gates the full response tail on applied client END_WRITE', { timeout: 45000 }, async t => {
  const f = await fixture(t, 'http-h1', 'ipv4'), client = await f.application(80), socket = client.transport;
  const body = Buffer.from(Array.from({ length: payload.requestBodyBytes }, (_, i) => i % 251));
  const request = Buffer.concat([Buffer.from(`POST ${payload.path} HTTP/1.1\r\nHost: ${C3_LOGICAL_HOST}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]);
  const state = writerState();
  for (let offset = 0; offset < request.length; offset += 4096) await write(socket, request.subarray(offset, offset + 4096), state);
  const header = (await bounded(headers(socket), 5000)).toString('ascii');
  assert.match(header, /^HTTP\/1\.1 200 OK\r\n/);
  assert.equal([...header.matchAll(/^content-length:[ \t]*([0-9]+)\r$/gmi)].length, 1);
  assert.match(header, new RegExp(`^content-length: ${payload.responseBodyBytes}\\r$`, 'mi'));
  assert.doesNotMatch(header, /^transfer-encoding:/mi);
  const prefix = await bounded(exact(socket, 4096), 5000);
  const held = await until(() => f.owner.snapshot(), value => value.origin.responsePrefixWritten);
  assert.equal(held.origin.responseBodyBytesWritten, 4096); assert.equal(held.origin.tailReleased, false);
  assert.equal(f.owner.inspect().probe.stream.client.eofEmitted, false); assert.equal(held.backend.clientEndWrites, 0);
  const releasing = f.owner.releaseTail();
  await new Promise(done => setTimeout(done, 275));
  assert.equal(f.owner.snapshot().origin.responseBodyBytesWritten, 4096); assert.equal(f.owner.snapshot().origin.tailReleased, false);
  await endWrite(socket, state);
  const tail = await bytesThroughEof(socket), response = Buffer.concat([prefix, tail]);
  assert.equal(response.length, payload.responseBodyBytes); assert.equal(digest(response), payload.responseBodySha256);
  await releasing; await client.finish();
  const done = await until(() => f.owner.snapshot(), value => value.gatewayStreamComplete);
  assert.equal(done.profile, 'http-h1'); assert.equal(done.family, 'ipv4');
  assert(done.origin.requestVerified && done.origin.captureMatched && done.origin.originalDestinationMatched && done.origin.responseEof && !done.origin.failed);
  assert(done.origin.tailReleaseRequested && done.origin.tailReleased && done.origin.clientEndWriteApplied);
  assert.equal(done.origin.requestBodyBytes, payload.requestBodyBytes); assert.equal(done.origin.requestBodySha256, payload.requestBodySha256);
  assert.equal(done.origin.responseBodyBytesWritten, payload.responseBodyBytes); assert.equal(done.origin.responseBodySha256, payload.responseBodySha256);
  assert.equal(done.origin.connections, 1); assert.equal(done.origin.requests, 1); assert.equal(done.origin.tlsConnections, 0); assert.equal(done.origin.upgradeRequests, 0);
  assert.equal(done.backend.captures, 1); assert.equal(done.backend.clientEndWrites, 1); assert.equal(done.backend.proxyMode, 'http-origin-connect');
  assert.deepEqual(done.backend.negotiatedCapabilities, C3_CAPABILITIES);
  assert.equal(done.enrollment.stream.streamLeases + done.enrollment.stream.chargedBytes, 0);
});

for (const family of ['ipv4', 'ipv6']) test(`actual enrolled ${family} HTTPS443 verifies distinct trust, full bodies, capture and normal cleanup`, { timeout: 45000 }, async t => {
  const f = await fixture(t, 'https-h1', family), client = await f.application(443), socket = await innerTls(client, f.ca);
  t.after(() => socket.destroy());
  const body = Buffer.from(Array.from({ length: payload.requestBodyBytes }, (_, i) => i % 251));
  const request = Buffer.concat([Buffer.from(`POST ${payload.path} HTTP/1.1\r\nHost: ${C3_LOGICAL_HOST}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]);
  const state = writerState(); for (let offset = 0; offset < request.length; offset += 4096) await write(socket, request.subarray(offset, offset + 4096), state);
  const reply = await bytesThroughEof(socket), end = reply.indexOf('\r\n\r\n'); assert(end > 0 && end < 4096);
  assert.match(reply.subarray(0, end).toString('ascii'), /^HTTP\/1\.1 200 OK\r\n/);
  assert.equal(reply.length - end - 4, payload.responseBodyBytes); assert.equal(digest(reply.subarray(end + 4)), payload.responseBodySha256);
  if (!socket.writableEnded) await endWrite(socket, state);
  try { await client.finish(); }
  catch (error) { t.diagnostic(JSON.stringify({ bridge: client.snapshot(), origin: f.owner.snapshot().origin, backend: f.owner.snapshot().backend,
    stream: f.owner.inspect()?.probe?.stream, io: f.owner.inspect()?.probe?.io })); throw error; }
  const done = await until(() => f.owner.snapshot(), value => value.gatewayStreamComplete);
  assert(done.origin.requestVerified && done.origin.captureMatched && done.origin.originalDestinationMatched && done.origin.responseEof && !done.origin.failed);
  assert.equal(done.origin.requestBodySha256, payload.requestBodySha256); assert.equal(done.origin.responseBodySha256, payload.responseBodySha256);
  assert.equal(done.origin.connections, 1); assert.equal(done.origin.tlsConnections, 1); assert(done.origin.tlsSniMatched && done.origin.tlsAlpnH1);
  assert.equal(done.backend.captures, 1); assert.equal(done.backend.proxyMode, null); assert.deepEqual(done.backend.negotiatedCapabilities, C3_CAPABILITIES);
});

for (const profile of ['http-upgrade', 'wss-h1']) test(`actual enrolled ${profile} preserves101 coalescing, application text/binary, ping/pong and real Close`, { timeout: 45000 }, async t => {
  const f = await fixture(t, profile, 'ipv4'), client = await f.application(profile === 'http-upgrade' ? 80 : 443);
  const socket = profile === 'http-upgrade' ? client.transport : await innerTls(client, f.ca); t.after(() => socket.destroy());
  const realKey = Buffer.from('0123456789abcdef').toString('base64'); assert.equal(Buffer.from(realKey, 'base64').length, 16);
  await write(socket, Buffer.from(`GET ${c3Upgrade.path} HTTP/1.1\r\nHost: ${C3_LOGICAL_HOST}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${realKey}\r\n\r\n`));
  const response = (await bounded(headers(socket), 5000)).toString('ascii'); assert.match(response, /^HTTP\/1\.1 101 /);
  const accept = [...response.matchAll(/^sec-websocket-accept:[ \t]*([^\r\n]+)\r$/gmi)]; assert.equal(accept.length, 1);
  assert.equal(accept[0][1], createHash('sha1').update(realKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64'));
  const ws = new ResearchWebSocket(socket, { role: 'client', maxBinaryBytes: 65536 });
  const first = await bounded(ws.next(), 5000); try { assert.equal(first.kind, 'text'); assert.equal(first.copyBytes().toString('utf8'), c3Upgrade.initialText); } finally { first.release(); }
  await ws.send('text', Buffer.from(c3Upgrade.clientText)); await ws.send('binary', binary()); await ws.send('ping', Buffer.alloc(0));
  let text = false, data = false, ping = false, pong = false;
  while (!text || !data || !ping || !pong) {
    const event = await bounded(ws.next(), 5000);
    try {
      if (event.kind === 'text') { assert.equal(text, false); assert.equal(event.copyBytes().toString('utf8'), c3Upgrade.clientText); text = true; }
      else if (event.kind === 'binary') { assert.equal(data, false); assert(event.copyBytes().equals(binary())); data = true; }
      else if (event.kind === 'ping') { assert.equal(ping, false); assert.equal(event.copyBytes().toString('ascii'), 'probe'); await ws.send('pong', event.copyBytes()); ping = true; }
      else { assert.equal(event.kind, 'pong'); assert.equal(pong, false); assert.equal(event.copyBytes().length, 0); pong = true; }
    } finally { event.release(); }
  }
  await ws.send('close', Buffer.from([3, 232]));
  const close = await bounded(ws.next(), 5000); try { assert.equal(close.kind, 'close'); assert.equal(close.closeCode, 1000); } finally { close.release(); }
  assert.equal((await bytesThroughEof(socket)).length, 0); await endWrite(socket);
  await client.finish(); await observeClose(socket); await ws.finish();
  const done = await until(() => f.owner.snapshot(), value => value.gatewayStreamComplete);
  assert(done.origin.upgradeAccepted && done.origin.requestVerified && done.origin.captureMatched && done.origin.originalDestinationMatched && !done.origin.failed);
  assert.equal(done.origin.connections, 1); assert.equal(done.origin.upgradeRequests, 1); assert.equal(done.origin.clientTextMessages, 1); assert.equal(done.origin.clientBinaryMessages, 1);
  assert.equal(done.origin.clientBinaryBytes, c3Upgrade.binaryBytes); assert.equal(done.origin.clientBinarySha256, digest(binary()));
  assert.equal(done.origin.clientPings, 1); assert.equal(done.origin.clientPongs, 1); assert(done.origin.clientCloseObserved && done.origin.serverCloseWritten);
  assert.equal(done.backend.captures, 1); assert.equal(done.backend.proxyMode, profile === 'http-upgrade' ? 'http-origin-connect' : null);
});

test('C3 private CSR CLI binds actual public CA, exact capabilities and all closed owners without free-form logs or private keys', { timeout: 30000 }, async () => {
  const crypto = createCryptoFixture(), args = [fileURLToPath(new URL('./gateway-origin-fixture.mjs', import.meta.url)), '--desktop-root', desktopRoot,
    '--desktop-commit', desktopCommit, '--profile', 'https-h1', '--family', 'ipv4'];
  const result = await runDraftCommand(process.execPath, args, { timeoutMillis: 25000, maxOutputBytes: 65536,
    stdinBytes: Buffer.from(JSON.stringify({ op: 'enroll', csrDer: crypto.csr().toString('base64url') }) + '\n{"op":"stop"}\n') });
  assert.equal(result.code, 0); assert(result.closeObserved && result.processGroupClosed && result.inputFinished && result.inputClosed); assert.equal(result.stderrBytes, 0);
  const lines = result.output.trim().split('\n').map(line => JSON.parse(line)); assert.deepEqual(lines.map(line => line.event), ['ready', 'enrolled', 'closed']);
  assert.deepEqual(lines[1].metadata, lines[0].metadata); assert.equal(lines[0].profile, 'https-h1'); assert.equal(lines[0].family, 'ipv4');
  assert.equal(lines[1].interceptionCaCertificateDer, lines[0].interceptionCaCertificateDer);
  const ca = new X509Certificate(Buffer.from(lines[0].interceptionCaCertificateDer, 'base64url'));
  assert.equal(createHash('sha256').update(ca.raw).digest('base64url'), lines[0].metadata.interceptionCaCertificateSha256);
  assert.equal(lines[1].approved.interceptionCaCertificateSha256, lines[0].metadata.interceptionCaCertificateSha256);
  assert.deepEqual(lines[1].approved.capabilities, C3_CAPABILITIES); assert.equal(result.output.includes('PRIVATE KEY'), false); joined(lines[2].snapshot);
});

test('C3 profiles and source pins are finite and failures never echo supplied configuration', async () => {
  for (const extra of [{ profile: 'CANARY_private', family: 'ipv4' }, { profile: 'https-h1', family: 'CANARY_private' },
    { profile: 'https-h1', family: 'ipv4', desktopCommit: 'fd63f6940226c8e3401a165082dfa9325abaca69' },
    { profile: 'http-h1', family: 'ipv6' }, { family: 'ipv4' }]) {
    await assert.rejects(startOriginGatewayFixture({ desktopRoot, desktopCommit, ...extra }), error => error.code === 'origin_fixture_failed' && !String(error).includes('CANARY_private'));
  }
});
