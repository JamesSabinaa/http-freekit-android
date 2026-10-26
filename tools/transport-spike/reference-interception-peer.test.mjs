// Actual private CSR/gateway/origin/process tests. Never print private IPC or hashes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import tls from 'node:tls';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { Duplex } from 'node:stream';
import { inspect } from 'node:util';
import { fileURLToPath } from 'node:url';
import { startReferenceInterceptionPeer } from './reference-interception-peer.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { originControl, originStream } from './companion-enrollment-origin-client.mjs';
import { upgradeEnrolled } from './companion-enrollment-stream-client.mjs';
import { nextApplication, until } from './companion-stream-peer-client.mjs';
import { bounded, observeClose, headers, write, safeError } from './companion-stream-peer-io.mjs';
import { encodeStream, decodeStream } from './companion-protocol-codec.mjs';
import { referenceInterceptionProfile as P } from './reference-interception-contract.mjs';

const capabilities = ['tcp-http-origin-connect', 'tcp-https-connect'];
const deadline = promise => bounded(promise, 10000);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const expected = bytes => Buffer.from('reference-origin:' + digest(bytes));
const peerFile = fileURLToPath(new URL('./reference-interception-peer.mjs', import.meta.url));
const finiteCodes = new Set(['peer_configuration', 'peer_input', 'peer_unavailable', 'peer_enrollment',
  'peer_revocation', 'peer_cleanup', 'peer_watchdog', 'peer_output']);
const safeFailure = error => finiteCodes.has(error?.code) && typeof error.joined === 'boolean' &&
  !JSON.stringify(error).includes('BEGIN') && !inspect(error).includes('BEGIN');
function joined(state) {
  assert(state.privateDirectoryRemoved, 'Owned directory removed after joins');
  assert(state.backend.closed && state.assets.closed && state.gateway.closed, 'Independent owners closed');
  assert(state.gateway.issuerChildrenJoined && state.gateway.storeClosed && state.gateway.authorityClosed && state.gateway.listenersClosed);
  for (const k of ['activeOwners', 'activeSockets', 'activeRequests', 'listeners']) assert.equal(state.backend[k], 0, k);
  assert.equal(state.backend.ownersCreated, state.backend.ownersClosed);
  for (const k of ['pendingCallbacks', 'pendingTimers', 'workers', 'signerGroups', 'issuerJobs', 'acceptedSockets',
    'tlsSockets', 'bodyReaders', 'requestTasks', 'pendingWriteCallbacks', 'registrationWaiters', 'listeners', 'activeSockets']) assert.equal(state.gateway[k], 0, k);
  for (const k of ['sessionLeases', 'streamLeases', 'chargedBytes', 'ownerRecords', 'authenticatedSockets', 'proxySockets',
    'listeners', 'workers', 'timers', 'pendingCallbacks']) assert.equal(state.gateway.stream[k], 0, k);
  for (const owner of [state.assets, state.gateway.issuer]) {
    assert.equal(owner.commandsStarted, owner.commandsClosed);
    assert.equal(owner.commandsStarted, owner.processGroupsClosed);
  }
}

// Local maintained TLS carrier over the existing actual WS client. No fake EOF,
// response or COMPLETE event; backpressure retains at most one received frame.
class Carrier extends Duplex {
  constructor(flow) {
    super({ allowHalfOpen: true, autoDestroy: false, highWaterMark: 4096 });
    this.flow = flow; this.localEof = false; this.remoteEof = false; this.normal = false;
    this.on('error', () => {}); this.observed = observeClose(this);
    this.pump = this.receive().catch(error => { this.failure = error; this.destroy(safeError('reference_carrier_failed')); });
  }
  _read() { const wake = this.wake; this.wake = null; wake?.(); }
  _write(bytes, _encoding, callback) {
    (async () => {
      for (let i = 0; i < bytes.length; i += 4096) await this.flow.ws.send('binary', bytes.subarray(i, i + 4096));
    })().then(() => callback(), () => callback(safeError('reference_carrier_failed')));
  }
  _final(callback) {
    this.flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: this.flow.id }))
      .then(() => { this.localEof = true; callback(); }, () => callback(safeError('reference_carrier_failed')));
  }
  _destroy(error, callback) {
    this._read();
    if (this.normal) { callback(error); return; }
    if (!error && !this.aborting && this.localEof) {
      deadline(this.pump).then(() => callback(this.failure), async () => {
        try { await this.flow.ws.cancel(); } finally { callback(safeError('reference_carrier_failed')); }
      });
    } else this.flow.ws.cancel().then(() => callback(error), () => callback(safeError('reference_carrier_failed')));
  }
  async receive() {
    while (true) {
      const event = await nextApplication(this.flow);
      let pause = false, close = false;
      try {
        if (event.kind === 'binary') {
          assert(!this.remoteEof && !this.destroyed, 'No discarded or post-EOF bytes');
          const bytes = event.copyBytes(); assert(bytes.length <= 4096);
          pause = !this.push(bytes);
        } else if (event.kind === 'text') {
          const value = decodeStream(event.copyBytes()).toWire();
          assert(value.type === 'end_write' && value.streamId === this.flow.id && !this.remoteEof, 'Actual directional EOF');
          this.remoteEof = true; this.push(null);
        } else {
          assert(event.kind === 'close' && event.closeCode === 1000 && this.localEof && this.remoteEof, 'Natural WS completion');
          close = true;
        }
      } finally { event.release(); }
      if (close) {
        await this.flow.ws.send('close', Buffer.from([3, 232]));
        await this.flow.ws.finish(); await this.flow.closed; this.normal = true; return;
      }
      if (pause && !this.destroyed) await new Promise(resolve => { this.wake = resolve; });
    }
  }
  async join() { await deadline(this.pump); if (this.failure) throw this.failure; assert(this.localEof && this.remoteEof && this.normal); }
  async abort() {
    this.aborting = true; this.destroy();
    if (!this.normal) await deadline(this.flow.ws.cancel());
    await deadline(Promise.all([this.observed, this.pump]));
  }
}
async function environment(operation) {
  const peer = await startReferenceInterceptionPeer();
  const controls = [], carriers = [], sockets = [];
  let primary;
  try {
    const ready = peer.ready();
    const fixture = { metadata: () => ({ material: () => structuredClone(ready.metadata) }) };
    const crypto = createCryptoFixture();
    const { approved } = await peer.enroll(crypto.csr());
    const certificate = new X509Certificate(Buffer.from(approved.clientCertificateDer, 'base64url'));
    assert(certificate.checkPrivateKey(crypto.device.privateKey), 'Actual CSR key bound to approved certificate');
    assert(approved.interceptionCaCertificateSha256 === createHash('sha256').update(Buffer.from(ready.interceptionCaDer, 'base64url')).digest('base64url'), 'Exact public CA approval binding');
    assert.deepEqual(approved.capabilities, capabilities);
    const credential = { approved, enrollmentId: approved.enrollmentId,
      key: crypto.device.privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: certificate.toString() };
    await operation({ peer, fixture, credential, ready,
      async open(mode = 'http') {
        const control = await originControl(fixture, credential, capabilities); controls.push(control);
        const flow = await originStream(fixture, credential, control, 'reference-peer', mode === 'http' ? 'http-origin-connect' : null);
        const carrier = new Carrier(flow); carriers.push(carrier);
        const port = mode === 'http' ? 80 : 443;
        await write(carrier, Buffer.from(`CONNECT ${P.address}:${port} HTTP/1.1\r\nHost: ${P.address}:${port}\r\n\r\n`));
        const ack = await deadline(headers(carrier));
        assert(ack.equals(Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n')), 'Actual CONNECT acknowledgement');
        return { carrier, control };
      },
      tls(carrier) {
        const socket = tls.connect({ socket: carrier, servername: P.hostname,
          ca: new X509Certificate(Buffer.from(ready.interceptionCaDer, 'base64url')).toString(), rejectUnauthorized: true,
          minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], allowHalfOpen: true });
        socket.on('error', () => {}); sockets.push({ socket, closed: observeClose(socket) }); return socket;
      },
    });
  } catch (error) { primary = error; }
  const suppressed = [];
  const cleanup = async action => { try { await deadline(action()); } catch { suppressed.push(safeError('reference_test_cleanup_failed')); } };
  for (const { socket, closed } of sockets) await cleanup(async () => { socket.destroy(); await closed; });
  for (const carrier of carriers) await cleanup(() => carrier.abort());
  for (const control of controls) await cleanup(async () => { await control.ws.cancel(); await control.pump; await control.closed; });
  await cleanup(async () => { const a = peer.close(), b = peer.close(); assert(a === b, 'Repeated close shares real result'); joined(await a); });
  if (primary) { if (suppressed.length) Object.defineProperty(primary, 'suppressed', { value: suppressed }); throw primary; }
  assert.equal(suppressed.length, 0, 'All independent test owners joined');
}
async function post(socket, body) {
  let request;
  try {
    await deadline(new Promise((resolve, reject) => {
      request = http.request({ host: P.hostname, port: 80, method: 'POST', path: P.path, createConnection: () => socket,
        headers: { host: P.hostname, 'content-length': body.length, connection: 'close' } }, reply => {
        const parts = []; let size = 0;
        reply.on('data', chunk => { size += chunk.length; if (size > P.maxBodyBytes) reply.destroy(); else parts.push(chunk); });
        reply.on('error', () => reject(safeError('reference_response_failed')));
        reply.on('end', () => {
          try { assert(reply.complete && reply.statusCode === 200); assert(Buffer.concat(parts).equals(expected(body)), 'Actual complete origin response'); resolve(); }
          catch (error) { reject(error); }
        });
      });
      request.on('error', () => reject(safeError('reference_request_failed')));
      request.once('finish', () => socket.end()); request.end(body);
    }));
  } catch (error) { request?.destroy(); throw error; }
}

for (const mode of ['http', 'https']) test(`private peer actual ${mode} CSR enrollment, origin proof, EOF and cleanup`, { timeout: 40000 }, async () => {
  await environment(async f => {
    const { carrier } = await f.open(mode);
    let socket = carrier;
    if (mode === 'https') {
      socket = f.tls(carrier);
      await deadline(new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', () => reject(safeError('reference_tls_failed'))); }));
      assert(socket.authorized && socket.alpnProtocol === 'http/1.1', 'Scoped verified H1 TLS');
    }
    const body = Buffer.from(Array.from({ length: P.maxBodyBytes }, (_, i) => (i * 23 + 7) & 255));
    await post(socket, body); await carrier.join();
    const state = await until(() => f.peer.snapshot(), s => s.stream?.resourcesReleased && s.backend.activeOwners === 0);
    assert(state.stream.phase === 'complete' && !state.stream.streamLease && state.stream.clientEofEmitted && state.stream.gatewayEofEmitted, 'Actual complete stream projection');
    assert.equal(state.stream.chargedBytes, 0);
    assert.equal(state.stream.fixtureUploadBytesRead, 0); assert.equal(state.stream.fixtureResponseBytesWritten, 0);
    assert.equal(state.backend.upstreamDials, 1);
    for (const k of ['interceptionTlsHandshakes', 'upstreamTlsHandshakes']) assert.equal(state.backend[k], mode === 'https' ? 1 : 0);
    assert.equal(state.evidence.length, 1);
    const row = state.evidence[0];
    assert(row.mode === mode && row.requestBytes === body.length && row.responseBytes === expected(body).length, 'Actual origin finite measurements');
    assert(row.requestSha256 === digest(body) && row.responseSha256 === digest(expected(body)), 'Private origin digest equality');
    state.evidence[0].mode = 'modified'; assert(f.peer.snapshot().evidence[0].mode === mode, 'Defensive private evidence');
  });
});

test('private peer real held owner revocation, saved credential refusal and probe cleanup', { timeout: 40000 }, async () => {
  await environment(async f => {
    const { carrier, control } = await f.open('https');
    await until(() => f.peer.snapshot(), s => s.backend.activeOwners === 1);
    assert.deepEqual(f.peer.revoke(), { revoked: true });
    const state = await until(() => f.peer.snapshot(), s => s.stream?.cleanupComplete && s.backend.activeOwners === 0);
    assert(state.stream.phase !== 'complete' && state.stream.resourcesReleased && !state.stream.streamLease, 'Actual revoked terminal outcome');
    assert.equal(state.stream.chargedBytes, 0); assert.equal(state.backend.upstreamDials, 0); assert.equal(state.evidence.length, 0);
    await carrier.flow.closed;
    for (const route of ['/companion/v1/control', '/companion/v1/streams']) {
      const refused = await upgradeEnrolled(f.fixture, f.credential, route, { scenario: null, token: control.token });
      assert.equal(refused.status, 403);
    }
  });
});

test('private peer close joins an actual held backend owner and seals new enrollment', { timeout: 40000 }, async () => {
  await environment(async f => {
    await f.open(); await until(() => f.peer.snapshot(), s => s.backend.activeOwners === 1);
    const closure = f.peer.close();
    assert.throws(() => f.peer.enroll(createCryptoFixture().csr()), error => error.code === 'peer_unavailable');
    const state = await closure; joined(state);
    assert(state.stream && state.stream.phase !== 'complete', 'Held owner is cancelled, never manufactured complete');
    assert.equal(state.backend.ownersCreated, 1); assert.equal(state.backend.upstreamDials, 0);
  });
});

test('private peer ready/snapshot defensive, redacted inspection, bounded one-shot CSR admission', { timeout: 40000 }, async () => {
  const peer = await startReferenceInterceptionPeer();
  try {
    assert(JSON.stringify(peer) === '"[Private reference interception peer]"' && !inspect(peer).includes('metadata'), 'Default peer inspection redacted');
    const first = peer.ready(), again = peer.ready();
    assert(first.metadata !== again.metadata && JSON.stringify(first) === JSON.stringify(again), 'Ready is defensive and stable');
    first.metadata.webSocketPort = -1; assert(peer.ready().metadata.webSocketPort > 0);
    assert(peer.snapshot().stream === null, 'Absent actual stream is null');
    for (const bad of [null, 'csr', new Uint8Array(0), new Uint8Array(4097)]) assert.throws(() => peer.enroll(bad), error => error.code === 'peer_input');
    const csr = createCryptoFixture().csr();
    const enrollment = peer.enroll(csr);
    assert.throws(() => peer.enroll(csr), error => error.code === 'peer_input');
    const { approved } = await enrollment; assert(approved.type === 'pair_approved');
    approved.capabilities.length = 0;
    assert(peer.snapshot().stream === null);
  } finally { joined(await peer.close()); }
});

test('private peer close during actual enrollment suppresses late approved publication and joins issuer', { timeout: 40000 }, async () => {
  const peer = await startReferenceInterceptionPeer();
  const result = peer.enroll(createCryptoFixture().csr()).then(() => false, error => safeFailure(error));
  const closed = peer.close(); assert(await result, 'No late successful enrollment after admission seal'); joined(await closed);
});

test('private peer rejects configuration and cleans real failed OpenSSL startup without provider diagnostics', { timeout: 15000 }, async () => {
  for (const openssl of ['', '\0', '\n', 3]) await assert.rejects(startReferenceInterceptionPeer({ openssl }), error => safeFailure(error) && error.code === 'peer_configuration');
  const temp = fs.realpathSync(os.tmpdir());
  const before = new Set(fs.readdirSync(temp).filter(name => name.startsWith('freekit-reference-peer-')));
  await assert.rejects(startReferenceInterceptionPeer({ openssl: '/nonexistent-reference-peer-openssl' }), error => safeFailure(error) && error.joined);
  assert(fs.readdirSync(temp).filter(name => name.startsWith('freekit-reference-peer-')).every(name => before.has(name)), 'Joined command failure leaves no owned directory');
});

async function cli(args = []) {
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', peerFile, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
  const events = [], waiters = [];
  let pending = Buffer.alloc(0), total = 0, stderr = 0, bad = false, exit;
  const notify = () => { for (const wake of waiters.splice(0)) wake(); };
  child.stdin.on('error', () => {}); child.on('error', () => { bad = true; notify(); });
  child.stderr.on('data', bytes => { stderr += bytes.length; if (stderr > 16384) { bad = true; child.kill('SIGTERM'); } });
  child.stdout.on('data', bytes => {
    total += bytes.length;
    if (total > 1048576) { bad = true; child.kill('SIGTERM'); return; }
    pending = Buffer.concat([pending, bytes]);
    while (pending.includes(10)) {
      const end = pending.indexOf(10), line = pending.subarray(0, end); pending = pending.subarray(end + 1);
      try {
        if (line.length + 1 > 16384 || line.some(v => v < 32 || v > 126)) throw 0;
        const value = JSON.parse(line);
        if (JSON.stringify(value) !== line.toString() || value.format !== 'http-freekit-reference-interception-peer' || value.revision !== 1) throw 0;
        events.push(value); notify();
      } catch { bad = true; }
    }
    if (pending.length > 16384) { bad = true; child.kill('SIGTERM'); }
  });
  const closed = new Promise(resolve => child.once('close', (code, signal) => { exit = { code, signal }; notify(); resolve(); }));
  const next = async () => {
    while (!events.length && !exit) await deadline(new Promise(resolve => waiters.push(resolve)));
    assert(events.length > 0 && !bad, 'Actual bounded canonical private CLI envelope'); return events.shift();
  };
  return {
    next, send: value => deadline(write(child.stdin, Buffer.from(JSON.stringify(value) + '\n'))),
    raw: async bytes => {
      for (let at = 0; at < bytes.length; at += 8192) await deadline(write(child.stdin, bytes.subarray(at, at + 8192)));
    }, eof: () => child.stdin.end(),
    async join(expectedCode) {
      await deadline(closed); assert.equal(exit.code, expectedCode); assert(exit.signal === null, 'Real child exit, not forced termination');
      assert(!bad && !pending.length && stderr === 0, 'No raw stderr, partial or unbounded private output');
    },
    async cleanup() {
      if (!exit) { child.stdin.end(); try { await deadline(closed); } catch { child.kill('SIGTERM'); await deadline(closed); assert.fail('CLI required forced termination'); } }
    },
  };
}

test('private CLI no-argument actual ready, CSR approval, revoke, snapshots and joined stop', { timeout: 40000 }, async () => {
  const p = await cli();
  try {
    const ready = await p.next(); assert(ready.event === 'ready' && ready.metadata.webSocketPort > 0);
    const crypto = createCryptoFixture();
    await p.send({ op: 'enroll', csrDer: crypto.csr().toString('base64url') });
    const enrolled = await p.next(); assert(enrolled.event === 'enrolled' && enrolled.approved.type === 'pair_approved');
    assert(new X509Certificate(Buffer.from(enrolled.approved.clientCertificateDer, 'base64url')).checkPrivateKey(crypto.device.privateKey), 'CLI actual CSR identity binding');
    await p.send({ op: 'revoke' }); const revoked = await p.next(); assert(revoked.event === 'revoked' && revoked.revoked === true);
    // Several valid lines may be coalesced into the same read.
    await p.raw(Buffer.from('{"op":"snapshot"}\n{"op":"snapshot"}\n'));
    for (let i = 0; i < 2; i++) { const event = await p.next(); assert(event.event === 'snapshot' && event.snapshot.stream === null); }
    await p.send({ op: 'stop' }); const closed = await p.next(); assert(closed.event === 'closed'); joined(closed.snapshot); await p.join(0);
  } finally { await p.cleanup(); }
});

for (const [label, input] of [
  ['duplicate key', '{"op":"snapshot","op":"snapshot"}\n'], ['extra key', '{"op":"snapshot","extra":1}\n'],
  ['noncanonical', '{ "op":"snapshot"}\n'], ['trailing data', '{"op":"snapshot"}x\n'],
  ['unknown operation', '{"op":"forward"}\n'], ['non-ASCII', '{"op":"é"}\n'],
  ['padded CSR', '{"op":"enroll","csrDer":"AA=="}\n'], ['empty CSR', '{"op":"enroll","csrDer":""}\n'],
  ['noncanonical base64url', '{"op":"enroll","csrDer":"AB"}\n'],
  ['oversize decoded CSR', JSON.stringify({ op: 'enroll', csrDer: Buffer.alloc(4097).toString('base64url') }) + '\n'],
  ['line bound', 'x'.repeat(8193)], ['partial EOF', '{"op":'],
]) test(`private CLI ${label} fails finitely and joins cleanup`, { timeout: 30000 }, async () => {
  const p = await cli();
  try {
    // Exercise immediate admission sealing during the real asynchronous startup,
    // independently of whether this host can open the defended SQLite Store.
    await p.raw(Buffer.from(input));
    if (label === 'partial EOF') p.eof();
    const failed = await p.next(); assert(failed.event === 'failed' && failed.code === 'peer_input' && failed.joined === true, 'Finite actual joined failure'); await p.join(1);
  } finally { await p.cleanup(); }
});

test('private CLI command and cumulative byte bounds seal during real startup', { timeout: 40000 }, async () => {
  const largeLine = JSON.stringify({ op: 'enroll', csrDer: Buffer.alloc(4096).toString('base64url') }) + '\n';
  // Each line is canonical and bounded; 48 commands are below the command cap.
  // Only the cumulative byte limit is exceeded by this second input.
  assert(Buffer.byteLength(largeLine) <= 8192 && Buffer.byteLength(largeLine.repeat(48)) > 262144);
  for (const input of [Buffer.from('{"op":"snapshot"}\n'.repeat(65)), Buffer.from(largeLine.repeat(48))]) {
    const p = await cli();
    try {
      // A rejection can close stdin before the actual write callback; join it in either case.
      try { await p.raw(input); } catch { /* Actual pipe rejection, not successful delivery. */ }
      let event;
      do { event = await p.next(); } while (event.event === 'snapshot');
      assert(event.event === 'failed' && event.code === 'peer_input' && event.joined === true); await p.join(1);
    } finally { await p.cleanup(); }
  }
});

test('private CLI stop and EOF seal in-flight enrollment without late approval publication', { timeout: 40000 }, async () => {
  for (const stop of [true, false]) {
    const p = await cli();
    try {
      assert((await p.next()).event === 'ready');
      const enroll = JSON.stringify({ op: 'enroll', csrDer: createCryptoFixture().csr().toString('base64url') }) + '\n';
      await p.raw(Buffer.from(enroll + (stop ? '{"op":"stop"}\n' : '')));
      if (!stop) p.eof();
      const event = await p.next();
      assert(event.event === (stop ? 'closed' : 'failed'), 'No late enrolled publication');
      if (stop) joined(event.snapshot); else assert(event.code === 'peer_input' && event.joined === true);
      await p.join(stop ? 0 : 1);
    } finally { await p.cleanup(); }
  }
});

test('private CLI rejects arguments without startup or raw diagnostics', { timeout: 10000 }, async () => {
  const p = await cli(['--target']);
  try {
    const event = await p.next(); assert(event.event === 'failed' && event.code === 'peer_configuration' && event.joined === true);
    await p.join(1);
  } finally { await p.cleanup(); }
});
