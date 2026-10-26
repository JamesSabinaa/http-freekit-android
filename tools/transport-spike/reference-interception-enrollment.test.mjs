// New host-only reference proof: not C5, desktop compatibility, Android or USB.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import tls from 'node:tls';
import { Duplex } from 'node:stream';
import { createHash } from 'node:crypto';
import { createReferenceInterceptionAssets } from './reference-interception-assets.mjs';
import { startReferenceInterceptionBackend } from './reference-interception-backend.mjs';
import { referenceInterceptionProfile as profile } from './reference-interception-contract.mjs';
import { startEnrollmentOriginFixture } from './companion-enrollment-origin.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enrollOrigin, originControl, originStream } from './companion-enrollment-origin-client.mjs';
import { upgradeEnrolled } from './companion-enrollment-stream-client.mjs';
import { nextApplication, until } from './companion-stream-peer-client.mjs';
import { bounded, headers, observeClose, safeError, write } from './companion-stream-peer-io.mjs';
import { decodeStream, encodeStream } from './companion-protocol-codec.mjs';
import { HTTP_ORIGIN_CAPABILITY, HTTP_ORIGIN_PROXY_MODE } from './companion-http-origin.mjs';

const capabilities = [HTTP_ORIGIN_CAPABILITY, 'tcp-https-connect'];
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
// Independently derive expected bytes; never substitute this for actual origin I/O.
const expectedResponse = body => Buffer.from('reference-origin:' + digest(body), 'ascii');
const deadline = promise => bounded(promise, profile.timeoutMillis);

// Only the maintained enrolled client owns TLS/WSS framing. This local adapter
// exposes its ordered binary application bytes to Node TLS, not a fake TCP peer.
// One leased inbound frame and one bounded write are retained at a time. push()
// backpressure stops ws.next(); _write completion waits for real WS I/O.
class StreamDuplex extends Duplex {
  constructor(flow) {
    super({ allowHalfOpen: true, autoDestroy: false, highWaterMark: 4096 });
    this.flow = flow;
    this.localEof = false;
    this.remoteEof = false;
    this.normalClose = false;
    this.failure = null;
    this.aborting = false;
    this.wake = null;
    this.on('error', () => {});
    this.closedEvent = observeClose(this);
    this.pump = this.receive().catch(failure => {
      this.failure = failure;
      this.destroy(safeError('reference_stream_failed'));
    });
  }
  _read() { const wake = this.wake; this.wake = null; wake?.(); }
  _write(bytes, _encoding, done) {
    (async () => {
      for (let offset = 0; offset < bytes.length; offset += 4096) {
        await this.flow.ws.send('binary', bytes.subarray(offset, offset + 4096));
      }
    })().then(() => done(), () => done(safeError('reference_stream_write_failed')));
  }
  _final(done) {
    this.flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: this.flow.id }))
      .then(() => { this.localEof = true; done(); }, () => done(safeError('reference_stream_end_failed')));
  }
  _destroy(failure, done) {
    this._read();
    if (this.normalClose) { done(failure); return; }
    // Maintained TLS's JSStreamSocket.doClose() destroys its carrier after TLS
    // shutdown, independently of the carrier's still-pending remote END_WRITE.
    // A completed local END_WRITE permits only a bounded drain, not completion:
    // receive()/join() still require actual remote EOF, Close1000 and its ack.
    if (!failure && !this.aborting && this.localEof) {
      deadline(this.pump).then(() => done(this.failure), failure => {
        // Timeout remains a failure; abort and join the actual WS owner rather
        // than synthesizing remote EOF or letting a destroy callback hang.
        this.flow.ws.cancel().then(() => done(failure), () => done(failure));
      });
      return;
    }
    this.flow.ws.cancel().then(() => done(failure), () => done(failure ?? safeError('reference_stream_cleanup_failed')));
  }
  async receive() {
    while (true) {
      const event = await nextApplication(this.flow);
      let pause = false, close = false;
      try {
        if (event.kind === 'binary') {
          assert.equal(this.remoteEof, false, 'No bytes after remote END_WRITE');
          assert.equal(this.destroyed, false, 'Do not discard binary records after TLS carrier teardown');
          const bytes = event.copyBytes();
          assert(bytes.length <= 4096, 'Bounded incoming frame');
          pause = !this.push(bytes);
        } else if (event.kind === 'text') {
          const message = decodeStream(event.copyBytes()).toWire();
          assert.equal(message.type, 'end_write');
          assert.equal(message.streamId, this.flow.id);
          assert.equal(this.remoteEof, false);
          this.remoteEof = true;
          this.push(null);
        } else {
          assert.equal(event.kind, 'close');
          assert.equal(event.closeCode, 1000);
          assert(this.localEof && this.remoteEof, 'Both real directional EOFs precede normal Close');
          close = true;
        }
      } finally { event.release(); }
      if (close) {
        await this.flow.ws.send('close', Buffer.from([3, 232]));
        await this.flow.ws.finish();
        await this.flow.closed;
        this.normalClose = true;
        return;
      }
      if (pause && !this.destroyed) await new Promise(done => { this.wake = done; });
    }
  }
  async join() {
    await deadline(this.pump);
    if (this.failure) throw this.failure;
    assert(this.localEof && this.remoteEof && this.normalClose, 'Actual WS EOF/Close acknowledgement joined');
  }
  async abort() {
    this.aborting = true;
    this.destroy();
    if (!this.normalClose) await deadline(this.flow.ws.cancel());
    await deadline(Promise.all([this.closedEvent, this.pump]));
  }
}

function assertBackendClosed(state) {
  assert.equal(state.closed, true);
  assert.equal(state.ownersCreated, state.ownersClosed);
  for (const key of ['activeOwners', 'activeSockets', 'activeRequests', 'listeners']) assert.equal(state[key], 0, key);
}
function assertGatewayClosed(state) {
  assert(state.closed && state.admissionClosed && state.authorityClosed && state.storeClosed);
  assert(state.listenersClosed && state.issuerChildrenJoined);
  for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'workers', 'signerGroups', 'issuerJobs',
    'acceptedSockets', 'tlsSockets', 'bodyReaders', 'requestTasks', 'pendingWriteCallbacks', 'registrationWaiters', 'listeners']) {
    assert.equal(state[key], 0, key);
  }
  assert.deepEqual(state.stream, { sessionLeases: 0, streamLeases: 0, chargedBytes: 0, ownerRecords: 0,
    authenticatedSockets: 0, proxySockets: 0, listeners: 0, workers: 0, timers: 0, pendingCallbacks: 0, unavailable: false });
  assert.equal(state.issuer.commandsStarted, state.issuer.commandsClosed);
  assert.equal(state.issuer.commandsStarted, state.issuer.processGroupsClosed);
}

async function environment(operation) {
  const parent = fs.realpathSync(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(parent, 'freekit-reference-enrolled-'));
  fs.chmodSync(directory, 0o700);
  const assetDirectory = path.join(directory, 'assets'), enrollmentDirectory = path.join(directory, 'enrollment');
  for (const child of [assetDirectory, enrollmentDirectory]) fs.mkdirSync(child, { mode: 0o700 });
  let assets, backend, gateway, primary;
  const controls = [], carriers = [], tlsUsers = [], flows = [];
  const suppressed = [];
  const retain = failure => { if (!primary) primary = failure; else suppressed.push(failure); };
  let joined = true;
  const cleanup = async action => {
    try { await deadline(action()); }
    catch (failure) { joined = false; retain(failure); }
  };
  try {
    assets = await createReferenceInterceptionAssets({ directory: assetDirectory });
    backend = await startReferenceInterceptionBackend({ assets });
    gateway = await startEnrollmentOriginFixture({ directory: enrollmentDirectory, mode: 'create',
      trustedProxyFactory: backend.factory, supportedCapabilities: capabilities,
      interceptionCaCertificateDer: assets.caDer('interception') });
    await operation({ assets, backend, gateway,
      async enroll() {
        const credential = await enrollOrigin(gateway, createCryptoFixture(), capabilities);
        assert.deepEqual(credential.approved.capabilities, capabilities);
        // Enrollment approval binds the same public interception CA, not either
        // the enrollment authority, gateway identity or separate upstream CA.
        assert(credential.approved.interceptionCaCertificateSha256 ===
          createHash('sha256').update(assets.caDer('interception')).digest('base64url'), 'Approved CA binding');
        return credential;
      },
      async control(credential) { const control = await originControl(gateway, credential, capabilities); controls.push(control); return control; },
      async stream(credential, control, mode = 'http', id = 'reference-flow') {
        const flow = await originStream(gateway, credential, control, id, mode === 'http' ? HTTP_ORIGIN_PROXY_MODE : null);
        flows.push(flow);
        const carrier = new StreamDuplex(flow); carriers.push(carrier); return carrier;
      },
      trackTls(socket) { tlsUsers.push({ socket, closed: observeClose(socket) }); return socket; },
    });
  } catch (failure) { if (failure.joined === false) joined = false; retain(failure); }
  // Attempt every independent owner even when an earlier cleanup fails. Keep the
  // primary operation failure, attaching cleanup failures rather than replacing it.
  for (const { socket, closed } of tlsUsers) await cleanup(async () => { socket.destroy(); await closed; });
  for (const carrier of carriers) await cleanup(() => carrier.abort());
  for (const flow of flows) await cleanup(async () => { await flow.ws.cancel(); await flow.closed; });
  for (const control of controls) await cleanup(async () => { await control.ws.cancel(); await control.pump; await control.closed; });
  if (gateway) await cleanup(async () => assertGatewayClosed(await gateway.close()));
  if (backend) await cleanup(async () => { await backend.close(); assertBackendClosed(backend.snapshot()); });
  if (assets && joined) await cleanup(async () => {
    const state = await assets.close();
    assert(state.closed);
    assert.equal(state.commandsStarted, state.commandsClosed);
    assert.equal(state.commandsStarted, state.processGroupsClosed);
  });
  if (joined) {
    assert.equal(path.dirname(directory), parent);
    fs.rmSync(directory, { recursive: true });
  }
  if (primary) {
    if (suppressed.length) Object.defineProperty(primary, 'suppressed', { value: suppressed });
    throw primary;
  }
}

function connectPreface(port, address = profile.address) {
  return Buffer.from(`CONNECT ${address}:${port} HTTP/1.1\r\nHost: ${address}:${port}\r\n\r\n`, 'ascii');
}
async function connect(carrier, port) {
  const preface = connectPreface(port);
  // Fragment the exact fixed tuple over actual authenticated binary WS frames.
  await deadline(write(carrier, preface.subarray(0, 9)));
  await deadline(write(carrier, preface.subarray(9)));
  const acknowledgement = await deadline(headers(carrier));
  assert(acknowledgement.equals(Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n')), 'Exact CONNECT acknowledgement');
}
async function innerTls(f, carrier, role = 'interception') {
  const socket = f.trackTls(tls.connect({ socket: carrier, servername: profile.hostname,
    ca: f.assets.caPem(role), rejectUnauthorized: true, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1'], allowHalfOpen: true }));
  socket.on('error', () => {});
  await deadline(new Promise((resolve, reject) => {
    socket.once('secureConnect', resolve);
    socket.once('error', () => reject(safeError('reference_inner_tls_failed')));
  }));
  assert.equal(socket.authorized, true);
  assert(socket.getPeerX509Certificate().checkHost(profile.hostname) === profile.hostname, 'Fixed inner TLS hostname');
  return socket;
}
async function post(socket, body) {
  let request;
  const response = new Promise((resolve, reject) => {
    request = http.request({ host: profile.hostname, port: 80, method: 'POST', path: profile.path,
      createConnection: () => socket, headers: { host: profile.hostname, 'content-length': body.length, connection: 'close' } }, reply => {
      const chunks = []; let count = 0;
      reply.on('data', bytes => {
        count += bytes.length;
        if (count > profile.maxBodyBytes) { reply.destroy(); reject(safeError('reference_response_bound')); }
        else chunks.push(bytes);
      });
      reply.on('error', () => reject(safeError('reference_response_failed')));
      reply.on('end', () => {
        try {
          assert.equal(reply.statusCode, 200);
          assert.equal(reply.complete, true);
          assert(Buffer.concat(chunks).equals(expectedResponse(body)), 'Actual full origin response');
          resolve();
        } catch (failure) { reject(failure); }
      });
    });
    request.on('error', () => reject(safeError('reference_request_failed')));
    // Actual upload half-close (TLS close_notify for HTTPS), not an injected
    // model event. The remote direction must still deliver the complete reply.
    request.once('finish', () => socket.end());
    request.end(body);
  });
  try { await deadline(response); }
  catch (failure) { request?.destroy(); throw failure; }
}
async function complete(f, credential, carrier) {
  await carrier.join();
  const state = await until(() => f.gateway.inspectEnrollment(credential.enrollmentId), value => value.probe.stream.resourcesReleased);
  assert.equal(state.probe.stream.phase, 'complete');
  assert.equal(state.probe.stream.streamLease, false);
  assert(state.probe.stream.client.eofEmitted && state.probe.stream.gateway.eofEmitted);
  assert.equal(state.probe.control.chargedBytes, 0);
  // No scenario fixture produced a response or consumed the request.
  assert.equal(state.probe.fixture.uploadBytesRead, 0);
  assert.equal(state.probe.fixture.responseBytesWritten, 0);
  await until(() => f.backend.snapshot(), value => value.activeOwners === 0);
}
function successfulEvidence(f, mode, body) {
  const state = f.backend.snapshot();
  assert.equal(state.ownersCreated, 1);
  assert.equal(state.ownersClosed, 1);
  assert.equal(state.upstreamDials, 1);
  assert.equal(state.interceptedHttpRequests, mode === 'http' ? 1 : 0);
  assert.equal(state.interceptedHttpsRequests, mode === 'https' ? 1 : 0);
  assert.equal(state.upstreamHttpRequests, mode === 'http' ? 1 : 0);
  assert.equal(state.upstreamHttpsRequests, mode === 'https' ? 1 : 0);
  assert.equal(state.interceptionTlsHandshakes, mode === 'https' ? 1 : 0);
  assert.equal(state.upstreamTlsHandshakes, mode === 'https' ? 1 : 0);
  const rows = f.backend.evidence();
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.mode, mode);
  assert.equal(row.requestBytes, body.length);
  assert.equal(row.responseBytes, expectedResponse(body).length);
  assert(row.requestSha256 === digest(body), 'Private actual-origin request digest comparison');
  assert(row.responseSha256 === digest(expectedResponse(body)), 'Private actual-origin response digest comparison');
}
function noDispatch(backend) {
  const state = backend.snapshot();
  for (const key of ['upstreamDials', 'interceptedHttpRequests', 'interceptedHttpsRequests',
    'upstreamHttpRequests', 'upstreamHttpsRequests', 'upstreamTlsHandshakes']) assert.equal(state[key], 0, key);
  assert.equal(backend.evidence().length, 0);
}

for (const mode of ['http', 'https']) test(`enrolled reference ${mode}: actual POST, independent origin and remote COMPLETE after natural half-close`, { timeout: 30000 }, async t => {
  let stage = 'fixture';
  try {
    await environment(async f => {
      stage = 'enrollment';
      const credential = await f.enroll();
      stage = 'control';
      const control = await f.control(credential);
      stage = 'stream';
      const carrier = await f.stream(credential, control, mode);
      stage = 'connect';
      await connect(carrier, mode === 'http' ? profile.httpPort : profile.httpsPort);
      stage = 'inner_tls';
      const application = mode === 'https' ? await innerTls(f, carrier) : carrier;
      const body = Buffer.from(Array.from({ length: profile.maxBodyBytes }, (_, i) => (i * 19 + 3) & 255));
      stage = 'post';
      await post(application, body);
      stage = 'remote_complete';
      await complete(f, credential, carrier);
      if (mode === 'https') {
        stage = 'tls_eof';
        assert.equal(application.readableEnded, true, 'Actual inner TLS read EOF');
        assert.equal(application.writableFinished, true, 'Actual inner TLS shutdown finished');
      }
      stage = 'origin_evidence';
      successfulEvidence(f, mode, body);
      stage = 'cleanup';
    });
  } catch (failure) {
    // Fixed labels only: retain the original error without traffic, TLS provider
    // messages, credentials, certificate fingerprints or private measurements.
    t.diagnostic(`reference_${mode}_${stage}`);
    throw failure;
  }
});

test('enrolled reference HTTPS wrong interception trust has no decrypted request or upstream dial', { timeout: 30000 }, async () => {
  await environment(async f => {
    const credential = await f.enroll(), control = await f.control(credential);
    const carrier = await f.stream(credential, control, 'https');
    await connect(carrier, profile.httpsPort);
    // The separate origin CA is real but cannot authorize the interception leaf.
    await assert.rejects(innerTls(f, carrier, 'origin'), failure => failure.code === 'reference_inner_tls_failed');
    await carrier.abort();
    await until(() => f.gateway.inspectEnrollment(credential.enrollmentId), value => value.probe.stream.resourcesReleased);
    await until(() => f.backend.snapshot(), state => state.activeOwners === 0);
    noDispatch(f.backend);
    assert.equal(f.backend.snapshot().ownersCreated, 1);
  });
});

test('enrolled reference target refusal fails closed without a legacy or upstream dispatch', { timeout: 30000 }, async () => {
  await environment(async f => {
    const credential = await f.enroll(), control = await f.control(credential);
    const carrier = await f.stream(credential, control);
    await deadline(write(carrier, connectPreface(profile.httpPort, '198.18.0.3')));
    await deadline(carrier.flow.closed);
    await carrier.abort();
    const state = await until(() => f.gateway.inspectEnrollment(credential.enrollmentId), value => value.probe.stream.resourcesReleased);
    assert.equal(state.probe.stream.phase, 'failed');
    await until(() => f.backend.snapshot(), value => value.activeOwners === 0);
    assert.equal(f.backend.snapshot().rejectedPrefaces, 1);
    noDispatch(f.backend);
    assert.equal(state.probe.fixture.uploadBytesRead, 0);
    assert.equal(state.probe.fixture.responseBytesWritten, 0);
  });
});

test('enrolled reference missing credentials cannot open control or streams', { timeout: 30000 }, async () => {
  await environment(async f => {
    for (const route of ['/companion/v1/control', '/companion/v1/streams']) {
      // The enrolled listener requires a TLS client certificate: rejection is
      // before HTTP dispatch, not a made-up unauthenticated 403 response.
      await assert.rejects(upgradeEnrolled(f.gateway, null, route, { scenario: null }));
    }
    assert.equal(f.backend.snapshot().ownersCreated, 0);
    noDispatch(f.backend);
  });
});

test('enrolled reference revocation seals a real active backend and refuses saved credentials without fallback', { timeout: 30000 }, async () => {
  await environment(async f => {
    const credential = await f.enroll(), control = await f.control(credential);
    const carrier = await f.stream(credential, control, 'https');
    await connect(carrier, profile.httpsPort);
    // Revocation occurs with a real backend owner, before any inner TLS request.
    f.gateway.revoke(credential.enrollmentId);
    await until(() => f.gateway.inspectEnrollment(credential.enrollmentId), value => value.probe.cleanup.complete);
    await deadline(carrier.flow.closed);
    await carrier.abort();
    await until(() => f.backend.snapshot(), value => value.activeOwners === 0);
    for (const route of ['/companion/v1/control', '/companion/v1/streams']) {
      const result = await upgradeEnrolled(f.gateway, credential, route, { scenario: null, token: control.token });
      assert.equal(result.status, 403);
    }
    assert.equal(f.backend.snapshot().ownersCreated, 1);
    assert.equal(f.backend.snapshot().ownersClosed, 1);
    noDispatch(f.backend);
  });
});
