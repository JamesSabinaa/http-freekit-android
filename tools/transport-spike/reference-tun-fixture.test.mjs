// Real host HTTPS/stream proof only, never Android Keystore evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import tls from 'node:tls';
import { Duplex } from 'node:stream';
import { createHash, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { startReferenceTunFixture, ReferenceTunError } from './reference-tun-fixture.mjs';
import { referenceInterceptionProfile as profile } from './reference-interception-contract.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enrollmentRequest } from './companion-enrollment-stream-client.mjs';
import { originControl, originStream } from './companion-enrollment-origin-client.mjs';
import { nextApplication, until } from './companion-stream-peer-client.mjs';
import { bounded, headers, observeClose, safeError, write } from './companion-stream-peer-io.mjs';
import { decodeStream, encodeStream } from './companion-protocol-codec.mjs';
import { HTTP_ORIGIN_CAPABILITY, HTTP_ORIGIN_PROXY_MODE } from './companion-http-origin.mjs';
const capabilities = [HTTP_ORIGIN_CAPABILITY, 'tcp-https-connect'];
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const expectedResponse = body => Buffer.from('reference-origin:' + digest(body), 'ascii');
const deadline = promise => bounded(promise, profile.timeoutMillis);
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
    ca: new X509Certificate(Buffer.from(f.ca, 'base64url')).toString(), rejectUnauthorized: true, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3',
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
for (const mode of ['http', 'https']) test(`reference TUN module actual HTTPS registration/approval and ${mode} origin`, { timeout: 30000 }, async () => {
  const owner = await startReferenceTunFixture();
  let control, carrier, application, primary;
  const cleanupFailures = [];
  const attempt = async action => { try { await deadline(action()); } catch (error) { cleanupFailures.push(error); } };
  try {
    assert.equal(owner.snapshot().stream, null);
    assert(!inspect(owner).includes('desktopId')); assert.equal(JSON.stringify(owner), '"[Private reference TUN fixture]"');
    const m = owner.metadata().material(), invitation = owner.createInvitation().material(), crypto = createCryptoFixture();
    assert.throws(() => owner.createInvitation(), e => e.code === 'tun_input');
    const waiting = owner.waitForRegistered(invitation.invitationId);
    const response = await enrollmentRequest(owner, '/companion/v1/pair', {
      protocolVersion: 1, type: 'pair', desktopId: m.desktopId, invitationId: invitation.invitationId,
      invitationSecret: invitation.invitationSecret, csrDer: crypto.csr().toString('base64url'),
      deviceName: 'Reference TUN host test', capabilities,
    });
    assert.equal(response.status, 200); assert.equal(response.material.type, 'pair_registered');
    const registration = (await waiting).material();
    assert(registration.enrollmentId === response.material.enrollmentId,'Actual registered identity agrees');
    const approved = (await owner.approve(registration.enrollmentId)).material();
    assert.deepEqual(approved.capabilities, capabilities);
    assert(JSON.stringify(owner.readResult(registration.enrollmentId).material()) === JSON.stringify(approved),'Saved actual approval agrees');
    const credential = { approved, enrollmentId: approved.enrollmentId,
      key: crypto.device.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      cert: new X509Certificate(Buffer.from(approved.clientCertificateDer, 'base64url')).toString() };
    // Fetch interception CA from the actual authenticated credential listener.
    const { default: https } = await import('node:https');
    const { tlsOptions } = await import('./companion-enrollment-stream-client.mjs');
    const fetched = await deadline(new Promise((resolve,reject) => {
      const request = https.get({ ...tlsOptions(owner,credential,m.credentialPort), path: '/companion/v1/ca', agent: false,
        headers: { host: `${m.logicalName}:${m.credentialPort}`, accept: 'application/pkix-cert', connection: 'close' } }, reply => {
        const chunks = []; let length = 0;
        reply.on('data', bytes => { length += bytes.length; if (length > 8192) reply.destroy(); else chunks.push(bytes); });
        reply.on('error',reject); reply.on('end',() => resolve({status:reply.statusCode,bytes:Buffer.concat(chunks)}));
      }); request.on('error',reject); request.setTimeout(5000,() => request.destroy());
    }));
    assert.equal(fetched.status,200);
    const ca = fetched.bytes.toString('base64url');
    assert(fetched.bytes.length > 0 && fetched.bytes.length <= 4096);
    assert(createHash('sha256').update(Buffer.from(ca,'base64url')).digest('base64url') === approved.interceptionCaCertificateSha256,'Authenticated CA matches approved binding');
    control = await originControl(owner,credential,capabilities);
    const flow = await originStream(owner,credential,control,'reference-tun-test',mode === 'http' ? HTTP_ORIGIN_PROXY_MODE : null);
    carrier = new StreamDuplex(flow);
    await connect(carrier,mode === 'http' ? 80 : 443);
    const f = { ca, trackTls: socket => { application = socket; return socket; } };
    application = mode === 'https' ? await innerTls(f,carrier) : carrier;
    const body = Buffer.from(Array.from({length:4096},(_,i) => (i * 31 + 7) & 255));
    await post(application,body); await carrier.join();
    await until(() => owner.snapshot(),s => s.stream?.resourcesReleased && s.backend.activeOwners === 0);
    const state = owner.snapshot();
    assert.equal(state.stream.phase,'complete'); assert.equal(state.stream.clientEofEmitted,true);
    assert.equal(state.stream.gatewayEofEmitted,true); assert.equal(state.stream.streamLease,false);
    assert.equal(state.stream.chargedBytes,0); assert.equal(state.evidence.length,1);
    assert.equal(state.evidence[0].requestBytes,4096); assert.equal(state.evidence[0].responseBytes,81);
    assert(state.evidence[0].requestSha256 === digest(body),'Private actual origin request comparison');
    assert(state.evidence[0].responseSha256 === digest(expectedResponse(body)),'Private actual origin response comparison');
    state.evidence.length = 0; assert.equal(owner.snapshot().evidence.length,1);
  } catch (error) { primary = error; }
  finally {
    await attempt(async () => {
      if (application && application !== carrier) { const ended = observeClose(application); application.destroy(); await ended; }
    });
    if (carrier) await attempt(() => carrier.abort());
    if (control) await attempt(async () => { await control.ws.cancel(); await control.pump; await control.closed; });
    await attempt(async () => {
      const closed = await owner.close(); assert.equal(closed.privateDirectoryRemoved,true);
      assert.equal(closed.backend.activeOwners,0); assert.equal(closed.gateway.closed,true);
      assert.equal(await owner.close(),closed);
      assert.throws(() => owner.metadata(),e => e.code === 'tun_unavailable');
    });
  }
  if (primary || cleanupFailures.length) {
    const failure = primary ?? cleanupFailures.shift();
    if (cleanupFailures.length) throw new AggregateError([failure,...cleanupFailures],'Reference test and cleanup failed');
    throw failure;
  }
});
test('module close seals and joins pending real registration waiter', { timeout:30000 }, async () => {
  const owner = await startReferenceTunFixture();
  const invitation = owner.createInvitation().material();
  const waiting = assert.rejects(owner.waitForRegistered(invitation.invitationId),e => e.code === 'tun_enrollment');
  const closing = owner.close(); assert.throws(() => owner.createInvitation(),e => e.code === 'tun_unavailable');
  await waiting; assert.equal((await closing).privateDirectoryRemoved,true);
});
test('module rejects hostile OpenSSL configuration without provider disclosure', async () => {
  for (const openssl of ['',null,'openssl\nprivate']) await assert.rejects(startReferenceTunFixture({openssl}),e => e instanceof ReferenceTunError && e.code === 'tun_configuration' && !e.message.includes('private'));
});
