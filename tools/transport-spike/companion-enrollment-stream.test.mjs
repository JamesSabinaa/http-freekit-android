import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes, createHash, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { performance } from 'node:perf_hooks';
import { setTimeout as pause } from 'node:timers/promises';
import tls from 'node:tls';
import { ResearchWebSocket } from './research-websocket.mjs';
import { startEnrollmentStreamFixture } from './companion-enrollment-stream.mjs';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { startEnrollmentIssuer } from './companion-enrollment-issuer.mjs';
import { createCompanionStreamServer } from './companion-stream-peer.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enroll, enrolledControl, enrolledStream, upgradeEnrolled, tlsOptions } from './companion-enrollment-stream-client.mjs';
import { until } from './companion-stream-peer-client.mjs';
import { bounded } from './companion-stream-peer-io.mjs';
import { requestHeader, pattern, uploadLength } from './companion-stream-peer-schema.mjs';

async function fixture(t, options = {}) {
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-enrolled-stream-'));
  fs.chmodSync(directory, 0o700);
  const owner = await startEnrollmentStreamFixture({ directory, mode: 'create', ...options }), clients = [];
  t.after(async () => {
    const result = await owner.close();
    await Promise.all(clients.map(async client => { await client.ws?.cancel(); await client.pump; }));
    assert(result.storeClosed && result.listenersClosed && result.issuerChildrenJoined);
    assert.equal(result.activeSockets + result.pendingCallbacks + result.pendingTimers + result.workers, 0);
    assert(directory.startsWith(root + path.sep)); fs.rmSync(directory, { recursive: true, force: true });
  });
  return { owner, directory, clients, track(client) { clients.push(client); return client; } };
}
async function blocked(owner, credential, flow) {
  let sendFailure = false, sendComplete = false;
  const sending = (async () => {
    await flow.ws.send('binary', requestHeader('cancel'));
    for (let offset = 0; offset < uploadLength('cancel'); offset += 4096) await flow.ws.send('binary', pattern(offset, Math.min(4096, uploadLength('cancel') - offset)));
    sendComplete = true;
  })().catch(() => { sendFailure = true; });
  let first = null, last, lastObserved;
  const end = performance.now() + 15000;
  while (performance.now() < end) {
    const start = performance.now(), state = owner.inspectEnrollment(credential.enrollmentId), local = flow.ws.snapshot(); const received = performance.now();
    const p = state.probe;
    lastObserved = { proxyPending: p?.io.proxyWritePending, proxyEntries: p?.io.proxyWriteEntries, ingress: p?.io.pendingIngressBytes,
      charged: p?.control.chargedBytes, callbacks: local.pendingWriteCallbacks, localCompleted: local.completedWrites, sendComplete, sendFailure };
    const positive = p?.io.proxyWritePending && p.io.pendingIngressBytes > 0 && p.io.backpressureCount > 0 && p.control.chargedBytes > 0 &&
      local.pendingWriteCallbacks === 1 && !sendComplete && !sendFailure;
    if (positive) {
      if (!first || first.id !== p.io.proxyWriteEntries || first.localCompleted !== local.completedWrites) first = { id: p.io.proxyWriteEntries, localCompleted: local.completedWrites, received };
      else if (start - first.received >= 250) { last = state; break; }
    } else first = null;
    await pause(20);
  }
  assert(last, 'Actual same proxy and client TLS callbacks remain pending across conservative 250ms observations: ' + JSON.stringify(lastObserved));
  assert.equal(sendFailure, false);
  return { sending, state: last };
}
async function closed(owner, id) { return until(() => owner.inspectEnrollment(id), value => value.probe?.cleanup.complete, 6000); }

test('enrolled adapter keeps A22a metadata plus only stream port and redacts inert missing inspection', { timeout: 10000 }, async t => {
  const f = await fixture(t), metadata = f.owner.metadata().material();
  assert.deepEqual(Object.keys(metadata).sort(), ['desktopId','logicalName','gatewayCertificateDer','gatewaySpkiSha256','enrollmentAuthorityDer','interceptionCaCertificateSha256','setupPort','credentialPort','webSocketPort'].sort());
  assert.equal(new Set([metadata.setupPort, metadata.credentialPort, metadata.webSocketPort]).size, 3);
  const first = f.owner.inspectEnrollment('unknown'); assert.equal(first.found, false); assert.equal(first.probe, null); assert.equal(first.controlsAdmitted, 0);
  first.terminalNotification.attempted = true; assert.equal(f.owner.inspectEnrollment('unknown').terminalNotification.attempted, false);
  const output = inspect(f.owner) + JSON.stringify(f.owner);
  for (const secret of [f.directory, metadata.desktopId, metadata.gatewayCertificateDer, metadata.gatewaySpkiSha256]) assert(!output.includes(secret));
  const credential = await enroll(f.owner, createCryptoFixture()), control = f.track(await enrolledControl(f.owner, credential));
  const flow = f.track(await enrolledStream(f.owner, credential, control)), options = tlsOptions(f.owner, credential, metadata.webSocketPort);
  const holders = { credential, control, flow, options };
  const diagnostics = inspect(holders, { depth: Infinity }) + JSON.stringify(holders);
  for (const secret of [credential.key, credential.cert, credential.enrollmentId, credential.approved.deviceId, metadata.desktopId,
    metadata.logicalName, control.token, control.ready.sessionId, 'BEGIN PRIVATE KEY', 'BEGIN CERTIFICATE']) assert(!diagnostics.includes(secret));
  assert.deepEqual(JSON.parse(JSON.stringify(holders)), { credential: { kind: 'EnrolledHostCredential' },
    control: { kind: 'EnrolledHostConnection' }, flow: { kind: 'EnrolledHostConnection' }, options: { kind: 'EnrolledHostTlsOptions' } });
  assert(options.key === credential.key && options.cert === credential.cert);
  assert(control.token === control.ready.sessionId); assert.equal(flow.socket.destroyed, false);
  for (const bad of [{ logicalName: 'host.invalid\n' }, { credentialAuthority: null }]) {
    await assert.rejects(createCompanionStreamServer({ tls: {}, authorize: () => true, ...bad }), e => e.code === 'stream_fixture_configuration');
  }
});

test('committed revoke invalidates blocked A synchronously, sends actual disconnect, preserves independent B and joins original charges', { timeout: 25000 }, async t => {
  const f = await fixture(t), a = await enroll(f.owner, createCryptoFixture()), b = await enroll(f.owner, createCryptoFixture());
  const controlA = f.track(await enrolledControl(f.owner, a)), flowA = f.track(await enrolledStream(f.owner, a, controlA));
  const controlB = f.track(await enrolledControl(f.owner, b)), flowB = f.track(await enrolledStream(f.owner, b, controlB));
  assert.equal(controlA.ready.desktopId, f.owner.metadata().material().desktopId);
  const held = await blocked(f.owner, a, flowA);
  f.owner.revoke(a.enrollmentId);
  const immediate = f.owner.inspectEnrollment(a.enrollmentId);
  assert.equal(immediate.probe.control.cause, 'device_revoked'); assert.equal(immediate.grantValid, false);
  assert.equal(immediate.probe.control.sessionLease, true); assert(immediate.probe.control.chargedBytes > 0);
  const writes = immediate.applicationWriteAdmissions;
  await held.sending;
  const clean = await closed(f.owner, a.enrollmentId); await controlA.pump;
  assert.equal(controlA.disconnect, 'device_revoked'); assert(clean.terminalNotification.attempted && clean.terminalNotification.completed);
  assert.equal(clean.terminalNotification.aborted, false); assert.equal(clean.applicationWriteAdmissions, writes); assert.equal(clean.writesAfterInvalidation, 0);
  assert.equal(clean.probe.io.retainedBytesAtAbort, 8192); assert.equal(clean.probe.pool.sessionLeases, 1);
  assert.equal(f.owner.inspectEnrollment(b.enrollmentId).probe.control.phase, 'active');
  await flowB.ws.send('binary', requestHeader('cancel'));
  await until(() => f.owner.inspectEnrollment(b.enrollmentId), v => v.probe.io.proxyWriteCompletions > 0);
  assert.equal((await upgradeEnrolled(f.owner, a, '/companion/v1/control')).status, 403);
  assert.equal((await upgradeEnrolled(f.owner, a, '/companion/v1/streams', { token: controlA.token })).status, 403);
});

test('CA-valid same-key substitute cannot attach to or replace the original exact-leaf grant', { timeout: 15000 }, async t => {
  const f = await fixture(t), crypto = createCryptoFixture(), credential = await enroll(f.owner, crypto);
  const control = f.track(await enrolledControl(f.owner, credential)), flow = f.track(await enrolledStream(f.owner, credential, control));
  const m = f.owner.metadata().material(), issuer = await startEnrollmentIssuer({ directory: f.directory, enrollmentAuthorityDer: m.enrollmentAuthorityDer });
  let other;
  try {
    const now = Math.floor(Date.now() / 1000) * 1000;
    const candidate = await issuer.issue({ material: () => ({ desktopId: m.desktopId, invitationId: 'same-key-research', enrollmentId: credential.enrollmentId,
      deviceId: credential.approved.deviceId, generation: 1, token: randomBytes(32).toString('base64url'), serial: '999', deviceSpkiDer: crypto.deviceSpkiDer.toString('base64url'),
      deviceSpkiSha256: createHash('sha256').update(crypto.deviceSpkiDer).digest('base64url'), csrDer: crypto.csr().toString('base64url'), capabilities: ['tcp-http'],
      notBefore: new Date(now).toISOString().replace('.000Z','Z'), notAfter: new Date(now + 60000).toISOString().replace('.000Z','Z'), subject: 'CN=HTTP FreeKit device', profile: 'p256-client-auth-v1' }) });
    other = { ...credential, cert: new X509Certificate(Buffer.from(candidate.material().clientCertificateDer, 'base64url')).toString() };
  } finally { await issuer.close(); }
  assert.equal((await upgradeEnrolled(f.owner, other, '/companion/v1/streams', { token: control.token })).status, 403);
  assert.equal((await upgradeEnrolled(f.owner, other, '/companion/v1/control')).status, 403);
  assert.equal(f.owner.inspectEnrollment(credential.enrollmentId).probe.stream.phase, 'open');
  await flow.ws.send('binary', requestHeader('cancel'));
  await until(() => f.owner.inspectEnrollment(credential.enrollmentId), v => v.probe.io.proxyWriteCompletions > 0);
});

test('real 60-second credential clips 120-second readiness, expires blocked I/O and refuses fresh TLS credential use', { timeout: 75000 }, async t => {
  const f = await fixture(t), a = await enroll(f.owner, createCryptoFixture()), control = f.track(await enrolledControl(f.owner, a));
  const flow = f.track(await enrolledStream(f.owner, a, control)), held = await blocked(f.owner, a, flow);
  const leafExpiry = Date.parse(new X509Certificate(a.cert).validTo);
  assert.equal(Date.parse(control.ready.expiresAt), leafExpiry);
  assert(leafExpiry - held.state.probe.timing.readyUtcMillis > 50000);
  const terminal = await until(() => f.owner.inspectEnrollment(a.enrollmentId), v => v.probe.control.cause === 'session_expired', 65000);
  assert(Date.now() >= leafExpiry || terminal.probe.timing.terminalElapsedMillis >= leafExpiry - terminal.probe.timing.readyUtcMillis);
  await held.sending;
  const clean = await closed(f.owner, a.enrollmentId); assert.equal(clean.writesAfterInvalidation, 0);
  assert.equal(f.owner.readResult(a.enrollmentId).material().code, 'credential_expired');
  const afterExpiryRevoke = f.owner.revoke(a.enrollmentId).material(); assert.equal(afterExpiryRevoke.code, 'credential_expired');
  const preserved = f.owner.inspectEnrollment(a.enrollmentId);
  assert.notEqual(preserved.invalidationCause, 'device_revoked'); assert.equal(preserved.probe.control.cause, 'session_expired');
  assert.equal(preserved.terminalNotification.attempted, false);
  assert.equal(clean.probe.control.sessionLease, false); assert.equal(clean.probe.control.chargedBytes, 0); assert(clean.probe.io.retainedBytesAtAbort > 0);
  await assert.rejects(upgradeEnrolled(f.owner, a, '/companion/v1/control'));
});

test('real 15-second session deadline releases the old owner but preserves its evidence and still-valid credential for a fresh control', { timeout: 30000 }, async t => {
  const f = await fixture(t, { sessionLifetimeMillis: 15000 }), a = await enroll(f.owner, createCryptoFixture());
  const control = f.track(await enrolledControl(f.owner, a)), flow = f.track(await enrolledStream(f.owner, a, control)), held = await blocked(f.owner, a, flow);
  const readyExpiry = Date.parse(control.ready.expiresAt), leafExpiry = Date.parse(new X509Certificate(a.cert).validTo);
  assert(readyExpiry < leafExpiry); assert(readyExpiry - held.state.probe.timing.readyUtcMillis <= 15000);
  await until(() => f.owner.inspectEnrollment(a.enrollmentId), v => v.probe.control.cause === 'session_expired', 16000);
  await held.sending; const clean = await closed(f.owner, a.enrollmentId);
  assert.equal(clean.grantValid, true); assert.equal(clean.probe.control.cause, 'session_expired'); assert.equal(clean.probe.control.sessionLease, false);
  assert.equal((await upgradeEnrolled(f.owner, a, '/companion/v1/streams', { token: control.token })).status, 403);
  const fresh = f.track(await enrolledControl(f.owner, a)); assert.notEqual(fresh.token, control.token);
  const retained = f.owner.inspectEnrollment(a.enrollmentId); assert.equal(retained.controlsAdmitted, 2);
  // Original-owner evidence is retained; the freshly sampled GLOBAL pool includes the new session.
  assert.deepEqual({ ...retained.probe, pool: null }, { ...clean.probe, pool: null });
  assert.equal(retained.probe.pool.sessionLeases, 1);
  assert.equal(retained.writesAfterInvalidation, 0); assert(Date.now() < leafExpiry);
});

test('actual active fixture shutdown joins streaming sockets and callbacks before releasing its durable Store', { timeout: 15000 }, async t => {
  const f = await fixture(t), a = await enroll(f.owner, createCryptoFixture()), control = f.track(await enrolledControl(f.owner, a));
  const flow = f.track(await enrolledStream(f.owner, a, control)), held = await blocked(f.owner, a, flow);
  const result = await f.owner.close(); await held.sending;
  assert(result.storeClosed && result.stream.listeners === 0);
  assert.equal(result.stream.sessionLeases + result.stream.streamLeases + result.stream.chargedBytes, 0);
  assert.equal(result.stream.workers + result.stream.timers + result.stream.pendingCallbacks, 0);
});

test('an injected live Store authorization error closes both real TLS owners as unavailable without forwarding or inventing revocation', { timeout: 15000 }, async () => {
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-enrolled-fault-')); fs.chmodSync(directory, 0o700);
  let service, fault = false, owner; const clients = [];
  try {
    owner = await startEnrollmentHttpsFixture({ directory, mode: 'create', credentialLifetimeSeconds: 60,
      authenticatedServiceFactory: async ({ tls, metadata, authorizeCertificate }) => {
        service = await createCompanionStreamServer({ tls, authorize: socket => socket.authorized,
          desktopId: metadata.desktopId, logicalName: metadata.logicalName,
          credentialAuthority: { gatewayExpiresAt: new X509Certificate(Buffer.from(metadata.gatewayCertificateDer, 'base64url')).validTo,
            authorizeCertificate: raw => { if (fault) throw Error('Injected storage unavailability'); return authorizeCertificate(raw); } } });
        return service;
      } });
    const wrapper = { metadata: () => ({ material: () => ({ ...owner.metadata().material(), webSocketPort: service.port }) }),
      createInvitation: () => owner.createInvitation(), approve: id => owner.approve(id) };
    const a = await enroll(wrapper, createCryptoFixture()), b = await enroll(wrapper, createCryptoFixture());
    const ca = await enrolledControl(wrapper, a), cb = await enrolledControl(wrapper, b); clients.push(ca, cb);
    const fa = await enrolledStream(wrapper, a, ca), fb = await enrolledStream(wrapper, b, cb); clients.push(fa, fb);
    const before = [a,b].map(c => service.inspectEnrollment(c.enrollmentId).applicationWriteAdmissions);
    fault = true;
    await fa.ws.send('binary', requestHeader('cancel')).catch(() => {});
    await until(() => service.inspectEnrollment(a.enrollmentId), v => v.probe.cleanup.complete);
    await until(() => service.inspectEnrollment(b.enrollmentId), v => v.probe.cleanup.complete);
    for (const [index,c] of [a,b].entries()) {
      const state = service.inspectEnrollment(c.enrollmentId);
      assert.equal(state.available, false); assert.equal(state.invalidationCause, 'network_unreachable');
      assert.equal(state.probe.control.cause, 'network_unreachable'); assert.equal(state.probe.fixture.uploadBytesRead, 0);
      assert.equal(state.applicationWriteAdmissions, before[index]); assert.equal(state.writesAfterInvalidation, 0);
      assert.equal(state.terminalNotification.attempted, false);
    }
    assert.throws(() => owner.createInvitation(), e => e.code === 'pairing_unavailable');
    assert.equal((await upgradeEnrolled(wrapper, a, '/companion/v1/control')).status, 400);
  } finally {
    if (owner) { const final = await owner.close(); assert(final.storeClosed && final.activeSockets === 0); }
    await Promise.all(clients.map(async c => { await c.ws.cancel(); await c.pump; }));
    assert(directory.startsWith(root + path.sep)); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('same-key re-enrollment after revoke has a new durable grant and cannot reuse the revoked session', { timeout: 15000 }, async t => {
  const f = await fixture(t), crypto = createCryptoFixture(), a = await enroll(f.owner, crypto);
  const ca = f.track(await enrolledControl(f.owner, a));
  f.owner.revoke(a.enrollmentId); await closed(f.owner, a.enrollmentId);
  const b = await enroll(f.owner, crypto); assert.notEqual(a.approved.deviceId, b.approved.deviceId);
  const cb = f.track(await enrolledControl(f.owner, b));
  assert.equal((await upgradeEnrolled(f.owner, b, '/companion/v1/streams', { token: ca.token })).status, 403);
  assert.equal((await upgradeEnrolled(f.owner, a, '/companion/v1/streams', { token: cb.token })).status, 403);
  assert.equal(f.owner.inspectEnrollment(a.enrollmentId).probe.control.cause, 'device_revoked');
  assert.equal(f.owner.inspectEnrollment(b.enrollmentId).probe.control.phase, 'active');
});

test('authenticated service startup failure joins listeners, issuer and Store and permits exact identity reopen', { timeout: 15000 }, async () => {
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-enrolled-start-')); fs.chmodSync(directory, 0o700);
  try {
    await assert.rejects(startEnrollmentHttpsFixture({ directory, mode: 'create', credentialLifetimeSeconds: 60,
      authenticatedServiceFactory: async () => { throw Error('Injected service startup failure'); } }), e => e.code === 'pairing_unavailable' && e.joined);
    const metadata = JSON.parse(fs.readFileSync(path.join(directory, 'enrollment-fixture.json')));
    const reopened = await startEnrollmentStreamFixture({ directory, mode: 'open', setupPort: metadata.setupPort, credentialPort: metadata.credentialPort });
    assert.equal(reopened.metadata().material().gatewaySpkiSha256, metadata.gatewaySpkiSha256);
    const final = await reopened.close(); assert(final.storeClosed && final.listenersClosed && final.issuerChildrenJoined);
  } finally { assert(directory.startsWith(root + path.sep)); fs.rmSync(directory, { recursive: true, force: true }); }
});

test('enrolled WSS requires a client certificate and refuses offered TLS1.2/1.3 sessions before revalidating the exact leaf', { timeout: 15000 }, async t => {
  const f = await fixture(t), a = await enroll(f.owner, createCryptoFixture());
  await assert.rejects(upgradeEnrolled(f.owner, null, '/companion/v1/control'));
  for (const version of ['TLSv1.2', 'TLSv1.3']) {
    const first = f.track(await upgradeEnrolled(f.owner, a, '/companion/v1/control', { minVersion: version, maxVersion: version }));
    let session = first.socket.getSession();
    first.socket.on('session', value => { session = Buffer.from(value); });
    await pause(30);
    assert(Buffer.isBuffer(session) && session.length > 0, 'Actual prior provider session offered');
    assert.equal(first.socket.isSessionReused(), false); await first.ws.cancel();
    await until(() => f.owner.snapshot(), v => v.stream.authenticatedSockets === 0);
    const second = f.track(await upgradeEnrolled(f.owner, a, '/companion/v1/control', { minVersion: version, maxVersion: version, session }));
    assert.equal(second.status, 101); assert.equal(second.socket.isSessionReused(), false); await second.ws.cancel();
    await until(() => f.owner.snapshot(), v => v.stream.authenticatedSockets === 0);
  }
});

test('actual control close during terminal notification aborts its callback owner without delaying synchronous revoke or claiming delivery', { timeout: 15000 }, async t => {
  const f = await fixture(t), a = await enroll(f.owner, createCryptoFixture()), control = f.track(await enrolledControl(f.owner, a));
  f.track(await enrolledStream(f.owner, a, control));
  const original = tls.TLSSocket.prototype.write, port = f.owner.metadata().material().webSocketPort;
  let intercepted = false, resolveAttempt;
  const attempted = new Promise(resolve => { resolveAttempt = resolve; });
  tls.TLSSocket.prototype.write = function (...args) {
    const bytes = args[0];
    if (!intercepted && this.localPort === port && Buffer.isBuffer(bytes) && bytes.includes(Buffer.from('device_revoked'))) {
      intercepted = true;
      // Delay this actual TLS write until the peer has really closed. Its real
      // callback is still invoked by Node; no successful completion is fabricated.
      this.once('close', () => { original.apply(this, args); resolveAttempt(); });
      control.socket.destroy();
      return false;
    }
    return original.apply(this, args);
  };
  try {
    f.owner.revoke(a.enrollmentId);
    const immediate = f.owner.inspectEnrollment(a.enrollmentId);
    assert.equal(immediate.probe.control.cause, 'device_revoked'); assert.equal(immediate.grantValid, false);
    await bounded(attempted, 3000);
    const clean = await closed(f.owner, a.enrollmentId);
    assert(intercepted && clean.terminalNotification.attempted && clean.terminalNotification.aborted);
    assert.equal(clean.terminalNotification.completed, false); assert.equal(clean.writesAfterInvalidation, 0);
    assert.equal(clean.probe.cleanup.pendingCallbacks + clean.probe.cleanup.workers + clean.probe.cleanup.timers, 0);
  } finally { tls.TLSSocket.prototype.write = original; }
});

test('fresh enrolled control awaits the prior terminal owner real join and rechecks admission before allocating', { timeout: 15000 }, async t => {
  const f = await fixture(t, { sessionLifetimeMillis: 2000 }), a = await enroll(f.owner, createCryptoFixture());
  const control = f.track(await enrolledControl(f.owner, a));
  const original = ResearchWebSocket.prototype.cancel;
  let release, actualJoined, intercepted = false, settled = false;
  const gate = new Promise(resolve => { release = resolve; }), joined = new Promise(resolve => { actualJoined = resolve; });
  ResearchWebSocket.prototype.cancel = function () {
    const result = original.call(this);
    if (this !== control.ws && !intercepted) {
      intercepted = true;
      // The actual transport/reader/writer join finishes first. Delay its owner
      // publication to deterministically expose the pre-admission lifecycle race.
      return result.then(async () => { actualJoined(); await gate; });
    }
    return result;
  };
  try {
    await bounded(joined, 4000);
    const held = f.owner.inspectEnrollment(a.enrollmentId);
    assert.equal(held.probe.control.cause, 'session_expired'); assert.equal(held.probe.control.sessionLease, true);
    const pending = enrolledControl(f.owner, a).then(value => { settled = true; return value; });
    pending.catch(() => {});
    await pause(50); assert.equal(settled, false); assert.equal(f.owner.inspectEnrollment(a.enrollmentId).controlsAdmitted, 1);
    assert(f.owner.snapshot().stream.workers > 0, 'Pre-owner upgrade remains owned while awaiting cleanup');
    release(); const fresh = f.track(await pending);
    assert.equal(fresh.status, 101); assert.equal(f.owner.inspectEnrollment(a.enrollmentId).controlsAdmitted, 2);
  } finally { release(); ResearchWebSocket.prototype.cancel = original; }
});

test('global close joins a pre-owner upgrade waiting on prior cleanup and refuses late admission before Store release', { timeout: 15000 }, async t => {
  const f = await fixture(t, { sessionLifetimeMillis: 2000 }), a = await enroll(f.owner, createCryptoFixture());
  const control = f.track(await enrolledControl(f.owner, a)), original = ResearchWebSocket.prototype.cancel;
  let release, actualJoined, intercepted = false;
  const gate = new Promise(resolve => { release = resolve; }), joined = new Promise(resolve => { actualJoined = resolve; });
  ResearchWebSocket.prototype.cancel = function () {
    const result = original.call(this);
    if (this !== control.ws && !intercepted) { intercepted = true; return result.then(async () => { actualJoined(); await gate; }); }
    return result;
  };
  try {
    await bounded(joined, 4000);
    const pending = upgradeEnrolled(f.owner, a, '/companion/v1/control'); pending.catch(() => {});
    await until(() => f.owner.snapshot(), v => v.stream.workers >= 1);
    let closed = false; const closing = f.owner.close().then(value => { closed = true; return value; });
    await pause(30); assert.equal(closed, false); assert.equal(f.owner.snapshot().storeClosed, false);
    release(); const final = await closing; await assert.rejects(pending);
    assert.equal(f.owner.inspectEnrollment(a.enrollmentId).controlsAdmitted, 1);
    assert(final.storeClosed && final.listenersClosed); assert.equal(final.workers + final.pendingCallbacks + final.pendingTimers + final.activeSockets, 0);
  } finally { release(); ResearchWebSocket.prototype.cancel = original; }
});
