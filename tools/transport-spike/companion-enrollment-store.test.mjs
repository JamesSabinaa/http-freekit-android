import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspect } from 'node:util';
import { randomBytes, sign } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createEnrollmentStore, openEnrollmentStore } from './companion-enrollment-store.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';

const reject = (code, work) => assert.throws(work, e => e.code === code && e.cause === undefined && !inspect(e).includes('file:'));
function fixture(t, overrides = {}) {
  const crypto = createCryptoFixture(), directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-enrollment-store-'));
  let utcMillis = crypto.utcMillis, monotonicMillis = 0, owner;
  const metadata = { desktopId: 'desktop_fixture', gatewaySpkiSha256: randomBytes(32).toString('base64url'), enrollmentAuthorityDer: crypto.caDer.toString('base64url'), interceptionCaCertificateSha256: randomBytes(32).toString('base64url'), supportedCapabilities: ['tcp', 'http'], credentialLifetimeSeconds: 3600, ...overrides };
  const options = { directory, metadata, clock: () => ({ utcMillis, monotonicMillis }) }, jobs = [];
  const api = { crypto, directory, metadata, options, jobs,
    get store() { return owner; }, create: () => owner = createEnrollmentStore(options), open: () => owner = openEnrollmentStore(options),
    advance: (ms, wall = true) => { monotonicMillis += ms; if (wall) utcMillis += ms; },
    setClock: (utc, mono) => { utcMillis = utc; monotonicMillis = mono; },
    reserve: (key = crypto, name = 'Fixture device', capabilities = ['tcp']) => { const invitation = owner.createInvitation().material(); const pair = { desktopId: metadata.desktopId, ...invitation, csrDer: key.csr().toString('base64url'), deviceName: name, capabilities }; return { pair, invitation, registration: owner.reserve(pair).material() }; },
    job: eid => { const result = owner.beginApproval(eid); if (result.kind === 'job') jobs.push(result.job); return result; },
    candidate: job => { const m = job.material(); return crypto.certificate({ serial: m.serial, notBefore: Date.parse(m.notBefore), notAfter: Date.parse(m.notAfter) }); },
  };
  t.after(() => { for (const job of jobs) { try { owner?.abandon(job); } catch {} } try { owner?.close(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } });
  return api;
}

test('explicit initialization, reserve, exact publication, lost-response reopen and exact allowlist', t => {
  const f = fixture(t); f.create(); const { registration } = f.reserve();
  assert.equal(f.store.readResult(registration.enrollmentId).material().type, 'pair_pending');
  const { job } = f.job(registration.enrollmentId), candidate = f.candidate(job);
  assert.equal(f.store.authorizeCertificate(candidate), null);
  const published = f.store.publish(job, candidate).material(); assert.equal(published.type, 'pair_approved');
  assert.equal(f.store.authorizeCertificate(candidate).material().deviceId, published.deviceId);
  assert.equal(f.store.authorizeCertificate(f.crypto.certificate({ serial: 999 })), null);
  assert.equal(f.job(registration.enrollmentId).kind, 'approved');
  f.store.close(); f.open(); assert.deepEqual(f.store.readResult(registration.enrollmentId).material(), published);
  assert.equal(f.store.authorizeCertificate(candidate).material().clientCertificateSha256.length, 43);
});
test('same validated key with different CSR signature resumes immutable first review; conflict and metadata precedence', t => {
  const f = fixture(t); f.create(); const { pair, registration } = f.reserve();
  const first = f.store.getBinding(f.metadata.desktopId, pair.invitationId, registration.enrollmentId).material();
  assert.deepEqual(f.store.reserve({ ...pair, csrDer: f.crypto.csr().toString('base64url') }).material(), registration);
  reject('invalid_message', () => f.store.reserve({ ...pair, deviceName: 'Changed' }));
  reject('invitation_used', () => f.store.reserve({ ...pair, csrDer: createCryptoFixture().csr().toString('base64url'), deviceName: 'Changed' }));
  assert.deepEqual(f.store.getBinding(f.metadata.desktopId, pair.invitationId, registration.enrollmentId).material(), first);
  f.advance(1000); reject('invitation_used', () => f.reserve());
});
test('invitation authentication and deadline gates precede CSR/quota; shared CSR/proof budget rolls at exact boundary', t => {
  const f = fixture(t); f.create(); const { pair, registration } = f.reserve();
  for (let i = 0; i < 20; i++) reject('authentication_failed', () => f.store.reserve({ ...pair, invitationSecret: randomBytes(32).toString('base64url'), csrDer: 'bad' }));
  const payload = Buffer.from('proof context'), signature = sign('sha256', payload, f.crypto.device.privateKey);
  for (let i = 0; i < 3; i++) assert(f.store.verifyProof(registration.enrollmentId, payload, signature));
  reject('pairing_limit', () => f.store.reserve(pair)); f.advance(1000); assert(f.store.verifyProof(registration.enrollmentId, payload, signature));
  const invitation = f.store.createInvitation().material(); f.advance(300000);
  reject('invitation_expired', () => f.store.reserve({ ...pair, ...invitation, csrDer: 'bad' }));
});
test('issuing intent recovers with same device but fresh generation, token and never-reused serial', t => {
  const f = fixture(t); f.create(); const { registration } = f.reserve(); const a = f.job(registration.enrollmentId).job;
  reject('pairing_limit', () => f.store.beginApproval(registration.enrollmentId)); f.store.abandon(a);
  const b = f.job(registration.enrollmentId).job; assert.equal(a.material().deviceId, b.material().deviceId);
  assert.notEqual(a.material().token, b.material().token); assert.equal(Number(b.material().serial), Number(a.material().serial) + 1);
  reject('authentication_failed', () => f.store.publish(a, f.candidate(a))); f.store.abandon(b); f.store.close(); f.open();
  const c = f.job(registration.enrollmentId).job; assert.equal(c.material().deviceId, a.material().deviceId); assert(Number(c.material().serial) > Number(b.material().serial));
});
test('reject/cancel/revoke races invalidate exact issuer candidates and preserve first terminal decision', t => {
  for (const operation of ['reject', 'cancel', 'revoke']) {
    const f = fixture(t); f.create(); const { registration } = f.reserve(); const job = f.job(registration.enrollmentId).job;
    const ended = f.store[operation](registration.enrollmentId).material(); reject('authentication_failed', () => f.store.publish(job, f.candidate(job)));
    assert.deepEqual(f.store.cancel(registration.enrollmentId).material(), ended); assert.equal(f.store.authorizeCertificate(f.candidate(job)), null);
    reject('invitation_used', () => f.store.beginApproval(registration.enrollmentId));
  }
});
test('cancellation after publication revokes only exact grant and stale leaf never authorizes reenrollment', t => {
  const f = fixture(t); f.create(); const a = f.reserve(), job = f.job(a.registration.enrollmentId).job, candidate = f.candidate(job);
  f.store.publish(job, candidate); f.store.cancel(a.registration.enrollmentId); assert.equal(f.store.authorizeCertificate(candidate), null);
  f.advance(1000); const b = f.reserve(), bjob = f.job(b.registration.enrollmentId).job, bcert = f.candidate(bjob); f.store.publish(bjob, bcert);
  f.store.revoke(a.registration.enrollmentId); assert(f.store.authorizeCertificate(bcert)); assert.equal(f.store.authorizeCertificate(candidate), null);
});
test('invalid signed candidate settles local handle without changing durable intent and forged jobs fail', t => {
  const f = fixture(t); f.create(); const { registration } = f.reserve(), job = f.job(registration.enrollmentId).job;
  reject('authentication_failed', () => f.store.publish(job, f.crypto.certificate({ serial: 999 })));
  reject('authentication_failed', () => f.store.publish({ material: () => job.material() }, f.candidate(job)));
  const retry = f.job(registration.enrollmentId).job; assert(Number(retry.material().serial) > Number(job.material().serial));
  f.store.abandon(retry); f.store.abandon(retry);
});
test('close denies auth immediately, retains exclusive owner through jobs, and allows joined abandon then retry', t => {
  const f = fixture(t); f.create(); const { registration } = f.reserve(), job = f.job(registration.enrollmentId).job;
  reject('pairing_unavailable', () => f.store.close()); reject('pairing_unavailable', () => f.store.now());
  reject('pairing_unavailable', () => openEnrollmentStore(f.options)); reject('pairing_unavailable', () => f.store.publish(job, f.candidate(job)));
  f.store.abandon(job); f.store.close(); f.open(); assert.equal(f.store.readResult(registration.enrollmentId).material().type, 'pair_pending');
});
test('frozen UTC cannot extend live reservation, result deadline suppresses cancellation, expiry wins over later revoke', t => {
  const f = fixture(t); f.create(); const { registration } = f.reserve(); f.advance(300000, false);
  assert.equal(f.store.readResult(registration.enrollmentId).material().code, 'invitation_expired');
  reject('invitation_expired', () => f.store.beginApproval(registration.enrollmentId));
  assert.equal(f.store.revoke(registration.enrollmentId).material().code, 'invitation_expired');
  f.advance(3300000, false); assert.equal(f.store.cancel(registration.enrollmentId).material().code, 'result_expired');
  assert.equal(f.store.getBinding(f.metadata.desktopId, f.store.getBinding(f.metadata.desktopId, registration.invitationId, registration.enrollmentId).material().invitationId, registration.enrollmentId).material().resultExpiresAt, registration.resultExpiresAt);
});
test('credential expiry and delivery expiry are independent and expired history reopens structurally', t => {
  const f = fixture(t, { credentialLifetimeSeconds: 7200 }); f.create(); const { registration } = f.reserve(), job = f.job(registration.enrollmentId).job, candidate = f.candidate(job);
  f.store.publish(job, candidate); f.advance(3600000); assert.equal(f.store.readResult(registration.enrollmentId).material().code, 'result_expired');
  assert(f.store.authorizeCertificate(candidate)); f.store.cancel(registration.enrollmentId); assert(f.store.authorizeCertificate(candidate));
  f.advance(3600000); assert.equal(f.store.authorizeCertificate(candidate), null); f.store.readResult(registration.enrollmentId); f.store.close(); f.open(); assert.equal(f.store.authorizeCertificate(candidate), null);
});
test('clock rollback latches unavailable; read-only clocks do not persist and cleanup bypasses latch', t => {
  const f = fixture(t); f.create(); const { registration } = f.reserve(), job = f.job(registration.enrollmentId).job;
  f.advance(100); f.store.now(); f.setClock(f.crypto.utcMillis, 99); reject('pairing_unavailable', () => f.store.now());
  reject('pairing_unavailable', () => f.store.authorizeCertificate(Buffer.of(1))); f.store.abandon(job); f.store.close();
  f.setClock(f.crypto.utcMillis, 0); f.open(); assert.equal(f.store.readResult(registration.enrollmentId).material().type, 'pair_pending');
});
test('explicit create/open fail closed for missing, empty, wrong identity and corruption without resetting', t => {
  const f = fixture(t); reject('pairing_unavailable', () => openEnrollmentStore(f.options)); f.create();
  reject('pairing_unavailable', () => createEnrollmentStore(f.options)); f.store.close();
  reject('pairing_unavailable', () => openEnrollmentStore({ ...f.options, metadata: { ...f.metadata, desktopId: 'other' } }));
  const file = path.join(f.directory, 'enrollment.sqlite'), before = fs.readFileSync(file);
  fs.writeFileSync(file, Buffer.alloc(0)); reject('pairing_unavailable', () => openEnrollmentStore(f.options)); assert.equal(fs.statSync(file).size, 0);
  fs.writeFileSync(file, before); const db = new DatabaseSync(file); db.exec('PRAGMA ignore_check_constraints=ON; UPDATE meta SET version=2'); db.close();
  reject('pairing_unavailable', () => openEnrollmentStore(f.options));
});
test('schema tampering, oversized public BLOB and nonregular DB are rejected before material access', t => {
  const f = fixture(t); f.create(); const { registration } = f.reserve(); f.store.close();
  const filename = path.join(f.directory, 'enrollment.sqlite'), db = new DatabaseSync(filename);
  db.exec('PRAGMA ignore_check_constraints=ON'); db.prepare('UPDATE enrollments SET csr=? WHERE id=?').run(Buffer.alloc(5000), registration.enrollmentId); db.close();
  reject('pairing_unavailable', () => openEnrollmentStore(f.options));
  const g = fixture(t); g.create(); g.store.close(); const gdb = new DatabaseSync(path.join(g.directory, 'enrollment.sqlite')); gdb.exec('CREATE TABLE unexpected(id INTEGER) STRICT'); gdb.close(); reject('pairing_unavailable', () => openEnrollmentStore(g.options));
});
test('snapshots/errors/default diagnostics contain no names, paths, secrets or public certificate bytes', t => {
  const f = fixture(t); f.create(); const invitation = f.store.createInvitation(), material = invitation.material(); material.invitationSecret = 'changed';
  for (const text of [inspect(f.store), JSON.stringify(f.store), inspect(invitation), JSON.stringify(invitation)]) { assert(!text.includes(f.directory)); assert(!text.includes(invitation.material().invitationSecret)); assert(!text.includes(f.metadata.enrollmentAuthorityDer)); }
  assert.notEqual(invitation.material().invitationSecret, material.invitationSecret);
});
test('held binding reconstruction remains possible while new challenges use exact monotonic result deadline', t => {
  const f = fixture(t); f.create(); const { registration, pair } = f.reserve();
  const observed = f.store.getBinding(f.metadata.desktopId, pair.invitationId, registration.enrollmentId, { requireLiveResult: true });
  const copy = observed.observedAt(); copy.utcMillis = 0; assert.equal(observed.observedAt().utcMillis, f.crypto.utcMillis);
  f.advance(3600000, false); assert.equal(observed.observedAt().monotonicMillis, 0);
  assert.equal(f.store.getBinding(f.metadata.desktopId, pair.invitationId, registration.enrollmentId).material().enrollmentId, registration.enrollmentId);
  reject('authentication_failed', () => f.store.getBinding(f.metadata.desktopId, pair.invitationId, registration.enrollmentId, { requireLiveResult: true }));
});
test('same-key CSR retry crossing result deadline is refused after fresh verification clock', t => {
  const f = fixture(t); f.create(); const { pair } = f.reserve(); f.store.close();
  let crossing = false, observations = 0;
  f.options.clock = () => ({ utcMillis: f.crypto.utcMillis + (crossing && ++observations > 1 ? 3600000 : 0), monotonicMillis: crossing && observations > 1 ? 3600000 : 0 });
  f.open(); crossing = true; reject('invitation_used', () => f.store.reserve(pair));
});
test('business SQL failure rolls back partial publication and latches unavailable instead of cached authorization', t => {
  const f = fixture(t); f.create(); const { registration } = f.reserve(), job = f.job(registration.enrollmentId).job, candidate = f.candidate(job);
  const original = DatabaseSync.prototype.prepare;
  DatabaseSync.prototype.prepare = function (sql) { if (sql.startsWith('INSERT INTO credentials')) return { run() { throw Object.assign(Error('private injected SQL failure'), { code: 'ERR_SQLITE_ERROR', errcode: 13 }); } }; return original.call(this, sql); };
  try { reject('pairing_unavailable', () => f.store.publish(job, candidate)); } finally { DatabaseSync.prototype.prepare = original; }
  reject('pairing_unavailable', () => f.store.authorizeCertificate(candidate)); f.store.abandon(job); f.store.close(); f.open();
  assert.equal(f.store.readResult(registration.enrollmentId).material().type, 'pair_pending'); assert.equal(f.store.authorizeCertificate(candidate), null);
  const retry = f.job(registration.enrollmentId).job; assert.equal(retry.material().serial, '2');
});
test('bounded invitation capacity refuses without eviction and only unused expired invitations are pruned', t => {
  const f = fixture(t); f.create(); for (let i = 0; i < 64; i++) f.store.createInvitation();
  reject('pairing_limit', () => f.store.createInvitation()); f.advance(300000); assert(f.store.createInvitation());
});
test('a later recovered job receives its own exact credential monotonic expiry anchor', t => {
  const f = fixture(t); f.create(); const { registration, pair } = f.reserve(), first = f.job(registration.enrollmentId).job;
  f.store.getBinding(f.metadata.desktopId, pair.invitationId, registration.enrollmentId); f.store.abandon(first); f.advance(100000);
  const later = f.job(registration.enrollmentId).job, candidate = f.candidate(later); f.store.publish(later, candidate);
  f.advance(3500000); assert(f.store.authorizeCertificate(candidate)); f.advance(100000); assert.equal(f.store.authorizeCertificate(candidate), null);
});
test('near-2100 invitation/result creation refuses before emitting an unrepresentable wire deadline', t => {
  const f = fixture(t); f.create(); f.setClock(Date.parse('2099-12-31T23:55:00Z'), 0);
  reject('pairing_unavailable', () => f.store.createInvitation());
  f.store.close(); f.setClock(Date.parse('2099-12-31T23:00:00Z'), 0); f.open();
  const invitation = f.store.createInvitation().material();
  reject('pairing_unavailable', () => f.store.reserve({ ...invitation, desktopId: f.metadata.desktopId, csrDer: f.crypto.csr().toString('base64url'), deviceName: 'Boundary fixture', capabilities: ['tcp'] }));
});
