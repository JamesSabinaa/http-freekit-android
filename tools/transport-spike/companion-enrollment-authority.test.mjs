import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspect } from 'node:util';
import test from 'node:test';
import { createEnrollmentAuthority } from './companion-enrollment-authority.mjs';
import { enrollmentMessage, enrollmentProofPayload } from './companion-enrollment-codec.mjs';
import { createEnrollmentStore, openEnrollmentStore } from './companion-enrollment-store.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';

const badSignature = Buffer.from('3006020101020101', 'hex').toString('base64url');
const encode = value => Buffer.from(JSON.stringify(value));
const context = challenge => Object.fromEntries(['desktopId', 'gatewaySpkiSha256', 'invitationId',
  'enrollmentId', 'deviceSpkiSha256', 'purpose'].map(key => [key, challenge[key]]));

function fixture(t, fixtureUtcMillis) {
  const crypto = createCryptoFixture(fixtureUtcMillis === undefined ? {} : { utcMillis: fixtureUtcMillis });
  if (fixtureUtcMillis !== undefined) crypto.caDer = crypto.certificate({ ca: true,
    notAfter: Math.min(fixtureUtcMillis + 86400000, Date.parse('2099-12-31T23:59:59Z')) });
  const temporaryRoot = fs.realpathSync(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(temporaryRoot, 'freekit-enrollment-authority-'));
  let utcMillis = crypto.utcMillis, monotonicMillis = 0;
  const metadata = { desktopId: 'fixture', gatewaySpkiSha256: randomBytes(32).toString('base64url'),
    enrollmentAuthorityDer: crypto.caDer.toString('base64url'),
    interceptionCaCertificateSha256: randomBytes(32).toString('base64url'),
    supportedCapabilities: ['tcp-http'], credentialLifetimeSeconds: 7200 };
  const options = { directory, metadata, clock: () => ({ utcMillis, monotonicMillis }) };
  let store = createEnrollmentStore(options), authority;
  const hooks = {}, counters = { verify: 0, read: 0, cancel: 0 };
  const adapter = {
    now: () => store.now(),
    reserve: value => store.reserve(value),
    getBinding: (...args) => {
      const result = store.getBinding(...args);
      return hooks.binding ? hooks.binding(result, args) : result;
    },
    verifyProof: (...args) => {
      counters.verify++;
      const valid = store.verifyProof(...args);
      hooks.afterVerify?.(valid);
      return valid;
    },
    readResult: id => {
      counters.read++;
      if (hooks.readFailure) throw Error('private storage/provider path');
      return store.readResult(id);
    },
    cancel: id => { counters.cancel++; return store.cancel(id); },
  };
  const authorities = [];
  function create(random) {
    authority = createEnrollmentAuthority({ store: adapter, ...(random ? { randomBytes: random } : {}) });
    authorities.push(authority);
    return authority;
  }
  create();
  const request = (channel, material) => authority.request(channel, encode(material)).material();
  const api = {
    crypto, metadata, hooks, counters, directory, options, request, create,
    get store() { return store; }, get authority() { return authority; },
    advance(ms, wall = true) { monotonicMillis += ms; if (wall) utcMillis += ms; },
    pair(key = crypto.device) {
      const invitation = store.createInvitation().material();
      const pair = { protocolVersion: 1, type: 'pair', desktopId: metadata.desktopId,
        invitationId: invitation.invitationId, invitationSecret: invitation.invitationSecret,
        csrDer: crypto.csr({ key }).toString('base64url'), deviceName: 'Synthetic device', capabilities: ['tcp-http'] };
      const registered = request('pair_request', pair);
      assert.equal(registered.type, 'pair_registered');
      return { key, pair, ...registered };
    },
    challenge(record, purpose = 'status') {
      return request('challenge_request', { protocolVersion: 1, type: 'pair_challenge',
        desktopId: metadata.desktopId, invitationId: record.invitationId,
        enrollmentId: record.enrollmentId, purpose });
    },
    signed(record, challenge, purpose = challenge.purpose) {
      const payload = enrollmentProofPayload(context(challenge), enrollmentMessage('challenge_response', challenge));
      return { protocolVersion: 1, type: purpose === 'status' ? 'pair_status' : 'pair_cancel',
        desktopId: metadata.desktopId, invitationId: record.invitationId,
        enrollmentId: record.enrollmentId, challengeId: challenge.challengeId,
        signature: sign('sha256', payload, record.key.privateKey).toString('base64url') };
    },
    submit(record, challenge, purpose = challenge.purpose, replacement) {
      return request(purpose === 'status' ? 'status_request' : 'cancel_request',
        { ...api.signed(record, challenge, purpose), ...(replacement ? { signature: replacement } : {}) });
    },
    reopen() {
      authority.close();
      store.close();
      store = openEnrollmentStore(options);
      create();
    },
    approve(record) {
      const { job } = store.beginApproval(record.enrollmentId);
      const material = job.material();
      const leaf = crypto.certificate({ key: record.key, serial: material.serial,
        notBefore: Date.parse(material.notBefore), notAfter: Date.parse(material.notAfter) });
      return { leaf, result: store.publish(job, leaf).material() };
    },
  };
  t.after(() => {
    for (const owner of authorities) owner.close();
    store.close();
    const resolved = path.resolve(directory);
    assert.equal(resolved.startsWith(temporaryRoot + path.sep), true);
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  return api;
}

test('actual SQLite reservation and real key proofs are purpose-bound and single-use', t => {
  const f = fixture(t), record = f.pair(), challenge = f.challenge(record);
  assert.equal(challenge.type, 'pair_challenge');
  assert.equal(f.submit(record, challenge).type, 'pair_pending');
  assert.equal(f.submit(record, challenge).code, 'authentication_failed');
  const calls = f.counters.verify;
  f.advance(1000);
  const cancellation = f.challenge(record, 'cancel');
  assert.equal(f.submit(record, cancellation, 'status').code, 'authentication_failed');
  assert.equal(f.counters.verify, calls);
  assert.equal(f.submit(record, cancellation).code, 'pairing_cancelled');
  assert.equal(f.store.readResult(record.enrollmentId).material().code, 'pairing_cancelled');
});

test('unknown credentials and substituted contexts are rejected before shared crypto', t => {
  const f = fixture(t), record = f.pair(), challenge = f.challenge(record);
  const signed = f.signed(record, challenge);
  for (const changed of [
    { desktopId: 'other' }, { invitationId: 'other' }, { enrollmentId: 'enr_' + randomBytes(32).toString('base64url') },
    { challengeId: 'ech_' + randomBytes(32).toString('base64url') },
  ]) assert.equal(f.request('status_request', { ...signed, ...changed }).code, 'authentication_failed');
  assert.equal(f.counters.verify, 0);
  assert.equal(f.submit(record, challenge).type, 'pair_pending');
});

test('three invalid signatures exhaust a resident slot without allowing a later valid proof', t => {
  const f = fixture(t), record = f.pair();
  f.advance(1000);
  const challenge = f.challenge(record);
  for (let index = 0; index < 3; index++) assert.equal(f.submit(record, challenge, 'status', badSignature).code, 'authentication_failed');
  assert.equal(f.submit(record, challenge).code, 'authentication_failed');
  assert.equal(f.counters.verify, 3);
  f.advance(1000);
  assert.equal(f.challenge(record).type, 'pair_challenge');
  f.advance(1000);
  assert.equal(f.challenge(record).code, 'pairing_limit');
  f.advance(8000);
  assert.equal(f.challenge(record).type, 'pair_challenge');
});

test('shared CSR/proof quota refusal leaves the nonce attempt count and valid proof intact', t => {
  const f = fixture(t), record = f.pair(), challenge = f.challenge(record);
  for (let index = 0; index < 3; index++) assert.equal(f.request('pair_request', record.pair).type, 'pair_registered');
  for (let index = 0; index < 4; index++) assert.equal(f.submit(record, challenge).code, 'pairing_limit');
  f.advance(1000);
  assert.equal(f.submit(record, challenge).type, 'pair_pending');
  assert.equal(f.submit(record, challenge).code, 'authentication_failed');
});

test('authoritative ten-second monotonic expiry and verification-time expiry deny result reads', t => {
  for (const duringVerification of [false, true]) {
    const f = fixture(t), record = f.pair(), challenge = f.challenge(record);
    if (duringVerification) f.hooks.afterVerify = valid => { assert.equal(valid, true); f.advance(10000, false); };
    else f.advance(10000, false);
    assert.equal(f.submit(record, challenge).code, 'authentication_failed');
    assert.equal(f.counters.read, 0);
    assert.equal(f.counters.verify, duringVerification ? 1 : 0);
    delete f.hooks.afterVerify;
    assert.equal(f.submit(record, challenge).code, 'authentication_failed');
  }
});

test('final immutable binding recheck detects trusted-store substitution during verification', t => {
  const f = fixture(t), record = f.pair(), challenge = f.challenge(record);
  f.hooks.afterVerify = () => {
    f.hooks.binding = snapshot => ({ material: () => ({ ...snapshot.material(), gatewaySpkiSha256: randomBytes(32).toString('base64url') }) });
  };
  assert.equal(f.submit(record, challenge).code, 'authentication_failed');
  assert.equal(f.counters.read, 0);
});

test('held proofs crossing result deadline consume once and cannot cancel an active grant', t => {
  for (const wall of [true, false]) for (const purpose of ['status', 'cancel']) {
    const f = fixture(t), record = f.pair(), { leaf } = f.approve(record);
    f.advance(3595000, wall);
    const challenge = f.challenge(record, purpose);
    assert.equal(challenge.type, 'pair_challenge');
    f.advance(5000, wall);
    assert.equal(f.submit(record, challenge).code, 'result_expired');
    assert.equal(f.submit(record, challenge).code, 'authentication_failed');
    assert.equal(f.challenge(record, purpose).code, 'authentication_failed');
    assert.notEqual(f.store.authorizeCertificate(leaf), null);
  }
});

test('lost approved responses recover exact immutable public result with fresh proof', t => {
  const f = fixture(t), record = f.pair(), { result, leaf } = f.approve(record);
  const challenge = f.challenge(record);
  assert.deepEqual(f.submit(record, challenge), result);
  f.advance(1000);
  assert.deepEqual(f.submit(record, f.challenge(record)), result);
  f.reopen();
  assert.deepEqual(f.submit(record, f.challenge(record)), result);
  f.store.revoke(record.enrollmentId);
  f.advance(1000);
  assert.equal(f.submit(record, f.challenge(record)).code, 'device_revoked');
  assert.equal(f.store.authorizeCertificate(leaf), null);
});

test('a result-read failure never restores a consumed nonce and latches this authority closed', t => {
  const f = fixture(t), record = f.pair(), challenge = f.challenge(record);
  f.hooks.readFailure = true;
  assert.equal(f.submit(record, challenge).code, 'pairing_unavailable');
  delete f.hooks.readFailure;
  assert.equal(f.submit(record, challenge).code, 'pairing_unavailable');
  f.reopen();
  assert.equal(f.submit(record, challenge).code, 'authentication_failed');
  assert.equal(f.submit(record, f.challenge(record)).type, 'pair_pending');
});

test('global/per-enrollment rate and live slot limits do not evict existing challenges', t => {
  const f = fixture(t), a = f.pair(), b = f.pair(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }));
  const first = f.challenge(a);
  assert.equal(f.challenge(b).code, 'pairing_limit');
  f.advance(100);
  const second = f.challenge(b);
  assert.equal(second.type, 'pair_challenge');
  f.advance(899);
  assert.equal(f.challenge(a).code, 'pairing_limit');
  f.advance(1);
  const third = f.challenge(a);
  assert.equal(third.type, 'pair_challenge');
  f.advance(1000);
  assert.equal(f.challenge(a).code, 'pairing_limit');
  assert.equal(f.submit(a, first).type, 'pair_pending');
  assert.equal(f.submit(a, third).type, 'pair_pending');
  assert.equal(f.submit(b, second).type, 'pair_pending');
});

test('32-owner live challenge capacity is bounded and expired slots become available', t => {
  const f = fixture(t), records = [];
  for (let index = 0; index < 33; index++) {
    if (index > 0) f.advance(100);
    const record = f.pair(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }));
    records.push(record);
    const challenge = f.challenge(record);
    assert.equal(challenge.type, index < 32 ? 'pair_challenge' : 'pair_error');
    if (index === 32) assert.equal(challenge.code, 'pairing_limit');
  }
  f.advance(6800);
  assert.equal(f.challenge(records[32]).type, 'pair_challenge');
});

test('consumed ID tombstones prevent deterministic random collisions until original expiry', t => {
  const f = fixture(t), record = f.pair();
  let calls = 0;
  f.create(() => { calls++; return Buffer.alloc(32, 7); });
  const challenge = f.challenge(record);
  assert.equal(calls, 2);
  assert.equal(f.submit(record, challenge).type, 'pair_pending');
  f.advance(1000);
  assert.equal(f.challenge(record).code, 'pairing_limit');
  assert.equal(calls, 10);
  f.advance(9000);
  assert.equal(f.challenge(record).type, 'pair_challenge');
  assert.equal(calls, 12);
});

test('issuance time follows the final live Store observation after random generation', t => {
  const f = fixture(t), record = f.pair();
  let calls = 0;
  f.create(() => { if (++calls === 2) f.advance(1500); return randomBytes(32); });
  const challenge = f.challenge(record);
  assert.equal(challenge.expiresAt, new Date(f.crypto.utcMillis + 11000).toISOString().replace('.000Z', 'Z'));
  f.advance(9999, false);
  assert.equal(f.submit(record, challenge).type, 'pair_pending');
});

test('an unrepresentable informational challenge expiry fails closed at the wire year boundary', t => {
  const f = fixture(t, Date.parse('2099-12-31T22:59:55Z')), record = f.pair();
  f.advance(3595000);
  assert.equal(f.challenge(record).code, 'pairing_unavailable');
  assert.equal(f.counters.verify, 0);
});

test('synchronous reentrancy is denied before duplicate proof verification or state access', t => {
  const f = fixture(t), record = f.pair(), challenge = f.challenge(record);
  let inner;
  f.hooks.afterVerify = () => { inner = f.submit(record, challenge); };
  assert.equal(f.submit(record, challenge).type, 'pair_pending');
  assert.equal(inner.code, 'pairing_unavailable');
  assert.equal(f.counters.verify, 1);
  assert.equal(f.counters.read, 1);
});

test('decode errors precede unavailable state and default diagnostics disclose no setup material', t => {
  const f = fixture(t), record = f.pair();
  for (const representation of [String(f.authority), inspect(f.authority), JSON.stringify(f.authority)]) {
    assert.equal(representation.includes(record.pair.invitationSecret), false);
  }
  f.authority.close();
  assert.equal(f.authority.request('pair_request', Buffer.alloc(16385)).material().code, 'message_too_large');
  assert.equal(f.authority.request('pair_request', Buffer.from('{"protocolVersion":2}')).material().code, 'unsupported_version');
  assert.equal(f.request('pair_request', record.pair).code, 'pairing_unavailable');
});
