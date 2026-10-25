import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { enrollmentFixtureAssets } from './companion-enrollment-https-assets.mjs';
import { startEnrollmentOriginFixture } from './companion-enrollment-origin.mjs';
import { enrollOriginCsr } from './companion-enrollment-origin-client.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('base64url');
const capabilities = ['tcp-http-origin-connect', 'tcp-https-connect'];
function directory(t, beforeRemove = async () => {}) {
  const root = fs.realpathSync(os.tmpdir()), owned = fs.mkdtempSync(path.join(root, 'freekit-interception-ca-'));
  fs.chmodSync(owned, 0o700);
  t.after(async () => { await beforeRemove(); assert.equal(path.dirname(owned), root); fs.rmSync(owned, { recursive: true, force: true }); });
  return owned;
}
function publicCa() {
  const crypto = createCryptoFixture({ utcMillis: Math.floor(Date.now() / 1000) * 1000 });
  return { crypto, der: crypto.certificate({ ca: true, eku: null }) };
}
const input = directory => ({ directory, mode: 'create', openssl: process.env.OPENSSL_BIN ?? 'openssl', setupPort: 0, credentialPort: 0 });

test('supplied public interception CA is snapshotted, persisted and reopened without generating an unused private CA', { timeout: 15000 }, async t => {
  const owned = directory(t), { der } = publicCa(), mutable = Buffer.from(der);
  const starting = enrollmentFixtureAssets({ ...input(owned), interceptionCaCertificateDer: mutable });
  mutable.fill(0);
  const assets = await starting, metadata = assets.metadata().material();
  assert.equal(metadata.interceptionCaCertificateSha256, digest(der));
  assert(new X509Certificate(fs.readFileSync(path.join(owned, 'interception.pem'))).raw.equals(der));
  assert.equal(fs.existsSync(path.join(owned, 'interception-key.pem')), false);
  assert.notEqual(metadata.enrollmentAuthorityDer, der.toString('base64url'));
  assert.notEqual(metadata.gatewayCertificateDer, der.toString('base64url'));
  assets.commitPorts(41001, 41002);
  const reopen = { ...input(owned), mode: 'open', setupPort: 41001, credentialPort: 41002 };
  const opened = await enrollmentFixtureAssets({ ...reopen, interceptionCaCertificateDer: der });
  assert.deepEqual(opened.metadata().material(), assets.metadata().material());
  await assert.rejects(enrollmentFixtureAssets(reopen), error => error.code === 'pairing_unavailable');
  await assert.rejects(enrollmentFixtureAssets({ ...reopen, interceptionCaCertificateDer: publicCa().der }), error => error.code === 'pairing_unavailable');
  fs.writeFileSync(path.join(owned, 'interception-key.pem'), 'must not be silently retained');
  await assert.rejects(enrollmentFixtureAssets({ ...reopen, interceptionCaCertificateDer: der }), error => error.code === 'pairing_unavailable');
});

test('invalid, non-CA, expired and unsupported public inputs fail before any child or private identity is created', async t => {
  const { crypto, der } = publicCa(), otherKey = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  const invalid = [null, der.toString('base64url'), Buffer.alloc(0), Buffer.alloc(4097), Buffer.from('PRIVATE CANARY'),
    Buffer.concat([der, Buffer.of(0)]), Buffer.from(new X509Certificate(der).toString()),
    crypto.certificate(), crypto.certificate({ ca: true }),
    crypto.certificate({ ca: true, eku: null, notAfter: Math.floor(Date.now() / 1000) * 1000 - 1000 }),
    crypto.certificate({ ca: true, eku: null, notBefore: Math.floor(Date.now() / 1000) * 1000 - 123 }),
    crypto.certificate({ ca: true, eku: null, key: publicCa().crypto.authority }),
    crypto.certificate({ ca: true, eku: null, key: otherKey, signer: otherKey })];
  for (const [index, value] of invalid.entries()) {
    const owned = directory(t);
    await assert.rejects(enrollmentFixtureAssets({ ...input(owned), openssl: 'must-not-start', interceptionCaCertificateDer: value }),
      error => error.code === 'pairing_unavailable' && !JSON.stringify(error).includes('CANARY'));
    assert.deepEqual(fs.readdirSync(owned), [], `Rejected public input ${index} must precede private initialization`);
  }
});

test('real approved enrollment binds the provided public CA and defensive full capability intersection', { timeout: 15000 }, async t => {
  let owner;
  const owned = directory(t, async () => {
    if (owner) { const closed = await owner.close(); assert(closed.storeClosed && closed.listenersClosed && closed.issuerChildrenJoined); }
  }), { der } = publicCa(), supported = [...capabilities];
  const starting = startEnrollmentOriginFixture({ directory: owned, mode: 'create', interceptionCaCertificateDer: der,
    supportedCapabilities: supported, trustedProxyFactory() { throw Error('No stream is opened by enrollment'); } });
  supported.fill('tcp-http');
  owner = await starting;
  const approved = (await enrollOriginCsr(owner, createCryptoFixture().csr(), capabilities)).material();
  assert.equal(owner.metadata().material().interceptionCaCertificateSha256, digest(der));
  assert.equal(approved.interceptionCaCertificateSha256, digest(der));
  assert.deepEqual(approved.capabilities, capabilities);
  assert.equal(fs.existsSync(path.join(owned, 'interception-key.pem')), false);
});
