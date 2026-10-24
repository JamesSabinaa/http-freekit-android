import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import test from 'node:test';
import { createCryptoFixture, fixedSubject, seq, tlv } from './companion-enrollment-crypto-fixtures.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';

const f = createCryptoFixture();
const logicalName = 'enrollment.freekit.invalid';
const gateway = f.certificate({ key: f.other, signer: f.other, subject: fixedSubject, issuer: fixedSubject,
  eku: Buffer.from('300a06082b06010505070301', 'hex'),
  extraExtensions: [f.extension('551d11', seq(tlv(0x82, Buffer.from(logicalName))))] });
const metadata = { desktopId: 'desktop-fixture', logicalName,
  gatewayCertificateDer: gateway.toString('base64url'),
  gatewaySpkiSha256: createHash('sha256').update(new X509Certificate(gateway).publicKey.export({ format: 'der', type: 'spki' })).digest('base64url'),
  enrollmentAuthorityDer: f.caDer.toString('base64url'),
  interceptionCaCertificateSha256: Buffer.alloc(32, 8).toString('base64url'), setupPort: 12345, credentialPort: 23456 };
const invitation = { invitationId: 'inv-fixture', invitationSecret: Buffer.alloc(32, 9).toString('base64url'),
  expiresAt: '2030-01-02T00:05:00Z' };
const rejects = operation => assert.throws(operation, e =>
  e.code === 'invalid_enrollment_runtime_input' && e.message === 'invalid_enrollment_runtime_input' &&
  e.cause === undefined && !inspect(e).includes('PRIVATE'));

test('binary input has exact magic, big-endian ports, ordered LP16 fields and no extra bytes', () => {
  const bytes = encodeEnrollmentRuntimeInput(metadata, invitation);
  assert.deepEqual(bytes.subarray(0, 8), Buffer.from([72, 70, 75, 69, 78, 82, 49, 0]));
  assert.equal(bytes.readUInt16BE(8), 12345);
  assert.equal(bytes.readUInt16BE(10), 23456);
  let at = 12;
  const expected = [gateway, Buffer.from(metadata.gatewaySpkiSha256, 'base64url'), Buffer.from(logicalName),
    Buffer.from(metadata.desktopId), Buffer.from(invitation.invitationId),
    Buffer.alloc(32, 9), Buffer.from(invitation.expiresAt)];
  for (const field of expected) {
    const length = bytes.readUInt16BE(at); at += 2;
    assert.equal(length, field.length);
    assert.deepEqual(bytes.subarray(at, at + length), field); at += length;
  }
  assert.equal(at, bytes.length);
  assert.ok(bytes.length <= 16384);
});

test('input encoding copies all material and preserves no caller-owned mutable bytes', () => {
  const first = encodeEnrollmentRuntimeInput(metadata, invitation);
  const frozen = Buffer.from(first);
  first.fill(0);
  assert.deepEqual(encodeEnrollmentRuntimeInput(metadata, invitation), frozen);
});

test('metadata/invitation exact field/type/port/name bounds fail without retaining causes', () => {
  for (const change of [{ extra: true }, { setupPort: 0 }, { setupPort: 65536 }, { credentialPort: true },
    { credentialPort: metadata.setupPort },
    { desktopId: 'bad\n' }, { desktopId: 'a'.repeat(129) }, { logicalName: '127.0.0.1' },
    { logicalName: 'name:123' }, { logicalName: 'bad..name' }, { logicalName: '-bad.name' }]) {
    rejects(() => encodeEnrollmentRuntimeInput({ ...metadata, ...change }, invitation));
  }
  for (const change of [{ extra: true }, { invitationId: '' }, { expiresAt: '2030-02-29T00:00:00Z' },
    { expiresAt: '2030-01-02T00:05:00.000Z' }, { invitationSecret: invitation.invitationSecret + '=' }]) {
    rejects(() => encodeEnrollmentRuntimeInput(metadata, { ...invitation, ...change }));
  }
  rejects(() => encodeEnrollmentRuntimeInput(null, invitation));
});

test('gateway seed must match exact DER, SPKI pin and DNS SAN through the provider', () => {
  for (const change of [
    { gatewayCertificateDer: Buffer.concat([gateway, Buffer.of(0)]).toString('base64url') },
    { gatewayCertificateDer: 'AQ' }, { gatewayCertificateDer: Buffer.alloc(4097).toString('base64url') },
    { gatewaySpkiSha256: Buffer.alloc(32, 1).toString('base64url') },
    { logicalName: 'other.freekit.invalid' },
  ]) rejects(() => encodeEnrollmentRuntimeInput({ ...metadata, ...change }, invitation));
});

test('host seed construction rejects accessors and reports only fixed misuse category', () => {
  const hostile = Object.defineProperty({ ...metadata }, 'gatewayCertificateDer',
    { get() { throw Error('PRIVATE_SEED_CAUSE'); } });
  rejects(() => encodeEnrollmentRuntimeInput(hostile, invitation));
  rejects(() => encodeEnrollmentRuntimeInput(metadata, Object.defineProperty({ ...invitation }, 'invitationSecret',
    { get() { throw Error('PRIVATE_INVITATION_CAUSE'); } })));
});
