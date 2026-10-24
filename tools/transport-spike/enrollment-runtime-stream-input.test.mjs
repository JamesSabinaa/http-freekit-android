import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import test from 'node:test';
import { createCryptoFixture, fixedSubject, seq, tlv } from './companion-enrollment-crypto-fixtures.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';
import { encodeEnrolledStreamInput } from './enrollment-runtime-stream-input.mjs';

const f = createCryptoFixture(), logicalName = 'enrolled-stream.freekit.invalid';
const gateway = f.certificate({ key: f.other, signer: f.other, subject: fixedSubject, issuer: fixedSubject,
  eku: Buffer.from('300a06082b06010505070301', 'hex'),
  extraExtensions: [f.extension('551d11', seq(tlv(0x82, Buffer.from(logicalName))))] });
const base = { desktopId: 'desktop-stream-fixture', logicalName,
  gatewayCertificateDer: gateway.toString('base64url'),
  gatewaySpkiSha256: createHash('sha256').update(new X509Certificate(gateway).publicKey.export({ format: 'der', type: 'spki' })).digest('base64url'),
  enrollmentAuthorityDer: f.caDer.toString('base64url'), interceptionCaCertificateSha256: Buffer.alloc(32, 8).toString('base64url'),
  setupPort: 12345, credentialPort: 23456 };
const metadata = { ...base, webSocketPort: 34567 };
const invitation = { invitationId: 'stream-fixture', invitationSecret: Buffer.alloc(32, 9).toString('base64url'), expiresAt: '2030-01-02T00:05:00Z' };
const rejects = operation => assert.throws(operation, e => e.code === 'invalid_enrolled_stream_input' &&
  e.message === 'invalid_enrolled_stream_input' && e.cause === undefined && !inspect(e).includes('PRIVATE'));

test('all finite scenarios embed the validated A22a seed with exact binary boundaries', () => {
  const seed = encodeEnrollmentRuntimeInput(base, invitation);
  for (const scenario of [1, 2, 3]) {
    const bytes = encodeEnrolledStreamInput(metadata, invitation, scenario);
    assert.deepEqual(bytes.subarray(0, 8), Buffer.from([72, 70, 75, 83, 84, 82, 49, 0]));
    assert.equal(bytes.readUInt16BE(8), 34567); assert.equal(bytes[10], scenario);
    assert.equal(bytes.readUInt16BE(11), seed.length); assert.equal(bytes.length, seed.length + 13);
    assert.deepEqual(bytes.subarray(13), seed); assert.ok(bytes.length <= 16384);
  }
});

test('unknown scenarios and colliding, absent or invalid stream ports fail closed', () => {
  for (const scenario of [0, 4, 1.5, '1', null, undefined]) rejects(() => encodeEnrolledStreamInput(metadata, invitation, scenario));
  for (const webSocketPort of [0, 65536, 1.5, '34567', 12345, 23456, undefined]) {
    rejects(() => encodeEnrolledStreamInput({ ...metadata, webSocketPort }, invitation, 1));
  }
});

test('metadata cannot add fields or invoke accessors during private input construction', () => {
  rejects(() => encodeEnrolledStreamInput({ ...metadata, extra: 'PRIVATE' }, invitation, 1));
  const accessor = { ...metadata }; let called = false;
  Object.defineProperty(accessor, 'webSocketPort', { enumerable: true, get() { called = true; return 34567; } });
  rejects(() => encodeEnrolledStreamInput(accessor, invitation, 1)); assert.equal(called, false);
  rejects(() => encodeEnrolledStreamInput(Object.create(metadata), invitation, 1));
});

test('the wrapper preserves strict seed validation and exposes no rejected material in errors', () => {
  rejects(() => encodeEnrolledStreamInput(metadata, { ...invitation, invitationSecret: 'PRIVATE' }, 1));
  rejects(() => encodeEnrolledStreamInput({ ...metadata, gatewaySpkiSha256: Buffer.alloc(32).toString('base64url') }, invitation, 2));
});
