import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { sign, generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createCryptoFixture, seq, tlv, fixedSubject } from './companion-enrollment-crypto-fixtures.mjs';
import { validateEnrollmentCsr, validateEnrollmentAuthority, validateEnrollmentCertificate, verifyEnrollmentSignature } from './companion-enrollment-crypto.mjs';

const f = createCryptoFixture();
const reject = work => assert.throws(work, error => error.code === 'authentication_failed' && error.cause === undefined && !inspect(error).includes('file:'));
const leaf = (overrides = {}, options = {}) => validateEnrollmentCertificate(f.certificate(overrides), { authority: f.caDer, utcMillis: f.utcMillis, ...options });

test('independent OpenSSL accepts actual fixed-subject CSR and provider verifies both public certificates', () => {
  const openssl = process.env.OPENSSL_BIN ?? 'openssl';
  for (const [args, input] of [[['req', '-inform', 'DER', '-verify', '-noout'], f.csr()], [['x509', '-inform', 'DER', '-noout'], f.caDer], [['x509', '-inform', 'DER', '-noout'], f.certificate()]]) {
    const result = spawnSync(openssl, args, { input, timeout: 5000, maxBuffer: 4096 });
    assert.equal(result.status, 0, 'OpenSSL public fixture validation');
  }
  assert.equal(validateEnrollmentCsr(f.csr()).material().deviceSpkiDer, f.deviceSpkiDer.toString('base64url'));
  validateEnrollmentAuthority(f.caDer, { utcMillis: f.utcMillis }); leaf();
});
test('distinct real ECDSA signatures resume by canonical SPKI rather than raw CSR bytes', () => {
  const a = f.csr(), b = f.csr(); assert.notDeepEqual(a, b);
  assert.equal(validateEnrollmentCsr(a).material().deviceSpkiSha256, validateEnrollmentCsr(b).material().deviceSpkiSha256);
});
test('correctly signed malformed Name, different subject and PrintableString subject fail fixed CSR profile', () => {
  for (const subject of [seq(Buffer.of(255)), seq(), seq(tlv(49, seq(Buffer.from('0603550403', 'hex'), tlv(19, Buffer.from('HTTP FreeKit device'))))), Buffer.from(fixedSubject).fill(65, 14, 15)]) {
    reject(() => validateEnrollmentCsr(f.csr({ subject })));
  }
});
test('CSR rejects requested attributes, wrong version, curve, compressed point and mismatched key', () => {
  reject(() => validateEnrollmentCsr(f.csr({ key: generateKeyPairSync('ec', { namedCurve: 'secp384r1' }) })));
  for (const options of [{ attributes: tlv(160, Buffer.from('3000', 'hex')) }, { version: 1 }, { publicKey: f.publicDer(f.other) },
    { publicKey: Buffer.concat([f.deviceSpkiDer.subarray(0, 25), Buffer.of(2), f.deviceSpkiDer.subarray(27, 59)]) }]) reject(() => validateEnrollmentCsr(f.csr(options)));
  const corrupt = f.csr(); corrupt[corrupt.length - 1] ^= 1; reject(() => validateEnrollmentCsr(corrupt));
});
test('CSR DER rejects trailing data, indefinite and nonminimal lengths before provider work', () => {
  const request = f.csr();
  for (const value of [Buffer.concat([request, Buffer.of(0)]), Buffer.of(48, 128, 0, 0), Buffer.from('3082000130', 'hex'), Buffer.alloc(4097), 'AA=']) reject(() => validateEnrollmentCsr(value));
});
test('public snapshots copy binary input and redact default inspection and JSON', () => {
  const input = f.csr(), snapshot = validateEnrollmentCsr(input), original = snapshot.material(); input.fill(0);
  assert.deepEqual(snapshot.material(), original); assert(!inspect(snapshot).includes(original.csrDer));
  assert(!JSON.stringify(snapshot).includes(original.deviceSpkiSha256)); const copy = snapshot.material(); copy.csrDer = 'changed';
  assert.deepEqual(snapshot.material(), original);
});
test('proof accepts real high-S and low-S signatures but rejects malformed scalars, suffixes and wrong context/key', () => {
  const payload = Buffer.from('bounded context'), signed = sign('sha256', payload, f.device.privateKey);
  assert(verifyEnrollmentSignature(f.deviceSpkiDer, payload, signed));
  const rLength = signed[3], r = signed.subarray(2, 4 + rLength), sValue = BigInt('0x' + signed.subarray(6 + rLength).toString('hex'));
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  let oppositeHex = (order - sValue).toString(16); if (oppositeHex.length % 2) oppositeHex = '0' + oppositeHex;
  let opposite = Buffer.from(oppositeHex, 'hex'); if (opposite[0] & 128) opposite = Buffer.concat([Buffer.of(0), opposite]);
  assert(verifyEnrollmentSignature(f.deviceSpkiDer, payload, seq(r, tlv(2, opposite))));
  assert(!verifyEnrollmentSignature(f.publicDer(f.other), payload, signed));
  assert(!verifyEnrollmentSignature(f.deviceSpkiDer, Buffer.from('different'), signed));
  for (const candidate of [Buffer.concat([signed, Buffer.of(0)]), Buffer.from('3006020100020101', 'hex'), Buffer.from('300702020001020101', 'hex'), Buffer.alloc(73)]) assert(!verifyEnrollmentSignature(f.deviceSpkiDer, payload, candidate));
});
test('authority requires own signature, same issuer and subject, critical pathlen0 and exact CA key usage', () => {
  for (const options of [{ signer: f.other }, { issuer: fixedSubject }, { basicCritical: false }, { usageCritical: false },
    { basic: Buffer.from('30030101ff', 'hex') }, { basic: Buffer.from('30060101ff020101', 'hex') }, { usage: Buffer.from('03020186', 'hex') }]) {
    reject(() => validateEnrollmentAuthority(f.certificate({ ca: true, ...options })));
  }
});
test('authority accepts absent or clientAuth EKU and rejects other purposes', () => {
  validateEnrollmentAuthority(f.certificate({ ca: true, eku: null }));
  validateEnrollmentAuthority(f.certificate({ ca: true, ekuCritical: true }));
  reject(() => validateEnrollmentAuthority(f.certificate({ ca: true, eku: Buffer.from('300a06082b06010505070301', 'hex') })));
});
test('leaf requires fixed subject, exact issuer/key and authority signature', () => {
  for (const options of [{ subject: seq() }, { signer: f.other }, { issuer: fixedSubject }]) reject(() => leaf(options));
  reject(() => leaf({}, { deviceSpkiDer: f.publicDer(f.other) }));
  leaf({}, { deviceSpkiDer: f.deviceSpkiDer });
});
test('leaf requires non-CA constraints, exact critical digitalSignature usage and clientAuth EKU', () => {
  for (const options of [{ basicCritical: false }, { basic: Buffer.from('30060101ff020100', 'hex') }, { usageCritical: false },
    { usage: Buffer.from('030205a0', 'hex') }, { eku: null }, { eku: Buffer.from('300a06082b06010505070301', 'hex') }]) reject(() => leaf(options));
  leaf({ ekuCritical: true });
});
test('certificate exact serial/date expectations reject otherwise valid signed candidates', () => {
  const cert = leaf().material();
  leaf({}, { serial: '2', notBefore: cert.notBefore, notAfter: cert.notAfter });
  for (const options of [{ serial: '3' }, { serial: '02' }, { serial: '9007199254740992' }, { notBefore: '2030-01-01T00:00:00Z' }, { notAfter: '2030-01-03T00:00:00Z' }]) reject(() => leaf({}, options));
  reject(() => leaf({ serial: 0 }));
});
test('current validity is explicit; expired history can be structurally verified without authorizing it', () => {
  validateEnrollmentAuthority(f.caDer); leaf({}, { utcMillis: undefined });
  for (const utcMillis of [f.utcMillis - 300001, f.utcMillis + 3600000, NaN, 1.1]) reject(() => leaf({}, { utcMillis }));
  reject(() => leaf({ notBefore: f.utcMillis - 86400001 }));
  reject(() => leaf({ notAfter: f.utcMillis + 86400001 }));
});
test('canonical 2050 GeneralizedTime is accepted and bad ranges fail', () => {
  const future = createCryptoFixture({ utcMillis: Date.parse('2050-01-02T00:00:00Z') });
  validateEnrollmentAuthority(future.caDer);
  validateEnrollmentCertificate(future.certificate(), { authority: future.caDer, utcMillis: future.utcMillis });
  reject(() => leaf({ notBefore: f.utcMillis + 1 }));
});
test('duplicate extensions and unknown critical extensions fail; bounded noncritical extension survives', () => {
  const custom = f.extension('2a030405', tlv(4, Buffer.from('opaque')), false);
  leaf({ extraExtensions: [custom] });
  for (const extraExtensions of [[custom, custom], [f.extension('2a030405', tlv(4, Buffer.of(1)), true)], [f.extension('2a030405', Buffer.from('3080', 'hex'))]]) reject(() => leaf({ extraExtensions }));
});
