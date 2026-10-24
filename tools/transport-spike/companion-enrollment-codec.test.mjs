import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { inspect } from 'node:util';
import test from 'node:test';
import { decodeEnrollment, encodeEnrollment, enrollmentMessage, enrollmentProofPayload,
  enrollmentComparisonCode, EnrollmentMessage } from './companion-enrollment-codec.mjs';

const b64 = (length, byte = 1) => Buffer.alloc(length, byte).toString('base64url');
const enrollmentId = 'enr_' + b64(32);
const challengeId = 'ech_' + b64(32, 2);
const date = '2026-10-24T12:00:00Z';
const binding = { desktopId: 'desk', invitationId: 'invite', enrollmentId };
const signature = Buffer.from('3006020101020101', 'hex').toString('base64url');
const pair = { protocolVersion: 1, type: 'pair', desktopId: 'desk', invitationId: 'invite',
  invitationSecret: b64(32, 7), csrDer: b64(1), deviceName: 'Téléphone "dev" \\',
  capabilities: ['tcp-https-connect', 'tcp-http'] };
const challenge = { protocolVersion: 1, type: 'pair_challenge', desktopId: 'desk',
  gatewaySpkiSha256: b64(32, 3), invitationId: 'invite', enrollmentId, challengeId,
  deviceSpkiSha256: b64(32, 4), purpose: 'status', nonce: b64(32, 5), expiresAt: date };
const context = Object.fromEntries(['desktopId', 'gatewaySpkiSha256', 'invitationId',
  'enrollmentId', 'deviceSpkiSha256', 'purpose'].map(key => [key, challenge[key]]));
const fixtures = [
  ['pair_request', pair],
  ['challenge_request', { protocolVersion: 1, type: 'pair_challenge', ...binding, purpose: 'status' }],
  ['status_request', { protocolVersion: 1, type: 'pair_status', ...binding, challengeId, signature }],
  ['cancel_request', { protocolVersion: 1, type: 'pair_cancel', ...binding, challengeId, signature }],
  ['pair_response', { protocolVersion: 1, type: 'pair_registered', ...binding,
    deviceSpkiSha256: b64(32), reservationExpiresAt: date, resultExpiresAt: date }],
  ['challenge_response', challenge],
  ['status_response', { protocolVersion: 1, type: 'pair_pending', desktopId: 'desk', enrollmentId,
    reservationExpiresAt: date, retryAfterMillis: 1000 }],
  ['status_response', { protocolVersion: 1, type: 'pair_approved', desktopId: 'desk', enrollmentId,
    deviceId: 'dev_' + b64(32, 6), clientCertificateDer: b64(1), enrollmentAuthorityDer: b64(1),
    interceptionCaCertificateSha256: b64(32), capabilities: ['tcp-http'],
    credentialExpiresAt: date, resultExpiresAt: date }],
  ...['status_response', 'cancel_response'].map(channel => [channel, { protocolVersion: 1,
    type: 'pair_ended', desktopId: 'desk', enrollmentId, code: 'pairing_cancelled' }]),
];
const wire = value => Buffer.from(JSON.stringify(value));
const rejection = (channel, input, code = 'invalid_message') =>
  assert.deepEqual(decodeEnrollment(channel, typeof input === 'string' ? Buffer.from(input) : input), { ok: false, code });
const misuse = operation => assert.throws(operation, error =>
  error.code === 'invalid_message' && error.message === 'invalid_message' && !Object.hasOwn(error, 'cause'));

test('all eight channels and success variants round trip through canonical snapshots', () => {
  for (const [channel, material] of fixtures) {
    const decoded = decodeEnrollment(channel, wire(material));
    assert.equal(decoded.ok, true);
    assert.equal(decoded.message.channel, channel);
    assert.deepEqual(encodeEnrollment(decoded.message), encodeEnrollment(enrollmentMessage(channel, material)));
  }
  const canonical = encodeEnrollment(enrollmentMessage('pair_request', pair)).toString('utf8');
  assert.equal(canonical, '{"protocolVersion":1,"type":"pair","desktopId":"desk","invitationId":"invite",' +
    '"invitationSecret":"' + pair.invitationSecret + '","csrDer":"AQ","deviceName":"Téléphone \\"dev\\" \\\\",' +
    '"capabilities":["tcp-http","tcp-https-connect"]}');
});

test('responses accept exact fixed errors and enforce type/channel separation', () => {
  for (const channel of ['pair_response', 'challenge_response', 'status_response', 'cancel_response']) {
    assert.equal(decodeEnrollment(channel, wire({ protocolVersion: 1, type: 'pair_error', code: 'pairing_limit' })).ok, true);
    rejection(channel, wire({ protocolVersion: 1, type: 'pair_error', code: 'secret detail' }));
  }
  for (const [channel, material] of fixtures) rejection(channel, wire({ ...material, extra: true }));
  rejection('pair_request', wire(challenge));
  rejection('cancel_response', wire(fixtures[6][1]));
  rejection('unknown', wire(pair));
});

test('body and UTF-8 limits precede parsing', () => {
  rejection('pair_request', Buffer.alloc(16385), 'message_too_large');
  rejection('pair_request', Buffer.alloc(0));
  rejection('pair_request', new Uint8Array([0xc0, 0x80]));
  rejection('pair_request', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), wire(pair)]));
  rejection('pair_request', '[]');
  rejection('pair_request', '{} trailing');
  rejection('pair_request', null);
});

test('decoded duplicates and unpaired escaped surrogates are structural errors', () => {
  for (const source of [
    '{"protocolVersion":1,"protocol\\u0056ersion":2}',
    '{"protocolVersion":2,"x":{"a":1,"\\u0061":2}}',
    '{"protocolVersion":2,"x":"\\ud800"}',
    '{"protocolVersion":2,"\\udc00":1}',
    '{"protocolVersion":2,"x":"\\x00"}',
    '{"protocolVersion":2,"x":"a\nb"}',
  ]) rejection('pair_request', source);
});

test('generic structural bounds precede unsupported version without extra key-token limits', () => {
  const prefix = '{"protocolVersion":2,"x":';
  rejection('pair_request', prefix + '[[[]]]}', 'invalid_message');
  rejection('pair_request', prefix + '[' + Array(17).fill('0').join(',') + ']}');
  rejection('pair_request', wire(Object.fromEntries([['protocolVersion', 2],
    ...Array.from({ length: 16 }, (_, i) => ['key' + i, 0])])));
  rejection('pair_request', prefix + '{"nested":{}}}', 'unsupported_version');
  rejection('pair_request', '{"protocolVersion":2,"' + 'a'.repeat(400) + '":true}', 'unsupported_version');
  rejection('pair_request', '{"protocolVersion":2,"unknown":"ok"}', 'unsupported_version');
  rejection('pair_request', '{"protocolVersion":2147483647}', 'unsupported_version');
  rejection('pair_request', '{"protocolVersion":2147483648}');
  rejection('pair_request', '{"protocolVersion":0}');
});

test('every numeric token is canonical and bounded before version dispatch', () => {
  for (const token of ['-0', '-1', '1.0', '1e0', '01', '10000000000', 'NaN', 'Infinity']) {
    rejection('pair_request', '{"protocolVersion":2,"unknown":' + token + '}');
  }
  rejection('pair_request', '{"protocolVersion":2,"unknown":9999999999}', 'unsupported_version');
  rejection('pair_request', '{"protocolVersion":true}');
});

test('wire escapes and insignificant whitespace decode but encode canonically', () => {
  const source = ' \r\n' + JSON.stringify(pair).replace('"desktopId"', '"desktop\\u0049d"')
    .replace('Téléphone', 'T\\u00e9l\\u00e9phone') + '\t';
  const result = decodeEnrollment('pair_request', Buffer.from(source));
  assert.equal(result.ok, true);
  assert.deepEqual(encodeEnrollment(result.message), encodeEnrollment(enrollmentMessage('pair_request', pair)));
});

test('base64url canonical bits, DER bounds and opaque CSR semantics are exact', () => {
  for (const invitationSecret of [b64(31), b64(33), b64(32) + '=', b64(32).slice(0, -1) + 'B', true]) {
    rejection('pair_request', wire({ ...pair, invitationSecret }));
  }
  rejection('pair_request', wire({ ...pair, csrDer: '' }));
  rejection('pair_request', wire({ ...pair, csrDer: b64(4097) }));
  assert.equal(decodeEnrollment('pair_request', wire({ ...pair, csrDer: b64(4096) })).ok, true);
  rejection('challenge_request', wire({ ...fixtures[1][1], enrollmentId: enrollmentId + '\n' }));
});

test('device display names exclude hidden controls and retain allowed Unicode within bytes', () => {
  for (const deviceName of ['', ' leading', 'trailing ', '\0', '\u007f', '\u0085', '\u2028',
    '\u202e', '\u2067', '\ufeff', '\ud800', 'é'.repeat(65)]) {
    rejection('pair_request', wire({ ...pair, deviceName }));
  }
  for (const deviceName of ['é'.repeat(64), '📱 dev', '\u00a0name\u00a0']) {
    assert.equal(decodeEnrollment('pair_request', wire({ ...pair, deviceName })).ok, true);
  }
});

test('capability sets and exact UTC calendar dates are checked', () => {
  for (const capabilities of [[], ['tcp-http', 'tcp-http'], ['Bad'], ['tcp-http\n'], Array(17).fill('a')]) {
    rejection('pair_request', wire({ ...pair, capabilities }));
  }
  for (const expiresAt of ['2026-02-29T12:00:00Z', '2026-10-24T24:00:00Z',
    '1999-12-31T23:59:59Z', '2100-01-01T00:00:00Z', date + '\n', '2026-10-24T12:00:00.000Z']) {
    rejection('challenge_response', wire({ ...challenge, expiresAt }));
  }
  assert.equal(decodeEnrollment('challenge_response', wire({ ...challenge, expiresAt: '2028-02-29T12:00:00Z' })).ok, true);
});

function requestWithSignature(bytes) {
  return wire({ ...fixtures[2][1], signature: bytes.toString('base64url') });
}
test('ECDSA signatures require complete minimal positive P-256-range DER', () => {
  for (const hex of ['3006020100020101', '3006020180020101', '300702020001020101',
    '300602010102010100', '308106020101020101', '3006020101020201',
    '3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101']) {
    rejection('status_request', requestWithSignature(Buffer.from(hex, 'hex')));
  }
});

test('real provider signatures and both high-S/low-S forms are accepted without verification claims', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const payload = Buffer.from('synthetic enrollment proof');
  const signed = sign('sha256', payload, privateKey);
  assert.equal(verify('sha256', payload, publicKey, signed), true);
  assert.equal(decodeEnrollment('status_request', requestWithSignature(signed)).ok, true);
  let offset = 2;
  const r = signed.subarray(offset, offset + 2 + signed[offset + 1]);
  offset += r.length;
  const originalS = BigInt('0x' + signed.subarray(offset + 2).toString('hex'));
  let hex = (0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n - originalS).toString(16);
  if (hex.length % 2) hex = '0' + hex;
  if (parseInt(hex.slice(0, 2), 16) & 0x80) hex = '00' + hex;
  const s = Buffer.concat([Buffer.from([2, hex.length / 2]), Buffer.from(hex, 'hex')]);
  const alternate = Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]);
  assert.equal(verify('sha256', payload, publicKey, alternate), true);
  assert.equal(decodeEnrollment('status_request', requestWithSignature(alternate)).ok, true);
});

test('message snapshots copy inputs and explicit outputs and redact every default diagnostic', () => {
  const input = { ...pair, capabilities: [...pair.capabilities] };
  const message = enrollmentMessage('pair_request', input);
  input.deviceName = 'changed';
  input.capabilities[0] = 'changed';
  const material = message.material();
  material.capabilities[0] = 'changed';
  const encoded = encodeEnrollment(message);
  encoded.fill(0);
  assert.deepEqual(message.material(), { ...pair, capabilities: ['tcp-http', 'tcp-https-connect'] });
  for (const rendered of [String(message), inspect(message), JSON.stringify(message)]) {
    assert.equal(rendered.includes(pair.invitationSecret), false);
    assert.equal(rendered.includes(pair.deviceName), false);
  }
  misuse(() => new EnrollmentMessage());
  misuse(() => encodeEnrollment({ material: () => pair }));
  misuse(() => enrollmentMessage('pair_request', { ...pair, protocolVersion: 2 }));
  misuse(() => enrollmentMessage('pair_response', message));
  misuse(() => enrollmentMessage('pair_request', Object.defineProperty({ ...pair }, 'deviceName',
    { get() { throw new Error(pair.invitationSecret); } })));
  const hostile = [...pair.capabilities];
  Object.defineProperty(hostile, '0', { get() { throw new Error(pair.invitationSecret); } });
  misuse(() => enrollmentMessage('pair_request', { ...pair, capabilities: hostile }));
});

test('proof payload has exact domain, LP16 order, route and raw hash/nonce suffix', () => {
  const typed = enrollmentMessage('challenge_response', challenge);
  const payload = enrollmentProofPayload(context, typed);
  const strings = ['status', 'POST', '/companion/v1/pair/status', 'desk', 'invite',
    enrollmentId, challengeId, date];
  const expectedHex = Buffer.from('HTTP FreeKit enrollment proof v1\0').toString('hex') +
    strings.map(value => Buffer.byteLength(value).toString(16).padStart(4, '0') + Buffer.from(value).toString('hex')).join('') +
    Buffer.concat([Buffer.alloc(32, 3), Buffer.alloc(32, 4), Buffer.alloc(32, 5)]).toString('hex');
  assert.equal(payload.toString('hex'), expectedHex);
  const cancel = enrollmentMessage('challenge_response', { ...challenge, purpose: 'cancel' });
  const cancelPayload = enrollmentProofPayload({ ...context, purpose: 'cancel' }, cancel);
  assert.equal(cancelPayload.includes(Buffer.from('/companion/v1/pair/cancel')), true);
  payload.fill(0);
  assert.equal(enrollmentProofPayload(context, typed).toString('hex'), expectedHex);
});

test('proof rejects every substituted identity or purpose and arbitrary signing material', () => {
  const typed = enrollmentMessage('challenge_response', challenge);
  for (const key of Object.keys(context)) {
    const changed = { ...context, [key]: key === 'purpose' ? 'cancel' :
      key.endsWith('Sha256') ? b64(32, 9) : key === 'enrollmentId' ? 'enr_' + b64(32, 9) : 'other' };
    misuse(() => enrollmentProofPayload(changed, typed));
  }
  misuse(() => enrollmentProofPayload({ ...context, extra: true }, typed));
  misuse(() => enrollmentProofPayload(context, challenge));
  misuse(() => enrollmentProofPayload(context, enrollmentMessage('challenge_response',
    { protocolVersion: 1, type: 'pair_error', code: 'pairing_limit' })));
  misuse(() => enrollmentProofPayload(null, typed));
});

test('comparison fingerprint is domain-separated, grouped lowercase and input-bounded', () => {
  const value = enrollmentComparisonCode(context.gatewaySpkiSha256, context.deviceSpkiSha256);
  const expected = createHash('sha256').update(Buffer.concat([
    Buffer.from('HTTP FreeKit pairing comparison v1\0'), Buffer.alloc(32, 3), Buffer.alloc(32, 4),
  ])).digest('hex').match(/.{8}/g).join('-');
  assert.equal(value, expected);
  assert.match(value, /^[0-9a-f]{8}(?:-[0-9a-f]{8}){7}$/);
  misuse(() => enrollmentComparisonCode(Buffer.alloc(32), context.deviceSpkiSha256));
  misuse(() => enrollmentComparisonCode(context.gatewaySpkiSha256, b64(31)));
});
