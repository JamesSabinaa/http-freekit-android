// A21 draft 0.4 foundation only. No listener, signing key or authorization.
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';

export const ENROLLMENT_MAX_BYTES = 16384;
export const ENROLLMENT_CHANNELS = Object.freeze([
  'pair_request', 'challenge_request', 'status_request', 'cancel_request',
  'pair_response', 'challenge_response', 'status_response', 'cancel_response',
]);
const decoderCodes = new Set(['invalid_message', 'message_too_large', 'unsupported_version']);
const errorCodes = new Set(['invalid_message', 'message_too_large', 'unsupported_version',
  'unsupported_capability', 'authentication_failed', 'invitation_expired',
  'invitation_used', 'pairing_limit', 'pairing_unavailable']);
const endedCodes = new Set(['pairing_rejected', 'pairing_cancelled', 'invitation_expired',
  'device_revoked', 'credential_expired', 'result_expired']);
const purposes = new Set(['status', 'cancel']);
const records = new WeakMap();
const brand = Symbol('enrollment-message');
const curveOrder = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export class EnrollmentError extends Error {
  constructor() {
    super('invalid_message');
    this.name = 'EnrollmentError';
    this.code = 'invalid_message';
  }
  toString() { return 'EnrollmentError(invalid_message)'; }
  toJSON() { return { code: 'invalid_message' }; }
  [inspect.custom]() { return this.toString(); }
}
class DecodeError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const invalid = () => { throw new EnrollmentError(); };
const copy = value => Object.fromEntries(Object.entries(value).map(([key, entry]) =>
  [key, Array.isArray(entry) ? [...entry] : entry]));

/** Explicit material/encoding access is separate from default diagnostics. */
export class EnrollmentMessage {
  constructor(key, channel, material) {
    if (key !== brand) invalid();
    for (const value of Object.values(material)) if (Array.isArray(value)) Object.freeze(value);
    records.set(this, Object.freeze({ channel, material: Object.freeze(material) }));
    Object.freeze(this);
  }
  get channel() { return records.get(this)?.channel ?? invalid(); }
  material() {
    const stored = records.get(this);
    if (!stored) invalid();
    return copy(stored.material);
  }
  toString() { return 'EnrollmentMessage([REDACTED])'; }
  toJSON() { return { kind: 'EnrollmentMessage', redacted: true }; }
  [inspect.custom]() { return this.toString(); }
}
Object.freeze(EnrollmentMessage.prototype);

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key =>
    typeof key !== 'string' || !keys.includes(key) ||
    !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))) invalid();
}
function field(value, key) {
  if (!value || typeof value !== 'object') invalid();
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid();
  return descriptor.value;
}
function text(value, pattern) {
  if (typeof value !== 'string' || !value.isWellFormed() ||
      pattern.exec(value)?.[0] !== value) invalid();
  return value;
}
function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < min || value > max) invalid();
  return value;
}
function binary(value, min, max = min) {
  if (typeof value !== 'string' || value.length < Math.ceil(min * 4 / 3) ||
      value.length > Math.ceil(max * 4 / 3) ||
      /^[A-Za-z0-9_-]+$/.exec(value)?.[0] !== value) invalid();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < min || bytes.length > max || bytes.toString('base64url') !== value) invalid();
  return value;
}
function id(value, prefix) {
  text(value, new RegExp('^' + prefix + '[A-Za-z0-9_-]{43}$'));
  binary(value.slice(prefix.length), 32);
  return value;
}
const identity = value => text(value, /^[A-Za-z0-9_-]{1,128}$/);
function timestamp(value) {
  text(value, /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value.slice(0, -1) + '.000Z') invalid();
  return value;
}
function deviceName(value) {
  if (typeof value !== 'string' || !value.isWellFormed() ||
      Buffer.byteLength(value, 'utf8') < 1 || Buffer.byteLength(value, 'utf8') > 128 ||
      value.startsWith(' ') || value.endsWith(' ') ||
      /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/u.test(value)) invalid();
  return value;
}
function capabilities(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) invalid();
  const values = [];
  for (let i = 0; i < value.length; i++) values.push(text(field(value, String(i)), /^[a-z][a-z0-9-]{0,31}$/));
  if (new Set(values).size !== values.length) invalid();
  return values.sort();
}
function member(value, allowed) {
  if (typeof value !== 'string' || !allowed.has(value)) invalid();
  return value;
}
function signature(value) {
  binary(value, 8, 72);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes[0] !== 0x30 || bytes[1] !== bytes.length - 2) invalid();
  let offset = 2;
  for (let index = 0; index < 2; index++) {
    if (bytes[offset++] !== 0x02) invalid();
    const length = bytes[offset++];
    if (length < 1 || length > 33 || offset + length > bytes.length) invalid();
    const scalar = bytes.subarray(offset, offset + length);
    if (scalar[0] & 0x80 || (length > 1 && scalar[0] === 0 && !(scalar[1] & 0x80))) invalid();
    const number = BigInt('0x' + scalar.toString('hex'));
    if (number < 1n || number >= curveOrder) invalid();
    offset += length;
  }
  if (offset !== bytes.length) invalid();
  return value;
}

const specifications = {
  pair_request: { pair: ['desktopId', 'invitationId', 'invitationSecret', 'csrDer', 'deviceName', 'capabilities'] },
  challenge_request: { pair_challenge: ['desktopId', 'invitationId', 'enrollmentId', 'purpose'] },
  status_request: { pair_status: ['desktopId', 'invitationId', 'enrollmentId', 'challengeId', 'signature'] },
  cancel_request: { pair_cancel: ['desktopId', 'invitationId', 'enrollmentId', 'challengeId', 'signature'] },
  pair_response: { pair_registered: ['desktopId', 'invitationId', 'enrollmentId', 'deviceSpkiSha256', 'reservationExpiresAt', 'resultExpiresAt'] },
  challenge_response: { pair_challenge: ['desktopId', 'gatewaySpkiSha256', 'invitationId', 'enrollmentId',
    'challengeId', 'deviceSpkiSha256', 'purpose', 'nonce', 'expiresAt'] },
  status_response: {
    pair_pending: ['desktopId', 'enrollmentId', 'reservationExpiresAt', 'retryAfterMillis'],
    pair_approved: ['desktopId', 'enrollmentId', 'deviceId', 'clientCertificateDer', 'enrollmentAuthorityDer',
      'interceptionCaCertificateSha256', 'capabilities', 'credentialExpiresAt', 'resultExpiresAt'],
    pair_ended: ['desktopId', 'enrollmentId', 'code'],
  },
  cancel_response: { pair_ended: ['desktopId', 'enrollmentId', 'code'] },
};
const validators = {
  desktopId: identity, invitationId: identity,
  enrollmentId: value => id(value, 'enr_'), challengeId: value => id(value, 'ech_'),
  deviceId: value => id(value, 'dev_'),
  invitationSecret: value => binary(value, 32), gatewaySpkiSha256: value => binary(value, 32),
  deviceSpkiSha256: value => binary(value, 32), nonce: value => binary(value, 32),
  interceptionCaCertificateSha256: value => binary(value, 32),
  csrDer: value => binary(value, 1, 4096), clientCertificateDer: value => binary(value, 1, 4096),
  enrollmentAuthorityDer: value => binary(value, 1, 4096),
  deviceName, capabilities, signature, purpose: value => member(value, purposes),
  reservationExpiresAt: timestamp, resultExpiresAt: timestamp, expiresAt: timestamp,
  credentialExpiresAt: timestamp, retryAfterMillis: value => integer(value, 1000, 1000),
};
function schema(channel, value, decode = false) {
  if (!ENROLLMENT_CHANNELS.includes(channel)) invalid();
  const version = integer(field(value, 'protocolVersion'), 1, 2147483647);
  if (version !== 1) {
    if (decode) throw new DecodeError('unsupported_version');
    invalid();
  }
  const type = field(value, 'type');
  const fields = type === 'pair_error' && channel.endsWith('_response')
    ? ['code'] : typeof type === 'string' && Object.hasOwn(specifications[channel], type)
      ? specifications[channel][type] : invalid();
  exact(value, ['protocolVersion', 'type', ...fields]);
  const material = { protocolVersion: 1, type };
  for (const key of fields) {
    material[key] = key === 'code' ? member(value[key], type === 'pair_error' ? errorCodes : endedCodes)
      : validators[key](value[key]);
  }
  return material;
}

/** Validate bounded structure and decoded duplicate names before whole-object allocation. */
function guard(source) {
  let offset = 0;
  const white = () => { while (offset < source.length && /[ \t\r\n]/.test(source[offset])) offset++; };
  function string() {
    const start = offset++;
    let ended = false;
    while (offset < source.length) {
      const character = source[offset++];
      if (character === '\\') { offset++; continue; }
      if (character === '"') { ended = true; break; }
    }
    if (!ended) invalid();
    const decoded = JSON.parse(source.slice(start, offset));
    if (!decoded.isWellFormed()) invalid();
    return decoded;
  }
  function value(depth) {
    white();
    const character = source[offset];
    if (character === '{' || character === '[') {
      if (depth > 3) invalid();
      const object = character === '{';
      const close = object ? '}' : ']';
      const keys = new Set();
      let count = 0;
      offset++;
      white();
      if (source[offset] === close) { offset++; return; }
      while (offset < source.length) {
        if (++count > 16) invalid();
        if (object) {
          if (source[offset] !== '"') invalid();
          const key = string();
          if (keys.has(key)) invalid();
          keys.add(key);
          white();
          if (source[offset++] !== ':') invalid();
        }
        value(depth + 1);
        white();
        if (source[offset] === close) { offset++; return; }
        if (source[offset++] !== ',') invalid();
        white();
      }
      invalid();
    } else if (character === '"') string();
    else {
      const start = offset;
      while (offset < source.length && !/[ \t\r\n,\]}]/.test(source[offset])) offset++;
      const token = source.slice(start, offset);
      if (!['true', 'false', 'null'].includes(token) && /^(0|[1-9][0-9]{0,9})$/.exec(token)?.[0] !== token) invalid();
    }
  }
  white();
  if (source[offset] !== '{') invalid();
  value(1);
  white();
  if (offset !== source.length) invalid();
}

export function decodeEnrollment(channel, input) {
  try {
    if (!(input instanceof Uint8Array)) invalid();
    if (input.byteLength > ENROLLMENT_MAX_BYTES) throw new DecodeError('message_too_large');
    if (input.byteLength < 1) invalid();
    const bytes = Buffer.from(input);
    if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) invalid();
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    guard(source);
    const message = new EnrollmentMessage(brand, channel, schema(channel, JSON.parse(source), true));
    return { ok: true, message };
  } catch (error) {
    return { ok: false, code: error instanceof DecodeError && decoderCodes.has(error.code) ? error.code : 'invalid_message' };
  }
}
export function enrollmentMessage(channel, material) {
  try {
    const stored = records.get(material);
    if (stored && stored.channel !== channel) invalid();
    const wire = schema(channel, stored ? stored.material : material);
    if (Buffer.byteLength(JSON.stringify(wire), 'utf8') > ENROLLMENT_MAX_BYTES) invalid();
    return new EnrollmentMessage(brand, channel, wire);
  } catch { invalid(); }
}
export function encodeEnrollment(message) {
  try {
    const stored = records.get(message);
    if (!stored) invalid();
    return Buffer.from(JSON.stringify(stored.material), 'utf8');
  } catch { invalid(); }
}

const contextKeys = ['desktopId', 'gatewaySpkiSha256', 'invitationId', 'enrollmentId', 'deviceSpkiSha256', 'purpose'];
export function enrollmentProofPayload(context, challenge) {
  try {
    exact(context, contextKeys);
    const validated = {};
    for (const key of contextKeys) validated[key] = validators[key](context[key]);
    const record = records.get(challenge);
    if (!record || record.channel !== 'challenge_response' || record.material.type !== 'pair_challenge') invalid();
    const wire = record.material;
    if (contextKeys.some(key => validated[key] !== wire[key])) invalid();
    const strings = [validated.purpose, 'POST', '/companion/v1/pair/' + validated.purpose,
      validated.desktopId, validated.invitationId, validated.enrollmentId, wire.challengeId, wire.expiresAt];
    const parts = [Buffer.from('HTTP FreeKit enrollment proof v1\0', 'ascii')];
    for (const string of strings) {
      const bytes = Buffer.from(string, 'utf8');
      const length = Buffer.alloc(2);
      length.writeUInt16BE(bytes.length);
      parts.push(length, bytes);
    }
    for (const key of ['gatewaySpkiSha256', 'deviceSpkiSha256', 'nonce']) parts.push(Buffer.from(wire[key], 'base64url'));
    const payload = Buffer.concat(parts);
    if (payload.length > 1024) invalid();
    return payload;
  } catch { invalid(); }
}
export function enrollmentComparisonCode(gatewayPin, deviceHash) {
  try {
    binary(gatewayPin, 32);
    binary(deviceHash, 32);
    return createHash('sha256').update('HTTP FreeKit pairing comparison v1\0', 'ascii')
      .update(Buffer.from(gatewayPin, 'base64url')).update(Buffer.from(deviceHash, 'base64url'))
      .digest('hex').match(/.{8}/g).join('-');
  } catch { invalid(); }
}
