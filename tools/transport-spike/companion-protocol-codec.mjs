// Research reference for stream draft0.3 plus HTTP-origin draft0.5. No transport or authentication.
import { inspect } from 'node:util';

export const MAX_TEXT_BYTES = 16384;
export const CONTROL_ERRORS = Object.freeze(['unsupported_version', 'unsupported_capability', 'authentication_failed',
  'device_revoked', 'proxy_unavailable', 'session_limit', 'stream_limit', 'invalid_message', 'network_unreachable', 'session_expired']);
export const STREAM_ERRORS = Object.freeze(['proxy_unavailable', 'stream_limit', 'invalid_message',
  'network_unreachable', 'device_revoked', 'session_expired', 'unsupported_capability']);
export const DEFAULT_LIMITS = Object.freeze({ maxFrameBytes: 65536, maxQueuedBytesPerStream: 1048576,
  maxQueuedBytesPerDevice: 4194304, maxConcurrentStreams: 64, maxQueuedFramesPerStream: 64, maxOpenedStreamsPerSession: 4096 });
export const DEFAULT_CAPABILITIES = Object.freeze(['tcp-http', 'tcp-https-connect']);
export const TRAFFIC_CAPABILITIES = Object.freeze([...DEFAULT_CAPABILITIES, 'tcp-http-origin-connect']);

const errorCodes = new Set([...CONTROL_ERRORS, 'message_too_large']);
export class CompanionProtocolError extends Error {
  constructor(code = 'invalid_message') {
    const safe = errorCodes.has(code) ? code : 'invalid_message';
    super(safe);
    this.name = 'CompanionProtocolError';
    this.code = safe;
  }
  toString() { return `CompanionProtocolError(${this.code})`; }
  toJSON() { return { error: this.code }; }
  [inspect.custom]() { return this.toString(); }
}
const invalid = () => { throw new CompanionProtocolError(); };
const records = new WeakMap();
const brand = Symbol('validated-message');

/** Material is available only through explicit wire access, never default diagnostics. */
export class CompanionMessage {
  constructor(key, channel, wire) {
    if (key !== brand) invalid();
    records.set(this, { channel, wire });
    Object.freeze(this);
  }
  toWire() { return clone(records.get(this).wire); }
  toString() { return 'CompanionMessage([REDACTED])'; }
  toJSON() { return { kind: 'CompanionMessage', redacted: true }; }
  [inspect.custom]() { return this.toString(); }
}

function clone(value) {
  if (Array.isArray(value)) return value.map(clone);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, clone(v)]));
  return value;
}
function ordered(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(ordered));
  if (value !== null && typeof value === 'object') {
    return Object.freeze(Object.fromEntries(Object.keys(value).sort().map(k => [k, ordered(value[k])])));
  }
  return value;
}
function exact(object, keys) {
  if (object === null || typeof object !== 'object' || Array.isArray(object) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(object))) invalid();
  const actual = Reflect.ownKeys(object);
  if (actual.length !== keys.length || actual.some(k => typeof k !== 'string' || !keys.includes(k))) invalid();
  for (const key of actual) if (!Object.hasOwn(Object.getOwnPropertyDescriptor(object, key), 'value')) invalid();
}
function integer(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum || Object.is(value, -0)) invalid();
  return value;
}
function text(value, pattern) {
  // JS `$` may stop before a final line terminator; require the entire decoded value.
  if (typeof value !== 'string' || pattern.exec(value)?.[0] !== value) invalid();
  return value;
}
export function validateCapabilities(value, empty = false) {
  if (!Array.isArray(value) || value.length < (empty ? 0 : 1) || value.length > 16) invalid();
  const entries = [];
  for (let i = 0; i < value.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid();
    entries.push(text(descriptor.value, /^[a-z][a-z0-9-]{0,31}$/));
  }
  if (new Set(entries).size !== entries.length) invalid();
  return entries.sort();
}
export function validateLimits(value) {
  exact(value, Object.keys(DEFAULT_LIMITS));
  const maxFrameBytes = integer(value.maxFrameBytes, 1, 65536);
  const maxQueuedBytesPerStream = integer(value.maxQueuedBytesPerStream, maxFrameBytes, 1048576);
  const maxQueuedBytesPerDevice = integer(value.maxQueuedBytesPerDevice, maxQueuedBytesPerStream, 4194304);
  const maxConcurrentStreams = integer(value.maxConcurrentStreams, 1, 64);
  return ordered({ maxFrameBytes, maxQueuedBytesPerStream, maxQueuedBytesPerDevice, maxConcurrentStreams,
    maxQueuedFramesPerStream: integer(value.maxQueuedFramesPerStream, 1, 64),
    maxOpenedStreamsPerSession: integer(value.maxOpenedStreamsPerSession, maxConcurrentStreams, 4096) });
}
export function tokenBytes(value) {
  text(value, /^[A-Za-z0-9_-]{43}$/);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) invalid();
  return bytes;
}
export function expiryMillis(value) {
  text(value, /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== `${value.slice(0, -1)}.000Z`) invalid();
  return time;
}

function schema(channel, value) {
  if (!['control', 'stream'].includes(channel)) invalid();
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  const descriptor = Object.getOwnPropertyDescriptor(value, 'type');
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid();
  const type = descriptor.value;
  const fields = channel === 'control' ? {
    hello: ['capabilities', 'requiredCapabilities'], session_ready: ['capabilities', 'desktopId', 'expiresAt', 'limits', 'sessionId'],
    cancel: [], disconnect: ['code'], error: ['code'],
  } : { open: ['streamId'], ready: ['streamId'], end_write: ['streamId'], cancel: ['streamId'], error: ['code', 'streamId'] };
  if (typeof type !== 'string' || !Object.hasOwn(fields, type)) invalid();
  const originMode = channel === 'stream' && type === 'open' && Object.hasOwn(value, 'proxyMode');
  exact(value, ['protocolVersion', 'type', ...fields[type], ...(originMode ? ['proxyMode'] : [])]);
  const protocolVersion = integer(value.protocolVersion, 1, 2147483647);
  const wire = { protocolVersion, type };
  if (channel === 'stream') wire.streamId = text(value.streamId, /^[A-Za-z0-9_-]{1,64}$/);
  if (originMode) wire.proxyMode = text(value.proxyMode, /^http-origin-connect$/);
  if (type === 'hello') {
    wire.capabilities = validateCapabilities(value.capabilities);
    wire.requiredCapabilities = validateCapabilities(value.requiredCapabilities, true);
    if (!wire.requiredCapabilities.every(c => wire.capabilities.includes(c))) invalid();
  }
  if (type === 'session_ready') {
    wire.capabilities = validateCapabilities(value.capabilities);
    wire.desktopId = text(value.desktopId, /^[A-Za-z0-9_-]{1,128}$/);
    expiryMillis(value.expiresAt);
    wire.expiresAt = value.expiresAt;
    wire.limits = validateLimits(value.limits);
    tokenBytes(value.sessionId);
    wire.sessionId = value.sessionId;
  }
  if (type === 'error' || type === 'disconnect') {
    const allowed = type === 'disconnect' ? ['desktop_stopped', 'device_revoked', 'session_expired'] :
      channel === 'control' ? CONTROL_ERRORS : STREAM_ERRORS;
    if (!allowed.includes(value.code)) invalid();
    wire.code = value.code;
  }
  // Version errors must never mask a defective schema.
  if (protocolVersion !== 1) throw new CompanionProtocolError('unsupported_version');
  return ordered(wire);
}

/** Structural guard only. JSON.parse remains responsible for JSON syntax/string decoding. */
function guard(source, { maxDepth = 3, maxMembers = 16, maximumInteger = 2147483647n, negative = false } = {}) {
  const stack = [];
  for (let i = 0; i < source.length; i++) {
    const character = source[i];
    if (character === '"') {
      const start = i++;
      let closed = false;
      for (; i < source.length; i++) {
        if (source[i] === '\\') { i++; continue; }
        if (source[i] === '"') { closed = true; break; }
      }
      if (!closed) invalid();
      const current = stack.at(-1);
      if (current?.kind === '{' && current.key) {
        const token = source.slice(start, i + 1);
        if (Buffer.byteLength(token, 'utf8') > 256) invalid();
        const key = JSON.parse(token);
        if (current.keys.has(key) || current.keys.size === maxMembers) invalid();
        current.keys.add(key);
        current.key = false;
      }
    } else if (character === '{' || character === '[') {
      if (stack.length === maxDepth) invalid();
      stack.push({ kind: character, key: true, keys: new Set() });
    } else if (character === '}' || character === ']') {
      if (stack.pop()?.kind !== (character === '}' ? '{' : '[')) invalid();
    } else if (character === ',') {
      if (stack.at(-1)?.kind === '{') stack.at(-1).key = true;
    } else if (/[0-9-]/.test(character)) {
      const start = i;
      while (i + 1 < source.length && !/[\s,\]}:]/.test(source[i + 1])) i++;
      const token = source.slice(start, i + 1);
      const pattern = negative ? /^(0|-?[1-9][0-9]*)$/ : /^(0|[1-9][0-9]*)$/;
      if (pattern.exec(token)?.[0] !== token || token.length > (negative ? 17 : 10)) invalid();
      const number = BigInt(token);
      if (number > maximumInteger || number < -maximumInteger) invalid();
    }
  }
  if (stack.length) invalid();
}

/** Bounded synthetic corpus JSON, not an application-message decoding alternative. */
export function decodeCorpusJson(input) {
  try {
    if (!(input instanceof Uint8Array) || input.byteLength < 1 || input.byteLength > 2 * 1024 * 1024) invalid();
    if (input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) invalid();
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input);
    guard(source, { maxDepth: 32, maxMembers: 4096, maximumInteger: 9007199254740991n, negative: true });
    return JSON.parse(source);
  } catch { invalid(); }
}

export function decodeMessage(channel, input) {
  try {
    if (!(input instanceof Uint8Array)) invalid();
    if (input.byteLength > MAX_TEXT_BYTES) throw new CompanionProtocolError('message_too_large');
    if (input.byteLength === 0) invalid();
    const bytes = Buffer.from(input);
    if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) invalid();
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    guard(source);
    return new CompanionMessage(brand, channel, schema(channel, JSON.parse(source)));
  } catch (problem) {
    if (problem instanceof CompanionProtocolError) throw problem;
    invalid();
  }
}
export function createMessage(channel, value) {
  try {
    const stored = records.get(value);
    if (stored && stored.channel !== channel) invalid();
    return new CompanionMessage(brand, channel, schema(channel, stored ? stored.wire : value));
  } catch (problem) {
    if (problem instanceof CompanionProtocolError) throw problem;
    invalid();
  }
}
export function encodeMessage(channel, value) {
  const message = createMessage(channel, value);
  const bytes = Buffer.from(JSON.stringify(records.get(message).wire), 'utf8');
  if (bytes.length > MAX_TEXT_BYTES) throw new CompanionProtocolError('message_too_large');
  return bytes;
}
export const decodeControl = input => decodeMessage('control', input);
export const decodeStream = input => decodeMessage('stream', input);
export const encodeControl = value => encodeMessage('control', value);
export const encodeStream = value => encodeMessage('stream', value);
