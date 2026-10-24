import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import test from 'node:test';
import { createMessage, decodeControl, decodeStream, encodeControl, encodeStream, DEFAULT_LIMITS } from './companion-protocol-codec.mjs';

const token = Buffer.alloc(32, 7).toString('base64url');
const hello = { protocolVersion: 1, type: 'hello', capabilities: ['tcp-https-connect', 'tcp-http'], requiredCapabilities: ['tcp-http'] };
const ready = { protocolVersion: 1, type: 'session_ready', capabilities: ['tcp-http'], desktopId: 'paired-computer',
  expiresAt: '2026-10-24T15:00:00Z', limits: { ...DEFAULT_LIMITS }, sessionId: token };
const decode = value => decodeControl(Buffer.from(JSON.stringify(value)));
const code = (operation, expected = 'invalid_message') => assert.throws(operation, error => error.code === expected && error.cause === undefined);

test('ordinary JSON ordering, whitespace and escapes normalize without requiring canonical input', () => {
  const input = Buffer.from(' \r\n{ "requiredCapabilities": ["tcp-http"], "capabilities": ["tcp-https-connect","tcp-http"], "t\\u0079pe": "hello", "protocolVersion": 1 }\t');
  assert.deepEqual(decodeControl(input).toWire(), { capabilities: ['tcp-http', 'tcp-https-connect'], protocolVersion: 1,
    requiredCapabilities: ['tcp-http'], type: 'hello' });
  assert.equal(encodeControl(decodeControl(input)).toString(), '{"capabilities":["tcp-http","tcp-https-connect"],"protocolVersion":1,"requiredCapabilities":["tcp-http"],"type":"hello"}');
  assert.deepEqual(decode(ready).toWire().limits, DEFAULT_LIMITS);
});

test('duplicate and escape-equivalent keys are rejected before version handling', () => {
  for (const input of [
    '{"protocolVersion":2,"type":"cancel","type":"cancel"}',
    '{"protocolVersion":2,"type":"cancel","t\\u0079pe":"cancel"}',
    JSON.stringify(ready).replace('"maxFrameBytes":65536', '"maxFrameBytes":65536,"maxFrameBytes":1'),
  ]) code(() => decodeControl(Buffer.from(input)));
});

test('bounded guard rejects nesting, members, long encoded keys and malformed syntax', () => {
  for (const input of ['[[[[0]]]]', '{"a":[[[0]]]}', '{' + Array.from({ length: 17 }, (_, i) => `"k${i}":0`).join(',') + '}',
    '{"' + '\\u0061'.repeat(43) + '":0}', '{"protocolVersion":1,"type":"cancel",}', '{}{}', '/*comment*/{}',
    '{"protocolVersion":1,"type":"cancel"', '{"a":"unterminated', '[1,2', '{"a":01}']) {
    code(() => decodeControl(Buffer.from(input)));
  }
});

test('strict UTF8, BOM and exact encoded-size boundaries precede schema/version', () => {
  const valid = encodeControl({ protocolVersion: 1, type: 'cancel' });
  assert.equal(decodeControl(Buffer.concat([valid, Buffer.alloc(16384 - valid.length, 32)])).toWire().type, 'cancel');
  code(() => decodeControl(Buffer.concat([valid, Buffer.alloc(16385 - valid.length, 32)])), 'message_too_large');
  code(() => decodeControl(Buffer.alloc(16385, 0xff)), 'message_too_large');
  for (const invalid of [Buffer.alloc(0), Buffer.from([0xef, 0xbb, 0xbf, ...valid]), Buffer.from([0xc0, 0xaf]),
    Buffer.from([0xed, 0xa0, 0x80]), Buffer.from([0xf4, 0x90, 0x80, 0x80]), Buffer.from([0xe2, 0x82])]) {
    code(() => decodeControl(invalid));
  }
});

test('integer spellings and complete schema are checked before unsupported version', () => {
  for (const number of ['-0', '-1', '1.0', '1e0', '01', '2147483648', '9007199254740993', 'true', 'null', '"1"']) {
    code(() => decodeControl(Buffer.from(`{"protocolVersion":${number},"type":"cancel"}`)));
  }
  code(() => decodeControl(Buffer.from('{"protocolVersion":2,"type":"cancel"}')), 'unsupported_version');
  code(() => decodeControl(Buffer.from('{"protocolVersion":2,"type":"cancel","unknown":0}')));
  code(() => decode({ ...ready, protocolVersion: 2, expiresAt: '2026-02-30T00:00:00Z' }));
  code(() => decode({ ...hello, protocolVersion: 2, requiredCapabilities: ['unoffered'] }));
});

test('capability syntax/unique/subset schema accepts unknown optional and required names', () => {
  assert.deepEqual(decode({ ...hello, capabilities: ['unknown-feature'], requiredCapabilities: ['unknown-feature'] }).toWire().capabilities,
    ['unknown-feature']);
  for (const invalid of [[], ['tcp-http', 'tcp-http'], ['Uppercase'], ['x'.repeat(33)], Array.from({ length: 17 }, (_, i) => `x${i}`)]) {
    code(() => decode({ ...hello, capabilities: invalid }));
  }
  code(() => decode({ ...hello, requiredCapabilities: ['unoffered'] }));
  assert.deepEqual(decode({ ...hello, requiredCapabilities: [] }).toWire().requiredCapabilities, []);
});

test('dates, canonical token, identifiers and negotiated relationships are strict', () => {
  for (const expiresAt of ['1999-12-31T23:59:59Z', '2100-01-01T00:00:00Z', '2026-02-29T00:00:00Z',
    '2026-01-01T24:00:00Z', '2026-10-24T15:00:00.000Z', '2026-10-24T15:00:00+00:00']) code(() => decode({ ...ready, expiresAt }));
  assert.equal(decode({ ...ready, expiresAt: '2000-02-29T00:00:00Z' }).toWire().expiresAt, '2000-02-29T00:00:00Z');
  for (const sessionId of [token + '=', token.slice(1), 'x'.repeat(43), token.slice(0, -1) + 'd']) code(() => decode({ ...ready, sessionId }));
  for (const desktopId of ['', 'x'.repeat(129), 'private computer', '\ud800']) code(() => decode({ ...ready, desktopId }));
  for (const limits of [{ ...DEFAULT_LIMITS, maxFrameBytes: 0 }, { ...DEFAULT_LIMITS, maxFrameBytes: 65537 },
    { ...DEFAULT_LIMITS, maxQueuedBytesPerStream: 65535 }, { ...DEFAULT_LIMITS, maxQueuedBytesPerDevice: 1048575 },
    { ...DEFAULT_LIMITS, maxConcurrentStreams: 65 }, { ...DEFAULT_LIMITS, maxQueuedFramesPerStream: 0 },
    { ...DEFAULT_LIMITS, maxOpenedStreamsPerSession: 63 }, { ...DEFAULT_LIMITS, maxOpenedStreamsPerSession: 4097 },
    { ...DEFAULT_LIMITS, extra: 1 }]) code(() => decode({ ...ready, limits }));
});

test('channel and exact error enums cannot smuggle destinations or credentials', () => {
  const open = { protocolVersion: 1, type: 'open', streamId: 'flow_1' };
  assert.deepEqual(decodeStream(encodeStream(open)).toWire(), open);
  code(() => decodeControl(encodeStream(open)));
  code(() => decodeStream(encodeControl(hello)));
  code(() => createMessage('stream', { ...open, destination: 'private.example' }));
  code(() => createMessage('stream', { ...open, sessionId: token }));
  code(() => createMessage('stream', { protocolVersion: 1, type: 'error', streamId: 'flow', code: 'unsupported_version' }));
  code(() => createMessage('control', { protocolVersion: 1, type: 'disconnect', code: 'network_unreachable' }));
});

test('decoded ASCII identifiers and capabilities reject final LF and CRLF in full', () => {
  for (const suffix of ['\n', '\r\n', '\r', '\u2028', '\u2029']) {
    code(() => decode({ ...ready, desktopId: 'desktop' + suffix }));
    code(() => decode({ ...hello, capabilities: ['tcp-http' + suffix], requiredCapabilities: [] }));
    code(() => decode({ ...hello, capabilities: ['tcp-http', 'optional' + suffix], requiredCapabilities: [] }));
    code(() => createMessage('stream', { protocolVersion: 1, type: 'open', streamId: 'flow' + suffix }));
    code(() => decodeStream(Buffer.from(JSON.stringify({ protocolVersion: 1, type: 'open', streamId: 'flow' + suffix }))));
    code(() => decode({ ...ready, sessionId: token + suffix }));
    code(() => decode({ ...ready, expiresAt: ready.expiresAt + suffix }));
  }
});

test('wire snapshots and default diagnostics never expose retained identity material', () => {
  const input = { ...ready, capabilities: ['tcp-http'], limits: { ...DEFAULT_LIMITS } };
  const message = createMessage('control', input);
  input.capabilities[0] = 'changed';
  input.limits.maxFrameBytes = 1;
  const exposed = message.toWire(); exposed.sessionId = 'changed'; exposed.capabilities.length = 0;
  assert.equal(message.toWire().sessionId, token);
  assert.equal(message.toWire().limits.maxFrameBytes, 65536);
  assert.deepEqual(message.toWire().capabilities, ['tcp-http']);
  for (const diagnostic of [String(message), JSON.stringify(message), inspect(message)]) {
    assert.ok(!diagnostic.includes(token) && !diagnostic.includes(ready.desktopId));
  }
  let failure;
  try { decodeControl(Buffer.from(`{"sessionId":"${token}", broken`)); } catch (error) { failure = error; }
  for (const diagnostic of [String(failure), JSON.stringify(failure), inspect(failure), failure.stack]) assert.ok(!diagnostic.includes(token));
  let read = false;
  code(() => encodeControl({ protocolVersion: 1, get type() { read = true; return 'cancel'; } }));
  assert.equal(read, false);
});
