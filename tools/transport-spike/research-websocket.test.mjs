import test from 'node:test';
import assert from 'node:assert/strict';
import { Duplex, PassThrough } from 'node:stream';
import net from 'node:net';
import { once } from 'node:events';
import { inspect } from 'node:util';
import { ResearchWebSocket, ResearchWebSocketError } from './research-websocket.mjs';

const bytes = text => Buffer.from(text, 'utf8');
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const code = expected => failure => failure instanceof ResearchWebSocketError && failure.code === expected;
function wire(opcode, payload = Buffer.alloc(0), { final = true, masked = false } = {}) {
  const size = payload.length;
  const extra = size < 126 ? 0 : size <= 65535 ? 2 : 8;
  const offset = 2 + extra + (masked ? 4 : 0);
  const result = Buffer.alloc(offset + size);
  result[0] = (final ? 128 : 0) | opcode;
  result[1] = (masked ? 128 : 0) | (extra === 0 ? size : extra === 2 ? 126 : 127);
  if (extra === 2) result.writeUInt16BE(size, 2);
  if (extra === 8) result.writeBigUInt64BE(BigInt(size), 2);
  const mask = Buffer.from([71, 29, 31, 43]);
  if (masked) mask.copy(result, offset - 4);
  for (let index = 0; index < size; index++) result[offset + index] = payload[index] ^ (masked ? mask[index & 3] : 0);
  return result;
}
function input(options = {}) {
  const stream = new PassThrough({ autoDestroy: false });
  return { stream, owner: new ResearchWebSocket(stream, { role: 'client', ...options }) };
}
async function invalid(frame, expected, options = {}) {
  const { stream, owner } = input(options);
  stream.write(frame);
  await assert.rejects(owner.next(), code(expected));
  await owner.cancel();
  return owner.snapshot();
}
async function read(owner, kind, expected) {
  const event = await owner.next();
  assert.equal(event.kind, kind);
  if (expected !== undefined) assert.deepEqual(event.copyBytes(), expected);
  event.release();
  return event;
}

class HeldWrites extends Duplex {
  constructor({ delayDestroy = false, emitClose = true, writableHighWaterMark = 1 } = {}) {
    super({ writableHighWaterMark, autoDestroy: false, emitClose });
    this.frames = [];
    this.callbacks = [];
    this.delayDestroy = delayDestroy;
  }
  _read() {}
  _write(chunk, _encoding, callback) {
    this.frames.push(Buffer.from(chunk));
    this.callbacks.push(callback);
  }
  complete() { assert.ok(this.callbacks.length); this.callbacks.shift()(); }
  _destroy(_failure, callback) {
    for (const pending of this.callbacks.splice(0)) pending(Error('PRIVATE_SOCKET_ERROR'));
    if (this.delayDestroy) this.destroyCallback = callback;
    else callback();
  }
}

test('configuration is bounded and refuses flowing or encoded sources', async () => {
  for (const options of [{ role: 'other' }, { maxBinaryBytes: 0 }, { maxBinaryBytes: 65537 },
    { maxFragments: 65 }, { maxInterleavedControls: 0 }, { cleanupTimeoutMillis: 0 },
    { initialBytes: Buffer.alloc(65551) }]) {
    const stream = new PassThrough();
    assert.throws(() => new ResearchWebSocket(stream, { role: 'client', ...options }), code('invalid_configuration'));
    stream.destroy();
  }
  const flowing = new PassThrough();
  flowing.resume();
  assert.throws(() => new ResearchWebSocket(flowing, { role: 'client' }), code('invalid_configuration'));
  flowing.destroy();
  const encoded = new PassThrough();
  encoded.setEncoding('utf8');
  assert.throws(() => new ResearchWebSocket(encoded, { role: 'client' }), code('invalid_configuration'));
  encoded.destroy();
});

test('coalesced frames stop exactly at one leased message and disclose underlying buffering', async () => {
  const { stream, owner } = input();
  const first = wire(2, bytes('first'));
  const second = wire(2, bytes('second'));
  stream.write(Buffer.concat([first, second]));
  const event = await owner.next();
  assert.deepEqual(event.copyBytes(), bytes('first'));
  const copy = event.copyBytes(); copy.fill(0);
  assert.deepEqual(event.copyBytes(), bytes('first'));
  assert.equal(owner.snapshot().sourceBytesRead, first.length);
  assert.equal(owner.snapshot().underlyingReadableBytes, second.length);
  await assert.rejects(owner.next(), code('message_pending'));
  assert.equal(owner.snapshot().sourceBytesRead, first.length);
  assert.equal(stream.listenerCount('data'), 0);
  event.release(); event.release();
  await assert.rejects(async () => event.copyBytes(), code('message_released'));
  await read(owner, 'binary', bytes('second'));
  await owner.cancel();
  await assert.rejects(owner.finish(), code('invalid_close_state'));
});

test('upgrade remainder is copied, bounded, and consumed without losing following frames', async () => {
  const head = Buffer.concat([wire(1, bytes('A')), wire(2, bytes('B'))]);
  const { owner } = input({ initialBytes: head });
  head.fill(0);
  await read(owner, 'text', bytes('A'));
  assert.equal(owner.snapshot().sourceBytesRead, 0);
  assert.equal(owner.snapshot().upgradeBytesRemaining, 3);
  await read(owner, 'binary', bytes('B'));
  assert.equal(owner.snapshot().upgradeBytesRemaining, 0);
  await owner.cancel();
});

test('one-byte input and concurrent read rejection preserve the first read', async () => {
  const { stream, owner } = input({ role: 'server' });
  const pending = owner.next();
  await assert.rejects(owner.next(), code('read_in_progress'));
  for (const byte of wire(1, bytes('slow'), { masked: true })) {
    stream.write(Buffer.from([byte]));
    await delay(1);
  }
  const event = await pending;
  assert.equal(event.kind, 'text');
  assert.deepEqual(event.copyBytes(), bytes('slow'));
  event.release();
  await owner.cancel();
});

test('RSV, reserved opcode, mask role, continuation order and fragmented controls are rejected', async () => {
  for (const frame of [Buffer.from([0xc2, 0]), wire(3), wire(15), wire(0), wire(9, bytes('p'), { final: false }),
    wire(2, bytes('masked'), { masked: true })]) {
    await invalid(frame, 'invalid_frame');
  }
  await invalid(wire(2), 'invalid_frame', { role: 'server' });
  await invalid(Buffer.concat([wire(1, bytes('a'), { final: false }), wire(2, bytes('b'))]), 'invalid_frame');
});

test('nonminimal extended lengths and the unsigned 64-bit high bit fail before allocation', async () => {
  for (const frame of [Buffer.from([0x82, 126, 0, 125]),
    Buffer.from([0x82, 127, 0, 0, 0, 0, 0, 0, 255, 255]),
    Buffer.from([0x82, 127, 128, 0, 0, 0, 0, 1, 0, 0])]) {
    const result = await invalid(frame, 'invalid_frame');
    assert.equal(result.payloadBytesAllocated, 0);
  }
});

test('advertised huge, binary, text and control lengths are bounded before body allocation', async () => {
  const headers = [Buffer.from([0x82, 127, 0, 0, 0, 1, 0, 0, 0, 0]),
    Buffer.from([0x82, 127, 0, 0, 0, 0, 0, 1, 0, 1]),
    Buffer.from([0x81, 126, 64, 1])];
  for (const frame of headers) {
    const result = await invalid(frame, 'message_too_large');
    assert.equal(result.payloadBytesAllocated, 0);
    assert.equal(result.peakReaderPayloadBytes, 0);
  }
  assert.equal((await invalid(Buffer.from([0x82, 2]), 'message_too_large', { maxBinaryBytes: 1 })).payloadBytesAllocated, 0);
});

test('invalid extended control markers reject on their two-byte header without awaiting a body', async () => {
  for (const marker of [126, 127]) {
    const result = await invalid(Buffer.from([0x89, marker]), 'invalid_frame');
    assert.equal(result.sourceBytesRead, 2);
    assert.equal(result.payloadBytesAllocated, 0);
  }
});

test('all legal length boundaries, including exactly 64KiB, survive masking', async () => {
  for (const size of [0, 1, 125, 126, 65535, 65536]) {
    const { stream, owner } = input({ role: 'server' });
    const payload = Buffer.alloc(size, 0xa5);
    stream.write(wire(2, payload, { masked: true }));
    await read(owner, 'binary', payload);
    assert.ok(owner.snapshot().peakReaderPayloadBytes <= 65536);
    await owner.cancel();
  }
});

test('fragmented UTF8 joins across codepoints and preserves interleaved controls', async () => {
  const { stream, owner } = input();
  const text = bytes('a😂z');
  stream.write(Buffer.concat([wire(1, text.subarray(0, 3), { final: false }), wire(9, bytes('ping')),
    wire(10, bytes('pong')), wire(0, text.subarray(3))]));
  await read(owner, 'ping', bytes('ping'));
  assert.equal(owner.snapshot().fragmentBytes, 3);
  await read(owner, 'pong', bytes('pong'));
  await read(owner, 'text', text);
  assert.equal(owner.snapshot().fragmentBytes, 0);
  assert.ok(owner.snapshot().peakReaderPayloadBytes <= 2 * text.length);
  await owner.cancel();
});

test('cumulative fragment length is rejected before allocating or reading the next payload', async () => {
  const prefix = wire(2, bytes('abc'), { final: false });
  const result = await invalid(Buffer.concat([prefix, Buffer.from([0x80, 2])]), 'message_too_large', { maxBinaryBytes: 4 });
  assert.equal(result.payloadBytesAllocated, 3);
  assert.equal(result.sourceBytesRead, prefix.length + 2);
});

test('zero-byte fragment floods and interleaved controls have explicit research count limits', async () => {
  const fragments = [wire(2, Buffer.alloc(0), { final: false })];
  for (let index = 0; index < 64; index++) fragments.push(wire(0, Buffer.alloc(0), { final: false }));
  assert.equal((await invalid(Buffer.concat(fragments), 'fragment_limit')).payloadBytesAllocated, 0);
  const { stream, owner } = input();
  stream.write(Buffer.concat([wire(2, Buffer.alloc(0), { final: false }), ...Array.from({ length: 65 }, () => wire(9))]));
  for (let index = 0; index < 64; index++) await read(owner, 'ping');
  await assert.rejects(owner.next(), code('control_limit'));
  await owner.cancel();
});

test('invalid complete or fragmented UTF8 is rejected, while BOM and LF are framing-valid', async () => {
  for (const payload of [Buffer.from([0xc0, 0xaf]), Buffer.from([0xed, 0xa0, 0x80]), Buffer.from([0xf0])]) {
    await invalid(wire(1, payload), 'invalid_utf8');
  }
  await invalid(Buffer.concat([wire(1, Buffer.from([0xf0]), { final: false }), wire(0, bytes('x'))]), 'invalid_utf8');
  const { stream, owner } = input();
  const payload = bytes('\uFEFFline\n');
  stream.write(wire(1, payload));
  await read(owner, 'text', payload); // Companion JSON has its own stricter BOM rule.
  await owner.cancel();
});

test('wire close codes, close UTF8 and valid LF/CRLF reasons are handled separately from identifiers', async () => {
  for (const value of [999, 1004, 1005, 1006, 1015, 1016, 2999, 5000]) {
    const body = Buffer.alloc(2); body.writeUInt16BE(value);
    await invalid(wire(8, body), 'invalid_close');
  }
  await invalid(wire(8, Buffer.from([3])), 'invalid_close');
  await invalid(wire(8, Buffer.from([3, 232, 0xff])), 'invalid_utf8');
  for (const value of [1000, 1014, 3000, 4999]) {
    const { stream, owner } = input();
    const body = Buffer.concat([Buffer.from([value >> 8, value & 255]), bytes('PRIVATE_REASON\n\r\n')]);
    stream.write(wire(8, body));
    const event = await owner.next();
    assert.equal(event.closeCode, value);
    assert.deepEqual(event.copyBytes(), body);
    assert.doesNotMatch(inspect(event), /PRIVATE_REASON/);
    event.release();
    await assert.rejects(owner.next(), code('connection_closed'));
    await owner.cancel();
  }
  const { stream, owner } = input();
  stream.write(wire(8));
  const event = await owner.next(); assert.equal(event.closeCode, 1005); event.release();
  await owner.cancel();
});

test('a close interrupts an unfinished fragmented message without exposing partial application bytes', async () => {
  const { stream, owner } = input();
  stream.write(Buffer.concat([wire(2, bytes('PRIVATE_PARTIAL'), { final: false }), wire(8, Buffer.from([3, 232]))]));
  await read(owner, 'close', Buffer.from([3, 232]));
  assert.equal(owner.snapshot().fragmentBytes, 0);
  await owner.cancel();
});

test('truncated headers, mask and payload reject and stop the stream', async () => {
  for (const frame of [Buffer.from([0x82]), Buffer.from([0x82, 126, 0]), Buffer.from([0x82, 3, 1]),
    Buffer.from([0x82, 127, 0, 0])]) {
    const { stream, owner } = input();
    stream.end(frame);
    await assert.rejects(owner.next(), code('unexpected_eof'));
    await owner.cancel();
    assert.equal(owner.snapshot().transportClosed, true);
  }
  const { stream, owner } = input({ role: 'server' });
  stream.end(Buffer.from([0x82, 128, 1, 2]));
  await assert.rejects(owner.next(), code('unexpected_eof'));
  await owner.cancel();
});

test('writer serializes accepted data/control, snapshots input and waits for callback plus backpressure', async () => {
  const stream = new HeldWrites();
  const owner = new ResearchWebSocket(stream, { role: 'server' });
  const payload = bytes('first');
  let completed = false;
  const first = owner.send('binary', payload).then(() => { completed = true; });
  payload.fill(0);
  const second = owner.send('ping', bytes('p'));
  await assert.rejects(owner.send('text', bytes('third')), code('write_backpressure'));
  assert.equal(stream.frames.length, 1);
  assert.equal(owner.snapshot().queuedWrites, 2);
  assert.equal(owner.snapshot().writeBackpressured, true);
  await delay(5);
  assert.equal(completed, false);
  assert.deepEqual(stream.frames[0], wire(2, bytes('first')));
  stream.complete(); await first;
  assert.equal(stream.frames.length, 2);
  assert.deepEqual(stream.frames[1], wire(9, bytes('p')));
  stream.complete(); await second;
  assert.equal(owner.snapshot().completedWrites, 2);
  await owner.cancel();
});

test('write returning true is still not completion until the actual callback', async () => {
  const stream = new HeldWrites({ writableHighWaterMark: 1024 });
  const owner = new ResearchWebSocket(stream, { role: 'server' });
  let completed = false;
  const writing = owner.send('binary', bytes('held')).then(() => { completed = true; });
  assert.equal(owner.snapshot().writeBackpressured, false);
  await delay(5);
  assert.equal(completed, false);
  assert.equal(owner.snapshot().pendingWriteCallbacks, 1);
  stream.complete(); await writing;
  assert.equal(owner.snapshot().pendingWriteCallbacks, 0);
  await owner.cancel();
});

test('writer validates before snapshotting and produces secure-masked client frames at every length boundary', async () => {
  for (const size of [0, 125, 126, 65535, 65536]) {
    const stream = new HeldWrites();
    const owner = new ResearchWebSocket(stream, { role: 'client' });
    const payload = Buffer.alloc(size, 0x5a);
    const sent = owner.send('binary', payload);
    const frame = stream.frames[0];
    assert.equal(frame[0], 0x82);
    assert.equal(frame[1] & 128, 128);
    assert.equal(frame[1] & 127, size < 126 ? size : size <= 65535 ? 126 : 127);
    const maskOffset = 2 + (size < 126 ? 0 : size <= 65535 ? 2 : 8);
    const decoded = Buffer.from(frame.subarray(maskOffset + 4));
    for (let index = 0; index < decoded.length; index++) decoded[index] ^= frame[maskOffset + (index & 3)];
    assert.deepEqual(decoded, payload);
    stream.complete(); await sent; await owner.cancel();
  }
  const stream = new HeldWrites();
  const owner = new ResearchWebSocket(stream, { role: 'server', maxBinaryBytes: 2 });
  for (const [kind, value, expected] of [['binary', Buffer.alloc(3), 'message_too_large'],
    ['text', Buffer.alloc(16385), 'message_too_large'], ['ping', Buffer.alloc(126), 'message_too_large'],
    ['text', Buffer.from([255]), 'invalid_utf8'], ['close', Buffer.from([3, 237]), 'invalid_close'],
    ['other', bytes('x'), 'invalid_frame']]) await assert.rejects(owner.send(kind, value), code(expected));
  assert.equal(stream.frames.length, 0);
  assert.equal(owner.snapshot().queuedWriteBytes, 0);
  await owner.cancel();
});

test('immediate sequential awaited sends cannot strand work during writer-owner finalization', { timeout: 5000 }, async () => {
  const frames = [];
  const stream = new Duplex({ read() {}, write(chunk, _encoding, callback) { frames.push(Buffer.from(chunk)); callback(); } });
  const owner = new ResearchWebSocket(stream, { role: 'server' });
  try {
    for (let index = 0; index < 100; index++) {
      await owner.send('binary', Buffer.from([index]));
      await owner.send('ping', Buffer.from([index]));
    }
    assert.equal(frames.length, 200);
    assert.equal(owner.snapshot().completedWrites, 200);
    for (let index = 0; index < 100; index++) {
      assert.deepEqual(frames[index * 2], wire(2, Buffer.from([index])));
      assert.deepEqual(frames[index * 2 + 1], wire(9, Buffer.from([index])));
    }
  } finally { await owner.cancel(); }
});

test('cancel joins pending read/write and retains buffers until actual close, with static diagnostics', async () => {
  const stream = new HeldWrites({ delayDestroy: true });
  const owner = new ResearchWebSocket(stream, { role: 'server' });
  const reading = assert.rejects(owner.next(), code('cancelled'));
  const writing = assert.rejects(owner.send('binary', bytes('PRIVATE_BODY')), code('cancelled'));
  const queued = assert.rejects(owner.send('ping', bytes('p')), code('cancelled'));
  let joined = false;
  const stopping = owner.cancel().then(() => { joined = true; });
  await Promise.all([reading, writing, queued]);
  await delay(5);
  assert.equal(joined, false);
  assert.equal(owner.snapshot().transportClosed, false);
  assert.equal(owner.snapshot().queuedWriteBytes, 13);
  assert.doesNotMatch(inspect(owner), /PRIVATE_BODY|PRIVATE_SOCKET_ERROR/);
  stream.destroyCallback();
  await stopping;
  assert.equal(owner.snapshot().transportClosed, true);
  assert.equal(owner.snapshot().queuedWriteBytes, 0);
  assert.equal(owner.snapshot().reading, false);
  await owner.cancel();
});

test('cleanup deadline is a failure, never evidence of resource closure or buffer release', async () => {
  const stream = new HeldWrites({ emitClose: false });
  const owner = new ResearchWebSocket(stream, { role: 'server', cleanupTimeoutMillis: 20 });
  const writing = assert.rejects(owner.send('binary', bytes('held')), code('cancelled'));
  await assert.rejects(owner.cancel(), code('cleanup_incomplete'));
  await writing;
  assert.equal(owner.snapshot().transportClosed, false);
  assert.equal(owner.snapshot().queuedWriteBytes, 4);
  stream.emit('close'); // Fault-injection release; not real socket-close proof.
  assert.equal(owner.snapshot().queuedWriteBytes, 0);
});

test('transport close alone cannot join or release a write whose actual callback remains outstanding', async () => {
  class LateCallback extends HeldWrites { _destroy(_failure, callback) { callback(); } }
  const stream = new LateCallback();
  const owner = new ResearchWebSocket(stream, { role: 'server' });
  const writing = assert.rejects(owner.send('binary', bytes('retained')), code('cancelled'));
  const closed = once(stream, 'close');
  let joined = false;
  const stopping = owner.cancel().then(() => { joined = true; });
  await writing; await closed;
  assert.equal(owner.snapshot().transportClosed, true);
  assert.equal(owner.snapshot().pendingWriteCallbacks, 1);
  assert.equal(owner.snapshot().queuedWriteBytes, 8);
  assert.equal(joined, false);
  stream.complete();
  await stopping;
  assert.equal(owner.snapshot().pendingWriteCallbacks, 0);
  assert.equal(owner.snapshot().queuedWriteBytes, 0);
  assert.equal(owner.snapshot().completedWrites, 0);
});

test('valid peer transport closure preserves the leased close event until explicit release', async () => {
  const stream = new HeldWrites();
  const owner = new ResearchWebSocket(stream, { role: 'server' });
  const body = Buffer.from([3, 232]);
  stream.push(wire(8, body, { masked: true }));
  const event = await owner.next();
  const reply = owner.send('close', body); stream.complete(); await reply;
  const closed = once(stream, 'close'); stream.destroy(); await closed;
  assert.equal(owner.snapshot().errorCode, null);
  assert.equal(owner.snapshot().messageLeased, true);
  assert.deepEqual(event.copyBytes(), body);
  await assert.rejects(owner.finish(), code('invalid_close_state'));
  event.release();
  await owner.finish();
  assert.equal(owner.snapshot().messageLeased, false);
});

test('errors and default inspection contain static codes without source errors or traffic', async () => {
  const { stream, owner } = input();
  const reading = owner.next();
  stream.destroy(Error('PRIVATE_PATH_AND_TRAFFIC'));
  await assert.rejects(reading, failure => {
    assert.equal(failure.code, 'network_error');
    assert.doesNotMatch(inspect(failure), /PRIVATE_|\.mjs|[A-Z]:\\/);
    assert.equal(failure.stack, 'ResearchWebSocketError: network_error');
    return true;
  });
  await owner.cancel();
});

test('real loopback sockets exchange ordered messages and finish only after both close frames', { timeout: 10000 }, async () => {
  const server = net.createServer();
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const accepted = once(server, 'connection');
  const client = net.connect(server.address().port, '127.0.0.1');
  const connected = once(client, 'connect');
  const [peer] = await accepted; await connected;
  const left = new ResearchWebSocket(client, { role: 'client' });
  const right = new ResearchWebSocket(peer, { role: 'server' });
  try {
    await assert.rejects(left.finish(), code('invalid_close_state'));
    await left.send('binary', Buffer.alloc(65536, 71));
    await read(right, 'binary', Buffer.alloc(65536, 71));
    await right.send('text', bytes('reply\n'));
    await read(left, 'text', bytes('reply\n'));
    await left.send('close', Buffer.from([3, 232]));
    await read(right, 'close', Buffer.from([3, 232]));
    await right.send('close', Buffer.from([3, 232]));
    await read(left, 'close', Buffer.from([3, 232]));
    await Promise.all([left.finish(), right.finish()]);
    assert.equal(left.snapshot().errorCode, null);
    assert.equal(right.snapshot().errorCode, null);
    assert.equal(left.snapshot().transportClosed, true);
    assert.equal(right.snapshot().transportClosed, true);
  } finally {
    await Promise.all([left.cancel(), right.cancel()]);
    await new Promise(resolve => server.close(resolve));
  }
});

test('real pending socket read cancellation observes close and settles the owner', { timeout: 10000 }, async () => {
  const server = net.createServer();
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const accepted = once(server, 'connection');
  const client = net.connect(server.address().port, '127.0.0.1');
  const connected = once(client, 'connect');
  const [peer] = await accepted; await connected;
  const owner = new ResearchWebSocket(client, { role: 'client' });
  const pending = assert.rejects(owner.next(), code('cancelled'));
  try {
    await owner.cancel(); await pending;
    assert.equal(client.closed, true);
    assert.equal(owner.snapshot().reading, false);
    assert.equal(owner.snapshot().transportClosed, true);
    assert.equal(client.listenerCount('readable'), 0);
  } finally { peer.destroy(); await new Promise(resolve => server.close(resolve)); }
});

test('real nonreading TCP peer backpressures a write; cancel settles it only after actual close', { timeout: 20000 }, async () => {
  const server = net.createServer();
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const accepted = once(server, 'connection');
  const client = net.connect({ port: server.address().port, host: '127.0.0.1', writableHighWaterMark: 1024 });
  const connected = once(client, 'connect');
  const [peer] = await accepted; await connected;
  peer.pause();
  const owner = new ResearchWebSocket(client, { role: 'client' });
  const payload = Buffer.alloc(65536, 0xa7);
  let pending = null;
  let timer;
  try {
    // Generate/reuse bounded chunks, never retain an entire upload. Refuse a false positive
    // if this platform buffers the whole 32MiB fixture without withholding a write callback.
    for (let total = 0; total < 32 * 1024 * 1024 && pending === null; total += payload.length) {
      const writing = owner.send('binary', payload);
      const outcome = await Promise.race([
        writing.then(() => 'completed', failure => { throw failure; }),
        new Promise(resolve => { timer = setTimeout(() => resolve('waiting'), 20); }),
      ]);
      clearTimeout(timer);
      if (outcome === 'waiting') {
        assert.ok(client.writableLength > 0);
        assert.equal(owner.snapshot().writeBackpressured, true);
        assert.equal(owner.snapshot().pendingWriteCallbacks, 1);
        assert.equal(owner.snapshot().queuedWrites, 1);
        assert.equal(owner.snapshot().queuedWriteBytes, payload.length);
        pending = assert.rejects(writing, code('cancelled'));
      }
    }
    assert.notEqual(pending, null, 'bounded fixture must actually encounter an unfinished local socket write');
    await owner.cancel(); await pending;
    assert.equal(client.closed, true);
    assert.equal(owner.snapshot().transportClosed, true);
    assert.equal(owner.snapshot().queuedWriteBytes, 0);
    assert.equal(owner.snapshot().pendingWriteCallbacks, 0);
    assert.equal(owner.snapshot().reading, false);
    assert.equal(client.listenerCount('drain'), 0);
  } finally {
    clearTimeout(timer);
    await owner.cancel();
    peer.destroy(); await new Promise(resolve => server.close(resolve));
  }
});
