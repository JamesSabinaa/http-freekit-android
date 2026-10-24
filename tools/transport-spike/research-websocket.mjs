// Research only. No HTTP upgrade, authentication, application protocol, or production endpoint.
// Original implementation of the bounded RFC 6455 subset exercised by the foundation probe.
import { randomFillSync } from 'node:crypto';
import { Duplex } from 'node:stream';
import { inspect } from 'node:util';

const TEXT_LIMIT = 16384;
const BINARY_LIMIT = 65536;
const HEAD_LIMIT = BINARY_LIMIT + 14;
const OPCODES = Object.freeze({ text: 1, binary: 2, close: 8, ping: 9, pong: 10 });
const KINDS = Object.freeze({ 1: 'text', 2: 'binary', 8: 'close', 9: 'ping', 10: 'pong' });
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export class ResearchWebSocketError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ResearchWebSocketError';
    this.code = code;
    this.stack = `${this.name}: ${code}`;
  }
  toJSON() { return { code: this.code }; }
  [inspect.custom]() { return `${this.name} { code: ${this.code} }`; }
}
const error = code => new ResearchWebSocketError(code);
function integer(value, low, high) { return Number.isInteger(value) && value >= low && value <= high; }
function validUtf8(bytes) {
  try { decoder.decode(bytes); } catch { throw error('invalid_utf8'); }
}
function closeCode(bytes) {
  if (bytes.length === 0) return 1005; // Local observation only; never emit this code on the wire.
  if (bytes.length === 1) throw error('invalid_close');
  const code = bytes.readUInt16BE(0);
  if (!((code >= 1000 && code <= 1014 && ![1004, 1005, 1006].includes(code)) ||
      (code >= 3000 && code <= 4999))) throw error('invalid_close');
  validUtf8(bytes.subarray(2));
  return code;
}

class Message {
  #bytes;
  #release;
  constructor(kind, bytes, release, code = null) {
    this.kind = kind;
    this.byteLength = bytes.length;
    this.closeCode = code;
    this.#bytes = bytes;
    this.#release = release;
    Object.freeze(this);
  }
  // Explicit payload access. The caller owns each copy and must bound its own retention.
  copyBytes() {
    if (this.#bytes === null) throw error('message_released');
    return Buffer.from(this.#bytes);
  }
  release() {
    if (this.#bytes === null) return;
    this.#bytes = null;
    this.#release();
  }
  toJSON() { return { kind: this.kind, byteLength: this.byteLength, closeCode: this.closeCode }; }
  [inspect.custom]() { return `ResearchWebSocketMessage ${JSON.stringify(this.toJSON())}`; }
}

/**
 * Own an exclusively borrowed non-flowing Duplex (normally a connected TLSSocket).
 * next() pulls exactly one event; release it before another next(). Ping/pong are events,
 * not hidden writes. Outgoing messages are single final frames. Up to 64 fragments and
 * 64 interleaved controls per fragmented message are accepted by default.
 *
 * Application allocation: one leased event, one bounded fragmented message (plus its
 * final assembly copy), at most two outgoing snapshots and one active encoded frame.
 * copyBytes() copies are caller-owned. Node/TLS/kernel buffering is outside these bounds;
 * readableLength/writableLength are exposed separately, not called total-memory evidence.
 * No data listener, async iterator, unbounded write mailbox, hidden timer, or wire ACK.
 * The owner must supply deadlines and cancel on expiry. A write resolves after actual
 * local callback/drain, never proof that a remote application consumed those bytes.
 */
export class ResearchWebSocket {
  #socket;
  #role;
  #maximum;
  #maxFragments;
  #maxControls;
  #cleanupMillis;
  #head;
  #headOffset = 0;
  #fragment = null;
  #leased = null;
  #readerTask = null;
  #writerTask = null;
  #writes = [];
  #wakeReader = null;
  #wakeWriter = null;
  #ended = false;
  #closed = false;
  #failure = null;
  #receivedClose = false;
  #sentClose = false;
  #closeWritten = false;
  #finishing = false;
  #stopTask = null;
  #closedPromise;
  #resolveClosed;
  #sourceBytes = 0;
  #payloadAllocated = 0;
  #peakPayload = 0;
  #completedWrites = 0;
  #backpressured = false;
  #pendingCallbacks = 0;
  #callbacksIdle = null;
  #resolveCallbacksIdle = null;

  constructor(socket, { role, maxBinaryBytes = BINARY_LIMIT, initialBytes = Buffer.alloc(0),
    maxFragments = 64, maxInterleavedControls = 64, cleanupTimeoutMillis = 5000 } = {}) {
    if (!(socket instanceof Duplex) || socket.destroyed || socket.closed ||
        socket.readableFlowing === true || socket.readableEncoding !== null ||
        !['client', 'server'].includes(role) || !integer(maxBinaryBytes, 1, BINARY_LIMIT) ||
        !integer(maxFragments, 1, 64) || !integer(maxInterleavedControls, 1, 64) ||
        !integer(cleanupTimeoutMillis, 1, 30000) || !Buffer.isBuffer(initialBytes) || initialBytes.length > HEAD_LIMIT) {
      throw error('invalid_configuration');
    }
    this.#socket = socket;
    this.#role = role;
    this.#maximum = maxBinaryBytes;
    this.#maxFragments = maxFragments;
    this.#maxControls = maxInterleavedControls;
    this.#cleanupMillis = cleanupTimeoutMillis;
    this.#head = Buffer.from(initialBytes);
    this.#closedPromise = new Promise(resolve => { this.#resolveClosed = resolve; });
    socket.on('error', () => this.#fail('network_error'));
    socket.on('end', () => { this.#ended = true; this.#wakeReader?.(); });
    socket.once('close', () => {
      this.#closed = true;
      const handshakeComplete = this.#receivedClose && this.#closeWritten && this.#writes.length === 0;
      if (!this.#finishing && !handshakeComplete && this.#failure === null) this.#failure = error('connection_closed');
      this.#wakeReader?.();
      this.#wakeWriter?.();
      this.#resolveClosed();
      this.#releaseStopped();
    });
  }

  snapshot() {
    return Object.freeze({
      reading: this.#readerTask !== null, leasedBytes: this.#leased?.byteLength ?? 0,
      messageLeased: this.#leased !== null, fragmentBytes: this.#fragment?.length ?? 0,
      fragmentCount: this.#fragment?.count ?? 0, upgradeBytesRemaining: this.#head.length - this.#headOffset,
      sourceBytesRead: this.#sourceBytes, payloadBytesAllocated: this.#payloadAllocated,
      peakReaderPayloadBytes: this.#peakPayload, queuedWrites: this.#writes.length,
      queuedWriteBytes: this.#writes.reduce((sum, item) => sum + item.bytes.length, 0),
      completedWrites: this.#completedWrites, writeBackpressured: this.#backpressured,
      pendingWriteCallbacks: this.#pendingCallbacks,
      receivedClose: this.#receivedClose, closeWritten: this.#closeWritten,
      transportClosed: this.#closed, errorCode: this.#failure?.code ?? null,
      underlyingReadableBytes: this.#socket.readableLength,
      underlyingWritableBytes: this.#socket.writableLength,
    });
  }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return `ResearchWebSocket ${JSON.stringify(this.snapshot())}`; }

  next() {
    if (this.#readerTask !== null) return Promise.reject(error('read_in_progress'));
    if (this.#leased !== null) return Promise.reject(error('message_pending'));
    if (this.#failure !== null) return Promise.reject(this.#failure);
    if (this.#receivedClose || this.#closed || this.#finishing) return Promise.reject(error('connection_closed'));
    const task = this.#readEvent().catch(failure => {
      this.#fail(failure instanceof ResearchWebSocketError ? failure.code : 'network_error');
      throw this.#failure;
    }).finally(() => { this.#readerTask = null; this.#releaseStopped(); });
    this.#readerTask = task;
    return task;
  }

  send(kind, bytes) {
    if (this.#failure !== null) return Promise.reject(this.#failure);
    if (this.#closed || this.#finishing || this.#sentClose || (this.#receivedClose && kind !== 'close')) {
      return Promise.reject(error('connection_closed'));
    }
    // Includes the active write. Refusal happens before any payload snapshot/allocation.
    if (this.#writes.length >= 2) return Promise.reject(error('write_backpressure'));
    try {
      if (!Object.hasOwn(OPCODES, kind) || !(bytes instanceof Uint8Array)) throw error('invalid_frame');
      const limit = kind === 'text' ? TEXT_LIMIT : kind === 'binary' ? this.#maximum : 125;
      if (bytes.byteLength > limit) throw error('message_too_large');
      const view = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (kind === 'text') validUtf8(view);
      if (kind === 'close') closeCode(view);
      const copy = Buffer.from(view);
      const promise = new Promise((resolve, reject) => this.#writes.push({ kind, bytes: copy, resolve, reject }));
      if (kind === 'close') this.#sentClose = true;
      this.#startWriter();
      return promise;
    } catch (failure) {
      return Promise.reject(failure instanceof ResearchWebSocketError ? failure : error('invalid_frame'));
    }
  }

  // Abort is a request; resolution requires actual transport close and settled owned work.
  cancel() {
    if (this.#stopTask !== null) return this.#stopTask;
    this.#fail('cancelled');
    this.#stopTask = this.#join();
    return this.#stopTask;
  }

  // Both WS close frames and a released inbound event precede normal transport cleanup.
  finish() {
    if (this.#stopTask !== null) return this.#stopTask;
    if (this.#failure || !this.#receivedClose || !this.#closeWritten || this.#leased !== null ||
        this.#readerTask !== null || this.#writes.length !== 0) {
      return Promise.reject(error('invalid_close_state'));
    }
    this.#finishing = true;
    this.#socket.destroy();
    this.#stopTask = this.#join();
    return this.#stopTask;
  }

  async #join() {
    let timer;
    try {
      await Promise.race([
        (async () => {
          await Promise.allSettled([this.#readerTask, this.#writerTask].filter(Boolean));
          await this.#closedPromise;
          if (this.#pendingCallbacks > 0) await this.#callbacksIdle;
        })(),
        new Promise((_, reject) => { timer = setTimeout(() => reject(error('cleanup_incomplete')), this.#cleanupMillis); }),
      ]);
      this.#releaseStopped();
    } finally { clearTimeout(timer); }
  }

  #fail(code) {
    if (this.#failure === null) this.#failure = error(code);
    for (const item of this.#writes) item.reject(this.#failure);
    this.#wakeReader?.();
    this.#wakeWriter?.();
    this.#socket.destroy();
  }

  #releaseStopped() {
    if (!this.#closed || this.#readerTask !== null || this.#writerTask !== null || this.#pendingCallbacks !== 0) return;
    // A peer may close TCP immediately after the valid WS handshake. Preserve its leased
    // close event until the owner has inspected/released it; aborts explicitly invalidate it.
    if (this.#leased !== null && this.#failure === null && !this.#finishing) return;
    this.#leased?.release();
    this.#fragment = null;
    this.#head = Buffer.alloc(0);
    this.#headOffset = 0;
    this.#writes = [];
    this.#backpressured = false;
  }

  #checkOpen() {
    if (this.#failure !== null) throw this.#failure;
    if (this.#closed) throw error('connection_closed');
  }

  async #exact(length, payload = false) {
    this.#checkOpen();
    const result = Buffer.allocUnsafe(length);
    if (payload) {
      this.#payloadAllocated += length;
      this.#peakPayload = Math.max(this.#peakPayload, (this.#fragment?.length ?? 0) + length);
    }
    let offset = 0;
    while (offset < length) {
      this.#checkOpen();
      const headLength = Math.min(length - offset, this.#head.length - this.#headOffset);
      if (headLength > 0) {
        this.#head.copy(result, offset, this.#headOffset, this.#headOffset + headLength);
        this.#headOffset += headLength;
        offset += headLength;
        if (this.#headOffset === this.#head.length) {
          this.#head = Buffer.alloc(0);
          this.#headOffset = 0;
        }
        continue;
      }
      // read(n), never a flowing callback or unbounded read(). Do not consume later frames.
      const count = Math.min(length - offset, this.#socket.readableLength || 4096, 4096);
      const chunk = this.#socket.read(count);
      if (chunk !== null) {
        chunk.copy(result, offset);
        this.#sourceBytes += chunk.length;
        offset += chunk.length;
      } else {
        if (this.#ended || this.#socket.readableEnded) throw error('unexpected_eof');
        await new Promise(resolve => {
          const wake = () => {
            this.#socket.removeListener('readable', wake);
            this.#wakeReader = null;
            resolve();
          };
          this.#wakeReader = wake;
          this.#socket.once('readable', wake);
          if (this.#failure || this.#closed || this.#ended || this.#socket.readableLength > 0) wake();
        });
      }
    }
    return result;
  }

  async #readEvent() {
    while (true) {
      const header = await this.#exact(2);
      const final = (header[0] & 0x80) !== 0;
      const opcode = header[0] & 15;
      const control = opcode >= 8;
      const masked = (header[1] & 0x80) !== 0;
      if ((header[0] & 0x70) !== 0 || ![0, 1, 2, 8, 9, 10].includes(opcode) ||
          (control && (!final || (header[1] & 127) > 125)) || masked !== (this.#role === 'server') ||
          (opcode === 0 && this.#fragment === null) || (!control && opcode !== 0 && this.#fragment !== null)) {
        throw error('invalid_frame');
      }
      let length = header[1] & 127;
      if (length === 126) {
        length = (await this.#exact(2)).readUInt16BE(0);
        if (length < 126) throw error('invalid_frame');
      } else if (length === 127) {
        const extended = await this.#exact(8);
        if ((extended[0] & 128) !== 0) throw error('invalid_frame');
        const large = extended.readBigUInt64BE(0);
        if (large <= 65535n) throw error('invalid_frame');
        if (large > BigInt(BINARY_LIMIT)) throw error('message_too_large');
        length = Number(large);
      }
      const dataOpcode = opcode === 0 ? this.#fragment.opcode : opcode;
      const limit = control ? 125 : dataOpcode === 1 ? TEXT_LIMIT : this.#maximum;
      const accumulated = control ? 0 : this.#fragment?.length ?? 0;
      // Every length/cumulative/count check precedes the mask and payload allocation/read.
      if (length > limit || accumulated > limit - length) throw error('message_too_large');
      if (!control && (this.#fragment?.count ?? 0) + 1 > this.#maxFragments) throw error('fragment_limit');
      if (control && this.#fragment !== null && ++this.#fragment.controls > this.#maxControls) throw error('control_limit');
      const mask = masked ? await this.#exact(4) : null;
      let payload = await this.#exact(length, true);
      if (mask !== null) for (let index = 0; index < payload.length; index++) payload[index] ^= mask[index & 3];
      if (control) {
        let code = null;
        if (opcode === 8) {
          code = closeCode(payload);
          this.#receivedClose = true;
          this.#fragment = null;
        }
        return this.#lease(KINDS[opcode], payload, code);
      }
      if (this.#fragment !== null) {
        this.#fragment.chunks.push(payload);
        this.#fragment.length += length;
        this.#fragment.count++;
      } else if (!final) {
        this.#fragment = { opcode, chunks: [payload], length, count: 1, controls: 0 };
      }
      if (!final) continue;
      if (this.#fragment !== null) {
        this.#peakPayload = Math.max(this.#peakPayload, 2 * this.#fragment.length);
        this.#payloadAllocated += this.#fragment.length;
        payload = Buffer.concat(this.#fragment.chunks, this.#fragment.length);
        this.#fragment = null;
      }
      if (dataOpcode === 1) validUtf8(payload);
      return this.#lease(KINDS[dataOpcode], payload, null);
    }
  }

  #lease(kind, payload, code) {
    const message = new Message(kind, payload, () => {
      if (this.#leased === message) this.#leased = null;
      this.#releaseStopped();
    }, code);
    this.#leased = message;
    return message;
  }

  #startWriter() {
    if (this.#writerTask !== null) return;
    this.#writerTask = (async () => {
      while (this.#writes.length > 0 && this.#failure === null) {
        const item = this.#writes[0];
        try {
          await this.#writeFrame(item);
          this.#checkOpen();
          this.#writes.shift();
          this.#completedWrites++;
          if (item.kind === 'close') this.#closeWritten = true;
          item.resolve();
        } catch (failure) {
          this.#fail(failure instanceof ResearchWebSocketError ? failure.code : 'network_error');
        }
      }
    })().finally(() => {
      this.#writerTask = null;
      // A send awaiting the last item can enqueue in the microtask before this finally.
      if (this.#writes.length > 0 && this.#failure === null) this.#startWriter();
      this.#releaseStopped();
    });
  }

  async #writeFrame(item) {
    this.#checkOpen();
    const length = item.bytes.length;
    const sizeBytes = length < 126 ? 0 : length <= 65535 ? 2 : 8;
    const masked = this.#role === 'client';
    const payloadOffset = 2 + sizeBytes + (masked ? 4 : 0);
    const frame = Buffer.allocUnsafe(payloadOffset + length);
    frame[0] = 128 | OPCODES[item.kind];
    frame[1] = (masked ? 128 : 0) | (sizeBytes === 0 ? length : sizeBytes === 2 ? 126 : 127);
    if (sizeBytes === 2) frame.writeUInt16BE(length, 2);
    if (sizeBytes === 8) frame.writeBigUInt64BE(BigInt(length), 2);
    if (masked) {
      const maskOffset = 2 + sizeBytes;
      randomFillSync(frame.subarray(maskOffset, maskOffset + 4));
      for (let index = 0; index < length; index++) frame[payloadOffset + index] = item.bytes[index] ^ frame[maskOffset + (index & 3)];
    } else item.bytes.copy(frame, payloadOffset);
    await new Promise((resolve, reject) => {
      let callbackDone = false;
      let drainDone = false;
      let returned = false;
      let needsDrain = false;
      let settled = false;
      const cleanup = () => {
        this.#socket.removeListener('drain', drained);
        this.#wakeWriter = null;
        this.#backpressured = false;
      };
      const check = () => {
        if (settled) return;
        if (this.#failure || this.#closed) {
          settled = true; cleanup(); reject(this.#failure ?? error('connection_closed'));
        } else if (returned && callbackDone && (!needsDrain || drainDone)) {
          settled = true; cleanup(); resolve();
        }
      };
      const drained = () => { drainDone = true; check(); };
      this.#wakeWriter = check;
      this.#socket.on('drain', drained);
      let callbackObserved = false;
      this.#pendingCallbacks++;
      this.#callbacksIdle = new Promise(done => { this.#resolveCallbacksIdle = done; });
      const callback = failure => {
        if (callbackObserved) return;
        callbackObserved = true;
        this.#pendingCallbacks--;
        if (this.#pendingCallbacks === 0) this.#resolveCallbacksIdle();
        if (failure) this.#fail('network_error');
        callbackDone = true;
        check();
        this.#releaseStopped();
      };
      try {
        needsDrain = !this.#socket.write(frame, callback);
        this.#backpressured = needsDrain;
        returned = true;
        check();
      } catch { callback(error('network_error')); }
    });
  }
}
