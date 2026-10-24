// Bounded research socket operations. Positive completion is local I/O, never remote consumption.
import { ResearchWebSocketError } from './research-websocket.mjs';

export const fail = code => { throw new ResearchWebSocketError(code); };
export const safeError = code => new ResearchWebSocketError(code);

export class Changed {
  #waiters = new Set();
  #revision = 0;
  get revision() { return this.#revision; }
  notify() { this.#revision++; for (const done of this.#waiters) done(); this.#waiters.clear(); }
  wait(revision, stopped) {
    if (revision !== this.#revision || stopped()) return Promise.resolve();
    return new Promise(done => this.#waiters.add(done));
  }
}

const closeObservations = new WeakMap();
// Register at ownership admission, before starting I/O/destroy. All later joins reuse the
// actual event observation, even if a stream's public closed flag changes before its event.
export function observeClose(socket) {
  if (!closeObservations.has(socket)) {
    const state = { observed: socket.closed, promise: null };
    state.promise = state.observed ? Promise.resolve() : new Promise(done => socket.once('close', () => { state.observed = true; done(); }));
    closeObservations.set(socket, state);
  }
  return closeObservations.get(socket).promise;
}
export const closedObserved = socket => closeObservations.get(socket)?.observed === true;

// Exclusive non-flowing reader. Every call consumes <=maximum and never reads a following body.
export async function pull(socket, maximum) {
  if (!Number.isInteger(maximum) || maximum < 1 || maximum > 8192) fail('invalid_read_bound');
  while (true) {
    // A fully half-closed net.Socket can auto-destroy immediately after its real read EOF.
    // Preserve that observed EOF, while an abrupt destroy without read EOF remains a failure.
    if (socket.readableEnded && socket.readableLength === 0) return null;
    if (socket.destroyed) fail('socket_closed');
    const chunk = socket.read(Math.min(maximum, socket.readableLength || maximum));
    if (chunk !== null) return chunk;
    if (socket.readableEnded) return null;
    await new Promise(done => {
      const wake = () => {
        socket.removeListener('readable', wake); socket.removeListener('end', wake);
        socket.removeListener('error', wake); socket.removeListener('close', wake); done();
      };
      socket.once('readable', wake); socket.once('end', wake); socket.once('error', wake); socket.once('close', wake);
      if (socket.destroyed || socket.readableEnded || socket.readableLength > 0) wake();
    });
  }
}

export async function exact(socket, count) {
  if (!Number.isInteger(count) || count < 0 || count > 8192) fail('invalid_read_bound');
  const result = Buffer.allocUnsafe(count);
  let offset = 0;
  while (offset < count) {
    const bytes = await pull(socket, count - offset);
    if (bytes === null) fail('unexpected_eof');
    bytes.copy(result, offset); offset += bytes.length;
  }
  return result;
}

export async function headers(socket) {
  const result = Buffer.allocUnsafe(8192);
  let count = 0;
  while (count < result.length) {
    const byte = await pull(socket, 1);
    if (byte === null) fail('unexpected_eof');
    result[count++] = byte[0];
    if (count >= 4 && result.subarray(count - 4, count).equals(Buffer.from('\r\n\r\n'))) return result.subarray(0, count);
  }
  fail('headers_too_large');
}

export function writerState() { return { entries: 0, completions: 0, pending: 0, idle: Promise.resolve(), resolveIdle: null }; }

export async function write(socket, bytes, state = writerState()) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > 8192 || state.pending !== 0) fail('invalid_write_bound');
  if (socket.destroyed) fail('socket_closed');
  state.entries++; state.pending++;
  state.idle = new Promise(done => { state.resolveIdle = done; });
  let callbackObserved = false;
  await new Promise((done, reject) => {
    let returned = false, completed = false, drained = false, needsDrain = false, settled = false;
    const finish = failure => {
      if (settled) return;
      if (failure || socket.destroyed) {
        settled = true; clean(); reject(safeError('socket_write_failed'));
      } else if (returned && completed && (!needsDrain || drained)) { settled = true; clean(); done(); }
    };
    const clean = () => { socket.removeListener('close', closed); socket.removeListener('error', closed); socket.removeListener('drain', drain); };
    const closed = () => finish(true);
    const drain = () => { drained = true; finish(); };
    const callback = failure => {
      if (callbackObserved) return;
      callbackObserved = true; state.pending--; state.resolveIdle();
      if (!failure) state.completions++;
      completed = true; finish(failure);
    };
    socket.once('close', closed); socket.once('error', closed); socket.on('drain', drain);
    try { needsDrain = !socket.write(bytes, callback); returned = true; finish(); }
    catch { callback(true); }
  });
}

export async function endWrite(socket, state = writerState()) {
  if (socket.destroyed) fail('socket_closed');
  if (state.pending !== 0) fail('invalid_write_bound');
  state.pending++;
  state.idle = new Promise(done => { state.resolveIdle = done; });
  let observed = false;
  await new Promise((done, reject) => {
    const clean = () => { socket.removeListener('close', bad); socket.removeListener('error', bad); };
    const bad = () => { clean(); reject(safeError('socket_end_failed')); };
    socket.once('close', bad); socket.once('error', bad);
    const callback = failure => {
      if (observed) return;
      observed = true; state.pending--; state.resolveIdle();
      clean(); failure ? reject(safeError('socket_end_failed')) : done();
    };
    try { socket.end(callback); } catch { callback(true); }
  });
}

export async function bounded(promise, milliseconds, code = 'cleanup_incomplete') {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(safeError(code)), milliseconds); })]);
  } finally { clearTimeout(timer); }
}
