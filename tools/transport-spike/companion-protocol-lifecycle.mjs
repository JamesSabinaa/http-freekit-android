// Draft0.3 plus additive0.5 model only. It starts no timer, authenticates no peer and closes no resource.
import { timingSafeEqual } from 'node:crypto';
import { inspect } from 'node:util';
import { CompanionProtocolError, decodeControl, decodeStream, DEFAULT_CAPABILITIES, TRAFFIC_CAPABILITIES,
  expiryMillis, tokenBytes, validateCapabilities } from './companion-protocol-codec.mjs';

const pools = new WeakMap(), controls = new WeakMap(), streams = new WeakMap();
const directions = ['client', 'gateway'];
const controlTerminal = state => ['closed', 'failed'].includes(state.phase);
const streamTerminal = state => ['complete', 'cancelled', 'failed'].includes(state.phase);
const localId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.exec(value)?.[0] === value;
const safeClock = clock => clock && Number.isSafeInteger(clock.utcMillis) &&
  Number.isSafeInteger(clock.monotonicMillis) && clock.monotonicMillis >= 0;
const invalid = () => { throw new CompanionProtocolError(); };
const freeze = value => {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
};
function result(code = 'ok', effects = [], bytes) {
  const value = { code, effects: Object.freeze(effects) };
  // Intentional payload access remains explicit and defensive; ordinary inspection omits it.
  if (bytes !== undefined) Object.defineProperty(value, 'bytes', { get: () => Buffer.from(bytes) });
  return Object.freeze(value);
}
function closeCause(state, phase, cause) {
  if (streamTerminal(state)) return;
  state.phase = phase;
  state.cause = cause;
}
function terminate(control, phase, cause) {
  const state = controls.get(control);
  if (controlTerminal(state)) return;
  state.phase = phase; state.cause = cause;
  const cancelled = cause === 'cancelled' || cause === 'desktop_stopped';
  for (const stream of state.children) closeCause(streams.get(stream), cancelled ? 'cancelled' : 'failed', cause);
}
function checkControl(control, clock) {
  const state = controls.get(control);
  if (controlTerminal(state)) return null;
  let cause;
  if (!safeClock(clock) || clock.monotonicMillis < state.watermark) cause = 'invalid_message';
  else {
    state.watermark = clock.monotonicMillis;
    if (state.phase === 'active') {
      if (clock.utcMillis >= state.expiry || clock.monotonicMillis - state.activated >= state.lifetime) cause = 'session_expired';
      else if (directions.some(d => clock.monotonicMillis - state.activity[d] >= 60000)) cause = 'network_unreachable';
    } else if (clock.monotonicMillis - state.created >= 15000) cause = 'network_unreachable';
  }
  if (cause) terminate(control, 'failed', cause);
  return cause ?? null;
}
function checkOwnStream(stream, clock) {
  const state = streams.get(stream);
  if (streamTerminal(state)) return null;
  const handshake = ['awaiting_open', 'awaiting_ready'].includes(state.phase);
  if (clock.monotonicMillis - (handshake ? state.created : state.progress) >= (handshake ? 15000 : 60000)) {
    closeCause(state, 'failed', 'network_unreachable');
    return 'network_unreachable';
  }
  return null;
}
function guardStream(stream, clock) {
  const state = streams.get(stream), wasTerminal = streamTerminal(state);
  const sessionFailure = checkControl(state.control, clock);
  if (wasTerminal) return 'invalid_message';
  if (sessionFailure) return sessionFailure;
  if (streamTerminal(state)) return 'invalid_message';
  return checkOwnStream(stream, clock);
}
function failStream(stream, code = 'invalid_message') {
  closeCause(streams.get(stream), 'failed', code);
  return result(code);
}
function eofAndPhase(stream) {
  const state = streams.get(stream), effects = [];
  if (streamTerminal(state) || state.wsClosed) return effects;
  for (const direction of directions) {
    const queue = state[direction];
    if (queue.sealed && !queue.eof && queue.bytes === 0) {
      queue.eof = true;
      effects.push(Object.freeze({ type: 'write_eof', stream, direction }));
    }
  }
  const sealed = directions.filter(d => state[d].sealed).length;
  state.phase = sealed === 0 ? 'open' : sealed === 1 ? 'half_closed' : state.client.bytes + state.gateway.bytes ? 'draining' : 'closing';
  return effects;
}
function releaseControl(control) {
  const state = controls.get(control), pool = pools.get(state.pool);
  if (state.released && state.children.size === 0) {
    if (state.lease) {
      pool.sessions.delete(control); pool.devices.delete(state.deviceId); state.lease = false;
    }
    state.history.clear();
  }
}
function releaseBytes(stream, count) {
  const state = streams.get(stream), owner = controls.get(state.control), pool = pools.get(owner.pool);
  owner.bytes -= count; pool.bytes -= count;
  if (owner.bytes < 0 || pool.bytes < 0) throw new Error('Protocol budget invariant');
}

export class CompanionBudgetPool {
  constructor({ maxSessions = 16, maxStreams = 256, maxBytes = 16777216 } = {}) {
    if (![[maxSessions, 16], [maxStreams, 256], [maxBytes, 16777216]].every(([v, max]) => Number.isSafeInteger(v) && v > 0 && v <= max)) invalid();
    pools.set(this, { maxSessions, maxStreams, maxBytes, sessions: new Set(), devices: new Map(), streams: new Set(), bytes: 0 });
    Object.freeze(this);
  }
  snapshot() { const p = pools.get(this); return freeze({ sessionLeases: p.sessions.size, streamLeases: p.streams.size, chargedBytes: p.bytes }); }
  toString() { return 'CompanionBudgetPool([REDACTED])'; }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return this.toString(); }
}

export class CompanionControl {
  constructor({ pool, deviceId, desktopId, supportedCapabilities = DEFAULT_CAPABILITIES, clock }) {
    if (!pools.has(pool) || !localId(deviceId) || !localId(desktopId)) invalid();
    const supported = validateCapabilities(supportedCapabilities, true);
    const valid = safeClock(clock);
    controls.set(this, { pool, deviceId, desktopId, supported, phase: valid ? 'awaiting_hello' : 'failed',
      cause: valid ? null : 'invalid_message', created: valid ? clock.monotonicMillis : 0,
      watermark: valid ? clock.monotonicMillis : 0, activity: {}, offer: [], required: [], negotiated: [],
      lease: false, wsClosed: false, closeCode: null, released: false, children: new Set(), history: new Set(), bytes: 0 });
    Object.freeze(this);
  }
  text(direction, input, clock) {
    const state = controls.get(this), terminal = controlTerminal(state);
    const timed = checkControl(this, clock);
    if (terminal) return result('invalid_message');
    if (timed) return result(timed);
    let message;
    try { message = decodeControl(input).toWire(); }
    catch (error) { const code = error instanceof CompanionProtocolError ? error.code : 'invalid_message'; terminate(this, 'failed', code); return result(code); }
    const wrong = () => { terminate(this, 'failed', 'invalid_message'); return result('invalid_message'); };
    if (!directions.includes(direction)) return wrong();
    if (message.type === 'hello') {
      if (direction !== 'client' || state.phase !== 'awaiting_hello') return wrong();
      if (!message.requiredCapabilities.every(c => state.supported.includes(c))) {
        terminate(this, 'failed', 'unsupported_capability'); return result('unsupported_capability');
      }
      state.offer = message.capabilities; state.required = message.requiredCapabilities; state.phase = 'awaiting_ready';
    } else if (message.type === 'session_ready') {
      if (direction !== 'gateway' || state.phase !== 'awaiting_ready') return wrong();
      let cause;
      const expiry = expiryMillis(message.expiresAt), remaining = expiry - clock.utcMillis;
      const pool = pools.get(state.pool);
      if (message.desktopId !== state.desktopId) cause = 'authentication_failed';
      else if (remaining <= 0) cause = 'session_expired';
      else if (remaining > 1800000) cause = 'invalid_message';
      else if (!message.capabilities.every(c => state.offer.includes(c))) cause = 'invalid_message';
      else if (!message.capabilities.every(c => state.supported.includes(c)) ||
          !state.required.every(c => message.capabilities.includes(c)) ||
          !message.capabilities.some(c => TRAFFIC_CAPABILITIES.includes(c))) cause = 'unsupported_capability';
      else if (message.limits.maxFrameBytes > pool.maxBytes) cause = 'invalid_message';
      else if (pool.sessions.size >= pool.maxSessions || pool.devices.has(state.deviceId)) cause = 'session_limit';
      if (cause) { terminate(this, 'failed', cause); return result(cause); }
      state.token = tokenBytes(message.sessionId); state.limits = message.limits;
      state.negotiated = Object.freeze([...message.capabilities]);
      state.expiry = expiry; state.activated = clock.monotonicMillis; state.lifetime = remaining;
      state.activity = { client: clock.monotonicMillis, gateway: clock.monotonicMillis };
      state.phase = 'active'; state.lease = true;
      pool.sessions.add(this); pool.devices.set(state.deviceId, this);
    } else if (message.type === 'cancel') {
      if (direction !== 'client' || !['awaiting_ready', 'active'].includes(state.phase)) return wrong();
      terminate(this, 'closed', 'cancelled');
    } else if (message.type === 'disconnect') {
      if (direction !== 'gateway' || state.phase !== 'active') return wrong();
      terminate(this, 'closed', message.code);
    } else if (message.type === 'error') {
      if (direction !== 'gateway' || !['awaiting_ready', 'active'].includes(state.phase)) return wrong();
      terminate(this, 'failed', message.code);
    }
    if (state.phase === 'active') state.activity[direction] = clock.monotonicMillis;
    return result();
  }
  activity(direction, clock) {
    const state = controls.get(this), terminal = controlTerminal(state), timed = checkControl(this, clock);
    if (terminal) return result('invalid_message');
    if (timed) return result(timed);
    if (state.phase !== 'active' || !directions.includes(direction)) { terminate(this, 'failed', 'invalid_message'); return result('invalid_message'); }
    state.activity[direction] = clock.monotonicMillis;
    return result();
  }
  allocateStream(deviceId, sessionHeader, clock) {
    const state = controls.get(this);
    const timed = checkControl(this, clock);
    if (timed) return result(timed);
    if (state.phase !== 'active') return result(state.cause === 'session_expired' ? 'session_expired' : 'authentication_failed');
    let presented;
    try { presented = tokenBytes(sessionHeader); } catch { return result('authentication_failed'); }
    if (deviceId !== state.deviceId || presented.length !== state.token.length || !timingSafeEqual(presented, state.token)) return result('authentication_failed');
    const pool = pools.get(state.pool);
    if (state.children.size >= state.limits.maxConcurrentStreams || pool.streams.size >= pool.maxStreams) return result('stream_limit');
    const stream = new CompanionStream(this, clock);
    state.children.add(stream); pool.streams.add(stream);
    return Object.freeze({ code: 'ok', effects: Object.freeze([]), stream });
  }
  localCancel(clock) {
    const state = controls.get(this), terminal = controlTerminal(state), timed = checkControl(this, clock);
    if (terminal) return result('invalid_message');
    if (timed) return result(timed);
    terminate(this, 'closed', 'cancelled'); return result();
  }
  tick(clock) {
    checkControl(this, clock);
    if (safeClock(clock)) for (const stream of controls.get(this).children) checkOwnStream(stream, clock);
    return result();
  }
  wsClosed(closeCode, clock) {
    checkControl(this, clock);
    const state = controls.get(this);
    if (!Number.isInteger(closeCode) || closeCode < 1000 || closeCode > 4999) { terminate(this, 'failed', 'invalid_message'); return result(); }
    if (!state.wsClosed) { state.wsClosed = true; state.closeCode = closeCode; terminate(this, 'failed', 'network_unreachable'); }
    return result();
  }
  resourcesClosed(clock) {
    checkControl(this, clock);
    const state = controls.get(this);
    if (!state.wsClosed) { state.wsClosed = true; terminate(this, 'failed', 'network_unreachable'); }
    state.released = true; releaseControl(this); return result();
  }
  snapshot() {
    const s = controls.get(this);
    return freeze({ phase: s.phase, cause: s.cause, sessionLease: s.lease, webSocketClosed: s.wsClosed,
      resourcesReleased: s.released, historyCount: s.history.size, streamLeases: s.children.size, chargedBytes: s.bytes });
  }
  toString() { return 'CompanionControl([REDACTED])'; }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return this.toString(); }
}

class CompanionStream {
  constructor(control, clock) {
    const queue = () => ({ frames: [], bytes: 0, sealed: false, eof: false });
    streams.set(this, { control, phase: 'awaiting_open', cause: null, id: null, created: clock.monotonicMillis,
      progress: clock.monotonicMillis, client: queue(), gateway: queue(), frames: 0,
      lease: true, wsClosed: false, closeCode: null, released: false });
    Object.freeze(this);
  }
  text(direction, input, clock) {
    const timed = guardStream(this, clock); if (timed) return result(timed);
    const state = streams.get(this), owner = controls.get(state.control);
    if (state.wsClosed) return failStream(this);
    let message;
    try { message = decodeStream(input).toWire(); }
    catch (error) { return failStream(this, error instanceof CompanionProtocolError ? error.code : 'invalid_message'); }
    if (!directions.includes(direction)) return failStream(this);
    if (state.phase !== 'awaiting_open' && message.streamId !== state.id) return failStream(this);
    if (message.type === 'open') {
      if (direction !== 'client' || state.phase !== 'awaiting_open') return failStream(this);
      const supported = message.proxyMode === 'http-origin-connect'
        ? owner.negotiated.includes('tcp-http-origin-connect')
        : owner.negotiated.some(capability => DEFAULT_CAPABILITIES.includes(capability));
      if (!supported) return failStream(this, 'unsupported_capability');
      if (owner.history.has(message.streamId)) return failStream(this);
      if (owner.history.size >= owner.limits.maxOpenedStreamsPerSession) return failStream(this, 'stream_limit');
      owner.history.add(message.streamId); state.id = message.streamId; state.phase = 'awaiting_ready';
    } else if (message.type === 'ready') {
      if (direction !== 'gateway' || state.phase !== 'awaiting_ready') return failStream(this);
      state.phase = 'open';
    } else if (message.type === 'cancel' || message.type === 'error') {
      if (state.phase === 'awaiting_open') return failStream(this);
      closeCause(state, message.type === 'cancel' ? 'cancelled' : 'failed', message.type === 'cancel' ? 'cancelled' : message.code);
    } else if (message.type === 'end_write') {
      if (!['open', 'half_closed', 'draining', 'closing'].includes(state.phase) || state[direction].sealed) return failStream(this);
      state[direction].sealed = true;
      state.progress = clock.monotonicMillis;
      return result('ok', eofAndPhase(this));
    }
    state.progress = clock.monotonicMillis;
    return result();
  }
  binary(direction, input, clock) {
    const timed = guardStream(this, clock); if (timed) return result(timed);
    const state = streams.get(this), owner = controls.get(state.control), pool = pools.get(owner.pool), limits = owner.limits;
    if (state.wsClosed || !directions.includes(direction) || !['open', 'half_closed'].includes(state.phase) ||
        !(input instanceof Uint8Array) || input.byteLength < 1 || input.byteLength > limits.maxFrameBytes || state[direction].sealed) return failStream(this);
    const count = input.byteLength;
    if (count > limits.maxQueuedBytesPerStream - state.client.bytes - state.gateway.bytes ||
        count > limits.maxQueuedBytesPerDevice - owner.bytes || count > pool.maxBytes - pool.bytes ||
        state.frames >= limits.maxQueuedFramesPerStream) return result('backpressure');
    const bytes = Buffer.from(input);
    state[direction].frames.push({ bytes, offset: 0 }); state[direction].bytes += count;
    state.frames++; owner.bytes += count; pool.bytes += count; state.progress = clock.monotonicMillis;
    return result();
  }
  peek(direction, count, clock) {
    const timed = guardStream(this, clock); if (timed) return result(timed);
    const state = streams.get(this), limits = controls.get(state.control).limits;
    if (state.wsClosed || !directions.includes(direction) || !Number.isSafeInteger(count) || count < 1 || count > limits.maxFrameBytes) return failStream(this);
    const queue = state[direction], bytes = Buffer.alloc(Math.min(count, queue.bytes));
    let offset = 0;
    for (const frame of queue.frames) {
      const length = Math.min(bytes.length - offset, frame.bytes.length - frame.offset);
      frame.bytes.copy(bytes, offset, frame.offset, frame.offset + length); offset += length;
      if (offset === bytes.length) break;
    }
    return result('ok', [], bytes);
  }
  drain(direction, count, clock) {
    const timed = guardStream(this, clock); if (timed) return result(timed);
    const state = streams.get(this);
    if (state.wsClosed || !directions.includes(direction) || !Number.isSafeInteger(count) || count < 1 || count > state[direction].bytes) return failStream(this);
    let remaining = count;
    const queue = state[direction];
    while (remaining) {
      const frame = queue.frames[0], consumed = Math.min(remaining, frame.bytes.length - frame.offset);
      frame.offset += consumed; remaining -= consumed;
      if (frame.offset === frame.bytes.length) { queue.frames.shift(); state.frames--; }
    }
    queue.bytes -= count; releaseBytes(this, count); state.progress = clock.monotonicMillis;
    return result('ok', eofAndPhase(this));
  }
  localCancel(clock) {
    const timed = guardStream(this, clock); if (timed) return result(timed);
    closeCause(streams.get(this), 'cancelled', 'cancelled'); return result();
  }
  tick(clock) { guardStream(this, clock); return result(); }
  wsClosed(closeCode, clock) {
    guardStream(this, clock);
    const state = streams.get(this);
    if (!Number.isInteger(closeCode) || closeCode < 1000 || closeCode > 4999) { failStream(this); return result(); }
    if (state.wsClosed) {
      if (state.closeCode !== closeCode) closeCause(state, 'failed', 'network_unreachable');
    } else {
      state.wsClosed = true; state.closeCode = closeCode;
      if (closeCode !== 1000 || state.phase !== 'closing') closeCause(state, 'failed', 'network_unreachable');
    }
    return result();
  }
  resourcesClosed(clock) {
    guardStream(this, clock);
    const state = streams.get(this), owner = controls.get(state.control), pool = pools.get(owner.pool);
    if (!state.wsClosed) { state.wsClosed = true; closeCause(state, 'failed', 'network_unreachable'); }
    if (!streamTerminal(state)) {
      if (state.phase === 'closing' && state.closeCode === 1000 && owner.phase === 'active') state.phase = 'complete';
      else closeCause(state, 'failed', 'network_unreachable');
    }
    if (!state.released) {
      releaseBytes(this, state.client.bytes + state.gateway.bytes);
      for (const direction of directions) { state[direction].frames.length = 0; state[direction].bytes = 0; }
      state.frames = 0; state.lease = false; state.released = true;
      owner.children.delete(this); pool.streams.delete(this); releaseControl(state.control);
    }
    return result();
  }
  snapshot() {
    const s = streams.get(this), queue = direction => ({ sealed: s[direction].sealed, eofEmitted: s[direction].eof, chargedBytes: s[direction].bytes });
    return freeze({ phase: s.phase, cause: s.cause, streamLease: s.lease, webSocketClosed: s.wsClosed,
      resourcesReleased: s.released, chargedFrames: s.frames, client: queue('client'), gateway: queue('gateway') });
  }
  toString() { return 'CompanionStream([REDACTED])'; }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return this.toString(); }
}
