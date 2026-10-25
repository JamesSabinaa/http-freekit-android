import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import test from 'node:test';
import { encodeControl, encodeStream } from './companion-protocol-codec.mjs';
import { CompanionBudgetPool, CompanionControl } from './companion-protocol-lifecycle.mjs';

const utc = Date.UTC(2026, 0, 1);
const clock = (monotonicMillis = 0, utcMillis = utc + monotonicMillis) => ({ utcMillis, monotonicMillis });
const token = Buffer.alloc(32, 11).toString('base64url');
const limits = Object.freeze({ maxFrameBytes: 4, maxQueuedBytesPerStream: 8, maxQueuedBytesPerDevice: 16,
  maxConcurrentStreams: 4, maxQueuedFramesPerStream: 4, maxOpenedStreamsPerSession: 8 });
const controlWire = value => encodeControl({ protocolVersion: 1, ...value });
const streamWire = (type, streamId = 'flow', extra = {}) => encodeStream({ protocolVersion: 1, type, streamId, ...extra });
const ok = operation => assert.equal(operation.code, 'ok');
const bytes = value => Buffer.from(value);
function active({ pool = new CompanionBudgetPool(), deviceId = 'device-a', negotiated = limits, lifetime = 300000 } = {}) {
  const control = new CompanionControl({ pool, deviceId, desktopId: 'desktop-a', clock: clock() });
  ok(control.text('client', controlWire({ type: 'hello', capabilities: ['tcp-http', 'tcp-https-connect'], requiredCapabilities: ['tcp-http'] }), clock()));
  ok(control.text('gateway', controlWire({ type: 'session_ready', capabilities: ['tcp-http', 'tcp-https-connect'], desktopId: 'desktop-a',
    sessionId: token, expiresAt: new Date(utc + lifetime).toISOString().replace('.000Z', 'Z'), limits: negotiated }), clock()));
  return { pool, control, deviceId };
}
function admitted(fixture, id = 'flow') {
  const allocation = fixture.control.allocateStream(fixture.deviceId, token, clock());
  ok(allocation);
  const stream = allocation.stream;
  ok(stream.text('client', streamWire('open', id), clock()));
  ok(stream.text('gateway', streamWire('ready', id), clock()));
  return stream;
}
function complete(stream, id = 'flow') {
  ok(stream.text('client', streamWire('end_write', id), clock()));
  ok(stream.text('gateway', streamWire('end_write', id), clock()));
  ok(stream.wsClosed(1000, clock()));
  ok(stream.resourcesClosed(clock()));
}

test('EOF is ordered after actual drain; WebSocket closure retains slot until real resource confirmation', () => {
  const fixture = active(), stream = admitted(fixture);
  ok(stream.binary('client', bytes('abcd'), clock()));
  ok(stream.binary('gateway', bytes('xy'), clock()));
  assert.deepEqual(stream.text('client', streamWire('end_write'), clock()).effects, []);
  assert.equal(stream.snapshot().phase, 'half_closed');
  assert.deepEqual(stream.text('gateway', streamWire('end_write'), clock()).effects, []);
  assert.equal(stream.snapshot().phase, 'draining');
  assert.deepEqual(stream.drain('client', 2, clock()).effects, []);
  assert.equal(stream.peek('client', 4, clock()).bytes.toString(), 'cd');
  assert.equal(stream.snapshot().chargedFrames, 2);
  const first = stream.drain('client', 2, clock());
  assert.deepEqual(first.effects.map(e => [e.type, e.direction]), [['write_eof', 'client']]);
  assert.equal(first.effects[0].stream, stream);
  assert.equal(stream.snapshot().phase, 'draining');
  assert.deepEqual(stream.drain('gateway', 2, clock()).effects.map(e => e.direction), ['gateway']);
  assert.equal(stream.snapshot().phase, 'closing');
  ok(stream.wsClosed(1000, clock()));
  assert.equal(stream.snapshot().phase, 'closing');
  assert.deepEqual(fixture.pool.snapshot(), { sessionLeases: 1, streamLeases: 1, chargedBytes: 0 });
  ok(stream.resourcesClosed(clock()));
  assert.equal(stream.snapshot().phase, 'complete');
  assert.equal(stream.snapshot().cause, null);
  assert.deepEqual(fixture.pool.snapshot(), { sessionLeases: 1, streamLeases: 0, chargedBytes: 0 });
  ok(stream.resourcesClosed(clock()));
});

test('reversed EOF keeps the opposite direction usable and does not emit EOF twice', () => {
  const fixture = active(), stream = admitted(fixture);
  assert.deepEqual(stream.text('gateway', streamWire('end_write'), clock()).effects.map(e => e.direction), ['gateway']);
  ok(stream.binary('client', bytes('abc'), clock()));
  assert.deepEqual(stream.text('client', streamWire('end_write'), clock()).effects, []);
  assert.deepEqual(stream.drain('client', 3, clock()).effects.map(e => e.direction), ['client']);
  assert.equal(stream.snapshot().phase, 'closing');
  assert.equal(stream.text('gateway', streamWire('end_write'), clock()).code, 'invalid_message');
  assert.equal(stream.snapshot().cause, 'invalid_message');
  assert.equal(stream.snapshot().streamLease, true);
});

test('peek spans independent frame boundaries, returns actual defensive bytes and never drains', () => {
  const fixture = active(), stream = admitted(fixture);
  const source = bytes('ab');
  ok(stream.binary('client', source, clock())); source.fill(0);
  ok(stream.binary('client', bytes('cd'), clock()));
  const prefix = stream.peek('client', 3, clock());
  assert.equal(prefix.bytes.toString(), 'abc');
  prefix.bytes.fill(0);
  assert.equal(stream.peek('client', 4, clock()).bytes.toString(), 'abcd');
  assert.equal(stream.snapshot().chargedFrames, 2);
  assert.equal(fixture.pool.snapshot().chargedBytes, 4);
  ok(stream.drain('client', 3, clock()));
  assert.equal(stream.snapshot().chargedFrames, 1);
  assert.equal(stream.peek('client', 4, clock()).bytes.toString(), 'd');
  assert.equal(stream.peek('gateway', 4, clock()).bytes.length, 0);
});

test('partial frames retain frame charges, and a backpressured offer is neither copied nor accepted', () => {
  const fixture = active({ negotiated: { ...limits, maxQueuedFramesPerStream: 2 } }), stream = admitted(fixture);
  ok(stream.binary('client', bytes('ab'), clock()));
  ok(stream.binary('gateway', bytes('cd'), clock()));
  ok(stream.drain('client', 1, clock()));
  const before = stream.snapshot();
  assert.equal(stream.binary('client', bytes('ef'), clock(10)).code, 'backpressure');
  assert.deepEqual(stream.snapshot(), before);
  assert.equal(stream.peek('client', 4, clock(10)).bytes.toString(), 'b');
  ok(stream.drain('gateway', 2, clock(10)));
  ok(stream.binary('client', bytes('ef'), clock(10)));
  assert.equal(stream.peek('client', 4, clock(10)).bytes.toString(), 'bef');
});

test('backpressure advances only the clock watermark and a subsequent rollback fails the controller', () => {
  const fixture = active({ negotiated: { ...limits, maxQueuedBytesPerStream: 4, maxQueuedFramesPerStream: 1 } }), stream = admitted(fixture);
  ok(stream.binary('client', bytes('abcd'), clock()));
  const before = stream.snapshot();
  assert.equal(stream.binary('gateway', bytes('x'), clock(10)).code, 'backpressure');
  assert.deepEqual(stream.snapshot(), before);
  assert.equal(stream.drain('client', 1, clock(9)).code, 'invalid_message');
  assert.equal(fixture.control.snapshot().cause, 'invalid_message');
  assert.equal(stream.snapshot().cause, 'invalid_message');
  assert.equal(fixture.pool.snapshot().chargedBytes, 4);
  ok(stream.resourcesClosed(clock(9)));
  ok(fixture.control.resourcesClosed(clock(9)));
  assert.deepEqual(fixture.pool.snapshot(), { sessionLeases: 0, streamLeases: 0, chargedBytes: 0 });
});

test('shared global bytes and stream slots retain real closing resources across independent owners', () => {
  const pool = new CompanionBudgetPool({ maxSessions: 2, maxStreams: 2, maxBytes: 6 });
  const first = active({ pool }), second = active({ pool, deviceId: 'device-b' });
  const a = admitted(first, 'a'), b = admitted(second, 'b');
  ok(a.binary('client', bytes('abcd'), clock()));
  assert.equal(b.binary('gateway', bytes('xyz'), clock()).code, 'backpressure');
  ok(a.drain('client', 2, clock()));
  ok(b.binary('gateway', bytes('xyz'), clock()));
  ok(a.localCancel(clock()));
  assert.equal(pool.snapshot().chargedBytes, 5);
  assert.equal(b.binary('client', bytes('pq'), clock()).code, 'backpressure');
  assert.equal(first.control.allocateStream(first.deviceId, token, clock()).code, 'stream_limit');
  ok(a.resourcesClosed(clock()));
  assert.equal(pool.snapshot().chargedBytes, 3);
  ok(b.binary('client', bytes('pq'), clock()));
  assert.equal(pool.snapshot().chargedBytes, 5);
  ok(first.control.allocateStream(first.deviceId, token, clock()));
});

test('device byte and concurrent limits include both directions and pending leases', () => {
  const fixture = active({ negotiated: { ...limits, maxQueuedBytesPerDevice: 8, maxConcurrentStreams: 2 } });
  const a = admitted(fixture, 'a'), b = admitted(fixture, 'b');
  ok(a.binary('client', bytes('abcd'), clock()));
  ok(b.binary('gateway', bytes('efgh'), clock()));
  assert.equal(a.binary('gateway', bytes('x'), clock()).code, 'backpressure');
  assert.equal(fixture.control.allocateStream(fixture.deviceId, token, clock()).code, 'stream_limit');
  ok(a.localCancel(clock()));
  assert.equal(fixture.control.snapshot().chargedBytes, 8);
  ok(a.resourcesClosed(clock()));
  const pending = fixture.control.allocateStream(fixture.deviceId, token, clock()); ok(pending);
  assert.equal(pending.stream.snapshot().phase, 'awaiting_open');
  assert.equal(fixture.control.allocateStream(fixture.deviceId, token, clock()).code, 'stream_limit');
});

test('control cancellation invalidates only nonterminal children and releases its session after every resource closes', () => {
  const fixture = active(), a = admitted(fixture, 'a'), b = admitted(fixture, 'b');
  ok(a.binary('client', bytes('ab'), clock()));
  ok(b.binary('gateway', bytes('cd'), clock()));
  ok(b.text('gateway', streamWire('error', 'b', { code: 'proxy_unavailable' }), clock()));
  ok(fixture.control.localCancel(clock()));
  assert.equal(fixture.control.snapshot().phase, 'closed');
  assert.equal(fixture.control.snapshot().cause, 'cancelled');
  assert.equal(a.snapshot().cause, 'cancelled');
  assert.equal(b.snapshot().cause, 'proxy_unavailable');
  assert.equal(a.peek('client', 1, clock()).code, 'invalid_message');
  assert.equal(a.drain('client', 1, clock()).code, 'invalid_message');
  assert.equal(fixture.pool.snapshot().chargedBytes, 4);
  ok(fixture.control.wsClosed(1000, clock()));
  ok(fixture.control.resourcesClosed(clock()));
  assert.equal(fixture.control.snapshot().sessionLease, true);
  ok(a.resourcesClosed(clock()));
  assert.equal(fixture.pool.snapshot().chargedBytes, 2);
  ok(b.resourcesClosed(clock()));
  assert.deepEqual(fixture.pool.snapshot(), { sessionLeases: 0, streamLeases: 0, chargedBytes: 0 });
  assert.equal(fixture.control.snapshot().historyCount, 0);
  ok(b.resourcesClosed(clock()));
});

test('clock/session expiry beats input and idle, never releases reservations or extends on UTC rollback', () => {
  const fixture = active({ lifetime: 60000 }), stream = admitted(fixture);
  ok(stream.binary('client', bytes('abc'), clock()));
  ok(fixture.control.activity('client', clock(59000)));
  ok(fixture.control.activity('gateway', clock(59000)));
  assert.equal(stream.binary('gateway', bytes('x'), clock(60000)).code, 'session_expired');
  assert.equal(stream.snapshot().cause, 'session_expired');
  assert.equal(fixture.pool.snapshot().chargedBytes, 3);
  assert.equal(fixture.control.allocateStream('wrong', 'wrong', clock(60001)).code, 'session_expired');
  const rollback = active({ lifetime: 1000 });
  ok(rollback.control.tick(clock(999, utc - 100000)));
  assert.equal(rollback.control.snapshot().phase, 'active');
  ok(rollback.control.tick(clock(1000, utc - 100000)));
  assert.equal(rollback.control.snapshot().cause, 'session_expired');
});

test('hello does not restart handshake and peeks/stream traffic cannot revive deadlines', () => {
  const pool = new CompanionBudgetPool();
  const control = new CompanionControl({ pool, deviceId: 'device', desktopId: 'desktop', clock: clock() });
  ok(control.text('client', controlWire({ type: 'hello', capabilities: ['tcp-http'], requiredCapabilities: [] }), clock(14999)));
  assert.equal(control.text('gateway', Buffer.from('broken'), clock(15000)).code, 'network_unreachable');
  assert.equal(pool.snapshot().sessionLeases, 0);
  const fixture = active(), stream = admitted(fixture);
  ok(stream.binary('client', bytes('x'), clock()));
  ok(fixture.control.activity('client', clock(59998)));
  ok(fixture.control.activity('gateway', clock(59998)));
  assert.equal(stream.peek('client', 1, clock(59999)).bytes.toString(), 'x');
  ok(fixture.control.tick(clock(60000)));
  assert.equal(fixture.control.snapshot().phase, 'active');
  assert.equal(stream.snapshot().cause, 'network_unreachable');
  const deadControl = active(), liveStream = admitted(deadControl);
  assert.equal(liveStream.binary('client', bytes('x'), clock(60000)).code, 'network_unreachable');
  assert.equal(deadControl.control.snapshot().cause, 'network_unreachable');
});

test('stream handshake runs from lease creation and snapshot is inert immutable inspection', () => {
  const fixture = active(), allocation = fixture.control.allocateStream(fixture.deviceId, token, clock()); ok(allocation);
  const stream = allocation.stream;
  ok(stream.text('client', streamWire('open'), clock(14999)));
  assert.equal(stream.snapshot().phase, 'awaiting_ready');
  assert.throws(() => { stream.snapshot().phase = 'open'; }, TypeError);
  assert.equal(stream.text('gateway', streamWire('ready'), clock(15000)).code, 'network_unreachable');
  assert.equal(stream.snapshot().streamLease, true);
  ok(stream.resourcesClosed(clock(15000)));
  assert.equal(stream.snapshot().streamLease, false);
});

test('wrong admission credentials cannot mutate a live owner and fresh/stored time failures retain precedence', () => {
  const fixture = active(), before = fixture.control.snapshot();
  for (const [device, header] of [['wrong', token], [fixture.deviceId, 'bad'], [fixture.deviceId, Buffer.alloc(32, 9).toString('base64url')]]) {
    assert.equal(fixture.control.allocateStream(device, header, clock()).code, 'authentication_failed');
    assert.deepEqual(fixture.control.snapshot(), before);
  }
  assert.equal(fixture.control.allocateStream(fixture.deviceId, token, clock(60000)).code, 'network_unreachable');
  assert.equal(fixture.control.allocateStream(fixture.deviceId, token, clock(60001)).code, 'authentication_failed');
  const badClock = active();
  assert.equal(badClock.control.allocateStream('wrong', 'wrong', { utcMillis: utc, monotonicMillis: NaN }).code, 'invalid_message');
  assert.equal(badClock.control.snapshot().cause, 'invalid_message');
  ok(badClock.control.resourcesClosed(clock()));
  assert.equal(badClock.pool.snapshot().sessionLeases, 0);
});

test('stream ID history remains bounded across completed streams and clears only after session release', () => {
  const fixture = active({ negotiated: { ...limits, maxConcurrentStreams: 1, maxOpenedStreamsPerSession: 2 } });
  complete(admitted(fixture, 'one'), 'one');
  const reused = fixture.control.allocateStream(fixture.deviceId, token, clock()).stream;
  assert.equal(reused.text('client', streamWire('open', 'one'), clock()).code, 'invalid_message');
  ok(reused.resourcesClosed(clock()));
  complete(admitted(fixture, 'two'), 'two');
  assert.equal(fixture.control.snapshot().historyCount, 2);
  const full = fixture.control.allocateStream(fixture.deviceId, token, clock()).stream;
  assert.equal(full.text('client', streamWire('open', 'three'), clock()).code, 'stream_limit');
  assert.equal(fixture.control.snapshot().historyCount, 2);
  ok(fixture.control.localCancel(clock()));
  ok(fixture.control.resourcesClosed(clock()));
  assert.equal(fixture.control.snapshot().historyCount, 2);
  ok(full.resourcesClosed(clock()));
  assert.equal(fixture.control.snapshot().historyCount, 0);
});

test('session leases cannot be replaced while control or child cleanup remains outstanding', () => {
  const pool = new CompanionBudgetPool({ maxSessions: 1 });
  const fixture = active({ pool }), stream = admitted(fixture);
  ok(fixture.control.localCancel(clock()));
  const attempt = () => {
    const c = new CompanionControl({ pool, deviceId: fixture.deviceId, desktopId: 'desktop-a', clock: clock() });
    ok(c.text('client', controlWire({ type: 'hello', capabilities: ['tcp-http'], requiredCapabilities: [] }), clock()));
    return c.text('gateway', controlWire({ type: 'session_ready', capabilities: ['tcp-http'], desktopId: 'desktop-a', sessionId: token,
      expiresAt: new Date(utc + 300000).toISOString().replace('.000Z', 'Z'), limits }), clock());
  };
  assert.equal(attempt().code, 'session_limit');
  ok(fixture.control.resourcesClosed(clock()));
  assert.equal(attempt().code, 'session_limit');
  ok(stream.resourcesClosed(clock()));
  assert.equal(attempt().code, 'ok');
});

test('premature/conflicting WebSocket closes and time-invalid resource confirmations cannot become success', () => {
  const fixture = active(), stream = admitted(fixture);
  ok(stream.binary('client', bytes('abc'), clock()));
  ok(stream.wsClosed(1000, clock()));
  assert.equal(stream.snapshot().cause, 'network_unreachable');
  assert.equal(fixture.pool.snapshot().chargedBytes, 3);
  ok(stream.wsClosed(1000, clock()));
  ok(stream.resourcesClosed(clock()));
  assert.equal(stream.snapshot().phase, 'failed');
  assert.equal(fixture.pool.snapshot().chargedBytes, 0);
  const second = admitted(fixture, 'second');
  ok(second.text('client', streamWire('end_write', 'second'), clock()));
  ok(second.text('gateway', streamWire('end_write', 'second'), clock()));
  ok(second.wsClosed(1000, clock()));
  ok(second.wsClosed(1001, clock()));
  assert.equal(second.snapshot().cause, 'network_unreachable');
  ok(second.resourcesClosed(clock()));
  const third = admitted(fixture, 'third');
  ok(third.text('client', streamWire('end_write', 'third'), clock()));
  ok(third.text('gateway', streamWire('end_write', 'third'), clock()));
  ok(third.wsClosed(1000, clock(1)));
  ok(third.resourcesClosed(clock(0)));
  assert.equal(third.snapshot().cause, 'invalid_message');
  assert.equal(third.snapshot().resourcesReleased, true);
  assert.equal(fixture.pool.snapshot().streamLeases, 0);
});

test('invalid stream input fails only that stream, retains charges, and diagnostics omit identities and payloads', () => {
  const fixture = active(), a = admitted(fixture, 'a'), b = admitted(fixture, 'b');
  const payload = bytes('hide'); ok(a.binary('client', payload, clock()));
  assert.equal(a.drain('client', 5, clock()).code, 'invalid_message');
  assert.equal(a.snapshot().client.chargedBytes, 4);
  assert.equal(fixture.control.snapshot().phase, 'active');
  ok(b.binary('gateway', bytes('safe'), clock()));
  const peek = b.peek('gateway', 4, clock());
  for (const value of [fixture.pool, fixture.control, a, b, peek]) {
    for (const diagnostic of [String(value), inspect(value), JSON.stringify(value)]) {
      for (const secret of [token, 'device-a', 'desktop-a', 'hide', 'safe']) assert.ok(!diagnostic.includes(secret));
    }
  }
  assert.equal(peek.bytes.toString(), 'safe');
  ok(a.resourcesClosed(clock()));
  assert.equal(fixture.pool.snapshot().chargedBytes, 4);
  assert.equal(b.peek('gateway', 4, clock()).bytes.toString(), 'safe');
});

test('local desktop and supported capability constructor values also require full ASCII matches', () => {
  for (const suffix of ['\n', '\r\n']) {
    assert.throws(() => new CompanionControl({ pool: new CompanionBudgetPool(), deviceId: 'device', desktopId: 'desktop' + suffix,
      clock: clock() }), error => error.code === 'invalid_message');
    assert.throws(() => new CompanionControl({ pool: new CompanionBudgetPool(), deviceId: 'device', desktopId: 'desktop',
      supportedCapabilities: ['tcp-http' + suffix], clock: clock() }), error => error.code === 'invalid_message');
  }
  for (const deviceId of ['device\n', 'device\r\n', 'has space', 'device:other', '', 'x'.repeat(129)]) {
    assert.throws(() => new CompanionControl({ pool: new CompanionBudgetPool(), deviceId, desktopId: 'desktop',
      clock: clock() }), error => error.code === 'invalid_message');
  }
});

test('an empty trusted local support set rejects required traffic capabilities without acquiring a lease', () => {
  const pool = new CompanionBudgetPool();
  const control = new CompanionControl({ pool, deviceId: 'device', desktopId: 'desktop', supportedCapabilities: [], clock: clock() });
  assert.equal(control.snapshot().phase, 'awaiting_hello');
  const negotiation = control.text('client', controlWire({ type: 'hello', capabilities: ['tcp-http'], requiredCapabilities: ['tcp-http'] }), clock());
  assert.equal(negotiation.code, 'unsupported_capability');
  assert.equal(control.snapshot().phase, 'failed');
  assert.equal(control.snapshot().cause, 'unsupported_capability');
  assert.deepEqual(pool.snapshot(), { sessionLeases: 0, streamLeases: 0, chargedBytes: 0 });
});

test('readiness combined defects follow identity, expiry, capability negotiation, frame-fit, lease order', () => {
  const attempt = fields => {
    const pool = new CompanionBudgetPool({ maxBytes: 1 });
    const control = new CompanionControl({ pool, deviceId: 'device', desktopId: 'desktop-a', clock: clock() });
    ok(control.text('client', controlWire({ type: 'hello', capabilities: ['tcp-http', 'tcp-https-connect'], requiredCapabilities: ['tcp-http'] }), clock()));
    return control.text('gateway', controlWire({ type: 'session_ready', capabilities: ['tcp-https-connect'], desktopId: 'desktop-a',
      sessionId: token, expiresAt: new Date(utc + 300000).toISOString().replace('.000Z', 'Z'), limits, ...fields }), clock());
  };
  assert.equal(attempt({}).code, 'unsupported_capability');
  assert.equal(attempt({ capabilities: ['tcp-http'] }).code, 'invalid_message');
  assert.equal(attempt({ desktopId: 'wrong', expiresAt: '2025-01-01T00:00:00Z', capabilities: ['unoffered'] }).code, 'authentication_failed');
  assert.equal(attempt({ expiresAt: '2025-01-01T00:00:00Z', capabilities: ['unoffered'] }).code, 'session_expired');
  assert.equal(attempt({ expiresAt: '2026-01-01T00:30:01Z' }).code, 'invalid_message');
});


const originCapability = 'tcp-http-origin-connect';
function c2Active({ supported = [originCapability], offered = supported, negotiated = supported, lifetime = 300000 } = {}) {
  const pool = new CompanionBudgetPool();
  const control = new CompanionControl({ pool, deviceId: 'c2-device', desktopId: 'c2-desktop', supportedCapabilities: supported, clock: clock() });
  ok(control.text('client', controlWire({ type: 'hello', capabilities: offered, requiredCapabilities: [] }), clock()));
  ok(control.text('gateway', controlWire({ type: 'session_ready', capabilities: negotiated, desktopId: 'c2-desktop', sessionId: token,
    expiresAt: new Date(utc + lifetime).toISOString().replace('.000Z', 'Z'), limits }), clock()));
  return { pool, control, allocate: () => { const result = control.allocateStream('c2-device', token, clock()); ok(result); return result.stream; } };
}

test('the third implemented traffic capability can establish a session and ordered HTTP-origin stream alone', () => {
  const fixture = c2Active(), stream = fixture.allocate();
  ok(stream.text('client', streamWire('open', 'c2', { proxyMode: 'http-origin-connect' }), clock()));
  ok(stream.text('gateway', streamWire('ready', 'c2'), clock()));
  ok(stream.binary('client', bytes('abcd'), clock()));
  assert.deepEqual(stream.text('client', streamWire('end_write', 'c2'), clock()).effects, []);
  assert.deepEqual(stream.drain('client', 4, clock()).effects.map(e => e.direction), ['client']);
  ok(stream.text('gateway', streamWire('end_write', 'c2'), clock()));
  ok(stream.wsClosed(1000, clock())); ok(stream.resourcesClosed(clock()));
  assert.equal(stream.snapshot().phase, 'complete');
  assert.deepEqual(fixture.pool.snapshot(), { sessionLeases: 1, streamLeases: 0, chargedBytes: 0 });
  assert.deepEqual(Object.keys(fixture.control.snapshot()), ['phase','cause','sessionLease','webSocketClosed','resourcesReleased','historyCount','streamLeases','chargedBytes']);
});

test('unsupported mode keeps its pending lease until closure and never claims the requested stream ID', () => {
  for (const modern of [false, true]) {
    const fixture = c2Active({ supported: modern ? ['tcp-http'] : [originCapability] });
    const denied = fixture.allocate();
    assert.equal(denied.text('client', streamWire('open', 'reusable', modern ? { proxyMode: 'http-origin-connect' } : {}), clock()).code, 'unsupported_capability');
    assert.equal(fixture.control.snapshot().historyCount, 0); assert.equal(fixture.pool.snapshot().streamLeases, 1);
    ok(denied.resourcesClosed(clock())); assert.equal(fixture.pool.snapshot().streamLeases, 0);
    const allowed = fixture.allocate();
    ok(allowed.text('client', streamWire('open', 'reusable', modern ? {} : { proxyMode: 'http-origin-connect' }), clock()));
    assert.equal(fixture.control.snapshot().historyCount, 1);
  }
});

test('open support uses the actual negotiated subset, independently of offered and locally supported capabilities', () => {
  for (const negotiated of [[originCapability], ['tcp-http']]) {
    const fixture = c2Active({ supported: ['tcp-http', originCapability], negotiated });
    const stream = fixture.allocate();
    const unsupported = negotiated[0] === originCapability ? {} : { proxyMode: 'http-origin-connect' };
    assert.equal(stream.text('client', streamWire('open', 'flow', unsupported), clock()).code, 'unsupported_capability');
    assert.equal(fixture.control.snapshot().historyCount, 0);
  }
});

test('role, phase and expiry checks precede unsupported mode; mode support precedes ID claim', () => {
  const wrongRole = c2Active({ supported: ['tcp-http'] });
  assert.equal(wrongRole.allocate().text('gateway', streamWire('open', 'flow', { proxyMode: 'http-origin-connect' }), clock()).code, 'invalid_message');
  const expired = c2Active({ supported: ['tcp-http'], lifetime: 1000 });
  const pending = expired.allocate();
  assert.equal(pending.text('client', streamWire('open', 'flow', { proxyMode: 'http-origin-connect' }), clock(1000)).code, 'session_expired');
  const repeated = c2Active(); const first = repeated.allocate();
  ok(first.text('client', streamWire('open', 'claimed', { proxyMode: 'http-origin-connect' }), clock()));
  assert.equal(first.text('client', streamWire('open', 'claimed'), clock()).code, 'invalid_message');
  ok(first.resourcesClosed(clock()));
  const second = repeated.allocate();
  assert.equal(second.text('client', streamWire('open', 'claimed'), clock()).code, 'unsupported_capability');
  assert.equal(repeated.control.snapshot().historyCount, 1);
});
