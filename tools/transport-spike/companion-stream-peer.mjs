// Authenticated research fixture only. Never import into the desktop gateway or production app.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import https from 'node:https';
import net from 'node:net';
import { Duplex } from 'node:stream';
import { performance } from 'node:perf_hooks';
import { inspect } from 'node:util';
import { startPeer, logicalName as defaultLogicalName } from './android-peer.mjs';
import { CompanionBudgetPool, CompanionControl } from './companion-protocol-lifecycle.mjs';
import { decodeControl, decodeStream, encodeControl, encodeStream, validateCapabilities, TRAFFIC_CAPABILITIES } from './companion-protocol-codec.mjs';
import { enrollmentPublicSnapshot } from './companion-enrollment-crypto.mjs';
import { ResearchWebSocket } from './research-websocket.mjs';
import { Changed, observeClose, closedObserved, pull, headers, write, writerState, endWrite, bounded, fail, safeError } from './companion-stream-peer-io.mjs';
import { SCENARIOS, LIMITS, DESKTOP_ID, SCENARIO_HEADER, SESSION_HEADER, RESPONSE_HEADER,
  RESPONSE_BODY_LENGTH, COMMANDS, pausedScenario, uploadLength, requestHeader, pattern } from './companion-stream-peer-schema.mjs';

const controlInactive = control => ['closed', 'failed'].includes(control.snapshot().phase);
const streamInactive = stream => ['complete', 'cancelled', 'failed'].includes(stream.snapshot().phase);
const supported = Object.freeze(['tcp-http', 'tcp-https-connect']);
const canonicalToken = text => typeof text === 'string' && /^[A-Za-z0-9_-]{43}$/.exec(text)?.[0] === text &&
  Buffer.from(text, 'base64url').length === 32 && Buffer.from(text, 'base64url').toString('base64url') === text;
const clock = () => ({ utcMillis: Date.now(), monotonicMillis: Math.floor(performance.now()) });
const digest = () => createHash('sha256');
const sameToken = (owner, token) => Buffer.isBuffer(owner.token) && canonicalToken(token) && timingSafeEqual(owner.token, Buffer.from(token, 'base64url'));
const deviceId = socket => 'dev_' + createHash('sha256').update(socket.getPeerX509Certificate().publicKey.export({ format: 'der', type: 'spki' })).digest('base64url');

function requestPolicy(request, logicalName, exactHost = false) {
  const seen = new Set();
  if (request.httpVersion !== '1.1' || request.rawHeaders.length > 64) return false;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index].toLowerCase();
    if (seen.has(name)) return false;
    seen.add(name);
  }
  if (['origin', 'cookie', 'authorization', 'transfer-encoding'].some(name => Object.hasOwn(request.headers, name))) return false;
  const host = request.headers.host;
  return (!exactHost && host === logicalName) || host === `${logicalName}:${request.socket.localPort}`;
}
function upgradePolicy(request, logicalName, exactHost) {
  if (!requestPolicy(request, logicalName, exactHost) || request.method !== 'GET' || request.headers.upgrade?.toLowerCase() !== 'websocket' ||
      request.headers.connection?.toLowerCase() !== 'upgrade' || request.headers['sec-websocket-version'] !== '13' ||
      request.headers['sec-websocket-extensions'] !== undefined || request.headers['sec-websocket-protocol'] !== undefined ||
      (request.headers['content-length'] !== undefined && request.headers['content-length'] !== '0')) return false;
  const key = request.headers['sec-websocket-key'];
  return typeof key === 'string' && Buffer.from(key, 'base64').length === 16 && Buffer.from(key, 'base64').toString('base64') === key;
}
function upgradeBytes(key) {
  const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  return Buffer.from(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
}
function response(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  if (body.length > 4096) fail('probe_bound');
  response.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length, connection: 'close' }).end(body);
}

export async function createCompanionStreamServer({ tls, authorize, credentialAuthority,
  desktopId = DESKTOP_ID, logicalName = defaultLogicalName, sessionLifetimeMillis = 120000, port = 0,
  trustedProxyFactory, supportedCapabilities }) {
  const enrolled = credentialAuthority !== undefined;
  const trusted = trustedProxyFactory !== undefined;
  let trafficCapabilities = supported;
  try {
    if (trusted !== (supportedCapabilities !== undefined) || (trusted && (typeof trustedProxyFactory !== 'function' || !enrolled))) throw 0;
    if (trusted) {
      trafficCapabilities = Object.freeze(validateCapabilities(supportedCapabilities));
      if (trafficCapabilities.some(value => !TRAFFIC_CAPABILITIES.includes(value))) throw 0;
    }
  } catch { fail('stream_fixture_configuration'); }
  const gatewayExpires = enrolled ? Date.parse(credentialAuthority?.gatewayExpiresAt) : 0;
  if (typeof authorize !== 'function' || !Number.isInteger(port) || port < 0 || port > 65535 ||
      !Number.isInteger(sessionLifetimeMillis) || sessionLifetimeMillis < 1000 || sessionLifetimeMillis > 1800000 ||
      typeof desktopId !== 'string' || /^[A-Za-z0-9_-]{1,128}$/.exec(desktopId)?.[0] !== desktopId ||
      typeof logicalName !== 'string' || logicalName.length > 253 || /^[a-z0-9.-]+$/.exec(logicalName)?.[0] !== logicalName ||
      (enrolled && (typeof credentialAuthority?.authorizeCertificate !== 'function' || !Number.isSafeInteger(gatewayExpires) || gatewayExpires <= Date.now()))) fail('stream_fixture_configuration');
  const grantFields = ['desktopId', 'deviceId', 'enrollmentId', 'clientCertificateSha256', 'deviceSpkiSha256', 'credentialExpiresAt'];
  const grantEqual = (left, right) => left && right && grantFields.every(name => left[name] === right[name]);
  const pool = new CompanionBudgetPool({ maxSessions: 4, maxStreams: 8, maxBytes: 65536 });
  const owners = new Map(); // One bounded latest record per issued SPKI; never exported.
  const enrollmentRecords = new Map(); // Original owner retained for private evidence after a later session.
  const sockets = new Set();
  const proxySockets = new Set();
  const ingressTasks = new Set(); // Includes upgrades awaiting a previous owner's real join.
  const accepted = new Map(), awaiting = new Map();
  let closing = false, closeTask, unavailable = false;
  let proxyListenerClosed = trusted, httpsListenerClosed = false;
  const proxy = trusted ? null : net.createServer({ allowHalfOpen: true, pauseOnConnect: true });
  if (proxy) {
  proxy.once('close', () => { proxyListenerClosed = true; });
  proxy.maxConnections = 8;
  proxy.on('error', () => {});
  proxy.on('connection', socket => {
    observeClose(socket);
    socket.on('error', () => {});
    proxySockets.add(socket);
    socket.once('close', () => proxySockets.delete(socket));
    if (closing) { socket.destroy(); return; }
    const waiting = awaiting.get(socket.remotePort);
    if (waiting) { awaiting.delete(socket.remotePort); waiting(socket); }
    else {
      const port = socket.remotePort;
      const timer = setTimeout(() => { accepted.delete(port); socket.destroy(); }, 1000);
      socket.once('close', () => { clearTimeout(timer); accepted.delete(port); });
      accepted.set(port, { socket, timer });
    }
  });
  try {
    await bounded(new Promise((done, reject) => { proxy.once('error', reject); proxy.listen(0, '127.0.0.1', done); }), 5000, 'stream_fixture_startup_failed');
  } catch {
    closing = true;
    await bounded(new Promise(done => proxy.close(done)), 5000);
    fail('stream_fixture_startup_failed');
  }
  }

  let server;
  try {
    server = https.createServer({ ...tls, maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 },
      (request, reply) => {
        if (closing) { request.socket.destroy(); return; }
        ownIngress(httpRequest(request, reply), request.socket);
      });
  } catch {
    closing = true;
    for (const entry of accepted.values()) clearTimeout(entry.timer);
    const closes = [...proxySockets].map(socket => { const closed = observeClose(socket); socket.destroy(); return closed; });
    await bounded(Promise.allSettled([...closes, ...(proxy ? [new Promise(done => proxy.close(done))] : [])]), 5000);
    fail('stream_fixture_startup_failed');
  }
  server.maxConnections = 16;
  server.once('close', () => { httpsListenerClosed = true; });
  server.maxHeadersCount = 32;
  server.maxRequestsPerSocket = 1;
  server.setTimeout(5000, socket => socket.destroy());
  server.on('connection', socket => {
    observeClose(socket);
    sockets.add(socket); socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    if (closing) socket.destroy();
  });
  server.on('tlsClientError', () => {});
  if (enrolled) {
    server.on('newSession', (_id, _data, done) => done());
    server.on('resumeSession', (_id, done) => done(null, null));
    server.on('secureConnection', socket => {
      if (socket.servername !== logicalName || socket.isSessionReused() ||
          (socket.alpnProtocol && socket.alpnProtocol !== 'http/1.1')) socket.destroy();
    });
  }
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('dropRequest', (_request, socket) => socket.destroy());
  server.on('upgrade', (request, socket, head) => {
    if (closing) { socket.destroy(); return; }
    ownIngress(upgrade(request, socket, head), socket);
  });

  function ownIngress(promise, socket) {
    const work = promise.catch(() => socket.destroy()).finally(() => ingressTasks.delete(work));
    ingressTasks.add(work);
  }

  function markTerminal(owner) {
    if (owner.timing.terminalUtcMillis === null && controlInactive(owner.model)) {
      owner.timing.terminalUtcMillis = Date.now();
      owner.timing.terminalElapsedMillis = owner.activated === null ? 0 : Math.floor(performance.now() - owner.activated);
    }
  }
  function timer(owner, operation, milliseconds) {
    const handle = setInterval(operation, milliseconds);
    owner.timers.add(handle);
    return handle;
  }
  function task(holder, operation, onFailure) {
    const promise = Promise.resolve().then(operation).catch(() => { if (!holder.stopping) onFailure(); })
      .finally(() => { holder.workers.delete(promise); holder.changed.notify(); });
    holder.workers.add(promise);
    return promise;
  }
  function check(result) { if (result.code !== 'ok') fail('model_operation_failed'); return result; }
  function invalidate(owner, cause, notify = false) {
    if (owner.grant && cause !== 'session_expired') owner.grantValid = false;
    owner.invalidationCause ??= cause;
    if (!controlInactive(owner.model)) {
      const state = owner.model.snapshot();
      if (state.phase === 'active') owner.model.text('gateway', encodeControl({ protocolVersion: 1,
        type: cause === 'network_unreachable' ? 'error' : 'disconnect', code: cause }), clock());
      else owner.model.wsClosed(1006, clock());
    }
    markTerminal(owner);
    stopControl(owner, notify ? cause : null);
  }
  function unavailableAuthority() {
    unavailable = true;
    for (const owner of owners.values()) invalidate(owner, 'network_unreachable');
  }
  function grantFor(socket) {
    if (unavailable || closing || !socket.authorized || !authorize(socket)) return null;
    if (!enrolled) return { deviceId: deviceId(socket) };
    try {
      const leaf = socket.getPeerX509Certificate()?.raw;
      if (!leaf || leaf.length > 4096) return null;
      const value = credentialAuthority.authorizeCertificate(Buffer.from(leaf))?.material();
      if (!value) return null;
      if (Object.keys(value).length !== grantFields.length || !grantFields.every(name => typeof value[name] === 'string') ||
          value.desktopId !== desktopId || value.clientCertificateSha256 !== createHash('sha256').update(leaf).digest('base64url') ||
          value.deviceSpkiSha256 !== createHash('sha256').update(socket.getPeerX509Certificate().publicKey.export({ type: 'spki', format: 'der' })).digest('base64url') ||
          !Number.isSafeInteger(Date.parse(value.credentialExpiresAt))) throw safeError('invalid_grant');
      return { ...value, leaf: Buffer.from(leaf) };
    } catch { unavailableAuthority(); return null; }
  }
  function validateOwner(owner) {
    if (!enrolled) return !owner.stopping;
    if (owner.stopping || !owner.grantValid || unavailable || closing) return false;
    owner.revalidations++;
    const now = clock();
    if (now.utcMillis >= owner.credentialExpires || now.utcMillis >= gatewayExpires ||
        now.monotonicMillis - owner.grantedAt.monotonicMillis >= owner.credentialLifetime) {
      owner.grantValid = false; invalidate(owner, 'session_expired'); return false;
    }
    // An operational boundary must enforce the negotiated deadline itself; a busy
    // event loop must not defer admission decisions until the 50ms watcher runs.
    owner.model.tick(now); markTerminal(owner);
    if (controlInactive(owner.model)) { stopControl(owner); return false; }
    try {
      const fresh = credentialAuthority.authorizeCertificate(Buffer.from(owner.grant.leaf))?.material();
      if (!grantEqual(owner.grant, fresh)) { owner.grantValid = false; invalidate(owner, 'network_unreachable'); return false; }
      return true;
    } catch { unavailableAuthority(); return false; }
  }
  function live(record) {
    if (!validateOwner(record.owner) || record.stopping || record.owner.stopping || controlInactive(record.owner.model) || streamInactive(record.model)) fail('stream_inactive');
  }
  function guardApplicationSocket(record, socket) {
    if (!enrolled) return;
    const original = socket.write;
    socket.write = function (...args) {
      live(record);
      // There is no asynchronous boundary between the final guard and actual write.
      // Callback completion after invalidation is allowed and never counted as a new admission.
      if (record.owner.invalidationCause !== null) record.owner.writesAfterInvalidation++;
      record.owner.applicationWriteAdmissions++;
      return original.apply(this, args);
    };
  }
  function retained(record) {
    if (record.retained) return;
    record.retained = true;
    const state = record.model.snapshot();
    record.io.retainedBytesAtAbort = state.client.chargedBytes + state.gateway.chargedBytes;
    record.io.retainedFramesAtAbort = state.chargedFrames;
    record.io.retainedStreamLeasesAtAbort = state.streamLease ? 1 : 0;
  }
  function stopStream(record, normal = false) {
    if (record.cleanupTask) return record.cleanupTask;
    if (!normal) retained(record);
    record.stopping = true;
    record.changed.notify();
    // Seal/interrupt before returning; startup and every actual closure remain owned.
    if (record.trustedOwner && !record.trustedClose) {
      try {
        const closing = record.trustedOwner.close();
        record.trustedClose = closing instanceof Promise ? closing : Promise.reject(safeError('cleanup_incomplete'));
      } catch { record.trustedClose = Promise.reject(safeError('cleanup_incomplete')); }
      record.trustedClose.catch(() => {});
    }
    if (!normal) record.socket.destroy();
    record.proxy?.destroy(); record.fixtureSocket?.destroy();
    record.cleanupTask = bounded((async () => {
      if (record.ws) { if (normal) await record.ws.finish(); else await record.ws.cancel(); }
      else { record.socket.destroy(); await record.socketClosed; }
      await Promise.allSettled([...record.workers]);
      if (record.trustedStart) await Promise.allSettled([record.trustedStart]);
      if (record.trustedClose) await record.trustedClose;
      if (record.trustedClosed) await record.trustedClosed;
      // Pairing can complete while a worker is being cancelled. Recheck the admitted
      // resources after workers settle, before confirming any model release.
      record.proxy?.destroy(); record.fixtureSocket?.destroy();
      if (record.proxyClosedPromise) await record.proxyClosedPromise;
      if (record.fixtureClosedPromise) await record.fixtureClosedPromise;
      await Promise.all([record.proxyWriter.idle, record.fixtureWriter.idle, record.upgradeWriter.idle]);
      if (record.ws?.snapshot().pendingWriteCallbacks) fail('cleanup_incomplete');
      record.pendingIngressBytes = 0;
      record.model.resourcesClosed(clock());
      record.closed = true;
    })(), 5000);
    record.cleanupTask.catch(() => { record.cleanupFailed = true; });
    return record.cleanupTask;
  }
  function stopControl(owner, notification = null) {
    if (owner.cleanupTask) return owner.cleanupTask;
    markTerminal(owner);
    owner.stopping = true;
    for (const handle of owner.timers) clearInterval(handle);
    owner.timers.clear(); owner.changed.notify();
    if (!notification || !owner.ws) owner.socket.destroy();
    const streamStops = [...owner.records].map(record => stopStream(record));
    owner.cleanupTask = bounded((async () => {
      if (notification && owner.ws && !owner.socket.destroyed) {
        owner.terminalNotification.attempted = true;
        const handle = setTimeout(() => owner.socket.destroy(), 1000);
        owner.notificationTimer = true;
        try {
          await owner.ws.send('text', encodeControl({ protocolVersion: 1, type: 'disconnect', code: notification }));
          owner.terminalNotification.completed = true;
        } catch { owner.terminalNotification.aborted = true; }
        finally { clearTimeout(handle); owner.notificationTimer = false; owner.socket.destroy(); }
      }
      if (owner.ws) await owner.ws.cancel(); else await owner.socketClosed;
      await Promise.all(streamStops);
      await Promise.allSettled([...owner.workers]);
      await owner.upgradeWriter.idle;
      owner.model.resourcesClosed(clock());
      owner.closed = true;
    })(), 5000);
    owner.cleanupTask.catch(() => { owner.cleanupFailed = true; });
    return owner.cleanupTask;
  }

  function authorizeOwner(request, active = false) {
    const grant = grantFor(request.socket);
    if (!grant) return null;
    const owner = owners.get(grant.deviceId);
    if (!owner || !sameToken(owner, request.headers[SESSION_HEADER])) return null;
    if (enrolled && (!grantEqual(owner.grant, grant) || !owner.grant.leaf.equals(grant.leaf))) return null;
    if (active) {
      if (!validateOwner(owner)) return null;
      owner.model.tick(clock()); markTerminal(owner);
      if (controlInactive(owner.model) || owner.stopping) { stopControl(owner); return null; }
    }
    return owner;
  }
  async function httpRequest(request, reply) {
    if (trusted) return response(reply, 404, { error: 'rejected' });
    if (closing || unavailable || !requestPolicy(request, logicalName, enrolled) || !authorize(request.socket)) return response(reply, 400, { error: 'rejected' });
    if (request.url === '/research/probe' && request.method === 'GET') {
      if (request.headers['content-length'] !== undefined && request.headers['content-length'] !== '0') return response(reply, 400, { error: 'rejected' });
      const owner = authorizeOwner(request);
      return response(reply, owner ? 200 : 403, owner ? probe(owner) : { error: 'rejected' });
    }
    if (request.url !== '/research/command' || request.method !== 'POST') return response(reply, 404, { error: 'rejected' });
    const owner = authorizeOwner(request, true);
    if (!owner) return response(reply, 403, { error: 'rejected' });
    const length = request.headers['content-length'];
    if (request.headers['content-type'] !== 'application/json' || !/^[1-9][0-9]{0,2}$/.test(length ?? '') || Number(length) > 128) {
      return response(reply, 400, { error: 'rejected' });
    }
    const body = Buffer.allocUnsafe(Number(length));
    let count = 0;
    for await (const chunk of request) {
      if (chunk.length > body.length - count) { request.destroy(); return; }
      chunk.copy(body, count); count += chunk.length;
    }
    if (count !== body.length) return response(reply, 400, { error: 'rejected' });
    const record = owner.latest;
    if (!record || record.stopping) return response(reply, 409, { error: 'gate_unavailable' });
    if (body.equals(Buffer.from(COMMANDS.release_response_tail)) && owner.scenario === 'gated' && record.fixture.responsePrefixWritten) {
      record.fixture.responseTailReleased = true;
    } else if (body.equals(Buffer.from(COMMANDS.resume_proxy_read)) && owner.scenario === 'backpressure') {
      record.fixture.proxyReadPaused = false;
    } else return response(reply, 400, { error: 'rejected' });
    record.changed.notify();
    response(reply, 200, { ok: true });
  }

  async function upgrade(request, socket, head) {
    if (closing || unavailable || !upgradePolicy(request, logicalName, enrolled) || !authorize(socket) || head.length > 65550) return rejectUpgrade(socket, 400);
    const grant = grantFor(socket);
    if (!grant) return rejectUpgrade(socket, 403);
    if (request.url === '/companion/v1/control') {
      const scenario = trusted ? null : request.headers[SCENARIO_HEADER], id = grant.deviceId;
      if ((trusted ? request.headers[SCENARIO_HEADER] !== undefined : !SCENARIOS.includes(scenario)) || request.headers[SESSION_HEADER] !== undefined) return rejectUpgrade(socket, 400);
      let previous = owners.get(id);
      if (enrolled && previous && !previous.closed && controlInactive(previous.model) && previous.cleanupTask) {
        // No new model lease exists during this wait. Join the existing bounded
        // cleanup rather than racing local client closure against server release.
        try { await previous.cleanupTask; } catch { return rejectUpgrade(socket, 503); }
        if (closing || unavailable || socket.destroyed) { socket.destroy(); return; }
        const fresh = grantFor(socket);
        if (!fresh || !grantEqual(grant, fresh) || !grant.leaf.equals(fresh.leaf)) return rejectUpgrade(socket, 403);
        previous = owners.get(id); // A concurrent waiting control may have won admission.
      }
      if ((previous && !previous.closed) || (!previous && owners.size >= 8)) return rejectUpgrade(socket, 429);
      const history = enrolled ? enrollmentRecords.get(grant.enrollmentId) : null;
      if (enrolled && ((!history && enrollmentRecords.size >= 8) || (history && history.controlsAdmitted >= Number.MAX_SAFE_INTEGER))) return rejectUpgrade(socket, 429);
      const grantedAt = clock();
      const owner = { model: new CompanionControl({ pool, deviceId: id, desktopId, clock: grantedAt, supportedCapabilities: trafficCapabilities }),
        grant: enrolled ? grant : null, grantValid: enrolled, grantedAt, revalidations: 0, invalidationCause: null,
        credentialExpires: enrolled ? Date.parse(grant.credentialExpiresAt) : 0,
        credentialLifetime: enrolled ? Date.parse(grant.credentialExpiresAt) - grantedAt.utcMillis : 0,
        terminalNotification: { attempted: false, completed: false, aborted: false }, notificationTimer: false,
        applicationWriteAdmissions: 0, writesAfterInvalidation: 0,
        id, scenario, capabilities: Object.freeze([]), socket, socketClosed: observeClose(socket), ws: null, token: null,
        workers: new Set(), timers: new Set(), changed: new Changed(), records: new Set(), latest: null,
        ordinal: 0, stopping: false, closed: false, cleanupTask: null, cleanupFailed: false, activated: null,
        upgradeWriter: writerState(), timing: { readyUtcMillis: 0, expiresUtcMillis: 0, terminalUtcMillis: null, terminalElapsedMillis: null } };
      owners.set(id, owner);
      if (enrolled) {
        if (history) history.controlsAdmitted++;
        else enrollmentRecords.set(grant.enrollmentId, { original: owner, controlsAdmitted: 1 });
      }
      socket.setTimeout(0);
      socket.once('close', () => {
        owner.model.wsClosed(1006, clock()); markTerminal(owner);
        if (!owner.stopping) stopControl(owner);
      });
      timer(owner, () => {
        if (!validateOwner(owner)) return;
        owner.model.tick(clock()); markTerminal(owner);
        if (controlInactive(owner.model)) stopControl(owner);
        for (const record of owner.records) if (streamInactive(record.model) && !record.closed) stopStream(record);
      }, 50);
      task(owner, async () => {
        if (!validateOwner(owner)) fail('stream_inactive');
        await write(socket, upgradeBytes(request.headers['sec-websocket-key']), owner.upgradeWriter);
        owner.ws = new ResearchWebSocket(socket, { role: 'server', initialBytes: head, maxBinaryBytes: 4096 });
        await controlReader(owner);
      }, () => stopControl(owner));
    } else if (request.url === '/companion/v1/streams') {
      if (request.headers[SCENARIO_HEADER] !== undefined) return rejectUpgrade(socket, 400);
      const owner = authorizeOwner(request, true);
      if (!owner) return rejectUpgrade(socket, 403);
      if (owner.ordinal >= 64) return rejectUpgrade(socket, 429);
      const allocation = owner.model.allocateStream(grant.deviceId, request.headers[SESSION_HEADER], clock());
      markTerminal(owner);
      if (allocation.code !== 'ok') return rejectUpgrade(socket, allocation.code === 'stream_limit' ? 429 : 403);
      const record = newRecord(owner, allocation.stream, socket);
      for (const previous of owner.records) if (previous.closed) owner.records.delete(previous);
      owner.records.add(record); owner.latest = record; owner.ordinal++;
      socket.setTimeout(0);
      socket.once('close', () => {
        record.model.wsClosed(record.observedCloseCode, clock());
        if (!record.stopping) stopStream(record);
      });
      task(record, async () => {
        live(record);
        await write(socket, upgradeBytes(request.headers['sec-websocket-key']), record.upgradeWriter);
        record.ws = new ResearchWebSocket(socket, { role: 'server', initialBytes: head, maxBinaryBytes: 4096 });
        await streamReader(record);
      }, () => stopStream(record));
    } else rejectUpgrade(socket, 404);
  }

  function rejectUpgrade(socket, status) {
    // No session/key/identity material in HTTP rejection or close reasons.
    socket.end(`HTTP/1.1 ${status} Rejected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
  }
  async function controlReader(owner) {
    while (!owner.stopping) {
      const event = await owner.ws.next();
      try {
        if (!validateOwner(owner)) return;
        if (event.kind === 'ping' || event.kind === 'pong') {
          check(owner.model.activity('client', clock()));
          if (event.kind === 'ping') { await owner.ws.send('pong', event.copyBytes()); check(owner.model.activity('gateway', clock())); }
        } else if (event.kind === 'text') {
          const bytes = event.copyBytes();
          check(owner.model.text('client', bytes, clock())); markTerminal(owner);
          const message = decodeControl(bytes).toWire();
          if (message.type === 'hello') {
            const capabilities = trafficCapabilities.filter(value => message.capabilities.includes(value));
            if (capabilities.length === 0) fail('unsupported_capability');
            owner.token = randomBytes(32);
            const readyClock = clock();
            const expiresUtcMillis = enrolled ? Math.floor(Math.min(readyClock.utcMillis + sessionLifetimeMillis, owner.credentialExpires, gatewayExpires) / 1000) * 1000 :
              Math.ceil(readyClock.utcMillis / 1000) * 1000 + (owner.scenario === 'expiry' ? 30000 : 120000);
            const ready = encodeControl({ protocolVersion: 1, type: 'session_ready', capabilities, desktopId,
              expiresAt: new Date(expiresUtcMillis).toISOString().replace('.000Z', 'Z'), sessionId: owner.token.toString('base64url'), limits: LIMITS });
            check(owner.model.text('gateway', ready, readyClock));
            owner.capabilities = Object.freeze([...capabilities]);
            owner.timing.readyUtcMillis = readyClock.utcMillis; owner.timing.expiresUtcMillis = expiresUtcMillis; owner.activated = readyClock.monotonicMillis;
            if (!validateOwner(owner)) return;
            await owner.ws.send('text', ready);
            timer(owner, () => {
              if (!validateOwner(owner) || owner.stopping || controlInactive(owner.model)) return;
              owner.ws.send('ping', Buffer.alloc(0)).then(() => { if (!owner.stopping) check(owner.model.activity('gateway', clock())); })
                .catch(() => stopControl(owner));
            }, 10000);
          }
          if (controlInactive(owner.model)) { stopControl(owner); return; }
        } else { stopControl(owner); return; }
      } finally { event.release(); }
    }
  }

  function newRecord(owner, model, socket) {
    const record = { owner, model, socket, socketClosed: observeClose(socket), observedCloseCode: 1006,
      ws: null, proxy: null, fixtureSocket: null, proxyClosedPromise: null, fixtureClosedPromise: null,
      trustedOwner: null, trustedStart: null, trustedClose: null, trustedClosed: null, normalCloseWrite: null, proxyMode: undefined,
      workers: new Set(), changed: new Changed(), upgradeWriter: writerState(), proxyWriter: writerState(), fixtureWriter: writerState(),
      stopping: false, closed: false, cleanupFailed: false, cleanupTask: null, retained: false, id: null,
      pendingIngressBytes: 0, clientEof: null, gatewayEof: null,
      fixture: { proxyReadPaused: trusted ? false : pausedScenario(owner.scenario), uploadBytesRead: 0, uploadPrefixSeen: false,
        uploadEof: false, uploadVerified: false, uploadSha256: null, responseBytesWritten: 0,
        responsePrefixWritten: false, responseTailReleased: owner.scenario !== 'gated', responseEof: false, responseSha256: null },
      io: { wsWriteEntries: 0, wsWriteCompletions: 0, backpressureCount: 0, resumedPendingCount: 0,
        retainedBytesAtAbort: 0, retainedFramesAtAbort: 0, retainedStreamLeasesAtAbort: 0 } };
    guardApplicationSocket(record, socket);
    return record;
  }
  async function connectProxy(record) {
    live(record);
    if (trusted) {
      const grant = enrollmentPublicSnapshot(Object.fromEntries(grantFields.map(name => [name, record.owner.grant[name]])));
      const context = Object.freeze({ proxyMode: record.proxyMode, negotiatedCapabilities: Object.freeze([...record.owner.capabilities]), grant,
        admissionAllowed: () => { try { live(record); return true; } catch { return false; } } });
      const owner = trustedProxyFactory(context);
      if (owner instanceof Promise) { owner.catch(() => {}); fail('trusted_proxy_invalid'); }
      record.trustedOwner = owner;
      const descriptor = name => Object.getOwnPropertyDescriptor(owner ?? {}, name);
      const transport = descriptor('transport')?.value;
      if (transport instanceof Duplex) {
        record.proxy = transport; record.proxyClosedPromise = observeClose(transport);
        transport.on('error', () => {}); guardApplicationSocket(record, transport);
      }
      if (!owner || Object.keys(owner).length !== 4 || !['transport', 'start', 'close', 'closed'].every(name => Object.hasOwn(descriptor(name) ?? {}, 'value')) ||
          !record.proxy || typeof owner.start !== 'function' || typeof owner.close !== 'function' || !(owner.closed instanceof Promise)) fail('trusted_proxy_invalid');
      const start = owner.start.bind(owner);
      record.trustedOwner = Object.freeze({ close: owner.close.bind(owner) });
      record.trustedClosed = owner.closed; record.trustedClosed.catch(() => {});
      record.trustedStart = Promise.resolve().then(() => {
        live(record);
        const starting = start();
        if (!(starting instanceof Promise)) fail('trusted_proxy_invalid');
        return starting;
      });
      record.trustedStart.catch(() => {});
      await bounded(record.trustedStart, 5000, 'proxy_unavailable');
      live(record);
      return;
    }
    const socket = new net.Socket({ allowHalfOpen: true, readableHighWaterMark: 4096, writableHighWaterMark: 4096 });
    socket.on('error', () => {});
    record.proxy = socket; record.proxyClosedPromise = observeClose(socket);
    guardApplicationSocket(record, socket);
    const pairing = new Promise((done, reject) => {
      const takeFixture = fixture => {
        // Transfer ownership and install close observation synchronously at admission.
        record.fixtureSocket = fixture;
        record.fixtureClosedPromise = observeClose(fixture);
        guardApplicationSocket(record, fixture);
        if (record.stopping || record.owner.stopping) fixture.destroy();
        done(fixture);
      };
      const bad = () => {
        const port = socket.localPort;
        if (awaiting.get(port) === takeFixture) awaiting.delete(port);
        const earlier = accepted.get(port);
        if (earlier) { accepted.delete(port); clearTimeout(earlier.timer); earlier.socket.destroy(); }
        reject(safeError('proxy_unavailable'));
      };
      socket.once('error', bad); socket.once('close', bad);
      socket.connect(proxy.address().port, '127.0.0.1', () => {
        const earlier = accepted.get(socket.localPort);
        if (earlier) {
          accepted.delete(socket.localPort); clearTimeout(earlier.timer); takeFixture(earlier.socket);
        } else if (record.stopping || record.owner.stopping) bad();
        else awaiting.set(socket.localPort, takeFixture);
      });
    });
    await bounded(pairing, 5000, 'proxy_unavailable');
    if (record.stopping || record.owner.stopping) {
      record.fixtureSocket?.destroy();
      if (record.fixtureClosedPromise) await record.fixtureClosedPromise;
      fail('stream_inactive');
    }
    live(record);
    task(record, () => fixedFixture(record), () => stopStream(record));
  }
  async function wsWrite(record, kind, bytes) {
    live(record); record.io.wsWriteEntries++;
    await record.ws.send(kind, bytes);
    record.io.wsWriteCompletions++;
  }
  function writeNormalClose(record) {
    // Server-initiated and peer-initiated paths share the same actual receipt.
    record.normalCloseWrite ??= wsWrite(record, 'close', Buffer.from([3, 232]));
    return record.normalCloseWrite;
  }
  function effects(record, result) {
    for (const effect of result.effects) {
      if (record.stopping) return;
      if (effect.direction === 'client' && record.clientEof === null) {
        record.clientEof = task(record, () => { live(record); return endWrite(record.proxy, record.proxyWriter); }, () => stopStream(record));
      } else if (effect.direction === 'gateway' && record.gatewayEof === null) {
        record.gatewayEof = task(record, () => wsWrite(record, 'text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: record.id })),
          () => stopStream(record));
      }
    }
    record.changed.notify();
  }
  async function offer(record, direction, bytes) {
    let waited = false;
    while (true) {
      live(record);
      const version = record.changed.revision;
      const result = record.model.binary(direction, bytes, clock());
      if (result.code === 'ok') {
        if (waited) record.io.resumedPendingCount++;
        if (direction === 'client') record.pendingIngressBytes = 0;
        record.changed.notify(); return;
      }
      if (result.code !== 'backpressure') fail('model_operation_failed');
      if (!waited) record.io.backpressureCount++;
      waited = true;
      if (direction === 'client') record.pendingIngressBytes = bytes.length;
      await record.changed.wait(version, () => record.stopping || record.owner.stopping);
    }
  }
  async function queueWriter(record, direction) {
    while (true) {
      live(record);
      const version = record.changed.revision;
      const peek = check(record.model.peek(direction, 4096, clock()));
      const bytes = peek.bytes;
      if (bytes.length > 0) {
        if (direction === 'client') await write(record.proxy, bytes, record.proxyWriter);
        else await wsWrite(record, 'binary', bytes);
        live(record);
        effects(record, check(record.model.drain(direction, bytes.length, clock())));
      } else {
        const state = record.model.snapshot()[direction];
        if (state.eofEmitted) {
          const eof = direction === 'client' ? record.clientEof : record.gatewayEof;
          if (eof) await eof;
          return;
        }
        await record.changed.wait(version, () => record.stopping || record.owner.stopping);
      }
    }
  }
  async function proxyReader(record) {
    while (true) {
      live(record);
      const bytes = await pull(record.proxy, 4096);
      live(record);
      if (bytes === null) {
        effects(record, check(record.model.text('gateway', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: record.id }), clock())));
        return;
      }
      await offer(record, 'gateway', bytes);
    }
  }
  async function streamReader(record) {
    let opened = false;
    while (!record.stopping) {
      const event = await record.ws.next();
      try {
        live(record);
        if (event.kind === 'ping') { await wsWrite(record, 'pong', event.copyBytes()); continue; }
        if (event.kind === 'pong') continue;
        if (event.kind === 'close') {
          const state = record.model.snapshot();
          const valid = event.closeCode === 1000 && state.phase === 'closing' && record.clientEof && record.gatewayEof;
          if (!valid) { stopStream(record); return; }
          await Promise.all([record.clientEof, record.gatewayEof]);
          if (trusted) await writeNormalClose(record);
          else await wsWrite(record, 'close', Buffer.from([3, 232]));
          record.observedCloseCode = 1000;
          // Return first: the separate cleanup owner joins this reader without self-await.
          queueMicrotask(() => { stopStream(record, true); });
          return;
        }
        if (event.kind === 'binary') {
          await offer(record, 'client', event.copyBytes());
        } else if (event.kind === 'text') {
          const bytes = event.copyBytes();
          const result = check(record.model.text('client', bytes, clock()));
          if (streamInactive(record.model)) { stopStream(record); return; }
          if (!opened) {
            const message = decodeStream(bytes).toWire();
            record.id = message.streamId; record.proxyMode = message.proxyMode;
            await connectProxy(record);
            const ready = encodeStream({ protocolVersion: 1, type: 'ready', streamId: record.id });
            check(record.model.text('gateway', ready, clock()));
            await wsWrite(record, 'text', ready); opened = true;
            const clientWriter = task(record, () => queueWriter(record, 'client'), () => stopStream(record));
            const gatewayWriter = task(record, () => queueWriter(record, 'gateway'), () => stopStream(record));
            task(record, () => proxyReader(record), () => stopStream(record));
            if (trusted) task(record, async () => {
              await Promise.all([clientWriter, gatewayWriter]); live(record);
              if (record.model.snapshot().phase !== 'closing' || !record.clientEof || !record.gatewayEof) fail('invalid_close_state');
              await Promise.all([record.clientEof, record.gatewayEof]); live(record);
              await writeNormalClose(record);
              // Only streamReader's actual valid peer Close may confirm closure.
            }, () => stopStream(record));
          }
          effects(record, result);
        }
      } finally { event.release(); }
    }
  }

  async function fixedFixture(record) {
    const socket = record.fixtureSocket, f = record.fixture;
    while (f.proxyReadPaused) {
      const version = record.changed.revision;
      live(record); await record.changed.wait(version, () => record.stopping || record.owner.stopping);
    }
    live(record);
    const head = await headers(socket);
    if (!head.equals(requestHeader(record.owner.scenario))) fail('fixture_request_mismatch');
    const uploadHash = digest().update(head);
    f.uploadBytesRead += head.length;
    let offset = 0;
    while (offset < uploadLength(record.owner.scenario)) {
      live(record);
      const bytes = await pull(socket, Math.min(4096, uploadLength(record.owner.scenario) - offset));
      if (bytes === null || !bytes.equals(pattern(offset, bytes.length))) fail('fixture_upload_mismatch');
      uploadHash.update(bytes); offset += bytes.length; f.uploadBytesRead += bytes.length;
      if (offset >= 4096 && !f.uploadPrefixSeen) {
        f.uploadPrefixSeen = true;
        if (record.owner.scenario === 'premature') { stopStream(record); return; }
      }
    }
    if (await pull(socket, 1) !== null) fail('fixture_extra_bytes');
    f.uploadEof = true; f.uploadVerified = true; f.uploadSha256 = uploadHash.digest('hex');
    const responseHash = digest();
    const send = async bytes => { live(record); await write(socket, bytes, record.fixtureWriter); responseHash.update(bytes); f.responseBytesWritten += bytes.length; };
    await send(RESPONSE_HEADER);
    await send(pattern(0, 4096, true));
    f.responsePrefixWritten = true;
    while (!f.responseTailReleased) {
      const version = record.changed.revision;
      live(record); await record.changed.wait(version, () => record.stopping || record.owner.stopping);
    }
    for (let offset = 4096; offset < RESPONSE_BODY_LENGTH; offset += 4096) await send(pattern(offset, Math.min(4096, RESPONSE_BODY_LENGTH - offset), true));
    await endWrite(socket, record.fixtureWriter);
    f.responseEof = true; f.responseSha256 = responseHash.digest('hex');
  }

  function probe(owner) {
    const r = owner.latest;
    const control = owner.model.snapshot(), stream = r?.model.snapshot() ?? null;
    const callbacks = (owner.ws?.snapshot().pendingWriteCallbacks ?? 0) + owner.upgradeWriter.pending +
      [...owner.records].reduce((sum, record) => sum + record.proxyWriter.pending + record.fixtureWriter.pending +
        record.upgradeWriter.pending + (record.ws?.snapshot().pendingWriteCallbacks ?? 0), 0);
    const cleanup = { controlClosed: closedObserved(owner.socket), streamClosed: !r || closedObserved(r.socket),
      proxyClosed: !r?.proxy || closedObserved(r.proxy), fixtureClosed: !r?.fixtureSocket || closedObserved(r.fixtureSocket),
      workers: owner.workers.size + [...owner.records].reduce((sum, record) => sum + record.workers.size, 0),
      timers: owner.timers.size + (owner.notificationTimer ? 1 : 0), pendingCallbacks: callbacks, complete: false };
    cleanup.complete = owner.closed && [...owner.records].every(record => record.closed) &&
      cleanup.controlClosed && cleanup.streamClosed && cleanup.proxyClosed && cleanup.fixtureClosed &&
      cleanup.workers === 0 && cleanup.timers === 0 && callbacks === 0 && !control.sessionLease && control.chargedBytes === 0 && control.streamLeases === 0;
    return { revision: 1, scenario: owner.scenario, streamOrdinal: owner.ordinal,
      timing: { ...owner.timing },
      control: { phase: control.phase, cause: control.cause, sessionLease: control.sessionLease, webSocketClosed: control.webSocketClosed,
        resourcesReleased: control.resourcesReleased, historyCount: control.historyCount, streamLeases: control.streamLeases, chargedBytes: control.chargedBytes },
      stream: stream ? { phase: stream.phase, cause: stream.cause, streamLease: stream.streamLease, webSocketClosed: stream.webSocketClosed,
        resourcesReleased: stream.resourcesReleased, chargedFrames: stream.chargedFrames, client: { ...stream.client }, gateway: { ...stream.gateway } } : null,
      pool: pool.snapshot(),
      fixture: r ? { ...r.fixture } : { proxyReadPaused: trusted ? false : pausedScenario(owner.scenario), uploadBytesRead: 0, uploadPrefixSeen: false,
        uploadEof: false, uploadVerified: false, uploadSha256: null, responseBytesWritten: 0, responsePrefixWritten: false,
        responseTailReleased: owner.scenario !== 'gated', responseEof: false, responseSha256: null },
      io: { proxyWriteEntries: r?.proxyWriter.entries ?? 0, proxyWriteCompletions: r?.proxyWriter.completions ?? 0,
        proxyWritePending: (r?.proxyWriter.pending ?? 0) > 0, wsWriteEntries: r?.io.wsWriteEntries ?? 0,
        wsWriteCompletions: r?.io.wsWriteCompletions ?? 0, wsWritePending: (r?.ws?.snapshot().pendingWriteCallbacks ?? 0) > 0,
        pendingIngressBytes: r?.pendingIngressBytes ?? 0, backpressureCount: r?.io.backpressureCount ?? 0,
        resumedPendingCount: r?.io.resumedPendingCount ?? 0, retainedBytesAtAbort: r?.io.retainedBytesAtAbort ?? 0,
        retainedFramesAtAbort: r?.io.retainedFramesAtAbort ?? 0, retainedStreamLeasesAtAbort: r?.io.retainedStreamLeasesAtAbort ?? 0 }, cleanup };
  }

  try {
    await bounded(new Promise((done, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', done); }), 5000, 'stream_fixture_startup_failed');
  } catch {
    closing = true;
    for (const entry of accepted.values()) clearTimeout(entry.timer);
    accepted.clear(); awaiting.clear();
    const closes = [...sockets, ...proxySockets].map(socket => { const closed = observeClose(socket); socket.destroy(); return closed; });
    await Promise.allSettled([...closes, ...(proxy ? [new Promise(done => proxy.close(done))] : []),
      new Promise(done => server.close(done))]);
    fail('stream_fixture_startup_failed');
  }
  return {
    port: server.address().port,
    invalidateEnrollment(enrollmentId, cause = 'device_revoked') {
      if (!enrolled || cause !== 'device_revoked') fail('invalid_invalidation');
      for (const owner of owners.values()) if (owner.grant.enrollmentId === enrollmentId) invalidate(owner, cause, true);
    },
    inspectEnrollment(enrollmentId) {
      const history = enrollmentRecords.get(enrollmentId), owner = history?.original;
      return structuredClone({ revision: 1, found: Boolean(owner), available: !unavailable && !closing,
        credentialExpiresUtcMillis: owner?.credentialExpires ?? null, gatewayExpiresUtcMillis: gatewayExpires,
        sessionPolicyMillis: sessionLifetimeMillis, grantValid: owner?.grantValid ?? false,
        invalidationCause: owner?.invalidationCause ?? null, revalidations: owner?.revalidations ?? 0,
        controlsAdmitted: history?.controlsAdmitted ?? 0, applicationWriteAdmissions: owner?.applicationWriteAdmissions ?? 0,
        writesAfterInvalidation: owner?.writesAfterInvalidation ?? 0,
        terminalNotification: owner ? { ...owner.terminalNotification } : { attempted: false, completed: false, aborted: false },
        probe: owner ? probe(owner) : null });
    },
    snapshot: () => ({ ...pool.snapshot(), ownerRecords: owners.size, authenticatedSockets: sockets.size, proxySockets: proxySockets.size,
      listeners: (httpsListenerClosed ? 0 : 1) + (proxyListenerClosed ? 0 : 1),
      ...(enrolled ? {
        workers: ingressTasks.size + [...owners.values()].reduce((sum, owner) => sum + owner.workers.size + [...owner.records].reduce((n, record) => n + record.workers.size, 0), 0),
        timers: [...owners.values()].reduce((sum, owner) => sum + owner.timers.size + (owner.notificationTimer ? 1 : 0), 0) + accepted.size,
        pendingCallbacks: [...owners.values()].reduce((sum, owner) => sum + probe(owner).cleanup.pendingCallbacks, 0),
        unavailable,
      } : {}) }),
    close() {
      if (closeTask) return closeTask;
      closing = true;
      closeTask = bounded((async () => {
        const ownerStops = [...owners.values()].map(owner => {
          if (!controlInactive(owner.model)) owner.model.localCancel(clock());
          return stopControl(owner);
        });
        for (const entry of accepted.values()) clearTimeout(entry.timer);
        accepted.clear(); awaiting.clear();
        const socketCloses = [...sockets, ...proxySockets].map(socket => { const closed = observeClose(socket); socket.destroy(); return closed; });
        // Start every independent teardown group even if an owner's join rejects. A failed
        // join remains a failure; it never skips listener/socket cleanup or releases models.
        const listenerCloses = [server, proxy].filter(Boolean).map(listener => new Promise((done, reject) => {
          listener.close(failure => failure ? reject(safeError('listener_cleanup_failed')) : done());
        }));
        const results = await Promise.allSettled([...ownerStops, ...socketCloses, ...listenerCloses, ...ingressTasks]);
        await Promise.allSettled([...ingressTasks]);
        if (results.some(result => result.status === 'rejected') || ingressTasks.size || sockets.size || proxySockets.size ||
            Object.values(pool.snapshot()).some(value => value !== 0)) fail('cleanup_incomplete');
        owners.clear();
      })(), 7000);
      return closeTask;
    },
  };
}

class CompanionStreamPeer {
  #base;
  #stream;
  constructor(base, stream) {
    this.#base = base; this.#stream = stream;
    this.metadata = Object.freeze({ ...base.metadata, webSocketPort: stream.port });
    Object.freeze(this);
  }
  get directory() { return this.#base.directory; } // Explicit host-test-only fixture access.
  get command() { return this.#base.command; }
  get validity() { return this.#base.validity; }
  snapshot() { return this.#stream.snapshot(); }
  close() { return this.#base.close(); }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return `CompanionStreamPeer ${JSON.stringify(this.snapshot())}`; }
}

export async function startCompanionStreamPeer({ openssl = process.env.OPENSSL_BIN ?? 'openssl' } = {}) {
  let stream;
  const base = await startPeer({ openssl, authenticatedServerFactory: async context => { stream = await createCompanionStreamServer(context); return stream; } });
  return new CompanionStreamPeer(base, stream);
}
