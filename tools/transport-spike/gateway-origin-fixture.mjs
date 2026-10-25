// Explicit local research process. Public CSR/record material is delivered only
// through private stdin/stdout; this is not an enrollment or management route.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { createDesktopOriginBackend, createDesktopOriginAuthorities, C3_CAPABILITIES, C3_DESKTOP_COMMIT, C3_LOGICAL_HOST } from './gateway-origin-desktop.mjs';
import { startEnrollmentOriginFixture } from './companion-enrollment-origin.mjs';
import { enrollOriginCsr } from './companion-enrollment-origin-client.mjs';
import { captureFactoryPayload as payload } from './capture-factory-descriptor.mjs';
import { observeClose, bounded, safeError, write, endWrite, writerState } from './companion-stream-peer-io.mjs';
import { ResearchWebSocket } from './research-websocket.mjs';

const format = 'http-freekit-origin-gateway-fixture';
const requestBody = () => Buffer.from(Array.from({ length: payload.requestBodyBytes }, (_, i) => i % 251));
const responseBody = () => Buffer.from(Array.from({ length: payload.responseBodyBytes }, (_, i) => (i * 7) % 253));
const retainedFailures = new Set();
const failure = () => safeError('origin_fixture_failed');
export const c3Profiles = Object.freeze(['https-h1', 'http-upgrade', 'wss-h1']);
export const c3Upgrade = Object.freeze({ path: '/factory-upgrade', initialText: 'origin-ready', clientText: 'capture-upgrade-€', binaryBytes: 4097 });
const upgradeBinary = () => Buffer.from(Array.from({ length: c3Upgrade.binaryBytes }, (_, i) => (i * 29 + 3) & 255));
const unexpectedTransportHeader = request => Object.keys(request.headers).some(name => name.startsWith('x-freekit-') ||
  ['authorization', 'proxy-authorization', 'cookie'].includes(name));

export async function startOriginGatewayFixture({ desktopRoot, desktopCommit, openssl = process.env.OPENSSL_BIN ?? 'openssl', profile, family } = {}) {
  const c3 = profile !== undefined;
  if (retainedFailures.size || c3 && (!c3Profiles.includes(profile) || !['ipv4', 'ipv6'].includes(family) || desktopCommit !== C3_DESKTOP_COMMIT) ||
      !c3 && family !== undefined) throw failure();
  const originalAddress = c3 && family === 'ipv6' ? '::1' : '127.0.0.2';
  const originalPort = c3 && profile !== 'http-upgrade' ? 443 : 80;
  const logicalHost = c3 ? C3_LOGICAL_HOST : payload.logicalHost;
  const temporaryRoot = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(temporaryRoot, 'freekit-origin-gateway-'));
  fs.chmodSync(directory, 0o700);
  const sockets = new Set(), tasks = new Set(), timers = new Set(), webSockets = new Set(), writers = new Set();
  let backend, enrollment, server, closeTask, closing = false, listenerClosed = false, privateDirectoryRemoved = false, pendingCallbacks = 0, startupUnjoined = false;
  let authorities, materialTask;
  let reply = null, enrollmentId = null, releaseTask, releaseRequested = false, releasePending = false, releaseTimer = null, releaseWake = null;
  const origin = { connections: 0, requests: 0, requestBodyBytes: 0, requestBodySha256: null, requestVerified: false,
    responseBodyBytesWritten: 0, responseBodySha256: null, responsePrefixWritten: false, responseEof: false,
    tailReleased: false, clientEndWriteApplied: false, originalDestinationMatched: false, captureMatched: false };
  if (c3) Object.assign(origin, { tlsConnections: 0, tlsSniMatched: false, tlsAlpnH1: false, upgradeRequests: 0, upgradeAccepted: false,
    clientTextMessages: 0, clientBinaryMessages: 0, clientBinaryBytes: 0, clientBinarySha256: null,
    clientPings: 0, clientPongs: 0, clientCloseObserved: false, serverCloseWritten: false, failed: false });
  function own(operation, socket) {
    const task = Promise.resolve().then(operation).catch(() => { if (c3 && !closing) origin.failed = true; socket?.destroy(); }).finally(() => tasks.delete(task)); tasks.add(task); return task;
  }
  function responseIo(bytes, end = false) {
    if (closing || !reply || reply.destroyed) return Promise.reject(failure());
    const target = reply, socket = reply.socket;
    pendingCallbacks++;
    return new Promise((done, reject) => {
      let settled = false, returned = false, completed = false, needsDrain = false, drained = false;
      const clean = () => { socket.removeListener('close', closed); target.removeListener('drain', drain); };
      const finish = error => {
        if (settled) return;
        if (error || socket.destroyed) { settled = true; clean(); pendingCallbacks--; reject(failure()); }
        else if (returned && completed && (!needsDrain || drained)) {
          settled = true; clean(); pendingCallbacks--; if (!end) origin.responseBodyBytesWritten += bytes.length; done();
        }
      };
      const closed = () => finish(true), drain = () => { drained = true; finish(); };
      socket.once('close', closed); target.on('drain', drain);
      const callback = error => { completed = true; finish(error); };
      try { if (end) target.end(callback); else needsDrain = !target.write(bytes, callback); returned = true; finish(); }
      catch { finish(true); }
    });
  }
  async function request(request, response) {
    origin.requests++;
    if (c3 && (profile !== 'https-h1' || unexpectedTransportHeader(request)) || origin.requests !== 1 || request.httpVersion !== '1.1' || request.method !== payload.method || request.url !== payload.path ||
        ![logicalHost, ...(c3 ? [`${logicalHost}:${originalPort}`] : [])].includes(request.headers.host) || request.headers['content-length'] !== String(payload.requestBodyBytes) ||
        request.headers['transfer-encoding'] !== undefined || request.headers.connection?.toLowerCase() !== 'close') throw failure();
    const chunks = []; let count = 0;
    for await (const chunk of request) { count += chunk.length; if (count > payload.requestBodyBytes) throw failure(); chunks.push(chunk); }
    const bytes = Buffer.concat(chunks);
    origin.requestBodyBytes = count; origin.requestBodySha256 = createHash('sha256').update(bytes).digest('hex');
    if (count !== payload.requestBodyBytes || !bytes.equals(requestBody())) throw failure();
    origin.requestVerified = true; reply = response;
    response.sendDate = false;
    response.writeHead(200, { 'content-length': payload.responseBodyBytes, connection: 'close', 'content-type': 'application/octet-stream' });
    await responseIo(responseBody().subarray(0, 4096)); origin.responsePrefixWritten = true;
    if (c3) {
      const body = responseBody();
      for (let offset = 4096; offset < body.length; offset += 4096) await responseIo(body.subarray(offset, offset + 4096));
      await responseIo(null, true); origin.responseEof = true;
      origin.responseBodySha256 = createHash('sha256').update(body).digest('hex');
    }
  }
  async function upgrade(request, socket, head) {
    const key = request.headers['sec-websocket-key'];
    origin.upgradeRequests++;
    if (profile === 'https-h1' || unexpectedTransportHeader(request) || origin.upgradeRequests !== 1 || request.httpVersion !== '1.1' || request.method !== 'GET' || request.url !== c3Upgrade.path ||
        ![logicalHost, `${logicalHost}:${originalPort}`].includes(request.headers.host) || request.headers.upgrade?.toLowerCase() !== 'websocket' ||
        !request.headers.connection?.toLowerCase().split(',').map(value => value.trim()).includes('upgrade') ||
        request.headers['sec-websocket-version'] !== '13' || request.headers.origin !== undefined || request.headers['content-length'] !== undefined ||
        request.headers['transfer-encoding'] !== undefined || request.headers['sec-websocket-extensions'] !== undefined || request.headers['sec-websocket-protocol'] !== undefined ||
        typeof key !== 'string' || /^[A-Za-z0-9+/]{22}==$/.exec(key)?.[0] !== key || Buffer.from(key, 'base64').toString('base64') !== key ||
        !(head instanceof Uint8Array) || head.length > 65536) throw failure();
    origin.requestVerified = true;
    const state = writerState(); writers.add(state);
    const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    const first = Buffer.from(c3Upgrade.initialText), response = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
    // One real write deliberately coalesces the accepted HTTP101 and first frame.
    await write(socket, Buffer.concat([response, Buffer.from([0x81, first.length]), first]), state);
    origin.upgradeAccepted = true;
    const ws = new ResearchWebSocket(socket, { role: 'server', initialBytes: Buffer.from(head), maxBinaryBytes: 65536 });
    webSockets.add(ws);
    try {
      while (!closing && !socket.destroyed) {
        const event = await ws.next(); let finished = false;
        try {
          const bytes = event.copyBytes();
          if (event.kind === 'text') {
            if (++origin.clientTextMessages !== 1 || !bytes.equals(Buffer.from(c3Upgrade.clientText))) throw failure();
            await ws.send('text', bytes);
          } else if (event.kind === 'binary') {
            if (++origin.clientBinaryMessages !== 1 || !bytes.equals(upgradeBinary())) throw failure();
            origin.clientBinaryBytes = bytes.length; origin.clientBinarySha256 = createHash('sha256').update(bytes).digest('hex');
            await ws.send('binary', bytes);
          } else if (event.kind === 'ping') {
            if (++origin.clientPings !== 1 || bytes.length !== 0) throw failure();
            await ws.send('pong', bytes); await ws.send('ping', Buffer.from('probe'));
          } else if (event.kind === 'pong') {
            if (++origin.clientPongs !== 1 || !bytes.equals(Buffer.from('probe'))) throw failure();
          } else if (event.kind === 'close') {
            if (origin.clientTextMessages !== 1 || origin.clientBinaryMessages !== 1 || origin.clientPings !== 1 || origin.clientPongs !== 1 ||
                event.closeCode !== 1000 || !bytes.equals(Buffer.from([3, 232]))) throw failure();
            origin.clientCloseObserved = true;
            await ws.send('close', Buffer.from([3, 232])); origin.serverCloseWritten = true; finished = true;
          } else throw failure();
        } finally { event.release(); }
        if (finished) {
          await endWrite(socket, state); await observeClose(socket); await ws.finish(); return;
        }
      }
      if (!closing) throw failure();
    } finally {
      if (!ws.snapshot().transportClosed) await ws.cancel();
      webSockets.delete(ws);
    }
  }
  const snapshot = () => {
    const original = enrollment && enrollmentId !== null ? enrollment.inspectEnrollment(enrollmentId).probe?.stream : null;
    return Object.freeze({ ...(c3 ? { profile, family } : {}), admissionClosed: closing, listenerClosed, privateDirectoryRemoved,
    gatewayStreamComplete: original?.phase === 'complete' && original.resourcesReleased === true && original.streamLease === false,
    activeSockets: sockets.size, pendingCallbacks: pendingCallbacks + [...webSockets].reduce((count, ws) => count + ws.snapshot().pendingWriteCallbacks, 0) +
      [...writers].reduce((count, state) => count + state.pending, 0),
    pendingTimers: timers.size + (releaseTimer === null ? 0 : 1), workers: tasks.size + (releasePending ? 1 : 0),
    origin: Object.freeze({ ...origin, tailReleaseRequested: releaseRequested }),
    backend: backend?.snapshot() ?? null, enrollment: enrollment?.snapshot() ?? null });
  };
  async function close() {
    if (closeTask) return closeTask;
    closing = true;
    releaseWake?.();
    const socketJoins = [...sockets].map(socket => { const closed = observeClose(socket); socket.destroy(); return closed; });
    for (const timer of timers) clearTimeout(timer); timers.clear();
    const listenerJoin = server?.listening ? new Promise((done, reject) => server.close(error => error ? reject(failure()) : done())) : Promise.resolve();
    closeTask = bounded((async () => {
      const results = await Promise.allSettled([listenerJoin, ...socketJoins, ...[...webSockets].map(ws => ws.cancel()),
        ...[...writers].map(state => state.idle), enrollment?.close(), backend?.close(), ...tasks, ...(materialTask ? [Promise.allSettled([materialTask])] : []),
        ...(releaseTask ? [Promise.allSettled([releaseTask])] : [])]);
      if (results.some(result => result.status === 'rejected') || sockets.size || tasks.size || timers.size || pendingCallbacks || releasePending || releaseTimer !== null ||
          webSockets.size || [...writers].some(state => state.pending) || startupUnjoined ||
          (enrollment && (!enrollment.snapshot().storeClosed || !enrollment.snapshot().issuerChildrenJoined))) throw failure();
      if (!directory.startsWith(temporaryRoot + path.sep) || !path.basename(directory).startsWith('freekit-origin-gateway-')) throw failure();
      fs.rmSync(directory, { recursive: true }); privateDirectoryRemoved = !fs.existsSync(directory);
      if (!privateDirectoryRemoved) throw failure();
      return snapshot();
    })(), 15000);
    closeTask.catch(() => retainedFailures.add({ enrollment, backend, server })); return closeTask;
  }
  try {
    if (c3) {
      materialTask = createDesktopOriginAuthorities({ desktopRoot, desktopCommit, directory });
      authorities = await materialTask;
    }
    backend = await createDesktopOriginBackend({ desktopRoot, desktopCommit,
      ...(c3 ? { httpsMaterial: authorities } : {}),
      authorizeDestination: endpoint => {
        const allowed = endpoint.address === originalAddress && endpoint.port === originalPort && endpoint.protocol === (originalPort === 443 ? 'https:' : 'http:');
        if (allowed) origin.originalDestinationMatched = true; return allowed;
      }, onCapture: capture => {
        if (capture.protocol === 'ws-frame') return; // Frame rows reference the captured Upgrade parent, not another HTTP request.
        if (!c3) { if (capture.url === `http://${payload.logicalHost}${payload.path}`) origin.captureMatched = true; }
        else {
          const url = new URL(capture.url), protocols = profile === 'https-h1' ? ['https:'] : profile === 'wss-h1' ? ['https:', 'wss:'] : ['http:', 'ws:'];
          if (protocols.includes(url.protocol) && url.hostname === logicalHost && (Number(url.port) || (originalPort === 443 ? 443 : 80)) === originalPort &&
              url.pathname === (profile === 'https-h1' ? payload.path : c3Upgrade.path)) origin.captureMatched = true;
        }
      } });
    const receive = (req, res) => { if (closing) req.socket.destroy(); else own(() => request(req, res), req.socket); };
    server = originalPort === 443 ? https.createServer({ ...authorities.originTlsOptions(), maxHeaderSize: 4096 }, receive) : http.createServer({ maxHeaderSize: 4096 }, receive);
    server.maxConnections = 4; server.maxHeadersCount = 16; server.maxRequestsPerSocket = 1;
    server.once('close', () => { listenerClosed = true; }); server.on('clientError', (_error, socket) => { if (c3 && !closing) origin.failed = true; socket.destroy(); });
    const ownSocket = socket => {
      if (sockets.has(socket)) return;
      observeClose(socket); sockets.add(socket); socket.on('error', () => {});
      const timer = setTimeout(() => { timers.delete(timer); if (c3 && !closing && !socket.destroyed) origin.failed = true; socket.destroy(); }, 15000); timers.add(timer);
      socket.once('close', () => { sockets.delete(socket); clearTimeout(timer); timers.delete(timer); });
      if (closing) socket.destroy();
    };
    server.on('connection', socket => { origin.connections++; ownSocket(socket); });
    if (c3) {
      server.on('secureConnection', socket => {
        ownSocket(socket); origin.tlsConnections++;
        origin.tlsSniMatched = origin.tlsConnections === 1 ? socket.servername === logicalHost : origin.tlsSniMatched && socket.servername === logicalHost;
        origin.tlsAlpnH1 = origin.tlsConnections === 1 ? socket.alpnProtocol === 'http/1.1' : origin.tlsAlpnH1 && socket.alpnProtocol === 'http/1.1';
      });
      server.on('tlsClientError', () => {});
      server.on('upgrade', (req, socket, head) => { ownSocket(socket); if (closing) socket.destroy(); else own(() => upgrade(req, socket, head), socket); });
    }
    await bounded(new Promise((done, reject) => { server.once('error', reject); server.listen(originalPort, originalAddress, done); }), 5000);
    const enrollmentDirectory = c3 ? path.join(directory, 'enrollment') : directory;
    if (c3) fs.mkdirSync(enrollmentDirectory, { mode: 0o700 });
    enrollment = await startEnrollmentOriginFixture({ directory: enrollmentDirectory, mode: 'create', openssl, trustedProxyFactory: backend.factory,
      ...(c3 ? { interceptionCaCertificateDer: authorities.interceptionCaCertificateDer(), supportedCapabilities: C3_CAPABILITIES } : {}) });
  } catch (error) {
    startupUnjoined = error?.joined === false;
    try { await close(); } catch { retainedFailures.add({ enrollment, backend, server }); }
    throw failure();
  }
  return Object.freeze({
    metadata: () => enrollment.metadata(), createInvitation: () => enrollment.createInvitation(),
    waitForRegistered: (id, options) => enrollment.waitForRegistered(id, options),
    approve(id) { enrollmentId = id; return enrollment.approve(id); },
    readResult: id => enrollment.readResult(id),
    async enroll(csr) {
      if (enrollmentId !== null) throw failure();
      const approved = await enrollOriginCsr(enrollment, csr, c3 ? C3_CAPABILITIES : undefined); enrollmentId = approved.material().enrollmentId; return approved;
    },
    releaseTail() {
      if (c3 || releaseRequested || closing || enrollmentId === null) return Promise.reject(failure());
      releaseRequested = true; releasePending = true;
      releaseTask = (async () => {
        const deadline = performance.now() + 5000;
        while (true) {
          const state = enrollment.inspectEnrollment(enrollmentId).probe;
          if (closing || !state || ['failed', 'closed'].includes(state.control.phase)) throw failure();
          if (origin.requestVerified && origin.responsePrefixWritten && state.stream?.client.eofEmitted === true &&
              state.io.proxyWritePending === false && state.io.pendingIngressBytes === 0 && backend.snapshot().clientEndWrites === 1) break;
          if (performance.now() >= deadline) throw failure();
          await new Promise(done => {
            releaseWake = () => { clearTimeout(releaseTimer); releaseTimer = null; releaseWake = null; done(); };
            releaseTimer = setTimeout(() => releaseWake?.(), 20);
          });
        }
        origin.clientEndWriteApplied = true; origin.tailReleased = true;
        const body = responseBody();
        for (let offset = 4096; offset < body.length; offset += 4096) await responseIo(body.subarray(offset, offset + 4096));
        await responseIo(null, true); origin.responseEof = true;
        origin.responseBodySha256 = createHash('sha256').update(body).digest('hex');
        return snapshot();
      })().finally(() => { releasePending = false; });
      releaseTask.catch(() => {}); return releaseTask;
    },
    inspect: () => enrollmentId === null ? null : enrollment.inspectEnrollment(enrollmentId), snapshot, close,
    ...(c3 ? { interceptionCaCertificateDer: () => authorities.interceptionCaCertificateDer() } : {}),
    inspectEnrollment: id => enrollment.inspectEnrollment(id),
    toJSON: snapshot, [inspect.custom]: () => '[Origin gateway research fixture]',
  });
}

async function main() {
  let owner, terminal = false, count = 0, inputBytes = 0, buffer = Buffer.alloc(0), chain = Promise.resolve(), timer;
  const emit = value => {
    const bytes = Buffer.from(JSON.stringify({ format, revision: 1, ...value }) + '\n');
    if (bytes.length > 16384) throw failure(); process.stdout.write(bytes);
  };
  async function stop(failed = false) {
    if (terminal) return; terminal = true; clearTimeout(timer); process.stdin.pause();
    try { const snapshot = await owner?.close(); emit({ event: failed ? 'failed' : 'closed', ...(snapshot ? { snapshot } : {}) }); }
    catch { emit({ event: 'failed' }); failed = true; }
    if (failed) process.exitCode = 1;
  }
  try {
    const c3 = process.argv.length === 10;
    if (!c3 && process.argv.length !== 6 || process.argv[2] !== '--desktop-root' || process.argv[4] !== '--desktop-commit' ||
        c3 && (process.argv[6] !== '--profile' || process.argv[8] !== '--family')) throw failure();
    const profile = c3 ? process.argv[7] : undefined, family = c3 ? process.argv[9] : undefined;
    owner = await startOriginGatewayFixture({ desktopRoot: process.argv[3], desktopCommit: process.argv[5], ...(c3 ? { profile, family } : {}) });
    const c3Public = c3 ? { profile, family, interceptionCaCertificateDer: owner.interceptionCaCertificateDer().toString('base64url') } : {};
    emit({ event: 'ready', metadata: owner.metadata().material(), desktopCommit: process.argv[5], ...c3Public });
    timer = setTimeout(() => { void stop(true); }, 90000);
    process.stdin.on('data', chunk => {
      if (terminal) return;
      inputBytes += chunk.length;
      if (inputBytes > 32768 || buffer.length + chunk.length > 16384) { void stop(true); return; }
      buffer = Buffer.concat([buffer, chunk]);
      let index;
      while ((index = buffer.indexOf(10)) >= 0) {
        const bytes = buffer.subarray(0, index); buffer = buffer.subarray(index + 1);
        chain = chain.then(async () => {
          if (terminal || ++count > 8 || bytes.length > 8192 || bytes.some(value => value < 32 || value > 126)) throw failure();
          const text = bytes.toString('ascii'), message = JSON.parse(text);
          if (JSON.stringify(message) !== text || !message || Array.isArray(message)) throw failure();
          if (message.op === 'enroll' && Object.keys(message).join(',') === 'op,csrDer' && typeof message.csrDer === 'string' &&
              /^[A-Za-z0-9_-]+$/.test(message.csrDer) && message.csrDer.length <= 5462) {
            const csr = Buffer.from(message.csrDer, 'base64url'); if (csr.toString('base64url') !== message.csrDer) throw failure();
            emit({ event: 'enrolled', approved: (await owner.enroll(csr)).material(), metadata: owner.metadata().material(), ...c3Public });
          } else if (Object.keys(message).join(',') === 'op' && message.op === 'release') { await owner.releaseTail(); emit({ event: 'released' }); }
          else if (Object.keys(message).join(',') === 'op' && message.op === 'snapshot') emit({ event: 'snapshot', snapshot: owner.snapshot() });
          else if (Object.keys(message).join(',') === 'op' && message.op === 'stop') await stop();
          else throw failure();
        }).catch(() => stop(true));
      }
      if (buffer.length > 8192) void stop(true);
    });
    process.stdin.once('end', () => { chain = chain.then(() => stop(buffer.length > 0)); });
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void stop(true); });
  } catch { await stop(true); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
