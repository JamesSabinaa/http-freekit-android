// Explicit local research process. Public CSR/record material is delivered only
// through private stdin/stdout; this is not an enrollment or management route.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { createDesktopOriginBackend } from './gateway-origin-desktop.mjs';
import { startEnrollmentOriginFixture } from './companion-enrollment-origin.mjs';
import { enrollOriginCsr } from './companion-enrollment-origin-client.mjs';
import { captureFactoryPayload as payload } from './capture-factory-descriptor.mjs';
import { observeClose, bounded, safeError } from './companion-stream-peer-io.mjs';

const format = 'http-freekit-origin-gateway-fixture';
const requestBody = () => Buffer.from(Array.from({ length: payload.requestBodyBytes }, (_, i) => i % 251));
const responseBody = () => Buffer.from(Array.from({ length: payload.responseBodyBytes }, (_, i) => (i * 7) % 253));
const retainedFailures = new Set();
const failure = () => safeError('origin_fixture_failed');

export async function startOriginGatewayFixture({ desktopRoot, desktopCommit, openssl = process.env.OPENSSL_BIN ?? 'openssl' } = {}) {
  if (retainedFailures.size) throw failure();
  const temporaryRoot = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(temporaryRoot, 'freekit-origin-gateway-'));
  fs.chmodSync(directory, 0o700);
  const sockets = new Set(), tasks = new Set(), timers = new Set();
  let backend, enrollment, server, closeTask, closing = false, listenerClosed = false, privateDirectoryRemoved = false, pendingCallbacks = 0, startupUnjoined = false;
  let reply = null, enrollmentId = null, releaseTask, releaseRequested = false, releasePending = false, releaseTimer = null, releaseWake = null;
  const origin = { connections: 0, requests: 0, requestBodyBytes: 0, requestBodySha256: null, requestVerified: false,
    responseBodyBytesWritten: 0, responseBodySha256: null, responsePrefixWritten: false, responseEof: false,
    tailReleased: false, clientEndWriteApplied: false, originalDestinationMatched: false, captureMatched: false };
  function own(operation, socket) {
    const task = Promise.resolve().then(operation).catch(() => socket?.destroy()).finally(() => tasks.delete(task)); tasks.add(task); return task;
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
    if (origin.requests !== 1 || request.httpVersion !== '1.1' || request.method !== payload.method || request.url !== payload.path ||
        request.headers.host !== payload.logicalHost || request.headers['content-length'] !== String(payload.requestBodyBytes) ||
        request.headers['transfer-encoding'] !== undefined || request.headers.connection?.toLowerCase() !== 'close') { request.socket.destroy(); return; }
    const chunks = []; let count = 0;
    for await (const chunk of request) { count += chunk.length; if (count > payload.requestBodyBytes) throw failure(); chunks.push(chunk); }
    const bytes = Buffer.concat(chunks);
    origin.requestBodyBytes = count; origin.requestBodySha256 = createHash('sha256').update(bytes).digest('hex');
    if (count !== payload.requestBodyBytes || !bytes.equals(requestBody())) throw failure();
    origin.requestVerified = true; reply = response;
    response.sendDate = false;
    response.writeHead(200, { 'content-length': payload.responseBodyBytes, connection: 'close', 'content-type': 'application/octet-stream' });
    await responseIo(responseBody().subarray(0, 4096)); origin.responsePrefixWritten = true;
  }
  const snapshot = () => {
    const original = enrollment && enrollmentId !== null ? enrollment.inspectEnrollment(enrollmentId).probe?.stream : null;
    return Object.freeze({ admissionClosed: closing, listenerClosed, privateDirectoryRemoved,
    gatewayStreamComplete: original?.phase === 'complete' && original.resourcesReleased === true && original.streamLease === false,
    activeSockets: sockets.size, pendingCallbacks, pendingTimers: timers.size + (releaseTimer === null ? 0 : 1), workers: tasks.size + (releasePending ? 1 : 0),
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
      const results = await Promise.allSettled([listenerJoin, ...socketJoins, enrollment?.close(), backend?.close(), ...tasks,
        ...(releaseTask ? [Promise.allSettled([releaseTask])] : [])]);
      if (results.some(result => result.status === 'rejected') || sockets.size || tasks.size || timers.size || pendingCallbacks || releasePending || releaseTimer !== null ||
          startupUnjoined || (enrollment && (!enrollment.snapshot().storeClosed || !enrollment.snapshot().issuerChildrenJoined))) throw failure();
      if (!directory.startsWith(temporaryRoot + path.sep) || !path.basename(directory).startsWith('freekit-origin-gateway-')) throw failure();
      fs.rmSync(directory, { recursive: true }); privateDirectoryRemoved = !fs.existsSync(directory);
      if (!privateDirectoryRemoved) throw failure();
      return snapshot();
    })(), 15000);
    closeTask.catch(() => retainedFailures.add({ enrollment, backend, server })); return closeTask;
  }
  try {
    backend = await createDesktopOriginBackend({ desktopRoot, desktopCommit,
      authorizeDestination: endpoint => {
        const allowed = endpoint.address === '127.0.0.2' && endpoint.port === 80 && endpoint.protocol === 'http:';
        if (allowed) origin.originalDestinationMatched = true; return allowed;
      }, onCapture: capture => {
        if (capture.url === `http://${payload.logicalHost}${payload.path}`) origin.captureMatched = true;
      } });
    server = http.createServer({ maxHeaderSize: 4096 }, (req, res) => { if (closing) req.socket.destroy(); else own(() => request(req, res), req.socket); });
    server.maxConnections = 4; server.maxHeadersCount = 16; server.maxRequestsPerSocket = 1;
    server.once('close', () => { listenerClosed = true; }); server.on('clientError', (_error, socket) => socket.destroy());
    server.on('connection', socket => {
      observeClose(socket); sockets.add(socket); origin.connections++; socket.on('error', () => {});
      const timer = setTimeout(() => { timers.delete(timer); socket.destroy(); }, 15000); timers.add(timer);
      socket.once('close', () => { sockets.delete(socket); clearTimeout(timer); timers.delete(timer); });
      if (closing) socket.destroy();
    });
    await bounded(new Promise((done, reject) => { server.once('error', reject); server.listen(80, '127.0.0.2', done); }), 5000);
    enrollment = await startEnrollmentOriginFixture({ directory, mode: 'create', openssl, trustedProxyFactory: backend.factory });
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
      const approved = await enrollOriginCsr(enrollment, csr); enrollmentId = approved.material().enrollmentId; return approved;
    },
    releaseTail() {
      if (releaseRequested || closing || enrollmentId === null) return Promise.reject(failure());
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
    if (process.argv.length !== 6 || process.argv[2] !== '--desktop-root' || process.argv[4] !== '--desktop-commit') throw failure();
    owner = await startOriginGatewayFixture({ desktopRoot: process.argv[3], desktopCommit: process.argv[5] });
    emit({ event: 'ready', metadata: owner.metadata().material(), desktopCommit: process.argv[5] });
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
            emit({ event: 'enrolled', approved: (await owner.enroll(csr)).material(), metadata: owner.metadata().material() });
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
