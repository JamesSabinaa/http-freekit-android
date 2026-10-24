// A22 loopback research only: no production endpoint or Android-accessible operator API.
import https from 'node:https';
import { constants as cryptoConstants, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { enrollmentFixtureAssets, EnrollmentFixtureError } from './companion-enrollment-https-assets.mjs';
import { startEnrollmentIssuer, EnrollmentIssuerError } from './companion-enrollment-issuer.mjs';
import { createEnrollmentStore, openEnrollmentStore } from './companion-enrollment-store.mjs';
import { createEnrollmentAuthority } from './companion-enrollment-authority.mjs';
import { decodeEnrollment, encodeEnrollment, enrollmentMessage } from './companion-enrollment-codec.mjs';

const retainedFailures = new Set(); // A failed owner cannot be GC'd into silently releasing its DB lease.
const status = { invalid_message: 400, unsupported_version: 400, unsupported_capability: 400, message_too_large: 413,
  authentication_failed: 403, invitation_expired: 409, invitation_used: 409, pairing_limit: 429, pairing_unavailable: 503 };
const fail = (code = 'pairing_unavailable', joined = true) => { throw new EnrollmentFixtureError(code, joined); };
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.exec(value)?.[0] === value;
const key = (role, socket) => `${role}:${socket.remoteAddress}:${socket.remotePort}`;
const closeObservations = new WeakMap();
function observeClose(socket) {
  if (!closeObservations.has(socket)) closeObservations.set(socket, new Promise(resolve => socket.once('close', resolve)));
  return closeObservations.get(socket);
}
function listen(server, port) {
  return new Promise((resolve, reject) => {
    const error = () => { clearTimeout(timer); reject(new EnrollmentFixtureError()); };
    const timer = setTimeout(error, 5000); server.once('error', error);
    server.listen(port, '127.0.0.1', () => { clearTimeout(timer); server.off('error', error); resolve(); });
  });
}
function policy(request, role, logicalName) {
  if (request.httpVersion !== '1.1' || request.rawHeaders.length > 64 || request.rawTrailers.length ||
    request.headers.host !== `${logicalName}:${request.socket.localPort}`) return false;
  const seen = new Set();
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index].toLowerCase(); if (seen.has(name)) return false; seen.add(name);
  }
  if (['origin', 'cookie', 'authorization', 'transfer-encoding', 'expect', 'upgrade', 'trailer'].some(name => Object.hasOwn(request.headers, name))) return false;
  if (role === 'credential') return request.method === 'GET' && request.url === '/research/enrollment/credential' &&
    (request.headers['content-length'] === undefined || request.headers['content-length'] === '0');
  return request.method === 'POST' && ['/companion/v1/pair', '/companion/v1/pair/status', '/companion/v1/pair/cancel'].includes(request.url) && request.headers['content-type'] === 'application/json';
}
function channel(request, body) {
  if (request.url === '/companion/v1/pair') return 'pair_request';
  if (request.url === '/companion/v1/pair/cancel') return 'cancel_request';
  // Both attempts apply the complete strict structural guard. Never JSON.parse a type discriminator.
  return decodeEnrollment('challenge_request', body).ok ? 'challenge_request' : 'status_request';
}
class EnrollmentHttpsFixture {
  #assets; #issuer; #store; #authority; #servers = new Map(); #listening = new Set();
  #connections = new Map(); #declined = new Map(); #tlsSockets = new Map(); #tasks = new Set(); #writes = new Set(); #jobs = new Map();
  #requestSockets = new WeakMap(); #cancelledWrites = 0;
  #service = null;
  #invitations = new Map(); #registrations = new Map(); #waiters = new Set();
  #closing = false; #closed = false; #unavailable = false; #closeTask; #bodyReaders = 0; #drop = false;
  #dropped = 0; #delivered = 0; #deliveredAfterDrop = 0; #dispatches = 0; #timerCount = 0; #storeClosed = false; #authorityClosed = false;
  constructor(assets, issuer, store) { this.#assets = assets; this.#issuer = issuer; this.#store = store; this.#authority = createEnrollmentAuthority({ store }); }
  async startAuthenticatedService(factory) {
    if (factory === undefined) return;
    if (typeof factory !== 'function' || this.#service) fail();
    const metadata = this.#assets.metadata().material();
    this.#service = await factory({
      tls: { ...this.#assets.tlsOptions(), requestCert: true, rejectUnauthorized: true,
        ca: new X509Certificate(Buffer.from(metadata.enrollmentAuthorityDer, 'base64url')).toString(), secureOptions: cryptoConstants.SSL_OP_NO_TICKET },
      metadata: structuredClone(metadata),
      authorizeCertificate: candidate => {
        this.#healthy();
        try { return this.#store.authorizeCertificate(candidate); }
        catch { this.#unavailable = true; fail(); }
      },
    });
    // Retain the owner before it starts auxiliary child/listener work. A failed
    // initialize can then be closed/joined without releasing the Store first.
    if (typeof this.#service?.initialize === 'function') await this.#service.initialize();
    if (!this.#service || !Number.isInteger(this.#service.port) || this.#service.port < 1 || this.#service.port > 65535 ||
        ['invalidateEnrollment', 'inspectEnrollment', 'snapshot', 'close'].some(name => typeof this.#service[name] !== 'function')) fail();
  }
  #timer(action, millis) {
    this.#timerCount++; let pending = true;
    const timer = setTimeout(() => { if (pending) { pending = false; this.#timerCount--; action(); } }, millis);
    return () => { if (pending) { pending = false; this.#timerCount--; clearTimeout(timer); } };
  }
  #healthy() {
    if (this.#service?.snapshot().unavailable) this.#unavailable = true;
    if (this.#closing || this.#closed || this.#unavailable) fail();
  }
  #limits() {
    for (const [role, server] of this.#servers) {
      const other = [...this.#connections.values()].filter(record => record.role !== role).length;
      server.maxConnections = Math.max(0, 16 - other);
    }
  }
  async start(setupPort, credentialPort) {
    const metadata = this.#assets.metadata().material(), tls = this.#assets.tlsOptions();
    for (const role of ['setup', 'credential']) {
      const server = https.createServer({ ...tls, maxHeaderSize: 8192, requireHostHeader: true, requestTimeout: 10000, headersTimeout: 5000,
        ...(role === 'credential' ? { requestCert: true, rejectUnauthorized: true, ca: new X509Certificate(Buffer.from(metadata.enrollmentAuthorityDer, 'base64url')).toString(), secureOptions: cryptoConstants.SSL_OP_NO_TICKET } : { requestCert: false }) },
      (request, reply) => {
        const work = this.#request(role, request, reply).catch(() => request.socket.destroy()); this.#tasks.add(work);
        work.then(() => this.#tasks.delete(work));
      });
      this.#servers.set(role, server); server.maxConnections = 16; server.maxHeadersCount = 33; server.maxRequestsPerSocket = 1;
      server.on('error', () => {}); server.on('tlsClientError', () => {});
      server.on('clientError', (_error, socket) => socket.destroy()); server.on('dropRequest', (_request, socket) => socket.destroy());
      server.on('checkContinue', (request) => request.socket.destroy()); server.on('checkExpectation', request => request.socket.destroy());
      server.on('upgrade', (_request, socket) => socket.destroy()); server.on('connect', (_request, socket) => socket.destroy());
      if (role === 'credential') {
        server.on('newSession', (_id, _data, done) => done());
        server.on('resumeSession', (_id, done) => done(null, null));
      }
      server.on('connection', socket => {
        socket.on('error', () => {}); const closed = observeClose(socket), recordKey = key(role, socket);
        if (this.#closing || this.#connections.size >= 16 || this.#connections.has(recordKey)) { this.#declined.set(socket, closed); closed.then(() => this.#declined.delete(socket)); socket.destroy(); return; }
        const record = { role, raw: socket, closed, served: false, header: null, whole: this.#timer(() => socket.destroy(), 10000) };
        this.#connections.set(recordKey, record); this.#limits();
        socket.once('close', () => { record.whole(); record.header?.(); this.#connections.delete(recordKey); this.#limits(); });
      });
      server.on('secureConnection', socket => {
        socket.on('error', () => {}); const closed = observeClose(socket); this.#tlsSockets.set(socket, closed);
        socket.once('close', () => this.#tlsSockets.delete(socket));
        const record = this.#connections.get(key(role, socket));
        if (!record || this.#closing || socket.servername !== metadata.logicalName || (socket.alpnProtocol && socket.alpnProtocol !== 'http/1.1') ||
          (role === 'credential' && socket.isSessionReused())) { socket.destroy(); return; }
        record.header = this.#timer(() => socket.destroy(), 5000);
      });
      server.once('close', () => this.#listening.delete(role));
      await listen(server, role === 'setup' ? setupPort : credentialPort); this.#listening.add(role);
    }
    this.#assets.commitPorts(this.#servers.get('setup').address().port, this.#servers.get('credential').address().port);
    return this;
  }
  #write(socket, source, write) {
    if (!socket) return Promise.reject(new EnrollmentFixtureError());
    const pending = {}; this.#writes.add(pending);
    return new Promise((resolve, reject) => {
      let owned = true, failed = false;
      const release = () => { owned = false; this.#writes.delete(pending); source.off('error', error); };
      const error = () => { failed = true; reject(new EnrollmentFixtureError()); socket.destroy(); };
      source.on('error', error);
      // Actual close cancels the write owner. It never substitutes for a successful
      // callback, and a requested destroy alone never releases retained ownership.
      observeClose(socket).then(() => { if (owned) { release(); this.#cancelledWrites++; reject(new EnrollmentFixtureError()); } });
      const callback = cause => {
        if (!owned) return;
        release(); if (cause || failed) reject(new EnrollmentFixtureError()); else resolve();
      };
      try { write(callback); } catch { error(); }
    });
  }
  async #reply(reply, code, body) {
    if (body.length > 16384) fail();
    const socket = this.#requestSockets.get(reply);
    await this.#write(socket, reply, callback => {
      reply.on('error', () => {});
      reply.writeHead(code, { 'content-type': 'application/json', 'content-length': String(body.length), connection: 'close' });
      reply.end(body, callback);
    });
  }
  #error(reply, code) { return this.#reply(reply, status[code], encodeEnrollment(enrollmentMessage('pair_response', { protocolVersion: 1, type: 'pair_error', code }))); }
  async #dropResponse(socket) {
    const closed = observeClose(socket);
    await this.#write(socket, socket, callback => socket.end(callback));
    await closed; this.#dropped++;
  }
  async #body(request, length) {
    if (this.#bodyReaders >= 4) fail('pairing_limit');
    this.#bodyReaders++; const body = Buffer.alloc(length);
    try {
      return await new Promise((resolve, reject) => {
        let at = 0, finished = false;
        const cleanup = () => { request.off('data', data); request.off('end', end); request.off('aborted', bad); request.off('error', bad); request.off('close', close); };
        const done = valid => { if (finished) return; finished = true; cleanup(); valid ? resolve(body) : reject(new EnrollmentFixtureError('invalid_message')); };
        const bad = () => done(false), close = () => { if (!request.complete) bad(); };
        const data = bytes => { if (bytes.length > length - at) { done(false); request.socket.destroy(); return; } bytes.copy(body, at); at += bytes.length; };
        const end = () => done(at === length && request.complete && request.rawTrailers.length === 0);
        request.on('data', data); request.once('end', end); request.once('aborted', bad); request.once('error', bad); request.once('close', close);
      });
    } finally { this.#bodyReaders--; }
  }
  async #request(role, request, reply) {
    request.on('error', () => {});
    this.#requestSockets.set(reply, request.socket);
    const record = this.#connections.get(key(role, request.socket)); record?.header?.();
    if (!record || record.served || this.#closing) { request.socket.destroy(); return; }
    record.served = true;
    const metadata = this.#assets.metadata().material();
    if (!policy(request, role, metadata.logicalName)) return this.#error(reply, 'invalid_message');
    if (this.#service?.snapshot().unavailable) this.#unavailable = true;
    if (this.#unavailable) return this.#error(reply, 'pairing_unavailable');
    if (role === 'credential') {
      const cert = request.socket.getPeerX509Certificate(); let authorized;
      try { authorized = request.socket.authorized === true && cert && this.#store.authorizeCertificate(cert.raw); }
      catch { this.#unavailable = true; return this.#error(reply, 'pairing_unavailable'); }
      if (!authorized) return this.#error(reply, 'authentication_failed');
      return this.#reply(reply, 200, Buffer.from('{"type":"credential_admitted"}'));
    }
    const text = request.headers['content-length'];
    if (typeof text !== 'string' || /^[1-9][0-9]{0,4}$/.exec(text)?.[0] !== text) return this.#error(reply, 'invalid_message');
    const length = Number(text); if (length > 16384) return this.#error(reply, 'message_too_large');
    let body;
    try { body = await this.#body(request, length); } catch (failure) {
      if (request.socket.destroyed) return; return this.#error(reply, failure.code === 'pairing_limit' ? 'pairing_limit' : 'invalid_message');
    }
    if (this.#closing) { request.socket.destroy(); return; }
    const selected = channel(request, body), response = this.#authority.request(selected, body), material = response.material(); this.#dispatches++;
    if (selected === 'pair_request' && material.type === 'pair_registered' && this.#invitations.has(material.invitationId)) {
      if (!this.#registrations.has(material.invitationId)) this.#registrations.set(material.invitationId, response);
      for (const waiter of [...this.#waiters]) if (waiter.invitationId === material.invitationId) waiter.complete(response);
    }
    if (selected === 'cancel_request' && material.type === 'pair_ended' && material.code === 'pairing_cancelled') {
      this.#service?.invalidateEnrollment(material.enrollmentId, 'device_revoked');
    }
    if (selected === 'status_request' && material.type === 'pair_approved' && this.#drop) { this.#drop = false; await this.#dropResponse(request.socket); return; }
    await this.#reply(reply, material.type === 'pair_error' ? status[material.code] : 200, encodeEnrollment(response));
    if (selected === 'status_request' && material.type === 'pair_approved') { this.#delivered++; if (this.#dropped > 0) this.#deliveredAfterDrop++; }
  }
  metadata() { return this.#assets.metadata(); }
  createInvitation() {
    this.#healthy(); const now = this.#store.now().utcMillis;
    for (const [invitationId, expires] of this.#invitations) if (now >= expires && !this.#registrations.has(invitationId) && ![...this.#waiters].some(waiter => waiter.invitationId === invitationId)) this.#invitations.delete(invitationId);
    if (this.#invitations.size >= 64) fail('pairing_limit');
    const invitation = this.#store.createInvitation(), material = invitation.material(); this.#invitations.set(material.invitationId, Date.parse(material.expiresAt)); return invitation;
  }
  waitForRegistered(invitationId, { timeoutMillis = 10000 } = {}) {
    this.#healthy(); if (!id(invitationId) || !this.#invitations.has(invitationId)) return Promise.reject(new EnrollmentFixtureError('authentication_failed'));
    if (!Number.isInteger(timeoutMillis) || timeoutMillis < 1 || timeoutMillis > 10000 || this.#waiters.size >= 4) return Promise.reject(new EnrollmentFixtureError('pairing_limit'));
    if (this.#registrations.has(invitationId)) return Promise.resolve(this.#registrations.get(invitationId));
    return new Promise((resolve, reject) => {
      const waiter = { invitationId, complete: result => { cancel(); this.#waiters.delete(waiter); resolve(result); }, stop: () => { cancel(); this.#waiters.delete(waiter); reject(new EnrollmentFixtureError()); } };
      const cancel = this.#timer(() => { this.#waiters.delete(waiter); reject(new EnrollmentFixtureError()); }, timeoutMillis); this.#waiters.add(waiter);
    });
  }
  approve(enrollmentId) {
    this.#healthy(); const result = this.#store.beginApproval(enrollmentId); if (result.kind === 'approved') return Promise.resolve(result.result);
    const entry = { job: result.job, task: null }; this.#jobs.set(result.job, entry);
    entry.task = (async () => {
      let joined = true;
      try {
        joined = false; const candidate = await this.#issuer.issue(result.job); joined = true;
        if (this.#closing || this.#unavailable) fail();
        return this.#store.publish(result.job, Buffer.from(candidate.material().clientCertificateDer, 'base64url'));
      } catch (failure) {
        if (failure instanceof EnrollmentIssuerError) joined = failure.joined;
        if (joined) this.#store.abandon(result.job); else this.#unavailable = true;
        throw new EnrollmentFixtureError(Object.hasOwn(status, failure?.code) ? failure.code : 'pairing_unavailable', joined);
      } finally { if (joined) this.#jobs.delete(result.job); }
    })();
    return entry.task;
  }
  reject(enrollmentId) { this.#healthy(); return this.#store.reject(enrollmentId); }
  revoke(enrollmentId) {
    this.#healthy(); const result = this.#store.revoke(enrollmentId);
    // Expiry or an earlier terminal decision can win inside the Store transaction.
    // Announce only a revocation that the durable result actually records.
    if (result.material().type === 'pair_ended' && result.material().code === 'device_revoked') this.#service?.invalidateEnrollment(enrollmentId, 'device_revoked');
    return result;
  }
  authenticatedService() { return this.#service; } // Explicit trusted composition only; never serialized.
  readResult(enrollmentId) { this.#healthy(); return this.#store.readResult(enrollmentId); }
  dropNextApprovedStatus() { this.#healthy(); if (this.#drop) fail('pairing_limit'); this.#drop = true; }
  snapshot() { const issuer = this.#issuer.snapshot(), service = this.#service?.snapshot(); return Object.freeze({ acceptedSockets: this.#connections.size, tlsSockets: this.#tlsSockets.size, bodyReaders: this.#bodyReaders,
    requestTasks: this.#tasks.size, pendingWriteCallbacks: this.#writes.size, timers: this.#timerCount, registrationWaiters: this.#waiters.size,
    issuerJobs: this.#jobs.size, listeners: this.#listening.size, dispatches: this.#dispatches, droppedApprovedResponses: this.#dropped,
    approvedResponsesDelivered: this.#delivered, approvedResponsesDeliveredAfterDrop: this.#deliveredAfterDrop,
    writeOwnersCancelledByClose: this.#cancelledWrites,
    admissionClosed: this.#closing, listenersClosed: this.#listening.size === 0 && (!service || service.listeners === 0), issuerChildrenJoined: issuer.closed && issuer.unjoinedChildren === 0 && issuer.commandsStarted === issuer.commandsClosed && issuer.commandsStarted === issuer.processGroupsClosed && service?.childrenJoined !== false,
    activeSockets: this.#connections.size + this.#tlsSockets.size + this.#declined.size + (service?.authenticatedSockets ?? 0) + (service?.proxySockets ?? 0),
    pendingCallbacks: this.#writes.size + (service?.pendingCallbacks ?? 0), pendingTimers: this.#timerCount + (service?.timers ?? 0),
    signerGroups: issuer.commandsStarted - issuer.processGroupsClosed, workers: this.#tasks.size + this.#jobs.size + this.#waiters.size + (service?.workers ?? 0),
    authorityClosed: this.#authorityClosed, storeClosed: this.#storeClosed, closing: this.#closing, closed: this.#closed, issuer }); }
  close() {
    if (this.#closed) return Promise.resolve(this.snapshot()); if (this.#closeTask) return this.#closeTask; this.#closing = true;
    this.#closeTask = (async () => {
      let timedOut = false, deadline;
      const attempt = (async () => {
        for (const waiter of [...this.#waiters]) waiter.stop();
        const sockets = [...this.#connections.values()].map(record => { record.raw.destroy(); return record.closed; });
        for (const [socket, closed] of this.#declined) { socket.destroy(); sockets.push(closed); }
        for (const [socket, closed] of this.#tlsSockets) { socket.destroy(); sockets.push(closed); }
        const listeners = [...this.#servers.values()].map(server => new Promise((resolve, reject) => server.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(new EnrollmentFixtureError()) : resolve())));
        const results = await Promise.allSettled([this.#issuer.close(), ...sockets, ...listeners, ...this.#tasks, ...[...this.#jobs.values()].map(entry => entry.task),
          ...(this.#service ? [this.#service.close()] : [])]);
        // Failed approvals may be expected cancellations; only their retained ownership can block release.
        if (timedOut || results[0].status !== 'fulfilled' || results.slice(1 + sockets.length, 1 + sockets.length + listeners.length).some(result => result.status !== 'fulfilled') ||
          (this.#service && results.at(-1).status !== 'fulfilled') ||
          this.#jobs.size || this.#connections.size || this.#declined.size || this.#tlsSockets.size || this.#tasks.size || this.#writes.size || this.#bodyReaders || this.#timerCount || this.#listening.size) fail('pairing_unavailable', false);
        this.#authority.close(); this.#authorityClosed = true; this.#store.close(); this.#storeClosed = true; this.#closed = true; return this.snapshot();
      })();
      try { return await Promise.race([attempt, new Promise((_, reject) => { deadline = setTimeout(() => { timedOut = true; reject(new EnrollmentFixtureError('pairing_unavailable', false)); }, 20000); })]); }
      finally { clearTimeout(deadline); }
    })();
    this.#closeTask.catch(() => { retainedFailures.add(this); }); return this.#closeTask;
  }
  toString() { return '[Enrollment HTTPS research fixture]'; }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return this.toString(); }
}
export async function startEnrollmentHttpsFixture({ directory, mode, openssl = process.env.OPENSSL_BIN ?? 'openssl', setupPort = 0, credentialPort = 0,
  authenticatedServiceFactory, credentialLifetimeSeconds = 3600 } = {}) {
  if (retainedFailures.size) fail(false);
  let issuer, store, fixture;
  try {
    const assets = await enrollmentFixtureAssets({ directory, mode, openssl, setupPort, credentialPort }), metadata = assets.metadata().material();
    issuer = await startEnrollmentIssuer({ directory, openssl, enrollmentAuthorityDer: metadata.enrollmentAuthorityDer });
    store = (mode === 'create' ? createEnrollmentStore : openEnrollmentStore)({ directory, metadata: { desktopId: metadata.desktopId,
      gatewaySpkiSha256: metadata.gatewaySpkiSha256, enrollmentAuthorityDer: metadata.enrollmentAuthorityDer,
      interceptionCaCertificateSha256: metadata.interceptionCaCertificateSha256, supportedCapabilities: ['tcp-http', 'tcp-https-connect'], credentialLifetimeSeconds } });
    fixture = new EnrollmentHttpsFixture(assets, issuer, store); await fixture.start(setupPort, credentialPort);
    await fixture.startAuthenticatedService(authenticatedServiceFactory); return fixture;
  } catch (failure) {
    let joined = failure?.joined !== false;
    try { if (fixture) await fixture.close(); else { await issuer?.close(); store?.close(); } } catch { joined = false; if (fixture) retainedFailures.add(fixture); else retainedFailures.add({ issuer, store }); }
    throw new EnrollmentFixtureError('pairing_unavailable', joined);
  }
}
