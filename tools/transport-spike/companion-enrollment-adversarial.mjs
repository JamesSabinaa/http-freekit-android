// A22c loopback-only wrong-peer fixture. No production trust or enrollment surface.
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { createHash, createPrivateKey, createPublicKey, randomBytes, X509Certificate, constants } from 'node:crypto';
import { inspect } from 'node:util';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { EnrollmentFixtureError, enrollmentPrivateDirectory } from './companion-enrollment-https-assets.mjs';
import { enrollmentPublicSnapshot } from './companion-enrollment-crypto.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';

const fail = (joined = true) => { throw new EnrollmentFixtureError('pairing_unavailable', joined); };
const date = millis => new Date(millis).toISOString().replace(/[-:T]/g, '').replace('.000Z', 'Z');
const hash = bytes => createHash('sha256').update(bytes).digest('base64url');
const writePrivate = (directory, name, bytes) => fs.writeFileSync(path.join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
function readPrivate(directory, name, max) {
  const filename = path.join(directory, name), stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > max ||
      (process.platform !== 'win32' && (stat.mode & 0o077))) fail();
  return fs.readFileSync(filename);
}

class AlternateTlsPeer {
  #work; #openssl; #metadata; #port; #boundPort = 0; #server = null; #everListening = false; #listenerClosed = true; #closedEvent;
  #raw = new Map(); #tls = new Map(); #commands = new Set(); #abort = new AbortController();
  #accepted = 0; #rejected = 0; #secure = 0; #http = 0; #callbacks = 0; #timers = 0;
  #started = 0; #childrenClosed = 0; #groupsClosed = 0; #unjoined = false;
  #starting = null; #initializing = false; #closing = false; #budgetClosed = false; #closeTask = null;
  constructor({ directory, openssl, metadata, port }) {
    this.#work = path.join(enrollmentPrivateDirectory(directory), 'adversarial-peer');
    this.#openssl = openssl; this.#metadata = structuredClone(metadata); this.#port = port;
    fs.mkdirSync(this.#work, { mode: 0o700 });
  }
  get port() { if (!this.#boundPort) fail(); return this.#boundPort; }
  #timer(operation, millis) {
    this.#timers++; let pending = true;
    const timer = setTimeout(() => { if (pending) { pending = false; this.#timers--; operation(); } }, millis);
    return () => { if (pending) { pending = false; this.#timers--; clearTimeout(timer); } };
  }
  #observe(socket, map) {
    if (map.has(socket)) return map.get(socket);
    socket.on('error', () => {});
    const closed = new Promise(resolve => socket.once('close', resolve)); map.set(socket, closed);
    closed.then(() => map.delete(socket)); return closed;
  }
  async #command(args) {
    if (this.#closing) fail();
    this.#started++;
    const task = runDraftCommand(this.#openssl, args, { cwd: this.#work, timeoutMillis: 5000, maxOutputBytes: 16384, abortSignal: this.#abort.signal });
    this.#commands.add(task);
    try {
      let result;
      try { result = await task; } catch { this.#unjoined = true; fail(false); }
      if (result.closeObserved) this.#childrenClosed++;
      if (result.processGroupClosed) this.#groupsClosed++;
      if (!result.closeObserved || !result.processGroupClosed) { this.#unjoined = true; fail(false); }
      if (this.#closing || result.reason || result.code !== 0) fail();
      return result.output;
    } finally { this.#commands.delete(task); }
  }
  initialize() {
    if (this.#starting) return this.#starting;
    this.#initializing = true;
    this.#starting = this.#start().catch(error => {
      if (error instanceof EnrollmentFixtureError) throw error; fail();
    }).finally(() => { this.#initializing = false; });
    return this.#starting;
  }
  async #start() {
    if (!/^OpenSSL 3\.[^\r\n]*$/.test((await this.#command(['version'])).trim())) fail();
    const name = this.#metadata.logicalName, now = Date.now(), t = Math.floor(now / 1000) * 1000, before = t - 300000, after = t + 7200000;
    if (/^[a-z0-9.-]{1,253}$/.exec(name)?.[0] !== name || before < Date.parse('2000-01-01T00:00:00Z') || after > Date.parse('2099-12-31T23:59:59Z')) fail();
    writePrivate(this.#work, 'request.cnf', '[req]\ndistinguished_name=subject\nprompt=no\nstring_mask=utf8only\n[subject]\nCN=HTTP FreeKit research\n');
    await this.#command(['req', '-config', 'request.cnf', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256', '-utf8',
      '-subj', `/CN=${name}`, '-keyout', 'peer-key.pem', '-out', 'peer.csr.pem']);
    fs.chmodSync(path.join(this.#work, 'peer-key.pem'), 0o600); fs.chmodSync(path.join(this.#work, 'peer.csr.pem'), 0o600);
    fs.mkdirSync(path.join(this.#work, 'issued'), { mode: 0o700 });
    writePrivate(this.#work, 'index.txt', ''); writePrivate(this.#work, 'serial', randomBytes(16).toString('hex') + '\n');
    writePrivate(this.#work, 'issuer.cnf', '[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=index.txt\nnew_certs_dir=issued\nserial=serial\ndefault_md=sha256\npolicy=subject\ncopy_extensions=none\nstring_mask=utf8only\n[subject]\ncommonName=supplied\n[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + name + '\n');
    await this.#command(['ca', '-config', 'issuer.cnf', '-batch', '-notext', '-md', 'sha256', '-selfsign', '-keyfile', 'peer-key.pem',
      '-startdate', date(before), '-enddate', date(after), '-extensions', 'server', '-in', 'peer.csr.pem', '-out', 'peer.pem']);
    fs.chmodSync(path.join(this.#work, 'peer.pem'), 0o600);
    const certBytes = readPrivate(this.#work, 'peer.pem', 16384), keyBytes = readPrivate(this.#work, 'peer-key.pem', 4096);
    const cert = new X509Certificate(certBytes), key = createPrivateKey(keyBytes), spki = cert.publicKey.export({ type: 'spki', format: 'der' });
    if (cert.raw.length > 4096 || cert.ca || key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
        cert.publicKey.asymmetricKeyType !== 'ec' || cert.publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
        !createPublicKey(key).export({ type: 'spki', format: 'der' }).equals(spki) || !cert.verify(cert.publicKey) || cert.subject !== cert.issuer ||
        cert.subjectAltName !== `DNS:${name}` || cert.checkHost(name, { subject: 'never', wildcards: false }) !== name ||
        Date.parse(cert.validFrom) !== before || Date.parse(cert.validTo) !== after || Date.now() < before || Date.now() >= after ||
        cert.keyUsage?.length !== 1 || cert.keyUsage[0] !== '1.3.6.1.5.5.7.3.1' || hash(spki) === this.#metadata.gatewaySpkiSha256) fail();
    if (this.#closing) fail();
    this.#server = https.createServer({ key: keyBytes, cert: certBytes, requestCert: false, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3',
      handshakeTimeout: 5000, secureOptions: constants.SSL_OP_NO_TICKET, ALPNProtocols: ['http/1.1'],
      maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 }, request => { this.#http++; request.socket.destroy(); });
    this.#closedEvent = new Promise(resolve => this.#server.once('close', () => { this.#listenerClosed = true; resolve(); }));
    this.#server.maxConnections = 8; this.#server.maxHeadersCount = 33; this.#server.maxRequestsPerSocket = 1;
    this.#server.on('error', () => {});
    this.#server.on('connection', socket => {
      const closed = this.#observe(socket, this.#raw); this.#accepted++;
      if (this.#closing || this.#budgetClosed) { socket.destroy(); return; }
      const cancel = this.#timer(() => socket.destroy(), 5000); closed.then(cancel);
      if (this.#accepted >= 8) { this.#budgetClosed = true; this.#server.close(); }
    });
    this.#server.on('secureConnection', socket => {
      this.#observe(socket, this.#tls); this.#secure++;
      if (this.#closing || socket.servername !== name || (socket.alpnProtocol && socket.alpnProtocol !== 'http/1.1')) socket.destroy();
    });
    this.#server.on('tlsClientError', (_error, socket) => { this.#rejected++; socket.destroy(); });
    this.#server.on('newSession', (_id, _data, done) => done()); this.#server.on('resumeSession', (_id, done) => done(null, null));
    this.#server.on('clientError', (_error, socket) => socket.destroy());
    for (const event of ['upgrade', 'connect', 'checkContinue', 'checkExpectation', 'dropRequest']) {
      this.#server.on(event, request => { this.#http++; request.socket.destroy(); });
    }
    await new Promise((resolve, reject) => {
      const cancel = this.#timer(() => reject(new EnrollmentFixtureError()), 5000);
      const error = () => { cancel(); reject(new EnrollmentFixtureError()); };
      this.#server.once('error', error);
      this.#server.listen(this.#port, '127.0.0.1', () => {
        cancel(); this.#server.off('error', error); this.#everListening = true; this.#listenerClosed = false;
        this.#boundPort = this.#server.address().port; resolve();
      });
    });
    if (this.#closing) fail();
  }
  snapshot() {
    return { accepted: this.#accepted, rejected: this.#rejected, httpDispatches: this.#http, secureConnections: this.#secure,
      activeSockets: this.#raw.size + this.#tls.size, pendingCallbacks: this.#callbacks, pendingTimers: this.#timers,
      workers: this.#commands.size + (this.#initializing ? 1 : 0), childrenStarted: this.#started, childrenClosed: this.#childrenClosed,
      childGroupsClosed: this.#groupsClosed, admissionClosed: this.#closing || this.#budgetClosed, listenerClosed: this.#listenerClosed };
  }
  async #closeListener() {
    if (!this.#server) return;
    this.#callbacks++;
    try {
      await new Promise((resolve, reject) => this.#server.close(error => {
        if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(new EnrollmentFixtureError('pairing_unavailable', false));
        else if (error && this.#everListening) this.#closedEvent.then(resolve);
        else { if (error) this.#listenerClosed = true; resolve(); }
      }));
    } finally { this.#callbacks--; }
  }
  #destroySockets() {
    return [...this.#raw, ...this.#tls].map(([socket, closed]) => { socket.destroy(); return closed; });
  }
  close() {
    if (this.#closeTask) return this.#closeTask;
    this.#closing = true; this.#abort.abort();
    this.#closeTask = (async () => {
      let cancel;
      try {
        await Promise.race([(async () => {
          const initial = await Promise.allSettled([...this.#destroySockets(), this.#closeListener(), ...this.#commands,
            ...(this.#starting ? [this.#starting] : [])]);
          const final = await Promise.allSettled([...this.#destroySockets(), this.#closeListener()]);
          if (initial.some((value, index) => value.status === 'rejected' && index < initial.length - (this.#starting ? 1 : 0)) ||
              final.some(value => value.status === 'rejected') || this.#unjoined || this.#commands.size || this.#initializing ||
              this.#raw.size || this.#tls.size || this.#callbacks || !this.#listenerClosed ||
              this.#started !== this.#childrenClosed || this.#started !== this.#groupsClosed) fail(false);
        })(), new Promise((_, reject) => { cancel = this.#timer(() => reject(new EnrollmentFixtureError('pairing_unavailable', false)), 10000); })]);
      } finally { cancel?.(); }
      return this.snapshot();
    })();
    return this.#closeTask;
  }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return '[Alternate TLS research peer]'; }
}

class AdversarialFixture {
  #base; #peer;
  constructor(base, peer) { this.#base = base; this.#peer = peer; Object.freeze(this); }
  metadata() { return enrollmentPublicSnapshot({ ...this.#base.metadata().material(), adversarialPeerPort: this.#peer.port }); }
  createInvitation() { return this.#base.createInvitation(); }
  waitForRegistered(id, options) { return this.#base.waitForRegistered(id, options); }
  approve(id) { return this.#base.approve(id); }
  reject(id) { return this.#base.reject(id); }
  revoke(id) { return this.#base.revoke(id); }
  readResult(id) { return this.#base.readResult(id); }
  dropNextApprovedStatus() { return this.#base.dropNextApprovedStatus(); }
  snapshot() { return { ...this.#base.snapshot(), alternateTls: this.#peer.snapshot() }; }
  async close() { await this.#base.close(); return this.snapshot(); }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return '[Adversarial enrollment research fixture]'; }
}

export async function startEnrollmentAdversarialFixture({ directory, mode, openssl = process.env.OPENSSL_BIN ?? 'openssl', setupPort = 0, credentialPort = 0 } = {}) {
  if (mode !== 'create') fail();
  let peer;
  const base = await startEnrollmentHttpsFixture({ directory, mode, openssl, setupPort, credentialPort,
    authenticatedServiceFactory: ({ metadata }) => {
      peer = new AlternateTlsPeer({ directory, openssl, metadata, port: 0 });
      return { get port() { return peer.port; }, initialize: () => peer.initialize(),
        invalidateEnrollment() { /* This peer owns no authenticated grants. */ },
        inspectEnrollment() { throw new EnrollmentFixtureError('authentication_failed'); },
        snapshot() { const value = peer.snapshot(); return { unavailable: false, authenticatedSockets: value.activeSockets,
          proxySockets: 0, listeners: value.listenerClosed ? 0 : 1, pendingCallbacks: value.pendingCallbacks,
          timers: value.pendingTimers, workers: value.workers,
          childrenJoined: value.childrenStarted === value.childrenClosed && value.childrenStarted === value.childGroupsClosed }; },
        close: () => peer.close(),
      };
    },
  });
  return new AdversarialFixture(base, peer);
}
