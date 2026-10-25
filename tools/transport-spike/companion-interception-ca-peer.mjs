// Private software-key JVM research peer. No management/public provisioning route.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { pathToFileURL } from 'node:url';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { enrollmentFixtureAssets } from './companion-enrollment-https-assets.mjs';
import { enrollmentRequest } from './companion-enrollment-stream-client.mjs';
import { enrollmentMessage } from './companion-enrollment-codec.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { bounded, observeClose, write, endWrite, writerState, safeError } from './companion-stream-peer-io.mjs';

export const interceptionCaCases = Object.freeze(['reference', 'rsa-reference', 'expiry', 'valid', 'wrong-gateway',
  'duplicate-length', 'duplicate-hash', 'duplicate-other', 'invalid-length', 'missing-length', 'oversize-length',
  'missing-type', 'wrong-type', 'invalid-hash', 'changed-ca', 'malformed-der', 'nonminimal-der', 'ber-der', 'trailing-der',
  'expired-ca', 'leaf-ca', 'bad-key-usage', 'unsupported-key', 'restricted-eku', 'response-trailing', 'response-truncated',
  'transfer-encoding', 'content-encoding', 'trailer', 'location', 'upgrade', 'bad-cache', 'bad-connection',
  'redirect', 'informational', 'header-limit', 'field-limit', 'field-count', 'folded-header', 'bare-lf', 'timeout', 'drip', 'hold-eof']);
const format = 'http-freekit-interception-ca-fixture';
const hash = value => createHash('sha256').update(value).digest('base64url');
const fail = () => { throw safeError('interception_ca_fixture_failed'); };
const publicBytes = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,5462}$/.test(value)) fail();
  const bytes = Buffer.from(value, 'base64url'); if (bytes.length < 1 || bytes.length > 4096 || bytes.toString('base64url') !== value) fail(); return bytes;
};
function replacementCa(kind) {
  const f = createCryptoFixture({ utcMillis: Math.floor(Date.now() / 1000) * 1000 - (kind === 'expired-ca' ? 172800000 : 0) });
  const key = kind === 'unsupported-key' ? generateKeyPairSync('ec', { namedCurve: 'secp384r1' }) :
    kind === 'rsa-reference' ? generateKeyPairSync('rsa', { modulusLength: 2048 }) : f.authority;
  return f.certificate({ ca: true, key, signer: key, eku: kind === 'restricted-eku' ? undefined : null,
    ...(kind === 'bad-key-usage' ? { usage: Buffer.from('03020780', 'hex') } : {}),
    ...(kind === 'rsa-reference' ? { algorithm: Buffer.from('300d06092a864886f70d01010b0500', 'hex') } : {}) });
}
function responseBody(kind, certificate, metadata) {
  if (['changed-ca', 'expired-ca', 'bad-key-usage', 'unsupported-key', 'restricted-eku'].includes(kind)) return replacementCa(kind);
  if (kind === 'leaf-ca') return publicBytes(metadata.gatewayCertificateDer);
  if (kind === 'malformed-der') return Buffer.from([0x30, 0]);
  if (kind === 'trailing-der') return Buffer.concat([certificate, certificate]);
  if (kind === 'nonminimal-der' || kind === 'ber-der') {
    const count = certificate[1] & 0x80 ? certificate[1] & 0x7f : 0;
    const contents = certificate.subarray(2 + count);
    if (kind === 'ber-der') return Buffer.concat([Buffer.from([0x30, 0x80]), contents, Buffer.from([0, 0])]);
    const length = count ? certificate.subarray(2, 2 + count) : Buffer.from([certificate[1]]);
    return Buffer.concat([Buffer.from([0x30, 0x80 | length.length + 1, 0]), length, contents]);
  }
  return Buffer.from(certificate);
}
function wire(kind, body, expected) {
  let status = 'HTTP/1.1 200 OK';
  let headers = [['Content-Type', 'application/pkix-cert'], ['Content-Length', String(body.length)],
    ['X-FreeKit-CA-SHA256', expected], ['Cache-Control', 'no-store'], ['Connection', 'close']];
  const replace = (key, value) => { headers = headers.filter(([name]) => name !== key); if (value !== null) headers.push([key, value]); };
  if (kind === 'duplicate-length') headers.push(['content-length', String(body.length)]);
  if (kind === 'duplicate-hash') headers.push(['x-freekit-ca-sha256', expected]);
  if (kind === 'duplicate-other') headers.push(['X-Research', 'one'], ['x-research', 'two']);
  if (kind === 'invalid-length') replace('Content-Length', '0' + body.length);
  if (kind === 'missing-length') replace('Content-Length', null);
  if (kind === 'oversize-length') replace('Content-Length', '4097');
  if (kind === 'missing-type') replace('Content-Type', null);
  if (kind === 'wrong-type') replace('Content-Type', 'application/pkix-cert; charset=binary');
  if (kind === 'invalid-hash') replace('X-FreeKit-CA-SHA256', expected + '=');
  if (kind === 'bad-cache') replace('Cache-Control', 'public');
  if (kind === 'bad-connection') replace('Connection', 'keep-alive');
  for (const [profile, name, value] of [['transfer-encoding','Transfer-Encoding','chunked'], ['content-encoding','Content-Encoding','gzip'],
    ['trailer','Trailer','X-Research'], ['location','Location','https://unused.invalid/'], ['upgrade','Upgrade','websocket']]) if (kind === profile) headers.push([name, value]);
  if (kind === 'redirect') { status = 'HTTP/1.1 302 Found'; headers.push(['Location', 'https://unused.invalid/']); }
  if (kind === 'informational') status = 'HTTP/1.1 100 Continue';
  if (kind === 'header-limit') for (let i = 0; i < 10; i++) headers.push(['X-Research-' + i, 'a'.repeat(900)]);
  if (kind === 'field-limit') headers.push(['X-Research', 'a'.repeat(1200)]);
  if (kind === 'field-count') for (let i = 0; i < 28; i++) headers.push(['X-Research-' + i, 'a']);
  let header = status + '\r\n' + headers.map(([name, value]) => name + ': ' + value + '\r\n').join('');
  if (kind === 'folded-header') header += ' folded: bad\r\n';
  header += '\r\n'; if (kind === 'bare-lf') header = header.replaceAll('\r\n', '\n');
  const payload = kind === 'response-truncated' ? body.subarray(0, body.length - 1) : kind === 'response-trailing' ? Buffer.concat([body, Buffer.of(0)]) : body;
  return Buffer.concat([Buffer.from(header, 'ascii'), payload]);
}

/** Same existing trusted service seam; no new fixture authorization or issuer API. */
function hostileService({ tls: options, metadata, authorizeCertificate }, kind, certificate, body) {
  const sockets = new Map(), tasks = new Set(), timers = new Set(), writers = new Set();
  let server, closing = false, listenerClosed = false, closeTask, accepted = 0, secureConnections = 0, authorized = 0, requests = 0, responses = 0, publishedBytes = 0;
  const timer = (action, millis) => { const value = setTimeout(() => { timers.delete(value); action(); }, millis); timers.add(value); return value; };
  const ownSocket = socket => {
    socket.on('error', () => {}); if (sockets.has(socket)) return;
    const closed = observeClose(socket); sockets.set(socket, closed);
    closed.then(() => sockets.delete(socket)); if (closing) socket.destroy();
  };
  const snapshot = () => Object.freeze({ admissionClosed: closing, listenerClosed, accepted, secureConnections, authorized, requests, completedResponses: responses, publishedBytes,
    listeners: server?.listening ? 1 : 0, authenticatedSockets: sockets.size, proxySockets: 0,
    pendingCallbacks: [...writers].reduce((sum, state) => sum + state.pending, 0), timers: timers.size, workers: tasks.size, childrenJoined: true });
  const run = (socket, action) => {
    const task = action().catch(() => socket.destroy()).finally(() => tasks.delete(task)); tasks.add(task); return task;
  };
  const response = async socket => {
    const state = writerState(); writers.add(state);
    try {
      if (kind === 'timeout') return;
      if (kind === 'drip') {
        const bytes = Buffer.from('HTTP/1.1 200 OK\r\n', 'ascii');
        for (const byte of bytes) {
          await new Promise(done => { const handle = timer(done, 1000); observeClose(socket).then(() => { clearTimeout(handle); timers.delete(handle); done(); }); });
          if (closing || socket.destroyed) return; await write(socket, Buffer.of(byte), state); publishedBytes++;
        }
        return;
      }
      const encoded = wire(kind, body, kind === 'changed-ca' ? metadata.interceptionCaCertificateSha256 : hash(body));
      // Publish exactly the header budget without its terminator, then hold open.
      // A correct client rejects the bound rather than waiting for EOF or a read timeout.
      const payload = kind === 'header-limit' ? encoded.subarray(0, 8192) : encoded;
      await write(socket, payload, state); publishedBytes += payload.length;
      responses++;
      if (!['hold-eof','header-limit'].includes(kind)) await endWrite(socket, state);
    } finally {
      // A rejected write promise can precede its real callback. Retain that callback owner until it settles.
      await state.idle; if (state.pending !== 0) fail(); writers.delete(state);
    }
  };
  return Object.freeze({
    get port() { return server?.address()?.port ?? 0; }, snapshot,
    async initialize() {
      server = tls.createServer({ ...options, ALPNProtocols: ['http/1.1'] }, socket => {
        ownSocket(socket); secureConnections++;
        if (closing || socket.servername !== metadata.logicalName || socket.isSessionReused() || !socket.authorized) { socket.destroy(); return; }
        let bytes = Buffer.alloc(0), served = false;
        socket.on('data', chunk => {
          if (closing || served || bytes.length + chunk.length > 8192) { socket.destroy(); return; }
          bytes = Buffer.concat([bytes, chunk]); const end = bytes.indexOf('\r\n\r\n'); if (end < 0) return;
          served = true;
          run(socket, async () => {
            const text = bytes.subarray(0, end).toString('ascii'), lines = text.split('\r\n');
            if (end + 4 !== bytes.length || lines.shift() !== 'GET /companion/v1/ca HTTP/1.1' || lines.length > 32) { socket.destroy(); return; }
            const fields = new Map();
            for (const line of lines) {
              const match = /^([A-Za-z0-9-]+): ([\x20-\x7e]*)$/.exec(line);
              if (!match || line.length > 1024 || fields.has(match[1].toLowerCase())) { socket.destroy(); return; }
              fields.set(match[1].toLowerCase(), match[2]);
            }
            if ([...fields.keys()].some(key => !['host','accept','connection','content-length'].includes(key)) ||
                fields.get('host') !== metadata.logicalName + ':' + server.address().port || fields.get('accept') !== 'application/pkix-cert' ||
                fields.get('connection') !== 'close' || fields.has('content-length') && fields.get('content-length') !== '0') { socket.destroy(); return; }
            const grant = authorizeCertificate(socket.getPeerX509Certificate()?.raw)?.material();
            if (!grant) { socket.destroy(); return; }
            authorized++; requests++; await response(socket);
          });
        });
      });
      server.maxConnections = 4; server.on('error', () => {}); server.on('tlsClientError', () => {});
      server.on('connection', socket => { accepted++; ownSocket(socket); const deadline = timer(() => socket.destroy(), 25000);
        observeClose(socket).then(() => { clearTimeout(deadline); timers.delete(deadline); }); });
      server.once('close', () => { listenerClosed = true; });
      await bounded(new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); }), 5000);
    },
    invalidateEnrollment() { for (const socket of sockets.keys()) socket.destroy(); }, inspectEnrollment() { return null; },
    close() {
      if (closeTask) return closeTask; closing = true;
      closeTask = (async () => {
        for (const handle of timers) clearTimeout(handle); timers.clear();
        const closed = [...sockets].map(([socket, observed]) => { socket.destroy(); return observed; });
        const listener = server ? new Promise((done, reject) => server.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(safeError('interception_ca_fixture_failed')) : done())) : Promise.resolve();
        const results = await bounded(Promise.allSettled([listener, ...closed, ...tasks]), 5000);
        if (results.some(value => value.status !== 'fulfilled') || sockets.size || tasks.size || writers.size || timers.size) fail();
        return snapshot();
      })(); return closeTask;
    }, toJSON: snapshot, [inspect.custom]: () => '[Owned hostile CA response fixture]',
  });
}

export async function startInterceptionCaPeer({ scenario, openssl = process.env.OPENSSL_BIN ?? 'openssl' } = {}, { wrongGatewayAssets = enrollmentFixtureAssets } = {}) {
  if (!interceptionCaCases.includes(scenario)) fail();
  const temporary = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(temporary, 'freekit-interception-ca-'));
  fs.chmodSync(directory, 0o700);
  const data = path.join(directory, 'enrollment'); fs.mkdirSync(data, { mode: 0o700 });
  let fixture, metadata, certificate, body, hostile, wrong, enrollmentId, closing = false, closeTask, startTask, privateDirectoryRemoved = false, enrollStarted = false, startupUnjoined = false;
  const suppliedCa = scenario === 'rsa-reference' ? replacementCa('rsa-reference') : undefined;
  const jobs = new Set();
  const available = () => { if (closing || !fixture) fail(); };
  const track = operation => { const task = operation().finally(() => jobs.delete(task)); jobs.add(task); return task; };
  const open = async mode => {
    const old = metadata;
    startTask = startEnrollmentHttpsFixture({ directory: data, mode, openssl, ...(old ? { setupPort: old.setupPort, credentialPort: old.credentialPort } : {}),
      credentialLifetimeSeconds: scenario === 'expiry' ? 60 : 3600,
      ...(suppliedCa ? { interceptionCaCertificateDer: suppliedCa } : {}),
      ...(!['reference','rsa-reference','expiry'].includes(scenario) ? { authenticatedServiceFactory: async config => {
        const assets = await enrollmentFixtureAssets({ directory: data, mode: 'open', openssl, setupPort: config.metadata.setupPort, credentialPort: config.metadata.credentialPort });
        certificate = assets.interceptionCaDer(); body = responseBody(scenario, certificate, config.metadata);
        hostile = hostileService({ ...config, ...(wrong ? { tls: { ...config.tls, ...wrong.tlsOptions() } } : {}) }, scenario, certificate, body); return hostile;
      } } : {}) }).then(value => { fixture = value; return value; });
    await startTask; metadata = fixture.metadata().material();
    const assets = await enrollmentFixtureAssets({ directory: data, mode: 'open', openssl, setupPort: metadata.setupPort, credentialPort: metadata.credentialPort,
      ...(suppliedCa ? { interceptionCaCertificateDer: suppliedCa } : {}) });
    if (!hostile) { certificate = assets.interceptionCaDer(); body = responseBody(scenario, certificate, metadata); }
    if (old && JSON.stringify(old) !== JSON.stringify(metadata)) fail();
  };
  const snapshot = () => Object.freeze({ fixture: fixture?.snapshot() ?? null, hostile: hostile?.snapshot() ?? null, privateDirectoryRemoved });
  const close = () => {
    if (closeTask) return closeTask; closing = true;
    closeTask = (async () => {
      try { await startTask; } catch (error) { if (error?.joined === false) fail(); }
      if (fixture) await fixture.close();
      await Promise.allSettled([...jobs]);
      const state = fixture?.snapshot();
      if (state && (!state.closed || !state.storeClosed || !state.issuerChildrenJoined || state.activeSockets || state.pendingCallbacks || state.pendingTimers || state.workers)) fail();
      if (startupUnjoined) fail();
      if (path.dirname(directory) !== temporary || !path.basename(directory).startsWith('freekit-interception-ca-') || fs.realpathSync(directory) !== directory) fail();
      fs.rmSync(directory, { recursive: true, force: true }); privateDirectoryRemoved = !fs.existsSync(directory);
      if (!privateDirectoryRemoved) fail(); return snapshot();
    })(); return closeTask;
  };
  try {
    if (scenario === 'wrong-gateway') { const other = path.join(directory, 'wrong'); fs.mkdirSync(other, { mode: 0o700 });
      wrong = await wrongGatewayAssets({ directory: other, mode: 'create', openssl, setupPort: 0, credentialPort: 0 }); }
    await open('create');
  } catch (error) { startupUnjoined ||= error?.joined === false; await close(); fail(); }
  return Object.freeze({
    ready: () => ({ metadata: structuredClone(metadata), nodeVersion: process.version, nodeOpenSsl: process.versions.openssl, peerPort: hostile?.port ?? metadata.credentialPort,
      referenceCaDer: certificate.toString('base64url'), responseHash: hash(body) }),
    enroll(csr) { available(); if (enrollStarted) fail(); enrollStarted = true;
      return track(async () => {
        const bytes = publicBytes(csr), invitation = fixture.createInvitation().material();
        const response = await enrollmentRequest(fixture, '/companion/v1/pair', { protocolVersion: 1, type: 'pair', desktopId: metadata.desktopId,
          invitationId: invitation.invitationId, invitationSecret: invitation.invitationSecret, csrDer: bytes.toString('base64url'), deviceName: 'Public CA software research',
          capabilities: ['tcp-http','tcp-https-connect'] });
        enrollmentMessage('pair_response', response.material); if (response.status !== 200 || response.material.type !== 'pair_registered') fail();
        enrollmentId = response.material.enrollmentId; const approved = (await fixture.approve(enrollmentId)).material(); enrollmentMessage('status_response', approved);
        if (approved.type !== 'pair_approved' || approved.interceptionCaCertificateSha256 !== metadata.interceptionCaCertificateSha256) fail();
        return { registered: response.material, approved };
      });
    },
    pause() { available(); return track(async () => { await fixture.close(); return snapshot(); }); },
    reopen() { available(); return track(async () => { await fixture.close(); if (closing) fail(); await open('open'); return { ...snapshot(), ...this.ready() }; }); },
    revoke() { available(); if (!enrollmentId) fail(); const result = fixture.revoke(enrollmentId).material();
      if (result.type !== 'pair_ended' || result.code !== 'device_revoked') fail(); return { revoked: true }; },
    status() { available(); if (!enrollmentId) fail(); const value = fixture.readResult(enrollmentId).material();
      if (value.type === 'pair_approved') return { active: true, ended: null };
      if (value.type !== 'pair_ended' || !['device_revoked','credential_expired'].includes(value.code)) fail(); return { active: false, ended: value.code }; },
    snapshot, close, toJSON: () => '[Public CA private peer]', [inspect.custom]: () => '[Public CA private peer]',
  });
}

async function main() {
  let owner, terminal = false, count = 0, bytes = Buffer.alloc(0), total = 0, chain = Promise.resolve(), startup;
  const emit = async value => {
    const output = Buffer.from(JSON.stringify({ format, revision: 1, ...value }) + '\n'); if (output.length > 16384) fail();
    const state = writerState();
    try { for (let offset = 0; offset < output.length; offset += 8192) await bounded(write(process.stdout, output.subarray(offset, offset + 8192), state), 5000); }
    catch (error) { process.stdout.destroy(); throw error; }
    finally { await bounded(state.idle, 5000); if (state.pending !== 0) fail(); }
  };
  const stop = async failed => {
    if (terminal) return; terminal = true; process.stdin.pause(); clearTimeout(deadline);
    try { owner = owner ?? await startup; const snapshot = await owner?.close(); await emit({ event: failed ? 'failed' : 'closed', snapshot: snapshot ?? null }); }
    catch { failed = true; process.exitCode = 1; try { await emit({ event: 'failed', snapshot: null }); } catch { /* Failed output cannot acknowledge closure. */ } }
    finally { process.stdin.destroy(); }
    if (failed) process.exitCode = 1;
  };
  const deadline = setTimeout(() => { void stop(true); }, 180000);
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--case') fail();
    startup = startInterceptionCaPeer({ scenario: process.argv[3] }); owner = await startup; await emit({ event: 'ready', ...owner.ready() });
    process.stdin.on('data', chunk => {
      if (terminal) return; total += chunk.length; if (total > 262144 || bytes.length + chunk.length > 8192) { void stop(true); return; }
      bytes = Buffer.concat([bytes, chunk]);
      while (true) {
        const end = bytes.indexOf(10); if (end < 0) break;
        const input = bytes.subarray(0, end); bytes = bytes.subarray(end + 1);
        if (input.some(byte => byte < 32 || byte > 126)) { void stop(true); return; }
        const line = input.toString('ascii');
        let value;
        try { value = JSON.parse(line); if (JSON.stringify(value) !== line || ++count > 64 || !value || Array.isArray(value)) fail(); }
        catch { void stop(true); return; }
        if (Object.keys(value).join(',') === 'op' && value.op === 'stop') { void stop(false); return; }
        chain = chain.then(async () => {
          if (terminal) return;
          if (Object.keys(value).join(',') === 'op,csrDer' && value.op === 'enroll') await emit({ event: 'enrolled', ...await owner.enroll(value.csrDer) });
          else if (Object.keys(value).join(',') === 'op' && value.op === 'snapshot') await emit({ event: 'snapshot', snapshot: owner.snapshot() });
          else if (Object.keys(value).join(',') === 'op' && value.op === 'pause') await emit({ event: 'paused', snapshot: await owner.pause() });
          else if (Object.keys(value).join(',') === 'op' && value.op === 'reopen') await emit({ event: 'reopened', ...await owner.reopen() });
          else if (Object.keys(value).join(',') === 'op' && value.op === 'revoke') await emit({ event: 'revoked', ...owner.revoke() });
          else if (Object.keys(value).join(',') === 'op' && value.op === 'status') await emit({ event: 'status', ...owner.status() });
          else fail();
        }).catch(() => stop(true));
      }
    });
    process.stdin.once('end', () => { void stop(true); });
    for (const signal of ['SIGINT','SIGTERM']) process.once(signal, () => { void stop(true); });
  } catch { await stop(true); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
