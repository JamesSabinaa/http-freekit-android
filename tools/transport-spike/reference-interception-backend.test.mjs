import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { duplexPair } from 'node:stream';
import { createReferenceInterceptionAssets } from './reference-interception-assets.mjs';
import { startReferenceInterceptionBackend } from './reference-interception-backend.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';

const host = 'reference-target.invalid', path = '/reference/proof';
const hash = value => createHash('sha256').update(value).digest('hex');
const expected = body => Buffer.from('reference-origin:' + hash(body));
const preface = mode => Buffer.from(`CONNECT 198.18.0.2:${mode === 'http' ? 80 : 443} HTTP/1.1\r\nHost: 198.18.0.2:${mode === 'http' ? 80 : 443}\r\n\r\n`);
const request = (body, extra = '') => Buffer.concat([Buffer.from(`POST ${path} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n${extra}\r\n`), body]);
const context = (mode, admissionAllowed = () => true) => ({ proxyMode: mode === 'http' ? 'http-origin-connect' : undefined,
  negotiatedCapabilities: ['tcp-http-origin-connect', 'tcp-https-connect'], admissionAllowed, grant: {} });
async function fixture(t, wrap = a => a) {
  const directory = await mkdtemp(join(tmpdir(), 'reference-backend-'));
  const assets = await createReferenceInterceptionAssets({ directory });
  let backend;
  try { backend = await startReferenceInterceptionBackend({ assets: wrap(assets) }); }
  catch (error) { await assets.close(); await rm(directory, { recursive: true }); throw error; }
  t.after(async () => {
    const snapshot = await backend.close();
    assert.equal(snapshot.closed, true);
    for (const field of ['activeOwners', 'activeSockets', 'activeRequests', 'listeners']) assert.equal(snapshot[field], 0, field);
    assert.equal(snapshot.ownersCreated, snapshot.ownersClosed);
    const material = await assets.close();
    assert.equal(material.closed, true); assert.equal(material.commandsStarted, material.commandsClosed);
    assert.equal(material.commandsStarted, material.processGroupsClosed);
    await rm(directory, { recursive: true });
  });
  return { backend, assets };
}
function collect(stream) {
  const chunks = [];
  stream.on('data', chunk => chunks.push(chunk));
  return new Promise((resolve, reject) => { stream.once('end', () => resolve(Buffer.concat(chunks))); stream.once('error', reject); });
}
async function acknowledge(transport, bytes) {
  const response = once(transport, 'data');
  transport.write(bytes);
  const [chunk] = await response;
  assert.equal(chunk.toString(), 'HTTP/1.1 200 Connection Established\r\n\r\n');
}
async function transaction(backend, assets, mode, body, { fragmented = false, coalesced = false, trust, servername = host } = {}) {
  const owner = backend.factory(context(mode)); await owner.start();
  if (fragmented) {
    const prefix = preface(mode);
    for (let i = 0; i < prefix.length - 1; i++) owner.transport.write(prefix.subarray(i, i + 1));
    await acknowledge(owner.transport, prefix.subarray(-1));
  } else if (coalesced && mode === 'http') {
    const received = collect(owner.transport);
    owner.transport.end(Buffer.concat([preface(mode), request(body)]));
    const all = await received; await owner.closed;
    return all.subarray(all.indexOf('\r\n\r\n') + 4);
  } else await acknowledge(owner.transport, preface(mode));
  let stream = owner.transport;
  if (mode === 'https') {
    stream = tls.connect({ socket: stream, servername, ca: trust ?? assets.caPem('interception'),
      rejectUnauthorized: true, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'] });
    // Attach the error observer before waiting for the handshake.
    stream.on('error', () => {});
    try { await once(stream, 'secureConnect'); }
    catch (error) { await owner.close(); throw error; }
    assert.equal(stream.authorized, true);
  }
  const received = collect(stream);
  // HTTP upload EOF must not discard the full response; TLS finishes with close_notify.
  if (mode === 'http') stream.end(request(body)); else stream.write(request(body));
  try {
    const result = await received;
    if (mode === 'https') stream.end();
    await owner.closed;
    return result;
  } catch (error) { await owner.close(); throw error; }
}
function assertResponse(response, body) {
  const separator = response.indexOf('\r\n\r\n');
  assert.match(response.subarray(0, separator).toString(), /^HTTP\/1.1 200 OK\r\n/);
  assert.equal(response.subarray(separator + 4).equals(expected(body)), true);
}
for (const mode of ['http', 'https']) test(`actual ${mode} origin computes exact body response and joins`, { timeout: 15000 }, async t => {
  const { backend, assets } = await fixture(t);
  const body = Buffer.from([0, 255, 13, 10, 65]);
  assertResponse(await transaction(backend, assets, mode, body, { fragmented: true }), body);
  const state = backend.snapshot();
  assert.equal(state.upstreamDials, 1);
  assert.equal(state[mode === 'http' ? 'upstreamHttpRequests' : 'upstreamHttpsRequests'], 1);
  assert.equal(state.interceptionTlsHandshakes, mode === 'https' ? 1 : 0);
  assert.equal(state.upstreamTlsHandshakes, mode === 'https' ? 1 : 0);
  const evidence = backend.evidence();
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].mode, mode); assert.equal(evidence[0].requestBytes, body.length); assert.equal(evidence[0].responseBytes, 81);
  assert.equal(evidence[0].requestSha256 === hash(body), true);
  assert.equal(evidence[0].responseSha256 === hash(expected(body)), true);
  evidence[0].requestBytes = 0; assert.equal(backend.evidence()[0].requestBytes, body.length);
});
test('coalesced HTTP preface and maximal body preserve bytes and EOF', { timeout: 15000 }, async t => {
  const { backend, assets } = await fixture(t), body = Buffer.alloc(4096, 201);
  assertResponse(await transaction(backend, assets, 'http', body, { coalesced: true }), body);
});
test('coalesced CONNECT and actual TLS ClientHello preserve handshake bytes', { timeout: 15000 }, async t => {
  const { backend, assets } = await fixture(t);
  const owner = backend.factory(context('https')); await owner.start();
  const [clientTransport, wire] = duplexPair({ allowHalfOpen: true, highWaterMark: 4096 });
  clientTransport.on('error', () => {}); wire.on('error', () => {});
  const hello = once(wire, 'data');
  const client = tls.connect({ socket: clientTransport, servername: host, ca: assets.caPem('interception'),
    rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] });
  client.on('error', () => {});
  try {
    const secure = once(client, 'secureConnect');
    const [helloBytes] = await hello; assert.equal(helloBytes.length <= 4096, true);
    await acknowledge(owner.transport, Buffer.concat([preface('https'), helloBytes]));
    owner.transport.pipe(wire); wire.pipe(owner.transport);
    await secure; assert.equal(client.authorized, true);
    const received = collect(client), body = Buffer.from('coalesced');
    client.write(request(body)); const response = await received; client.end();
    assertResponse(response, body); await owner.closed;
    assert.equal(backend.snapshot().upstreamTlsHandshakes, 1);
  } finally {
    client.destroy(); clientTransport.destroy(); wire.destroy(); await owner.close();
  }
});
for (const termination of ['end', 'deadline']) test(`clean TLS reply preserves raw upload until actual ${termination}`, { timeout: 15000 }, async t => {
  const { backend, assets } = await fixture(t);
  const owner = backend.factory(context('https')); await owner.start();
  await acknowledge(owner.transport, preface('https'));
  const [clientTransport, wire] = duplexPair({ allowHalfOpen: true, highWaterMark: 4096 });
  clientTransport.on('error', () => {}); wire.on('error', () => {});
  owner.transport.pipe(wire); wire.pipe(owner.transport, { end: false });
  const rawReadEof = once(owner.transport, 'end'), errors = [];
  owner.transport.on('error', error => errors.push(error.code));
  const localJoins = [clientTransport, wire].map(stream => new Promise(resolve => stream.once('close', resolve)));
  let joined = false;
  owner.closed.then(() => { joined = true; });
  const client = tls.connect({ socket: clientTransport, servername: host, ca: assets.caPem('interception'),
    rejectUnauthorized: true, allowHalfOpen: true, ALPNProtocols: ['http/1.1'] });
  localJoins.push(new Promise(resolve => client.once('close', resolve)));
  client.on('error', () => {});
  try {
    await once(client, 'secureConnect'); assert.equal(client.authorized, true);
    const reply = collect(client), body = Buffer.from('delayed-raw-end');
    client.write(request(body)); assertResponse(await reply, body);
    client.end(); await rawReadEof;
    // Drain queued TLS/raw close callbacks, without inventing upload EOF.
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(client.readableEnded, true); assert.equal(client.writableFinished, true);
    assert.equal(owner.transport.readableEnded, true);
    assert.equal(owner.transport.writableFinished, false);
    assert.equal(owner.transport.destroyed, false);
    assert.equal(joined, false); assert.equal(backend.snapshot().activeOwners, 1); assert.equal(errors.length, 0);
    await new Promise((resolve, reject) => owner.transport.write(Buffer.alloc(0), error => error ? reject(error) : resolve()));
    if (termination === 'end') {
      await new Promise((resolve, reject) => owner.transport.end(error => error ? reject(error) : resolve()));
    }
    await owner.closed;
    assert.equal(owner.transport.writableFinished, termination === 'end');
    assert.deepEqual(errors, termination === 'end' ? [] : ['backend_closed']);
    assert.equal(joined, true); assert.equal(backend.snapshot().activeOwners, 0);
  } finally {
    client.destroy(); clientTransport.destroy(); wire.destroy(); await owner.close(); await Promise.all(localJoins);
  }
});
for (const wrong of ['ca', 'hostname']) test(`incoming wrong ${wrong} never decrypts or dispatches`, { timeout: 15000 }, async t => {
  const { backend, assets } = await fixture(t);
  await assert.rejects(transaction(backend, assets, 'https', Buffer.from('private'),
    wrong === 'ca' ? { trust: assets.caPem('origin') } : { servername: 'other.invalid' }));
  assert.equal(backend.snapshot().interceptedHttpsRequests, 0);
  assert.equal(backend.snapshot().upstreamDials, 0);
  assert.deepEqual(backend.evidence(), []);
});
async function wrongHostnameIdentity(t, closeUsers) {
  const directory = await mkdtemp(join(tmpdir(), 'reference-hostname-'));
  await chmod(directory, 0o700);
  let key, cert;
  // Cleanup is conditional on the actual command/group join, not merely exit.
  let joined = false;
  t.after(async () => { await closeUsers(); key?.fill(0); if (joined) await rm(directory, { recursive: true }); });
  const keyPath = join(directory, 'key.pem'), certPath = join(directory, 'cert.pem');
  await writeFile(keyPath, '', { mode: 0o600 }); await writeFile(certPath, '', { mode: 0o600 });
  const command = await runDraftCommand('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt',
    'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1', '-subj', '/CN=wrong-reference.invalid',
    '-addext', 'subjectAltName=DNS:wrong-reference.invalid', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext', 'keyUsage=critical,digitalSignature,keyCertSign', '-addext', 'extendedKeyUsage=serverAuth',
    '-keyout', keyPath, '-out', certPath], { timeoutMillis: 5000, maxOutputBytes: 4096 });
  joined = command.closeObserved === true && command.processGroupClosed === true;
  assert.equal(joined, true); assert.equal(command.code, 0); assert.equal(Boolean(command.reason), false);
  key = await readFile(keyPath); cert = await readFile(certPath);
  // Positive control proves this exact identity is trusted when its real SAN is
  // requested, isolating hostname rejection from a certificate-chain failure.
  const server = tls.createServer({ key, cert, minVersion: 'TLSv1.2' });
  const sockets = new Set();
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); });
  server.on('secureConnection', socket => socket.end());
  server.on('tlsClientError', (_error, socket) => socket.destroy());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const client = tls.connect({ host: '127.0.0.1', port: server.address().port, ca: cert,
    servername: 'wrong-reference.invalid', rejectUnauthorized: true });
  client.on('error', () => {});
  try { await once(client, 'secureConnect'); assert.equal(client.authorized, true); }
  finally {
    const clientJoined = client.closed ? Promise.resolve() : once(client, 'close');
    client.destroy();
    const socketJoins = [...sockets].map(socket => { const closed = once(socket, 'close'); socket.destroy(); return closed; });
    await Promise.all([clientJoined, ...socketJoins, new Promise(resolve => server.close(resolve))]);
  }
  return { key, cert };
}
for (const wrong of ['ca', 'hostname']) test(`outgoing wrong ${wrong} refuses real TLS before origin request`, { timeout: 15000 }, async t => {
  let actualBackend;
  const identity = wrong === 'hostname' ? await wrongHostnameIdentity(t, () => actualBackend?.close()) : null;
  const { backend, assets } = await fixture(t, assets => ({
    caDer: role => assets.caDer(role),
    caPem: role => role === 'origin' ? identity?.cert ?? assets.caPem('interception') : assets.caPem(role),
    tlsOptions: role => ({ ...assets.tlsOptions(role), ...(role === 'origin' && identity ? identity : {}) }),
  }));
  actualBackend = backend;
  await assert.rejects(transaction(backend, assets, 'https', Buffer.from('private')));
  assert.equal(backend.snapshot().upstreamDials, 1);
  assert.equal(backend.snapshot().upstreamTlsHandshakes, 0);
  assert.equal(backend.snapshot().upstreamHttpsRequests, 0);
  assert.deepEqual(backend.evidence(), []);
});
test('invalid tuples, malformed and oversized prefaces never dial', { timeout: 15000 }, async t => {
  const { backend } = await fixture(t);
  for (const bytes of [Buffer.from('CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n'), Buffer.alloc(5000, 65),
    Buffer.from('CONNECT 198.18.0.2:443 HTTP/1.1\r\nHost: 198.18.0.2:443\r\n\r\n')]) {
    const owner = backend.factory(context('http')); await owner.start(); owner.transport.resume(); owner.transport.end(bytes); await owner.closed;
  }
  assert.equal(backend.snapshot().upstreamDials, 0); assert.equal(backend.snapshot().rejectedPrefaces, 3);
});
test('mode/capability mismatch, owner bound, cancellation and admission revocation', { timeout: 15000 }, async t => {
  const { backend } = await fixture(t);
  assert.throws(() => backend.factory({ ...context('https'), proxyMode: 'https' }));
  assert.throws(() => backend.factory({ ...context('http'), negotiatedCapabilities: ['tcp-https-connect'] }));
  let admitted = true;
  const one = backend.factory(context('http', () => admitted)), two = backend.factory(context('http'));
  assert.throws(() => backend.factory(context('http')));
  await one.start(); await two.start(); await two.close();
  await acknowledge(one.transport, preface('http'));
  admitted = false; one.transport.resume(); one.transport.end(request(Buffer.from('revoked'))); await one.closed;
  assert.equal(backend.snapshot().upstreamDials, 0);
});
test('single bounded request rejects duplicate headers, TE, trailers, wrong target and pipeline', { timeout: 15000 }, async t => {
  const { backend } = await fixture(t);
  const body = Buffer.from('x');
  for (const bytes of [request(body, `Host: ${host}\r\n`), request(body, 'Transfer-Encoding: chunked\r\n'),
    request(body, 'Trailer: x\r\n'), request(body, 'Upgrade: websocket\r\n'), request(body, 'Expect: 100-continue\r\n'),
    Buffer.from(request(body).toString().replace('POST ', 'GET ')),
    Buffer.from(request(body).toString().replace(`Host: ${host}`, 'Host: other.invalid')),
    Buffer.from(request(body).toString().replace(path, '/wrong')),
    Buffer.concat([request(body), request(body)]),
    Buffer.from(`POST ${path} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 4097\r\n\r\n`),
    request(body, 'X-Large: ' + 'a'.repeat(4096) + '\r\n')]) {
    const owner = backend.factory(context('http')); await owner.start(); await acknowledge(owner.transport, preface('http'));
    owner.transport.resume(); owner.transport.end(bytes); await owner.closed;
  }
  assert.equal(backend.snapshot().upstreamDials, 0);
});
test('asynchronous application admission is rechecked before the actual dial', { timeout: 15000 }, async t => {
  const { backend } = await fixture(t);
  let admitted = true;
  const owner = backend.factory(context('http', () => admitted)); await owner.start();
  await acknowledge(owner.transport, preface('http'));
  owner.transport.resume(); owner.transport.write(request(Buffer.from('revoked-before-dial')));
  admitted = false; owner.transport.end(); await owner.closed;
  assert.equal(backend.snapshot().interceptedHttpRequests, 1);
  assert.equal(backend.snapshot().upstreamDials, 0);
});
test('concurrent bound is not a lifetime cap and evidence is bounded private history', { timeout: 15000 }, async t => {
  const { backend, assets } = await fixture(t);
  for (let index = 0; index < 3; index++) {
    const body = Buffer.from([index]); assertResponse(await transaction(backend, assets, 'http', body), body);
  }
  assert.equal(backend.snapshot().ownersCreated, 3); assert.equal(backend.snapshot().ownersClosed, 3);
  assert.equal(backend.snapshot().upstreamHttpRequests, 3); assert.equal(backend.evidence().length, 2);
  const snapshot = backend.snapshot();
  assert.deepEqual(Object.keys(snapshot).sort(), ['ownersCreated', 'ownersClosed', 'activeOwners', 'activeSockets', 'activeRequests',
    'listeners', 'upstreamDials', 'interceptedHttpRequests', 'interceptedHttpsRequests', 'upstreamHttpRequests',
    'upstreamHttpsRequests', 'interceptionTlsHandshakes', 'upstreamTlsHandshakes', 'rejectedPrefaces', 'closed'].sort());
  assert.equal(JSON.stringify(backend).includes('Sha256'), false);
});
test('abort joins an outstanding transport callback with failure, not a write receipt', { timeout: 15000 }, async t => {
  const { backend } = await fixture(t);
  const owner = backend.factory(context('https'));
  let receipt;
  const callback = new Promise(resolve => owner.transport.write(Buffer.alloc(4096), error => { receipt = error; resolve(); }));
  await owner.close(); await callback;
  assert.equal(receipt instanceof Error, true); assert.equal(backend.snapshot().activeOwners, 0);
  assert.equal(backend.snapshot().upstreamDials, 0);
});
test('deadline closes incomplete preface and backend close joins never-started owners', { timeout: 15000 }, async t => {
  const { backend } = await fixture(t);
  const owner = backend.factory(context('http')); await owner.start(); owner.transport.write(Buffer.from('CON'));
  await owner.closed;
  backend.factory(context('https'));
  await backend.close(); assert.equal(backend.snapshot().closed, true);
  assert.throws(() => backend.factory(context('http')));
});
