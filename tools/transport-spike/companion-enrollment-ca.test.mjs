import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { createHash, generateKeyPairSync, randomBytes, sign, X509Certificate } from 'node:crypto';
import { setTimeout as pause } from 'node:timers/promises';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { enrollmentFixtureAssets } from './companion-enrollment-https-assets.mjs';
import { startEnrollmentIssuer } from './companion-enrollment-issuer.mjs';
import { createCryptoFixture, seq, tlv } from './companion-enrollment-crypto-fixtures.mjs';
import { enroll, tlsOptions } from './companion-enrollment-stream-client.mjs';

const root = fs.realpathSync(os.tmpdir());
const digest = bytes => createHash('sha256').update(bytes).digest('base64url');
const rejected = error => error.code === 'pairing_unavailable' && error.joined === true;
function directory(t) {
  const value = fs.mkdtempSync(path.join(root, 'freekit-public-ca-')); fs.chmodSync(value, 0o700);
  t.after(() => { assert(value.startsWith(root + path.sep)); fs.rmSync(value, { recursive: true, force: true }); }); return value;
}
function joined(snapshot) {
  assert(snapshot.closed && snapshot.admissionClosed && snapshot.listenersClosed && snapshot.storeClosed && snapshot.authorityClosed && snapshot.issuerChildrenJoined);
  for (const name of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers', 'bodyReaders', 'requestTasks', 'registrationWaiters']) assert.equal(snapshot[name], 0, name);
}
async function fixture(t, options = {}) {
  const dir = fs.mkdtempSync(path.join(root, 'freekit-public-ca-')); fs.chmodSync(dir, 0o700);
  let owner;
  t.after(async () => { if (owner) joined(await owner.close()); assert(dir.startsWith(root + path.sep)); fs.rmSync(dir, { recursive: true, force: true }); });
  owner = await startEnrollmentHttpsFixture({ directory: dir, mode: 'create', ...options });
  return { directory: dir, get owner() { return owner; },
    async reopen() { const m = owner.metadata().material(); joined(await owner.close()); owner = await startEnrollmentHttpsFixture({ directory: dir, mode: 'open', setupPort: m.setupPort, credentialPort: m.credentialPort, ...options }); } };
}
function head(owner, { role = 'credential', method = 'GET', route = '/companion/v1/ca', headers } = {}) {
  const m = owner.metadata().material(), port = role === 'setup' ? m.setupPort : m.credentialPort;
  return Buffer.from(`${method} ${route} HTTP/1.1\r\n` + (headers ?? `Host: ${m.logicalName}:${port}\r\nAccept: application/pkix-cert\r\nConnection: close\r\n`) + '\r\n');
}
async function connect(owner, credential, role = 'credential', extra = {}) {
  const m = owner.metadata().material(), socket = tls.connect({ ...tlsOptions(owner, credential, role === 'setup' ? m.setupPort : m.credentialPort), ...extra });
  socket.on('error', () => {}); const closed = new Promise(resolve => socket.once('close', resolve));
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { socket.destroy(); reject(Error('CA test TLS deadline')); }, 5000);
      socket.once('secureConnect', () => { clearTimeout(timer); resolve(); }); socket.once('error', () => { clearTimeout(timer); reject(Error('CA test TLS rejected')); });
    });
    return { socket, closed };
  } catch (error) { socket.destroy(); await closed; throw error; }
}
async function exchange(connection, request) {
  const { socket, closed } = connection; const chunks = []; let size = 0, ended = false, failure = false;
  const timer = setTimeout(() => socket.destroy(), 5000);
  socket.on('data', bytes => { size += bytes.length; if (size > 16384) { failure = true; socket.destroy(); } else chunks.push(bytes); });
  socket.once('error', () => { failure = true; }); socket.once('end', () => { ended = true; socket.end(); });
  try {
    await new Promise((resolve, reject) => socket.write(request, error => error ? reject(Error('CA test request failed')) : resolve()));
    await closed;
    return { bytes: Buffer.concat(chunks), ended, failure };
  } finally { clearTimeout(timer); socket.destroy(); await closed; }
}
async function request(owner, credential, options = {}) {
  return exchange(await connect(owner, credential, options.role, options.tls), head(owner, options));
}
function response(reply, status) {
  assert(reply.ended && !reply.failure, 'Actual bounded response EOF without I/O error');
  const split = reply.bytes.indexOf('\r\n\r\n'); assert(split >= 0 && split <= 8192);
  const lines = reply.bytes.subarray(0, split).toString('latin1').split('\r\n'); assert.match(lines.shift(), new RegExp(`^HTTP/1.1 ${status} `));
  const headers = {};
  for (const line of lines) { const at = line.indexOf(':'); assert(at > 0); const name = line.slice(0, at).toLowerCase(); assert(!Object.hasOwn(headers, name)); headers[name] = line.slice(at + 1).trim(); }
  const body = reply.bytes.subarray(split + 4); assert.equal(headers['content-length'], String(body.length)); assert.equal(headers.connection, 'close');
  for (const name of ['transfer-encoding', 'trailer', 'content-encoding', 'location', 'upgrade']) assert.equal(headers[name], undefined);
  return { headers, body };
}
function errorResponse(reply, status, code) {
  const r = response(reply, status); assert.equal(r.headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(r.body), { protocolVersion: 1, type: 'pair_error', code });
}
function caResponse(reply, expected) {
  const r = response(reply, 200); assert.equal(r.headers['content-type'], 'application/pkix-cert'); assert.equal(r.headers['cache-control'], 'no-store');
  assert(r.body.length > 0 && r.body.length <= 4096); assert.equal(r.headers['x-freekit-ca-sha256'], expected); assert.equal(digest(r.body), expected);
  const cert = new X509Certificate(r.body); assert(cert.raw.equals(r.body) && cert.ca && cert.verify(cert.publicKey)); return r.body;
}
// Software public-profile cases, with genuinely signed P256/RSA certificates.
function certificate({ pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), ca = true, usage = '03020106', eku = null,
  before = Date.now() - 60000, after = Date.now() + 3600000, signer = pair } = {}) {
  const algorithm = pair.privateKey.asymmetricKeyType === 'rsa' ? Buffer.from('300d06092a864886f70d01010b0500', 'hex') : Buffer.from('300a06082a8648ce3d040302', 'hex');
  const subject = seq(tlv(49, seq(tlv(6, Buffer.from('550403', 'hex')), tlv(12, Buffer.from('A23 public software CA')))));
  const time = value => tlv(23, Buffer.from(new Date(value).toISOString().replace(/[-:]/g, '').replace('T', '').replace('.000Z', 'Z').slice(2)));
  const ext = (oid, value) => seq(tlv(6, Buffer.from(oid, 'hex')), Buffer.from('0101ff', 'hex'), tlv(4, Buffer.from(value, 'hex')));
  const extensions = [ext('551d13', ca ? '30030101ff' : '3000'), ...(usage === null ? [] : [ext('551d0f', usage)]), ...(eku === null ? [] : [ext('551d25', eku)])];
  const info = seq(Buffer.from('a003020102', 'hex'), Buffer.from('020101', 'hex'), algorithm, subject, seq(time(Math.floor(before / 1000) * 1000), time(Math.floor(after / 1000) * 1000)), subject,
    pair.publicKey.export({ format: 'der', type: 'spki' }), tlv(163, seq(...extensions)));
  return seq(info, algorithm, tlv(3, Buffer.concat([Buffer.of(0), sign('sha256', info, signer.privateKey)])));
}

test('actual authenticated CA DER/hash survives reopen and public asset snapshots never alias retained state', { timeout: 15000 }, async t => {
  const f = await fixture(t), credential = await enroll(f.owner, createCryptoFixture());
  const m = f.owner.metadata().material(), expected = credential.approved.interceptionCaCertificateSha256;
  assert.equal(expected, m.interceptionCaCertificateSha256);
  const first = caResponse(await request(f.owner, credential), expected);
  const assets = await enrollmentFixtureAssets({ directory: f.directory, mode: 'open', openssl: process.env.OPENSSL_BIN ?? 'openssl', setupPort: m.setupPort, credentialPort: m.credentialPort });
  const copy = assets.interceptionCaDer(); assert(copy.equals(first)); copy.fill(0); assert(assets.interceptionCaDer().equals(first));
  const probe = response(await request(f.owner, credential, { route: '/research/enrollment/credential', headers: `Host: ${m.logicalName}:${m.credentialPort}\r\nConnection: close\r\n` }), 200);
  assert.equal(probe.body.toString(), '{"type":"credential_admitted"}'); assert.equal(probe.headers['content-type'], 'application/json');
  await f.reopen(); assert(caResponse(await request(f.owner, credential), expected).equals(first));
  caResponse(await request(f.owner, credential, { headers: `Host: ${m.logicalName}:${m.credentialPort}\r\nAccept: application/pkix-cert\r\nConnection: close\r\nContent-Length: 0\r\n` }), expected);
});

test('CA requests require each exact current leaf, not merely an enrollment-CA signature or earlier admission', { timeout: 15000 }, async t => {
  const f = await fixture(t), crypto = createCryptoFixture(), credential = await enroll(f.owner, crypto);
  const missing = await request(f.owner, null).catch(() => null); assert(!missing || missing.bytes.length === 0);
  const issuer = await startEnrollmentIssuer({ directory: f.directory, enrollmentAuthorityDer: f.owner.metadata().material().enrollmentAuthorityDer });
  let other;
  try {
    const now = Math.floor(Date.now() / 1000) * 1000;
    other = await issuer.issue({ material: () => ({ desktopId: credential.approved.desktopId, invitationId: credential.invitationId, enrollmentId: credential.enrollmentId,
      deviceId: 'dev_' + randomBytes(32).toString('base64url'), generation: 1, token: randomBytes(32).toString('base64url'), serial: '999',
      deviceSpkiDer: crypto.deviceSpkiDer.toString('base64url'), deviceSpkiSha256: digest(crypto.deviceSpkiDer), csrDer: crypto.csr().toString('base64url'), capabilities: ['tcp-http'],
      notBefore: new Date(now).toISOString().replace('.000Z', 'Z'), notAfter: new Date(now + 600000).toISOString().replace('.000Z', 'Z'), subject: 'CN=HTTP FreeKit device', profile: 'p256-client-auth-v1' }) });
  } finally { await issuer.close(); }
  const unpublished = { key: credential.key, cert: new X509Certificate(Buffer.from(other.material().clientCertificateDer, 'base64url')).toString() };
  errorResponse(await request(f.owner, unpublished), 403, 'authentication_failed');
  caResponse(await request(f.owner, credential), credential.approved.interceptionCaCertificateSha256);
  const admittedBeforeRevoke = await connect(f.owner, credential);
  assert.equal(f.owner.revoke(credential.enrollmentId).material().code, 'device_revoked');
  errorResponse(await exchange(admittedBeforeRevoke, head(f.owner)), 403, 'authentication_failed');
  errorResponse(await request(f.owner, credential), 403, 'authentication_failed');
  const independent = await enroll(f.owner, createCryptoFixture());
  caResponse(await request(f.owner, independent), independent.approved.interceptionCaCertificateSha256);
});

test('CA route strictly refuses setup, methods, targets, duplicate/extra headers and body framing', { timeout: 15000 }, async t => {
  const f = await fixture(t), credential = await enroll(f.owner, createCryptoFixture()), m = f.owner.metadata().material();
  errorResponse(await request(f.owner, null, { role: 'setup' }), 400, 'invalid_message');
  for (const options of [{ method: 'POST' }, { route: '/companion/v1/ca?x=1' }, { route: '/companion/v1/ca/' },
    ...['', 'Accept: */*\r\n', 'Accept: application/pkix-cert\r\nAccept: application/pkix-cert\r\n', 'Accept: application/pkix-cert\r\nCookie: x\r\n',
      'Accept: application/pkix-cert\r\nX-Unrequested: x\r\n', 'Accept: application/pkix-cert\r\nContent-Length: 1\r\n',
      'Accept: application/pkix-cert\r\nContent-Length: 00\r\n'].map(extra => ({ headers: `Host: ${m.logicalName}:${m.credentialPort}\r\nConnection: close\r\n${extra}` })),
    { headers: `Host: ${m.logicalName}:${m.credentialPort}\r\nAccept: application/pkix-cert\r\nConnection: keep-alive\r\n` }]) {
    errorResponse(await request(f.owner, credential, options), 400, 'invalid_message');
  }
  for (const extra of ['Transfer-Encoding: chunked\r\n', 'Trailer: x\r\n', 'Origin: https://untrusted.invalid\r\n', 'Authorization: Bearer x\r\n']) {
    const result = await request(f.owner, credential, { headers: `Host: ${m.logicalName}:${m.credentialPort}\r\nAccept: application/pkix-cert\r\nConnection: close\r\n${extra}` });
    if (result.bytes.length) errorResponse(result, 400, 'invalid_message');
  }
  const wrongHost = await request(f.owner, credential, { tls: { servername: 'different.invalid' } }).catch(() => null); assert(!wrongHost || wrongHost.bytes.length === 0);
  caResponse(await request(f.owner, credential), m.interceptionCaCertificateSha256);
});

test('CA assets accept signed RSA bounds/P256 and absent KU, but reject non-signing KU and malformed or unapproved replacements', { timeout: 20000 }, async t => {
  const absentKu = certificate({ usage: null }), rsa2048 = certificate({ pair: generateKeyPairSync('rsa', { modulusLength: 2048 }) });
  const f = await fixture(t, { interceptionCaCertificateDer: rsa2048 }), credential = await enroll(f.owner, createCryptoFixture());
  assert(caResponse(await request(f.owner, credential), digest(rsa2048)).equals(rsa2048));
  const m = f.owner.metadata().material(), pemPath = path.join(f.directory, 'interception.pem'), original = fs.readFileSync(pemPath);
  const badKu = certificate({ usage: '03020780' });
  // The public property is EKU, not KU. Actual Node24/OpenSSL rejects CA:true
  // with only digitalSignature through ca/X509_check_ca, even without any EKU.
  assert.equal(new X509Certificate(badKu).keyUsage, undefined); assert.equal(new X509Certificate(badKu).ca, false);
  assert.equal(rsa2048[1], 130);
  const overlongDer = Buffer.concat([Buffer.from([48, 131, 0]), rsa2048.subarray(2)]);
  const malformed = [overlongDer, Buffer.concat([rsa2048, Buffer.of(0)]), Buffer.alloc(4097), certificate({ ca: false }), badKu,
    certificate({ after: Date.now() - 1000 }), certificate({ before: Date.now() + 60000 }),
    certificate({ signer: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }) }),
    certificate({ pair: generateKeyPairSync('rsa', { modulusLength: 1024 }) }),
    certificate({ pair: generateKeyPairSync('ec', { namedCurve: 'secp384r1' }) }), certificate({ eku: '300a06082b06010505070302' })];
  for (const bytes of malformed) await assert.rejects(enrollmentFixtureAssets({ directory: directory(t), mode: 'create', openssl: process.env.OPENSSL_BIN ?? 'openssl', setupPort: 0, credentialPort: 0, interceptionCaCertificateDer: bytes }), rejected);
  const second = await fixture(t, { interceptionCaCertificateDer: absentKu });
  const secondCredential = await enroll(second.owner, createCryptoFixture()); caResponse(await request(second.owner, secondCredential), digest(absentKu));
  const upper = certificate({ pair: generateKeyPairSync('rsa', { modulusLength: 4096 }) });
  const assets = await enrollmentFixtureAssets({ directory: directory(t), mode: 'create', openssl: process.env.OPENSSL_BIN ?? 'openssl', setupPort: 0, credentialPort: 0, interceptionCaCertificateDer: upper });
  assert(assets.interceptionCaDer().equals(upper));
  for (const bytes of [Buffer.from('corrupt'), Buffer.concat([original, original]), Buffer.from(new X509Certificate(absentKu).toString()), Buffer.from(new X509Certificate(badKu).toString()), Buffer.from(new X509Certificate(certificate({ after: Date.now() - 1000 })).toString())]) {
    fs.writeFileSync(pemPath, bytes, { mode: 0o600 }); errorResponse(await request(f.owner, credential), 503, 'pairing_unavailable');
    assert.equal(f.owner.metadata().material().interceptionCaCertificateSha256, m.interceptionCaCertificateSha256);
  }
  fs.writeFileSync(pemPath, original, { mode: 0o600 }); caResponse(await request(f.owner, credential), m.interceptionCaCertificateSha256);
  await f.reopen(); caResponse(await request(f.owner, credential), m.interceptionCaCertificateSha256);
});

test('real credential expiry denies a previously completed mTLS handshake and fresh CA admission without changing approved trust', { timeout: 75000 }, async t => {
  const f = await fixture(t, { credentialLifetimeSeconds: 60 }), credential = await enroll(f.owner, createCryptoFixture());
  const expected = credential.approved.interceptionCaCertificateSha256;
  caResponse(await request(f.owner, credential), expected);
  const expires = Date.parse(new X509Certificate(credential.cert).validTo);
  while (Date.now() < expires - 1000) await pause(Math.min(250, expires - 1000 - Date.now()));
  const beforeExpiry = await connect(f.owner, credential);
  while (Date.now() < expires) await pause(Math.min(25, expires - Date.now()));
  errorResponse(await exchange(beforeExpiry, head(f.owner)), 403, 'authentication_failed');
  const fresh = await request(f.owner, credential).catch(() => null); assert(!fresh || fresh.bytes.length === 0);
  assert.equal(f.owner.metadata().material().interceptionCaCertificateSha256, expected);
});
