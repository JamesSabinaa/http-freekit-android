// Isolated research peer. Never use these automatic enrollment routes in production.
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey, randomBytes, verify, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { WebSocketServer } from 'ws';

export const logicalName = 'android-node-research.invalid';
export const expectedTests = [
  'nonexportableIdentityEnrollsAndEchoes64KiB', 'wrongPinIsRejected',
  'wrongHostnameIsRejected', 'missingClientCertificateIsRejected',
];
export const FIXTURE_BACKDATE_SECONDS = 300;
export const FIXTURE_LIFETIME_SECONDS = 3600;
export const MAX_RESEARCH_CLOCK_SKEW_MILLIS = 120000;
export const MAX_CLOCK_PROBE_MILLIS = 5000;

export function fixtureValidity(nowMillis = Date.now()) {
  if (!Number.isSafeInteger(nowMillis) || nowMillis < 946684800000 || nowMillis > 4102444800000) throw Error('invalid_fixture_issue_epoch');
  const hostIssueEpochSeconds = Math.floor(nowMillis / 1000);
  return Object.freeze({ hostIssueEpochSeconds, notBeforeEpochSeconds: hostIssueEpochSeconds - FIXTURE_BACKDATE_SECONDS,
    notAfterEpochSeconds: hostIssueEpochSeconds + FIXTURE_LIFETIME_SECONDS });
}
export function measureFixtureClock(deviceEpochText, hostBeforeMillis, hostAfterMillis) {
  fixtureValidity(hostBeforeMillis); fixtureValidity(hostAfterMillis);
  if (!/^[0-9]{10}$/.test(deviceEpochText) || hostAfterMillis < hostBeforeMillis) throw Error('invalid_device_clock_probe');
  const deviceEpochSeconds = Number(deviceEpochText);
  const roundTripMillis = hostAfterMillis - hostBeforeMillis;
  const skewMillis = deviceEpochSeconds * 1000 - Math.floor((hostBeforeMillis + hostAfterMillis) / 2);
  return { fixtureClockStatus: roundTripMillis > MAX_CLOCK_PROBE_MILLIS ? 'probe_budget_exceeded'
    : Math.abs(skewMillis) > MAX_RESEARCH_CLOCK_SKEW_MILLIS ? 'skew_exceeds_bound' : 'within_bound',
    fixtureHostBeforeProbeEpochMillis: hostBeforeMillis, fixtureHostAfterProbeEpochMillis: hostAfterMillis,
    fixtureDeviceEpochSeconds: deviceEpochSeconds, fixtureClockRoundTripMillis: roundTripMillis, fixtureClockSkewMillis: skewMillis };
}
const opensslDate = epoch => new Date(epoch * 1000).toISOString().replace(/[-:]/g, '').replace('T', '').slice(0, 14) + 'Z';

// Small strict DER envelope reader for this fixture's PKCS#10 profile, not a general ASN.1 parser.
function item(bytes, offset, limit = bytes.length) {
  const start = offset;
  if (offset + 2 > limit) throw Error('invalid_der');
  const tag = bytes[offset++];
  let length = bytes[offset++];
  if (length & 128) {
    const count = length & 127;
    if (count < 1 || count > 2 || offset + count > limit || bytes[offset] === 0) throw Error('invalid_der');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
    if (length < 128) throw Error('invalid_der');
  }
  const end = offset + length;
  if (end > limit) throw Error('invalid_der');
  return { tag, start, content: offset, end, raw: bytes.subarray(start, end) };
}
function children(bytes, parent, count) {
  const result = [];
  let cursor = parent.content;
  while (cursor < parent.end && result.length < count) {
    const child = item(bytes, cursor, parent.end);
    result.push(child);
    cursor = child.end;
  }
  if (cursor !== parent.end || result.length !== count) throw Error('invalid_der');
  return result;
}
export function verifyRequest(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 4096) throw Error('invalid_csr');
  const outer = item(bytes, 0);
  if (outer.tag !== 0x30 || outer.end !== bytes.length) throw Error('invalid_csr');
  const [info, algorithm, signature] = children(bytes, outer, 3);
  if (info.tag !== 0x30 || !algorithm.raw.equals(Buffer.from('300a06082a8648ce3d040302', 'hex')) ||
      signature.tag !== 3 || signature.end - signature.content < 2 || bytes[signature.content] !== 0) throw Error('invalid_csr');
  const [version, subject, spki, attributes] = children(bytes, info, 4);
  if (!version.raw.equals(Buffer.from('020100', 'hex')) || subject.tag !== 0x30 || subject.raw.length > 512 ||
      spki.tag !== 0x30 || !attributes.raw.equals(Buffer.from('a000', 'hex'))) throw Error('invalid_csr');
  const key = createPublicKey({ key: spki.raw, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'prime256v1' ||
      !key.export({ format: 'der', type: 'spki' }).equals(spki.raw) ||
      !verify('sha256', info.raw, key, bytes.subarray(signature.content + 1, signature.end))) throw Error('invalid_csr');
  return key;
}

export async function startPeer({ openssl = process.env.OPENSSL_BIN ?? 'openssl', nowMillis = Date.now(), authenticatedServerFactory } = {}) {
  if (authenticatedServerFactory !== undefined && typeof authenticatedServerFactory !== 'function') throw Error('invalid_authenticated_factory');
  const validity = fixtureValidity(nowMillis);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-android-node-'));
  fs.chmodSync(directory, 0o700);
  const sockets = new Set();
  const servers = [];
  let websocket;
  let authenticatedServer;
  let closeTask;
  const command = args => execFileSync(openssl, args, { cwd: directory, timeout: 5000, maxBuffer: 16384, stdio: ['ignore', 'pipe', 'pipe'] });
  const cleanDirectory = () => {
    if (path.dirname(fs.realpathSync(directory)) !== fs.realpathSync(os.tmpdir()) || !path.basename(directory).startsWith('freekit-android-node-')) throw Error('Unsafe fixture directory');
    fs.rmSync(directory, { recursive: true, force: true });
  };
  const close = () => {
    if (closeTask) return closeTask;
    closeTask = (async () => {
      let extensionFailure = false;
      try { await authenticatedServer?.close(); } catch { extensionFailure = true; }
      websocket?.clients.forEach(client => client.terminate());
      websocket?.close();
      sockets.forEach(socket => socket.destroy());
      await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
      cleanDirectory();
      if (extensionFailure) throw Error('authenticated_fixture_cleanup_failed');
    })();
    return closeTask;
  };
  try {
    if (!/^OpenSSL 3\./.test(command(['version']).toString())) throw Error('OpenSSL 3 is required');
    fs.writeFileSync(path.join(directory, 'request.cnf'), '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=HTTP FreeKit test device\n');
    fs.mkdirSync(path.join(directory, 'issued'));
    fs.writeFileSync(path.join(directory, 'index.txt'), '');
    fs.writeFileSync(path.join(directory, 'serial'), randomBytes(16).toString('hex') + '\n');
    fs.writeFileSync(path.join(directory, 'issuer.cnf'), '[ca]\ndefault_ca=issuer\n[issuer]\n' +
      'database=index.txt\nnew_certs_dir=issued\nserial=serial\nprivate_key=ca-key.pem\ncertificate=ca.pem\n' +
      'default_md=sha256\ndefault_days=1\npolicy=names\nunique_subject=no\ncopy_extensions=none\n[names]\ncommonName=supplied\n' +
      '[authority]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' +
      `[gateway]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${logicalName}\n` +
      '[client]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n');
    const issue = (name, section, selfSign = false) => {
      command(['ca', '-config', 'issuer.cnf', '-batch', '-notext', '-md', 'sha256',
        '-startdate', opensslDate(validity.notBeforeEpochSeconds), '-enddate', opensslDate(validity.notAfterEpochSeconds),
        '-extensions', section, '-in', `${name}.csr.pem`, '-out', `${name}.pem`,
        ...(selfSign ? ['-selfsign', '-keyfile', `${name}-key.pem`] : [])]);
      const certificate = new X509Certificate(fs.readFileSync(path.join(directory, `${name}.pem`)));
      if (Date.parse(certificate.validFrom) !== validity.notBeforeEpochSeconds * 1000 ||
          Date.parse(certificate.validTo) !== validity.notAfterEpochSeconds * 1000) throw Error('fixture_validity_profile_mismatch');
      return certificate;
    };
    for (const [name, subject] of [['ca', 'Ephemeral research enrollment CA'], ['server', logicalName]]) {
      command(['req', '-config', 'request.cnf', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256',
        '-subj', `/CN=${subject}`, '-keyout', `${name}-key.pem`, '-out', `${name}.csr.pem`]);
      issue(name, name === 'ca' ? 'authority' : 'gateway', true);
    }
    for (const name of ['ca-key.pem', 'server-key.pem']) fs.chmodSync(path.join(directory, name), 0o600);
    const serverCertificate = new X509Certificate(fs.readFileSync(path.join(directory, 'server.pem')));
    const authority = new X509Certificate(fs.readFileSync(path.join(directory, 'ca.pem')));
    const tls = { key: fs.readFileSync(path.join(directory, 'server-key.pem')), cert: serverCertificate.toString(),
      minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', handshakeTimeout: 5000 };
    const enrolled = new Set();
    let busy = false;
    let enrollments = 0;
    const enrollment = https.createServer({ ...tls, maxHeaderSize: 8192, requestTimeout: 10000, headersTimeout: 10000 }, (request, response) => {
      const length = request.headers['content-length'];
      if (request.method !== 'POST' || request.url !== '/research/enroll') return response.writeHead(404).end();
      if (request.headers['content-type'] !== 'application/pkcs10' || request.headers['transfer-encoding'] ||
          !/^[1-9][0-9]{0,3}$/.test(length ?? '') || Number(length) > 4096) return response.writeHead(413).end();
      if (busy || enrollments >= 8) return response.writeHead(429).end();
      busy = true;
      const deadline = setTimeout(() => request.destroy(), 10000);
      response.once('close', () => clearTimeout(deadline));
      const chunks = [];
      let received = 0;
      request.on('data', bytes => {
        received += bytes.length;
        if (received > Number(length)) request.destroy(); else chunks.push(bytes);
      });
      request.on('error', () => { busy = false; });
      request.on('aborted', () => { busy = false; });
      request.on('end', () => {
        try {
          if (received !== Number(length)) throw Error('invalid_csr');
          const csr = Buffer.concat(chunks);
          const key = verifyRequest(csr);
          fs.writeFileSync(path.join(directory, 'client.csr.pem'), '-----BEGIN CERTIFICATE REQUEST-----\n' +
            csr.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE REQUEST-----\n');
          const leaf = issue('client', 'client');
          const spki = key.export({ format: 'der', type: 'spki' });
          if (!leaf.publicKey.export({ format: 'der', type: 'spki' }).equals(spki) || !leaf.verify(authority.publicKey)) throw Error('invalid_issued_key');
          if (authority.raw.length > 4096 || leaf.raw.length > 4096) throw Error('oversized_certificate');
          enrolled.add(createHash('sha256').update(spki).digest('hex'));
          enrollments++;
          const first = Buffer.alloc(5); first[0] = 1; first.writeUInt32BE(authority.raw.length, 1);
          const second = Buffer.alloc(4); second.writeUInt32BE(leaf.raw.length);
          const body = Buffer.concat([first, authority.raw, second, leaf.raw]);
          response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': body.length, connection: 'close' }).end(body);
        } catch { response.writeHead(400).end(); }
        finally { busy = false; }
      });
    });
    const echo = https.createServer({ ...tls, ca: authority.toString(), requestCert: true, rejectUnauthorized: true, maxHeaderSize: 8192 }, (_request, response) => response.writeHead(404).end());
    websocket = new WebSocketServer({ noServer: true, maxPayload: 65536, perMessageDeflate: false });
    echo.on('upgrade', (request, socket, head) => {
      const certificate = request.socket.getPeerX509Certificate();
      const hash = certificate && createHash('sha256').update(certificate.publicKey.export({ format: 'der', type: 'spki' })).digest('hex');
      if (!request.socket.authorized || !enrolled.has(hash) || request.url !== '/research/echo' || request.headers.origin) return socket.destroy();
      websocket.handleUpgrade(request, socket, head, client => {
        client.on('error', () => {});
        client.on('message', (bytes, binary) => {
          if (!binary) return client.close(1003, 'binary_required');
          if (client.bufferedAmount + bytes.length > 65536) return client.terminate();
          client.send(bytes, { binary: true }, error => { if (error) client.terminate(); });
        });
      });
    });
    for (const server of [enrollment, echo]) {
      servers.push(server);
      server.maxConnections = 16;
      server.setTimeout(server === enrollment ? 5000 : 10000, socket => socket.destroy());
      server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
      server.on('tlsClientError', () => {});
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    }
    if (authenticatedServerFactory) {
      // Trusted in-process research seam only. Key material never enters public metadata.
      const authorize = socket => {
        const certificate = socket.getPeerX509Certificate();
        return socket.authorized === true && !!certificate && enrolled.has(createHash('sha256')
          .update(certificate.publicKey.export({ format: 'der', type: 'spki' })).digest('hex'));
      };
      authenticatedServer = await authenticatedServerFactory({
        tls: Object.freeze({ ...tls, key: Buffer.from(tls.key), ca: authority.toString(), requestCert: true, rejectUnauthorized: true }),
        authorize,
      });
      if (!authenticatedServer || !Number.isInteger(authenticatedServer.port) || authenticatedServer.port < 1 ||
          authenticatedServer.port > 65535 || typeof authenticatedServer.close !== 'function') throw Error('invalid_authenticated_factory_result');
    }
    return { directory, close, command, validity, metadata: { enrollmentPort: enrollment.address().port, webSocketPort: echo.address().port,
      gatewayDer: serverCertificate.raw.toString('base64url'), gatewayPin: createHash('sha256').update(serverCertificate.publicKey.export({ format: 'der', type: 'spki' })).digest('base64url') } };
  } catch (failure) { await close(); throw failure; }
}
