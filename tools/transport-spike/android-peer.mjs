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

export async function startPeer({ openssl = process.env.OPENSSL_BIN ?? 'openssl' } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-android-node-'));
  fs.chmodSync(directory, 0o700);
  const sockets = new Set();
  const servers = [];
  let websocket;
  let closed = false;
  const command = args => execFileSync(openssl, args, { cwd: directory, timeout: 5000, maxBuffer: 16384, stdio: ['ignore', 'pipe', 'pipe'] });
  const cleanDirectory = () => {
    if (path.dirname(fs.realpathSync(directory)) !== fs.realpathSync(os.tmpdir()) || !path.basename(directory).startsWith('freekit-android-node-')) throw Error('Unsafe fixture directory');
    fs.rmSync(directory, { recursive: true, force: true });
  };
  const close = async () => {
    if (closed) return;
    closed = true;
    websocket?.clients.forEach(client => client.terminate());
    websocket?.close();
    sockets.forEach(socket => socket.destroy());
    await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
    cleanDirectory();
  };
  try {
    if (!/^OpenSSL 3\./.test(command(['version']).toString())) throw Error('OpenSSL 3 is required');
    fs.writeFileSync(path.join(directory, 'request.cnf'), '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=HTTP FreeKit test device\n');
    command(['req', '-config', 'request.cnf', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256', '-days', '1',
      '-subj', '/CN=Ephemeral research enrollment CA', '-keyout', 'ca-key.pem', '-out', 'ca.pem',
      '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    command(['req', '-config', 'request.cnf', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256', '-days', '1',
      '-subj', `/CN=${logicalName}`, '-keyout', 'server-key.pem', '-out', 'server.pem',
      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature',
      '-addext', 'extendedKeyUsage=serverAuth', '-addext', `subjectAltName=DNS:${logicalName}`]);
    for (const name of ['ca-key.pem', 'server-key.pem']) fs.chmodSync(path.join(directory, name), 0o600);
    fs.writeFileSync(path.join(directory, 'client.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n');
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
          fs.writeFileSync(path.join(directory, 'client.csr'), csr);
          command(['x509', '-req', '-inform', 'DER', '-in', 'client.csr', '-CA', 'ca.pem', '-CAkey', 'ca-key.pem',
            '-set_serial', `0x${randomBytes(16).toString('hex')}`, '-days', '1', '-sha256', '-copy_extensions', 'none',
            '-extfile', 'client.ext', '-out', 'client.pem']);
          const leaf = new X509Certificate(fs.readFileSync(path.join(directory, 'client.pem')));
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
    return { directory, close, command, metadata: { enrollmentPort: enrollment.address().port, webSocketPort: echo.address().port,
      gatewayDer: serverCertificate.raw.toString('base64url'), gatewayPin: createHash('sha256').update(serverCertificate.publicKey.export({ format: 'der', type: 'spki' })).digest('base64url') } };
  } catch (failure) { await close(); throw failure; }
}
