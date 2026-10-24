// Host-test client only. Android implements its own credential/socket/model adapter.
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import tls from 'node:tls';
import { performance } from 'node:perf_hooks';
import { logicalName } from './android-peer.mjs';
import { ResearchWebSocket } from './research-websocket.mjs';
import { decodeControl, decodeStream, encodeControl, encodeStream } from './companion-protocol-codec.mjs';
import { headers, write, observeClose, bounded, safeError } from './companion-stream-peer-io.mjs';
import { COMMANDS } from './companion-stream-peer-schema.mjs';

const lookup = (_host, options, callback) => options.all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4);
function redacted(value, kind) {
  Object.defineProperty(value, Symbol.for('nodejs.util.inspect.custom'), { value: () => `${kind}([REDACTED])` });
  Object.defineProperty(value, 'toJSON', { value: () => ({ kind }) });
  return value;
}
export async function http(peer, credential, method, pathname, token, body = Buffer.alloc(0), extraHeaders = {}) {
  const options = { hostname: logicalName, port: pathname === '/research/enroll' ? peer.metadata.enrollmentPort : peer.metadata.webSocketPort,
    ca: new X509Certificate(Buffer.from(peer.metadata.gatewayDer, 'base64url')).toString(), lookup, agent: false,
    ...(credential ? { key: credential.key, cert: credential.cert } : {}), method, path: pathname,
    headers: { host: logicalName, connection: 'close', ...(token ? { 'X-FreeKit-Session': token } : {}),
      ...(method === 'POST' ? { 'content-type': pathname === '/research/enroll' ? 'application/pkcs10' : 'application/json', 'content-length': body.length } : {}), ...extraHeaders } };
  return bounded(new Promise((done, reject) => {
    const request = https.request(options, response => {
      const chunks = []; let count = 0;
      response.on('data', bytes => { count += bytes.length; if (count > 8201) request.destroy(); else chunks.push(bytes); });
      response.on('error', () => reject(safeError('host_http_failed')));
      response.on('end', () => done({ status: response.statusCode, bytes: Buffer.concat(chunks) }));
    });
    request.on('error', () => reject(safeError('host_http_failed')));
    request.setTimeout(5000, () => request.destroy());
    request.end(body);
  }), 6000, 'host_http_timeout');
}

export async function enrollHost(peer, name = 'host') {
  if (!/^[a-z]{1,16}$/.test(name)) throw safeError('invalid_host_fixture_name');
  peer.command(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256',
    '-config', 'request.cnf', '-keyout', `${name}-key.pem`, '-outform', 'DER', '-out', `${name}.csr`]);
  fs.chmodSync(path.join(peer.directory, `${name}-key.pem`), 0o600);
  const reply = await http(peer, null, 'POST', '/research/enroll', null, fs.readFileSync(path.join(peer.directory, `${name}.csr`)));
  if (reply.status !== 200 || reply.bytes[0] !== 1) throw safeError('host_enrollment_failed');
  const caLength = reply.bytes.readUInt32BE(1), leafLength = reply.bytes.readUInt32BE(5 + caLength);
  if (caLength < 1 || caLength > 4096 || leafLength < 1 || leafLength > 4096 || 9 + caLength + leafLength !== reply.bytes.length) {
    throw safeError('host_enrollment_failed');
  }
  const leaf = new X509Certificate(reply.bytes.subarray(9 + caLength));
  const credential = { key: fs.readFileSync(path.join(peer.directory, `${name}-key.pem`)), cert: leaf.toString(),
    deviceId: 'dev_' + createHash('sha256').update(leaf.publicKey.export({ type: 'spki', format: 'der' })).digest('base64url') };
  return redacted(credential, 'HostCredential');
}

export async function connectTls(peer, credential) {
  const socket = tls.connect({ host: '127.0.0.1', port: peer.metadata.webSocketPort, servername: logicalName,
    ca: new X509Certificate(Buffer.from(peer.metadata.gatewayDer, 'base64url')).toString(),
    ...(credential ? { cert: credential.cert, key: credential.key } : {}), rejectUnauthorized: true });
  socket.on('error', () => {});
  const closed = observeClose(socket);
  try {
    await bounded(new Promise((done, reject) => {
      socket.once('secureConnect', done); socket.once('error', () => reject(safeError('host_tls_failed')));
    }), 5000, 'host_tls_timeout');
    socket.setNoDelay(true);
    const peerCertificate = socket.getPeerX509Certificate();
    if (createHash('sha256').update(peerCertificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64url') !== peer.metadata.gatewayPin) {
      throw safeError('host_pin_failed');
    }
    return socket;
  } catch (failure) { socket.destroy(); await closed; throw failure; }
}

export async function upgrade(peer, credential, route, { scenario, token, extra = [], tail = Buffer.alloc(0), key: suppliedKey, version = '13' } = {}) {
  const socket = await connectTls(peer, credential);
  const key = suppliedKey === undefined ? randomBytes(16).toString('base64') : suppliedKey;
  const lines = [`GET ${route} HTTP/1.1`, `Host: ${logicalName}`, 'Upgrade: websocket', 'Connection: Upgrade',
    ...(key === null ? [] : [`Sec-WebSocket-Key: ${key}`]), `Sec-WebSocket-Version: ${version}`,
    ...(scenario ? [`X-FreeKit-Research-Scenario: ${scenario}`] : []), ...(token ? [`X-FreeKit-Session: ${token}`] : []), ...extra];
  try {
    await write(socket, Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n\r\n'), tail]));
    const head = (await bounded(headers(socket), 5000, 'host_upgrade_timeout')).toString('ascii');
    const status = Number(/^HTTP\/1\.1 ([0-9]{3}) /.exec(head)?.[1]);
    if (status !== 101) { const closed = observeClose(socket); socket.destroy(); await closed; return { status }; }
    const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    if (!head.includes(`Sec-WebSocket-Accept: ${accept}\r\n`)) throw safeError('host_upgrade_failed');
    return redacted({ status, socket, ws: new ResearchWebSocket(socket, { role: 'client', maxBinaryBytes: 4096 }) }, 'HostConnection');
  } catch (failure) { socket.destroy(); await observeClose(socket); throw failure; }
}

export async function nextApplication(connection) {
  while (true) {
    const event = await connection.ws.next();
    if (event.kind === 'ping' || event.kind === 'pong') {
      try { if (event.kind === 'ping') await connection.ws.send('pong', event.copyBytes()); }
      finally { event.release(); }
    } else return event;
  }
}

export async function control(peer, credential, scenario) {
  const connection = await upgrade(peer, credential, '/companion/v1/control', { scenario });
  if (connection.status !== 101) throw safeError('host_control_failed');
  await connection.ws.send('text', encodeControl({ protocolVersion: 1, type: 'hello', capabilities: ['tcp-http', 'tcp-https-connect'], requiredCapabilities: ['tcp-http'] }));
  const event = await nextApplication(connection);
  let ready;
  try {
    if (event.kind !== 'text') throw safeError('host_readiness_failed');
    ready = decodeControl(event.copyBytes()).toWire();
    if (ready.type !== 'session_ready') throw safeError('host_readiness_failed');
  } finally { event.release(); }
  connection.token = ready.sessionId;
  connection.ready = ready;
  connection.pump = (async () => {
    while (!connection.socket.destroyed) {
      const frame = await connection.ws.next();
      try {
        if (frame.kind === 'ping') await connection.ws.send('pong', frame.copyBytes());
        else if (frame.kind !== 'pong') throw safeError('host_control_ended');
      } finally { frame.release(); }
    }
  })().catch(() => {});
  connection.probe = async () => {
    const result = await http(peer, credential, 'GET', '/research/probe', connection.token);
    if (result.status !== 200 || result.bytes.length > 4096) throw safeError('host_probe_failed');
    return JSON.parse(result.bytes.toString('utf8'));
  };
  connection.command = command => http(peer, credential, 'POST', '/research/command', connection.token, Buffer.from(COMMANDS[command]));
  connection.cancel = async () => {
    if (!connection.socket.destroyed) {
      try { await connection.ws.send('text', encodeControl({ protocolVersion: 1, type: 'cancel' })); } catch { /* Peer may already have expired. */ }
      // A write callback is not remote consumption: observe the real model transition
      // through the separate authenticated probe before closing this control transport.
      await until(connection.probe, value => ['closed', 'failed'].includes(value.control.phase));
    }
    await connection.ws.cancel(); await connection.pump;
  };
  return connection;
}

export async function stream(peer, credential, control, id = 'stream') {
  const connection = await upgrade(peer, credential, '/companion/v1/streams', { token: control.token });
  if (connection.status !== 101) throw safeError('host_stream_failed');
  connection.id = id;
  await connection.ws.send('text', encodeStream({ protocolVersion: 1, type: 'open', streamId: id }));
  const event = await nextApplication(connection);
  try {
    if (event.kind !== 'text' || decodeStream(event.copyBytes()).toWire().type !== 'ready') throw safeError('host_stream_failed');
  } finally { event.release(); }
  return connection;
}

export async function until(operation, predicate, milliseconds = 5000) {
  const end = performance.now() + milliseconds;
  while (true) {
    const value = await operation();
    if (predicate(value)) return value;
    if (performance.now() >= end) throw safeError('host_observation_timeout');
    await new Promise(done => setTimeout(done, 20));
  }
}
