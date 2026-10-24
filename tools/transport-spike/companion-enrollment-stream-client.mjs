// Owned host-test client only; software keys never leave its private TEMP fixture.
import https from 'node:https';
import tls from 'node:tls';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { ResearchWebSocket } from './research-websocket.mjs';
import { headers, write, observeClose, bounded, safeError } from './companion-stream-peer-io.mjs';
import { nextApplication } from './companion-stream-peer-client.mjs';
import { encodeControl, encodeStream, decodeControl } from './companion-protocol-codec.mjs';

export function tlsOptions(fixture, credential, port) {
  const m = fixture.metadata().material();
  return { host: '127.0.0.1', port, servername: m.logicalName, rejectUnauthorized: true,
    ca: new X509Certificate(Buffer.from(m.gatewayCertificateDer, 'base64url')).toString(),
    ...(credential ? { key: credential.key, cert: credential.cert } : {}) };
}
export async function enroll(fixture, crypto) {
  const m = fixture.metadata().material(), invitation = fixture.createInvitation().material();
  const body = Buffer.from(JSON.stringify({ protocolVersion: 1, type: 'pair', desktopId: m.desktopId,
    invitationId: invitation.invitationId, invitationSecret: invitation.invitationSecret, csrDer: crypto.csr().toString('base64url'),
    deviceName: 'Enrolled stream software research', capabilities: ['tcp-http', 'tcp-https-connect'] }));
  const registration = await bounded(new Promise((resolve, reject) => {
    const request = https.request({ ...tlsOptions(fixture, null, m.setupPort), agent: false, method: 'POST', path: '/companion/v1/pair',
      headers: { host: `${m.logicalName}:${m.setupPort}`, 'content-type': 'application/json', 'content-length': body.length, connection: 'close' } }, reply => {
      const chunks = []; let count = 0;
      reply.on('data', chunk => { count += chunk.length; if (count > 16384) reply.destroy(); else chunks.push(chunk); });
      reply.on('error', () => reject(safeError('enrollment_client_failed')));
      reply.on('end', () => { if (reply.statusCode === 200) resolve(JSON.parse(Buffer.concat(chunks))); else reject(safeError('enrollment_client_failed')); });
    });
    request.on('error', () => reject(safeError('enrollment_client_failed'))); request.setTimeout(5000, () => request.destroy()); request.end(body);
  }), 6000);
  const approved = (await fixture.approve(registration.enrollmentId)).material();
  return { approved, enrollmentId: registration.enrollmentId, key: crypto.device.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    cert: new X509Certificate(Buffer.from(approved.clientCertificateDer, 'base64url')).toString() };
}
export async function upgradeEnrolled(fixture, credential, path, { token, scenario = path.endsWith('/control') ? 'cancel' : undefined, ...extraTls } = {}) {
  const m = fixture.metadata().material(), socket = tls.connect({ ...tlsOptions(fixture, credential, m.webSocketPort), ...extraTls });
  socket.on('error', () => {}); const closed = observeClose(socket);
  try {
    await bounded(new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', () => reject(safeError('enrolled_tls_failed'))); }), 5000);
    const key = randomBytes(16).toString('base64');
    await write(socket, Buffer.from(`GET ${path} HTTP/1.1\r\nHost: ${m.logicalName}:${m.webSocketPort}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n` +
      (scenario ? `X-FreeKit-Research-Scenario: ${scenario}\r\n` : '') + (token ? `X-FreeKit-Session: ${token}\r\n` : '') + '\r\n'));
    const bytes = await bounded(headers(socket), 5000), status = Number(/^HTTP\/1\.1 ([0-9]{3}) /.exec(bytes.toString('ascii'))?.[1]);
    if (status !== 101) { socket.destroy(); await closed; return { status }; }
    const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    if (!bytes.includes(Buffer.from(`Sec-WebSocket-Accept: ${accept}\r\n`))) throw safeError('enrolled_upgrade_failed');
    return { status, socket, ws: new ResearchWebSocket(socket, { role: 'client', maxBinaryBytes: 4096 }), closed };
  } catch (failure) { socket.destroy(); await closed; throw failure; }
}
export async function enrolledControl(fixture, credential) {
  const connection = await upgradeEnrolled(fixture, credential, '/companion/v1/control');
  if (connection.status !== 101) throw safeError('enrolled_control_failed');
  await connection.ws.send('text', encodeControl({ protocolVersion: 1, type: 'hello', capabilities: ['tcp-http', 'tcp-https-connect'], requiredCapabilities: ['tcp-http'] }));
  const event = await nextApplication(connection);
  try { connection.ready = decodeControl(event.copyBytes()).toWire(); if (connection.ready.type !== 'session_ready') throw safeError('enrolled_ready_failed'); }
  finally { event.release(); }
  connection.token = connection.ready.sessionId;
  connection.disconnect = null;
  connection.pump = (async () => {
    while (!connection.socket.destroyed) {
      const event = await connection.ws.next();
      try {
        if (event.kind === 'ping') await connection.ws.send('pong', event.copyBytes());
        else if (event.kind === 'text') connection.disconnect = decodeControl(event.copyBytes()).toWire().code;
      } finally { event.release(); }
    }
  })().catch(() => {});
  return connection;
}
export async function enrolledStream(fixture, credential, control) {
  const connection = await upgradeEnrolled(fixture, credential, '/companion/v1/streams', { token: control.token });
  if (connection.status !== 101) throw safeError('enrolled_stream_failed');
  connection.id = 'enrolled-flow';
  await connection.ws.send('text', encodeStream({ protocolVersion: 1, type: 'open', streamId: connection.id }));
  const event = await nextApplication(connection);
  try { if (event.kind !== 'text' || JSON.parse(event.copyBytes()).type !== 'ready') throw safeError('enrolled_stream_failed'); }
  finally { event.release(); }
  return connection;
}
