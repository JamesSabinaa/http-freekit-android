// Scoped host-test client. A new request asks for the actual origin capability;
// existing legacy enrollment helpers and their approved grants are unchanged.
import { X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { enrollmentRequest, upgradeEnrolled } from './companion-enrollment-stream-client.mjs';
import { encodeControl, decodeControl, encodeStream, decodeStream, validateCapabilities } from './companion-protocol-codec.mjs';
import { HTTP_ORIGIN_CAPABILITY, HTTP_ORIGIN_PROXY_MODE } from './companion-http-origin.mjs';
import { nextApplication } from './companion-stream-peer-client.mjs';
import { safeError } from './companion-stream-peer-io.mjs';
import { enrollmentPublicSnapshot } from './companion-enrollment-crypto.mjs';

const redact = value => {
  Object.defineProperty(value, inspect.custom, { value: () => '[Enrolled origin client]' });
  Object.defineProperty(value, 'toJSON', { value: () => '[Enrolled origin client]' });
  return value;
};
export async function enrollOriginCsr(fixture, csrDer, capabilities = [HTTP_ORIGIN_CAPABILITY]) {
  if (!(csrDer instanceof Uint8Array) || csrDer.length < 1 || csrDer.length > 4096) throw safeError('enrollment_client_failed');
  const requested = validateCapabilities(capabilities);
  const m = fixture.metadata().material(), invitation = fixture.createInvitation().material();
  const response = await enrollmentRequest(fixture, '/companion/v1/pair', { protocolVersion: 1, type: 'pair', desktopId: m.desktopId,
    invitationId: invitation.invitationId, invitationSecret: invitation.invitationSecret, csrDer: Buffer.from(csrDer).toString('base64url'),
    deviceName: 'Origin software research', capabilities: requested });
  if (response.status !== 200 || response.material.type !== 'pair_registered') throw safeError('enrollment_client_failed');
  const approved = (await fixture.approve(response.material.enrollmentId)).material();
  if (approved.capabilities.length !== requested.length || approved.capabilities.some((value, i) => value !== requested[i])) throw safeError('enrollment_client_failed');
  return enrollmentPublicSnapshot(approved);
}
export async function enrollOrigin(fixture, crypto, capabilities = [HTTP_ORIGIN_CAPABILITY]) {
  const approved = (await enrollOriginCsr(fixture, crypto.csr(), capabilities)).material();
  return redact({ approved, enrollmentId: approved.enrollmentId, key: crypto.device.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    cert: new X509Certificate(Buffer.from(approved.clientCertificateDer, 'base64url')).toString() });
}
export async function originControl(fixture, credential, capabilities = [HTTP_ORIGIN_CAPABILITY]) {
  const required = validateCapabilities(capabilities);
  const connection = await upgradeEnrolled(fixture, credential, '/companion/v1/control', { scenario: null });
  if (connection.status !== 101) throw safeError('enrolled_control_failed');
  await connection.ws.send('text', encodeControl({ protocolVersion: 1, type: 'hello', capabilities: required, requiredCapabilities: required }));
  const event = await nextApplication(connection);
  try {
    connection.ready = decodeControl(event.copyBytes()).toWire();
    if (connection.ready.type !== 'session_ready' || connection.ready.capabilities.length !== required.length || connection.ready.capabilities.some((value, i) => value !== required[i])) throw safeError('enrolled_ready_failed');
  } finally { event.release(); }
  connection.token = connection.ready.sessionId;
  connection.pump = (async () => {
    while (!connection.socket.destroyed) {
      const event = await connection.ws.next();
      try { if (event.kind === 'ping') await connection.ws.send('pong', event.copyBytes()); }
      finally { event.release(); }
    }
  })().catch(() => {});
  return connection;
}
export async function originStream(fixture, credential, control, id = 'origin-flow', mode = HTTP_ORIGIN_PROXY_MODE) {
  const connection = await upgradeEnrolled(fixture, credential, '/companion/v1/streams', { token: control.token });
  if (connection.status !== 101) throw safeError('enrolled_stream_failed');
  connection.id = id;
  await connection.ws.send('text', encodeStream({ protocolVersion: 1, type: 'open', streamId: id, ...(mode == null ? {} : { proxyMode: mode }) }));
  const event = await nextApplication(connection);
  try { if (event.kind !== 'text' || decodeStream(event.copyBytes()).toWire().type !== 'ready') throw safeError('enrolled_stream_failed'); }
  finally { event.release(); }
  return connection;
}
