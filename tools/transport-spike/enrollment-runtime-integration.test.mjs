// Real host software keys/private worker/HTTPS integration. No Android or Keystore claim.
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import { createHash, sign, X509Certificate } from 'node:crypto';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { decodeEnrollment, encodeEnrollment, enrollmentMessage, enrollmentProofPayload } from './companion-enrollment-codec.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const entry = fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url));
const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
function request(metadata, route, body, credential) {
  return new Promise((resolve, reject) => {
    const port = credential ? metadata.credentialPort : metadata.setupPort;
    const peer = https.request({ host: '127.0.0.1', port, servername: metadata.logicalName,
      method: body ? 'POST' : 'GET', path: route, agent: false,
      ca: new X509Certificate(Buffer.from(metadata.gatewayCertificateDer, 'base64url')).toString(),
      ...(credential ? { key: credential.key, cert: credential.cert } : {}),
      checkServerIdentity(_name, certificate) {
        const key = new X509Certificate(certificate.raw).publicKey.export({ format: 'der', type: 'spki' });
        if (createHash('sha256').update(key).digest('base64url') !== metadata.gatewaySpkiSha256) return Error('host_pin_failed');
        return tls.checkServerIdentity(metadata.logicalName, certificate);
      },
      headers: { Host: metadata.logicalName + ':' + port, Connection: 'close',
        ...(body ? { 'Content-Type': 'application/json', 'Content-Length': String(body.length) } : {}) },
    }, response => {
      const chunks = []; let count = 0;
      response.on('data', chunk => { count += chunk.length; if (count > 16384) peer.destroy(); else chunks.push(chunk); });
      response.once('error', () => reject(Error('host_response_failed')));
      response.once('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks) }));
    });
    peer.setTimeout(10000, () => peer.destroy());
    peer.once('error', () => reject(Error('host_request_failed')));
    peer.end(body);
  });
}
async function exchange(metadata, channel, material) {
  const route = channel === 'pair_request' ? '/companion/v1/pair' : '/companion/v1/pair/status';
  const response = await request(metadata, route, encodeEnrollment(enrollmentMessage(channel, material)));
  const decoded = decodeEnrollment(channel === 'pair_request' ? 'pair_response' :
    channel === 'challenge_request' ? 'challenge_response' : 'status_response', response.body);
  if (!decoded.ok || response.status !== 200) throw Error('host_enrollment_response_failed');
  return decoded.message;
}

test('actual parent owner composes private input, HTTPS approval/drop and same-identity worker restart', { timeout: 45000 }, async () => {
  const temp = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(temp, 'freekit-enrollment-parent-'));
  const owners = [];
  let owner;
  const open = async (mode, ports = { setupPort: 0, credentialPort: 0 }) => {
    owner = new EnrollmentRuntimeWorker({ entry }); owners.push(owner);
    return (await owner.request('start', { directory, mode, openssl: process.env.OPENSSL_BIN ?? 'openssl', ...ports },
      { timeoutMillis: 60000 })).material();
  };
  try {
    const metadata = await open('create');
    const invitation = (await owner.request('createInvitation')).material();
    const seed = encodeEnrollmentRuntimeInput(metadata, invitation);
    assert.equal(seed.subarray(0, 8).equals(Buffer.from('HFKENR1\0')), true);
    seed.fill(0);
    const device = createCryptoFixture();
    const registered = (await exchange(metadata, 'pair_request', { protocolVersion: 1, type: 'pair',
      desktopId: metadata.desktopId, invitationId: invitation.invitationId, invitationSecret: invitation.invitationSecret,
      csrDer: device.csr().toString('base64url'), deviceName: 'Parent software research',
      capabilities: ['tcp-http', 'tcp-https-connect'] })).material();
    const context = { desktopId: metadata.desktopId, gatewaySpkiSha256: metadata.gatewaySpkiSha256,
      invitationId: invitation.invitationId, enrollmentId: registered.enrollmentId,
      deviceSpkiSha256: registered.deviceSpkiSha256, purpose: 'status' };
    async function status(meta) {
      const challenge = await exchange(meta, 'challenge_request', { protocolVersion: 1, type: 'pair_challenge',
        desktopId: meta.desktopId, invitationId: invitation.invitationId, enrollmentId: registered.enrollmentId, purpose: 'status' });
      const proof = enrollmentProofPayload(context, challenge);
      return exchange(meta, 'status_request', { protocolVersion: 1, type: 'pair_status',
        desktopId: meta.desktopId, invitationId: invitation.invitationId, enrollmentId: registered.enrollmentId,
        challengeId: challenge.material().challengeId, signature: sign('sha256', proof, device.device.privateKey).toString('base64url') });
    }
    assert.equal((await status(metadata)).material().type, 'pair_pending');
    const observed = (await owner.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 })).material();
    assert.equal(sha(encodeEnrollment(enrollmentMessage('pair_response', observed))),
      sha(encodeEnrollment(enrollmentMessage('pair_response', registered))));
    assert.equal((await owner.request('dropNextApprovedStatus')).material().armed, true);
    const approved = (await owner.request('approve', { enrollmentId: registered.enrollmentId })).material();
    const approvedDigest = sha(encodeEnrollment(enrollmentMessage('status_response', approved)));
    await wait(1050);
    await assert.rejects(status(metadata), /^Error: host_request_failed$/);
    await wait(1050);
    assert.equal(sha(encodeEnrollment(await status(metadata))), approvedDigest);
    const firstClosed = (await owner.close()).material();
    assert.equal(firstClosed.droppedApprovedResponses, 1);
    assert.ok(firstClosed.approvedResponsesDeliveredAfterDrop >= 1);
    assert.equal(owner.commandObservation().closeObserved, true);
    assert.equal(owner.commandObservation().processGroupClosed, true);
    const restarted = await open('open', { setupPort: metadata.setupPort, credentialPort: metadata.credentialPort });
    assert.equal(sha(JSON.stringify(restarted)), sha(JSON.stringify(metadata)));
    const recovered = (await owner.request('readResult', { enrollmentId: registered.enrollmentId })).material();
    assert.equal(sha(encodeEnrollment(enrollmentMessage('status_response', recovered))), approvedDigest);
    assert.equal(sha(encodeEnrollment(await status(restarted))), approvedDigest);
    const credential = { key: device.device.privateKey.export({ format: 'pem', type: 'pkcs8' }),
      cert: new X509Certificate(Buffer.from(approved.clientCertificateDer, 'base64url')).toString() };
    const admitted = await request(restarted, '/research/enrollment/credential', undefined, credential);
    assert.equal(admitted.status, 200);
    assert.equal(admitted.body.toString(), '{"type":"credential_admitted"}');
    assert.ok((await owner.request('snapshot')).material().approvedResponsesDelivered >= 1);
  } finally {
    for (const child of owners) await child.close();
    assert.equal(owners.every(child => child.commandObservation().closeObserved && child.commandObservation().processGroupClosed &&
      child.closedSnapshot()?.material().storeClosed === true), true);
    const resolved = path.resolve(directory);
    assert.equal(path.dirname(resolved), temp);
    fs.rmSync(resolved, { recursive: true, force: true });
  }
});
