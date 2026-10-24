import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import https from 'node:https';
import { X509Certificate, createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { once } from 'node:events';
import { startEnrollmentAdversarialFixture } from './companion-enrollment-adversarial.mjs';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { enrollmentRequest, tlsOptions } from './companion-enrollment-stream-client.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { bounded, observeClose, write } from './companion-stream-peer-io.mjs';
import { until } from './companion-stream-peer-client.mjs';

const groupKeys = ['accepted','rejected','httpDispatches','secureConnections','activeSockets','pendingCallbacks','pendingTimers','workers',
  'childrenStarted','childrenClosed','childGroupsClosed','admissionClosed','listenerClosed'];
const root = fs.realpathSync(os.tmpdir());
function directory() { const value = fs.mkdtempSync(path.join(root, 'freekit-enrollment-alt-')); fs.chmodSync(value, 0o700); return value; }
function remove(value) { assert(value.startsWith(root + path.sep)); fs.rmSync(value, { recursive: true, force: true }); }
function closed(snapshot) {
  assert(snapshot.storeClosed && snapshot.listenersClosed && snapshot.issuerChildrenJoined);
  assert.equal(snapshot.activeSockets + snapshot.pendingCallbacks + snapshot.pendingTimers + snapshot.workers, 0);
  const alt = snapshot.alternateTls;
  assert(alt.admissionClosed && alt.listenerClosed); assert.equal(alt.activeSockets + alt.pendingCallbacks + alt.pendingTimers + alt.workers, 0);
  assert.equal(alt.childrenStarted, 3); assert.equal(alt.childrenClosed, 3); assert.equal(alt.childGroupsClosed, 3);
}

test('same-DNS different P256 peer actually rejects seed trust without client certificates or HTTP and leaves the correct reservation pending', { timeout: 15000 }, async () => {
  const d = directory(); let owner;
  try {
    owner = await startEnrollmentAdversarialFixture({ directory: d, mode: 'create' });
    const metadata = owner.metadata().material(), initial = owner.snapshot();
    assert.deepEqual(Object.keys(metadata).sort(), ['desktopId','logicalName','gatewayCertificateDer','gatewaySpkiSha256','enrollmentAuthorityDer',
      'interceptionCaCertificateSha256','setupPort','credentialPort','adversarialPeerPort'].sort());
    assert.equal(new Set([metadata.setupPort,metadata.credentialPort,metadata.adversarialPeerPort]).size, 3);
    assert.deepEqual(Object.keys(initial.alternateTls).sort(), groupKeys.sort());
    const crypto = createCryptoFixture(), invitation = owner.createInvitation().material();
    const pair = { protocolVersion: 1, type: 'pair', desktopId: metadata.desktopId, invitationId: invitation.invitationId,
      invitationSecret: invitation.invitationSecret, csrDer: crypto.csr().toString('base64url'), deviceName: 'Alternate peer research', capabilities: ['tcp-http'] };
    const registered = await enrollmentRequest(owner, '/companion/v1/pair', pair);
    assert.equal(registered.status, 200); assert.equal(registered.material.type, 'pair_registered');
    const before = owner.snapshot();
    const socket = tls.connect(tlsOptions(owner, null, metadata.adversarialPeerPort));
    socket.on('error', () => {}); const actualClose = observeClose(socket);
    await assert.rejects(bounded(new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', () => reject(Error('Expected alternate peer TLS rejection'))); }), 5000));
    socket.destroy(); await actualClose;
    const rejected = await until(() => owner.snapshot(), value => value.alternateTls.rejected >= 1 && value.alternateTls.activeSockets === 0);
    assert(rejected.alternateTls.accepted >= 1); assert.equal(rejected.alternateTls.secureConnections, 0); assert.equal(rejected.alternateTls.httpDispatches, 0);
    assert.equal(rejected.dispatches, before.dispatches); assert.equal(rejected.issuer.commandsStarted, before.issuer.commandsStarted);
    const retried = await enrollmentRequest(owner, '/companion/v1/pair', pair);
    assert.equal(retried.status, 200); assert(registered.material.enrollmentId === retried.material.enrollmentId);
    assert.equal(owner.readResult(registered.material.enrollmentId).material().type, 'pair_pending');
    // An independent normal TLS client trusts ONLY the alternate certificate.
    // It verifies that rejection above was not caused by an invalid name/date/key.
    const alternatePem = fs.readFileSync(path.join(d, 'adversarial-peer', 'peer.pem'));
    const cert = new X509Certificate(alternatePem);
    assert.equal(cert.subjectAltName, `DNS:${metadata.logicalName}`); assert.equal(cert.publicKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
    assert(createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64url') !== metadata.gatewaySpkiSha256);
    const trusted = tls.connect({ ...tlsOptions(owner, null, metadata.adversarialPeerPort), ca: alternatePem });
    trusted.on('error', () => {}); const trustedClose = observeClose(trusted);
    await bounded(new Promise((resolve, reject) => { trusted.once('secureConnect', resolve); trusted.once('error', () => reject(Error('Alternate identity validation failed'))); }), 5000);
    assert.equal(trusted.authorized, true); assert.equal(trusted.getPeerCertificate().subject.CN, metadata.logicalName);
    await write(trusted, Buffer.from(`GET / HTTP/1.1\r\nHost: ${metadata.logicalName}:${metadata.adversarialPeerPort}\r\nConnection: close\r\n\r\n`));
    await trustedClose;
    assert.equal(owner.snapshot().alternateTls.httpDispatches, 1); assert.equal(owner.snapshot().alternateTls.secureConnections, 1);
    const output = inspect(owner) + JSON.stringify(owner);
    for (const value of [d,metadata.logicalName,metadata.desktopId,metadata.gatewayCertificateDer,metadata.gatewaySpkiSha256,invitation.invitationSecret,'BEGIN ']) assert(!output.includes(value));
    closed(await owner.close());
    assert(owner.metadata().material().adversarialPeerPort === metadata.adversarialPeerPort);
  } finally { await owner?.close(); remove(d); }
});

test('alternate listener close joins an actual idle pre-handshake socket and administrative callbacks before Store release', { timeout: 10000 }, async () => {
  const d = directory(); let owner, socket;
  try {
    owner = await startEnrollmentAdversarialFixture({ directory: d, mode: 'create' });
    socket = net.connect({ host: '127.0.0.1', port: owner.metadata().material().adversarialPeerPort }); socket.on('error', () => {});
    const actualClose = observeClose(socket); await once(socket, 'connect');
    await until(() => owner.snapshot(), value => value.alternateTls.activeSockets > 0);
    const [first, second] = await Promise.all([owner.close(), owner.close()]); await actualClose;
    closed(first); closed(second);
  } finally { socket?.destroy(); await owner?.close(); remove(d); }
});

test('actual alternate bind failure after child commands joins its allocated initializer before allowing exact Store reopen', { timeout: 15000 }, async () => {
  const d = directory(), occupied = net.createServer(); occupied.listen(0, '127.0.0.1'); await once(occupied, 'listening');
  const original = https.Server.prototype.listen; let calls = 0;
  https.Server.prototype.listen = function (...args) {
    calls++; if (calls === 3) args[0] = occupied.address().port;
    return original.apply(this, args);
  };
  try {
    await assert.rejects(startEnrollmentAdversarialFixture({ directory: d, mode: 'create' }), error => error.code === 'pairing_unavailable' && error.joined);
    assert.equal(calls, 3); assert(fs.existsSync(path.join(d, 'adversarial-peer', 'peer.pem')));
  } finally { https.Server.prototype.listen = original; await new Promise(resolve => occupied.close(resolve)); }
  try {
    const metadata = JSON.parse(fs.readFileSync(path.join(d, 'enrollment-fixture.json')));
    const reopened = await startEnrollmentHttpsFixture({ directory: d, mode: 'open', setupPort: metadata.setupPort, credentialPort: metadata.credentialPort });
    assert(reopened.metadata().material().gatewaySpkiSha256 === metadata.gatewaySpkiSha256);
    const result = await reopened.close(); assert(result.storeClosed && result.listenersClosed && result.issuerChildrenJoined);
  } finally { remove(d); }
});
