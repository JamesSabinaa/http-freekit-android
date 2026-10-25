import assert from 'node:assert/strict';
import test from 'node:test';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { startInterceptionCaPeer, interceptionCaCases } from './companion-interception-ca-peer.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { observeClose, bounded } from './companion-stream-peer-io.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('base64url');

async function request(ready, credential) {
  let socket, closed;
  try {
    return await bounded(new Promise((resolve, reject) => {
      const call = https.request({ host: '127.0.0.1', port: ready.peerPort, servername: ready.metadata.logicalName,
        ca: new X509Certificate(Buffer.from(ready.metadata.gatewayCertificateDer, 'base64url')).toString(), rejectUnauthorized: true,
        key: credential.key, cert: credential.cert, agent: false, method: 'GET', path: '/companion/v1/ca',
        headers: { host: ready.metadata.logicalName + ':' + ready.peerPort, accept: 'application/pkix-cert', connection: 'close' } }, reply => {
        const chunks = []; let total = 0;
        reply.on('data', chunk => { total += chunk.length; if (total > 16384) reply.destroy(); else chunks.push(chunk); });
        reply.on('error', reject); reply.on('end', () => resolve({ status: reply.statusCode, headers: reply.headers, body: Buffer.concat(chunks) }));
      });
      call.once('socket', value => { socket = value; closed = observeClose(socket); });
      call.once('error', reject); call.setTimeout(5000, () => call.destroy()); call.end();
    }), 7000);
  } finally { socket?.destroy(); if (closed) await bounded(closed, 5000); }
}
async function fixture(scenario, action) {
  const peer = await startInterceptionCaPeer({ scenario });
  try {
    const crypto = createCryptoFixture({ utcMillis: Date.now() });
    const enrolled = await peer.enroll(crypto.csr().toString('base64url'));
    const credential = { key: crypto.device.privateKey.export({ format: 'pem', type: 'pkcs8' }),
      cert: new X509Certificate(Buffer.from(enrolled.approved.clientCertificateDer, 'base64url')).toString() };
    await action(peer, enrolled, credential);
  } finally {
    const result = await peer.close(); assert.equal(result.privateDirectoryRemoved, true);
    assert(result.fixture.closed && result.fixture.storeClosed && result.fixture.issuerChildrenJoined && result.fixture.listenersClosed);
    for (const key of ['activeSockets','pendingCallbacks','pendingTimers','workers','issuerJobs','signerGroups']) assert.equal(result.fixture[key], 0, key);
  }
}

test('private CA peer admits real software CSR/mTLS DER, preserves actual approval across reopen and denies revoked credentials', { timeout: 25000 }, async () => {
  await fixture('reference', async (peer, enrolled, credential) => {
    const ready = peer.ready(), response = await request(ready, credential), der = Buffer.from(ready.referenceCaDer, 'base64url');
    assert.equal(response.status, 200); assert(response.body.equals(der)); assert.equal(response.headers['x-freekit-ca-sha256'], hash(der));
    assert.equal(enrolled.approved.interceptionCaCertificateSha256, hash(der));
    await peer.pause(); const reopened = await peer.reopen(); assert.deepEqual(reopened.metadata, ready.metadata);
    assert.equal(reopened.referenceCaDer, ready.referenceCaDer); assert((await request(reopened, credential)).body.equals(der));
    assert.deepEqual(peer.revoke(), { revoked: true }); assert.deepEqual(peer.status(), { active: false, ended: 'device_revoked' });
    assert.equal((await request(reopened, credential)).status, 403);
  });
});
test('private CA peer can supply actual public-only RSA CA assets without replacing approval metadata on reopen', { timeout: 25000 }, async () => {
  await fixture('rsa-reference', async (peer, enrolled, credential) => {
    const ready = peer.ready(), ca = new X509Certificate(Buffer.from(ready.referenceCaDer, 'base64url'));
    assert.equal(ca.publicKey.asymmetricKeyType, 'rsa'); assert.equal(ca.publicKey.asymmetricKeyDetails.modulusLength, 2048);
    assert.equal(enrolled.approved.interceptionCaCertificateSha256, hash(ca.raw)); assert((await request(ready, credential)).body.equals(ca.raw));
    assert.equal((await peer.reopen()).referenceCaDer, ready.referenceCaDer);
  });
});
test('owned hostile TLS fixture uses the same gateway and current Store while emitting actual finite malformed bytes', { timeout: 25000 }, async () => {
  await fixture('nonminimal-der', async (peer, enrolled, credential) => {
    const ready = peer.ready(), response = await request(ready, credential);
    assert.equal(response.status, 200); assert.equal(response.headers['x-freekit-ca-sha256'], ready.responseHash);
    assert.notEqual(ready.responseHash, enrolled.approved.interceptionCaCertificateSha256);
    assert.equal(response.body[0], 0x30); assert.equal(response.body[2], 0); assert.equal(hash(response.body), ready.responseHash);
    const state = peer.snapshot().hostile; assert.equal(state.requests, 1); assert.equal(state.authorized, 1); assert.equal(state.completedResponses, 1);
  });
});
test('actual private peer CLI refuses unknown configuration without echoing material and joins its process group', async () => {
  assert(Object.isFrozen(interceptionCaCases)); assert.equal(new Set(interceptionCaCases).size, interceptionCaCases.length);
  const result = await runDraftCommand(process.execPath, [fileURLToPath(new URL('./companion-interception-ca-peer.mjs', import.meta.url)), '--case', 'PRIVATE_CA_CANARY'],
    { cwd: fileURLToPath(new URL('../../', import.meta.url)), timeoutMillis: 5000 });
  assert.equal(result.code, 1); assert(result.closeObserved && result.processGroupClosed);
  const value = JSON.parse(result.output.trim()); assert.deepEqual(value, { format: 'http-freekit-interception-ca-fixture', revision: 1, event: 'failed', snapshot: null });
  assert(!String(result.output + result.stderr).includes('PRIVATE_CA_CANARY'));
});

test('an unjoined pre-open wrong-gateway initialization retains its owned directory and cannot attest cleanup', async () => {
  let directory, calls = 0;
  try {
    await assert.rejects(startInterceptionCaPeer({ scenario: 'wrong-gateway' }, { async wrongGatewayAssets(options) {
      calls++; directory = path.dirname(options.directory);
      throw Object.assign(Error('PRIVATE_JOIN_CANARY'), { joined: false });
    } }), error => error.code === 'interception_ca_fixture_failed' && !String(error).includes('PRIVATE_JOIN_CANARY'));
    assert.equal(calls, 1); assert(directory && fs.existsSync(directory));
    assert.deepEqual(fs.readdirSync(directory).sort(), ['enrollment','wrong']);
  } finally {
    // This injected loader started no child. Its test owner removes the retained fake directory only after checking the refusal.
    if (directory) {
      assert.equal(path.dirname(directory), fs.realpathSync(os.tmpdir())); assert(path.basename(directory).startsWith('freekit-interception-ca-'));
      assert.equal(fs.realpathSync(directory), directory); fs.rmSync(directory, { recursive: true, force: true });
    }
  }
});
