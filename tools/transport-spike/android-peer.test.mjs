import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import test from 'node:test';
import WebSocket from 'ws';
import { FIXTURE_BACKDATE_SECONDS, FIXTURE_LIFETIME_SECONDS, fixtureValidity, logicalName, measureFixtureClock, startPeer, verifyRequest } from './android-peer.mjs';

function clientRequest(peer, curve = 'P-256') {
  peer.command(['req', '-new', '-newkey', 'ec', '-pkeyopt', `ec_paramgen_curve:${curve}`, '-nodes', '-sha256',
    '-config', 'request.cnf', '-keyout', 'host-client-key.pem', '-outform', 'DER', '-out', 'host-client.csr']);
  return fs.readFileSync(path.join(peer.directory, 'host-client.csr'));
}
function options(peer) {
  return { hostname: logicalName, port: peer.metadata.enrollmentPort,
    ca: new X509Certificate(Buffer.from(peer.metadata.gatewayDer, 'base64url')).toString(),
    lookup: (_hostname, options, callback) => options.all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4) };
}
async function enroll(peer, bytes, contentLength = bytes.length) {
  return new Promise((resolve, reject) => {
    const request = https.request({ ...options(peer), path: '/research/enroll', method: 'POST',
      headers: { 'content-type': 'application/pkcs10', 'content-length': contentLength }, timeout: 5000 }, response => {
      const chunks = []; let length = 0;
      response.on('data', chunk => { length += chunk.length; if (length > 8201) request.destroy(Error('oversized reply')); else chunks.push(chunk); });
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks) }));
    });
    request.on('timeout', () => request.destroy(Error('request timeout')));
    request.on('error', reject);
    request.end(bytes);
  });
}
test('strict CSR proof rejects tampering, trailing bytes, oversize and a different curve', { timeout: 20000 }, async () => {
  const peer = await startPeer();
  const directory = peer.directory;
  try {
    const csr = clientRequest(peer);
    assert.equal(verifyRequest(csr).asymmetricKeyDetails.namedCurve, 'prime256v1');
    const forged = Buffer.from(csr); forged[forged.length - 1] ^= 1;
    for (const invalid of [forged, Buffer.concat([csr, Buffer.from([0])]), Buffer.alloc(4097), Buffer.from([0x30, 0x80]), clientRequest(peer, 'P-384')]) {
      assert.throws(() => verifyRequest(invalid));
      assert.notEqual((await enroll(peer, invalid)).status, 200);
    }
    assert.equal((await enroll(peer, csr, 4097)).status, 413);
  } finally { await peer.close(); }
  assert.equal(fs.existsSync(directory), false);
});
test('issued key authenticates WSS 64 KiB and absent client identity is rejected', { timeout: 20000 }, async () => {
  const peer = await startPeer();
  const directory = peer.directory;
  try {
    const csr = clientRequest(peer);
    const reply = await enroll(peer, csr);
    assert.equal(reply.status, 200);
    assert.equal(reply.body[0], 1);
    const caLength = reply.body.readUInt32BE(1);
    assert.ok(caLength > 0 && caLength <= 4096);
    const authority = new X509Certificate(reply.body.subarray(5, 5 + caLength));
    const leafLength = reply.body.readUInt32BE(5 + caLength);
    const leaf = new X509Certificate(reply.body.subarray(9 + caLength));
    assert.equal(9 + caLength + leafLength, reply.body.length);
    assert.equal(leaf.verify(authority.publicKey), true);
    assert.equal(leaf.ca, false);
    const gateway = new X509Certificate(Buffer.from(peer.metadata.gatewayDer, 'base64url'));
    for (const certificate of [authority, gateway, leaf]) {
      assert.equal(Date.parse(certificate.validFrom), peer.validity.notBeforeEpochSeconds * 1000);
      assert.equal(Date.parse(certificate.validTo), peer.validity.notAfterEpochSeconds * 1000);
    }
    const verifyClientAt = epoch => peer.command(['verify', '-attime', String(epoch), '-CAfile', 'ca.pem', '-purpose', 'sslclient', 'client.pem']);
    verifyClientAt(peer.validity.hostIssueEpochSeconds - 120);
    assert.throws(() => verifyClientAt(peer.validity.notBeforeEpochSeconds - 1));
    assert.throws(() => verifyClientAt(peer.validity.notAfterEpochSeconds + 1));
    assert.deepEqual(leaf.publicKey.export({ type: 'spki', format: 'der' }), verifyRequest(csr).export({ type: 'spki', format: 'der' }));
    const tlsOptions = { ...options(peer), port: undefined, perMessageDeflate: false, handshakeTimeout: 5000 };
    const payload = Buffer.from(Array.from({ length: 65536 }, (_, i) => i % 251));
    await new Promise((resolve, reject) => {
      const socket = new WebSocket(`wss://${logicalName}:${peer.metadata.webSocketPort}/research/echo`, {
        ...tlsOptions, cert: leaf.toString(), key: fs.readFileSync(path.join(directory, 'host-client-key.pem')),
      });
      const deadline = setTimeout(() => { socket.terminate(); reject(Error('WSS exchange timeout')); }, 5000);
      socket.on('open', () => socket.send(payload));
      socket.on('message', (bytes, binary) => {
        try { assert.equal(binary, true); assert.deepEqual(bytes, payload); socket.close(1000); }
        catch (failure) { socket.terminate(); reject(failure); }
      });
      socket.on('close', code => { clearTimeout(deadline); code === 1000 ? resolve() : reject(Error('Unexpected WSS close')); });
      socket.on('error', error => { clearTimeout(deadline); reject(error); });
    });
    await assert.rejects(new Promise((resolve, reject) => {
      const socket = new WebSocket(`wss://${logicalName}:${peer.metadata.webSocketPort}/research/echo`, tlsOptions);
      socket.on('open', () => { socket.terminate(); resolve(); });
      socket.on('error', reject);
    }));
  } finally { await peer.close(); }
  assert.equal(fs.existsSync(directory), false);
});

test('research validity and measured clock skew stay within explicit limits', () => {
  const now = Date.UTC(2026, 9, 24, 12, 0, 0);
  const validity = fixtureValidity(now);
  assert.equal(validity.notBeforeEpochSeconds, now / 1000 - FIXTURE_BACKDATE_SECONDS);
  assert.equal(validity.notAfterEpochSeconds, now / 1000 + FIXTURE_LIFETIME_SECONDS);
  assert.equal(FIXTURE_BACKDATE_SECONDS, 300);
  assert.equal(FIXTURE_LIFETIME_SECONDS, 3600);
  assert.equal(measureFixtureClock(String(now / 1000), now, now + 10).fixtureClockStatus, 'within_bound');
  for (const skew of [-121, 121]) assert.equal(measureFixtureClock(String(now / 1000 + skew), now, now + 10).fixtureClockStatus, 'skew_exceeds_bound');
  assert.equal(measureFixtureClock(String(now / 1000), now, now + 5001).fixtureClockStatus, 'probe_budget_exceeded');
  assert.throws(() => measureFixtureClock('DO_NOT_RETAIN', now, now + 10), /invalid_device_clock_probe/);
  assert.throws(() => measureFixtureClock(String(now / 1000), now, now - 1), /invalid_device_clock_probe/);
  assert.throws(() => fixtureValidity(NaN), /invalid_fixture_issue_epoch/);
});
for (const [description, offset, expectedCode] of [
  ['future', 3600000, 'CERT_NOT_YET_VALID'], ['expired', -7200000, 'CERT_HAS_EXPIRED'],
]) test(`normal TLS rejects a ${description} research gateway certificate`, { timeout: 20000 }, async () => {
  const peer = await startPeer({ nowMillis: Date.now() + offset });
  try {
    const csr = clientRequest(peer);
    await assert.rejects(enroll(peer, csr), failure => failure.code === expectedCode);
  } finally { await peer.close(); }
});
