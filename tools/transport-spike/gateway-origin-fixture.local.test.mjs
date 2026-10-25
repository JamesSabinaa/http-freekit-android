// Explicit unpublished-desktop integration, never silently skipped by hosted CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { startOriginGatewayFixture } from './gateway-origin-fixture.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enrollOrigin, originControl, originStream } from './companion-enrollment-origin-client.mjs';
import { nextApplication, until } from './companion-stream-peer-client.mjs';
import { encodeStream } from './companion-protocol-codec.mjs';
import { encodeHttpOriginPreface } from './companion-http-origin.mjs';
import { captureFactoryPayload as payload } from './capture-factory-descriptor.mjs';
import { bounded } from './companion-stream-peer-io.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';

const desktopRoot = process.env.FREEKIT_DESKTOP_ROOT;
if (!desktopRoot) throw Error('Explicit FREEKIT_DESKTOP_ROOT is required for the real desktop integration');
const desktopCommit = process.env.FREEKIT_DESKTOP_COMMIT ?? 'fd63f6940226c8e3401a165082dfa9325abaca69';
const args = [fileURLToPath(new URL('./gateway-origin-fixture.mjs', import.meta.url)), '--desktop-root', desktopRoot, '--desktop-commit', desktopCommit];
function joined(snapshot) {
  assert(snapshot.admissionClosed && snapshot.listenerClosed && snapshot.privateDirectoryRemoved);
  assert.equal(snapshot.activeSockets + snapshot.pendingCallbacks + snapshot.pendingTimers + snapshot.workers, 0);
  assert.equal(snapshot.backend.activeOwners, 0); assert.equal(snapshot.backend.admitted, snapshot.backend.settled);
  assert(snapshot.enrollment.storeClosed && snapshot.enrollment.listenersClosed && snapshot.enrollment.issuerChildrenJoined);
  assert.equal(snapshot.enrollment.stream.sessionLeases + snapshot.enrollment.stream.streamLeases + snapshot.enrollment.stream.chargedBytes + snapshot.enrollment.stream.workers, 0);
}

test('real origin tail waits for decoded and drained client END_WRITE, then preserves full response and joins', { timeout: 20000 }, async () => {
  const owner = await startOriginGatewayFixture({ desktopRoot, desktopCommit }); let control, flow;
  try {
    // This direct test uses the same real explicit approval path as private CSR IPC.
    const crypto = createCryptoFixture(), approved = (await owner.enroll(crypto.csr())).material();
    const credential = { enrollmentId: approved.enrollmentId, approved, key: crypto.device.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      cert: new X509Certificate(Buffer.from(approved.clientCertificateDer, 'base64url')).toString() };
    control = await originControl(owner, credential); flow = await originStream(owner, credential, control);
    const body = Buffer.from(Array.from({ length: payload.requestBodyBytes }, (_, i) => i % 251));
    const request = Buffer.concat([encodeHttpOriginPreface(Uint8Array.of(127, 0, 0, 2)),
      Buffer.from(`POST ${payload.path} HTTP/1.1\r\nHost: ${payload.logicalHost}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]);
    for (let offset = 0; offset < request.length; offset += 4096) await flow.ws.send('binary', request.subarray(offset, offset + 4096));
    const chunks = []; let length = 0, prefixEnd = null;
    while (prefixEnd === null || length < prefixEnd + 4096) {
      const event = await bounded(nextApplication(flow), 5000);
      try { assert.equal(event.kind, 'binary'); const bytes = event.copyBytes(); chunks.push(bytes); length += bytes.length;
        const aggregate = Buffer.concat(chunks), end = aggregate.indexOf('\r\n\r\n', 39); if (end >= 39) prefixEnd = end + 4;
      } finally { event.release(); }
    }
    const held = await until(() => owner.snapshot(), value => value.origin.responsePrefixWritten);
    assert.equal(held.origin.responseBodyBytesWritten, 4096); assert.equal(held.origin.tailReleased, false);
    assert.equal(owner.inspect().probe.stream.client.eofEmitted, false);
    assert.equal(held.backend.clientEndWrites, 0);
    const releasing = owner.releaseTail();
    await new Promise(done => setTimeout(done, 275));
    assert.equal(owner.snapshot().origin.responseBodyBytesWritten, 4096);
    assert.equal(owner.snapshot().origin.tailReleased, false);
    assert.equal(owner.snapshot().workers, 1); // The actual bounded observation task.
    await flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: flow.id }));
    while (true) {
      const event = await bounded(nextApplication(flow), 5000);
      try {
        if (event.kind === 'text') { assert.equal(JSON.parse(event.copyBytes()).type, 'end_write'); break; }
        assert.equal(event.kind, 'binary'); chunks.push(event.copyBytes()); length += event.copyBytes().length; assert(length < 65536);
      } finally { event.release(); }
    }
    await releasing;
    const bytes = Buffer.concat(chunks), actualBody = bytes.subarray(prefixEnd);
    assert.equal(bytes.subarray(0, 39).toString('ascii'), 'HTTP/1.1 200 Connection Established\r\n\r\n');
    assert.match(bytes.subarray(39, prefixEnd).toString('ascii'), /^HTTP\/1\.1 200 OK\r\n/);
    assert.equal(actualBody.length, payload.responseBodyBytes);
    assert.equal(createHash('sha256').update(actualBody).digest('hex'), payload.responseBodySha256);
    assert.equal(owner.snapshot().origin.requestBodySha256, payload.requestBodySha256);
    assert(owner.snapshot().origin.clientEndWriteApplied && owner.snapshot().origin.captureMatched && owner.snapshot().origin.originalDestinationMatched);
    await flow.ws.send('close', Buffer.from([3, 232]));
    const close = await nextApplication(flow); try { assert.equal(close.kind, 'close'); assert.equal(close.closeCode, 1000); } finally { close.release(); }
    await flow.ws.finish();
    await until(() => owner.snapshot().gatewayStreamComplete, Boolean);
  } finally { await flow?.ws.cancel(); await control?.ws.cancel(); await control?.pump; joined(await owner.close()); }
});

test('actual private CSR CLI publishes the real matching public leaf and joins before deleting its private directory', { timeout: 15000 }, async () => {
  const crypto = createCryptoFixture();
  const input = Buffer.from(JSON.stringify({ op: 'enroll', csrDer: crypto.csr().toString('base64url') }) + '\n{"op":"stop"}\n');
  const result = await runDraftCommand(process.execPath, args, { timeoutMillis: 12000, maxOutputBytes: 65536, stdinBytes: input });
  assert.equal(result.code, 0); assert(result.closeObserved && result.processGroupClosed && result.inputFinished && result.inputClosed); assert.equal(result.stderrBytes, 0);
  const lines = result.output.trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(lines.map(line => line.event), ['ready', 'enrolled', 'closed']);
  assert.deepEqual(lines[1].metadata, lines[0].metadata);
  assert.deepEqual(lines[1].approved.capabilities, ['tcp-http-origin-connect']);
  const publicKey = new X509Certificate(Buffer.from(lines[1].approved.clientCertificateDer, 'base64url')).publicKey.export({ type: 'spki', format: 'der' });
  assert.deepEqual(publicKey, crypto.deviceSpkiDer);
  assert.equal(result.output.includes('PRIVATE KEY'), false); joined(lines[2].snapshot);
});

test('private CLI rejects unknown or duplicate commands with a fixed failure and actual cleanup', { timeout: 15000 }, async () => {
  const result = await runDraftCommand(process.execPath, args, { timeoutMillis: 12000, maxOutputBytes: 65536,
    stdinBytes: Buffer.from('{"op":"snapshot","op":"CANARY_private"}\n') });
  assert.equal(result.code, 1); assert(result.closeObserved && result.processGroupClosed); assert.equal(result.stderrBytes, 0);
  assert.equal(result.output.includes('CANARY_private'), false);
  const lines = result.output.trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(lines.map(line => line.event), ['ready', 'failed']); joined(lines[1].snapshot);
});
