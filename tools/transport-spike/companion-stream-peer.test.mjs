import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { startCompanionStreamPeer } from './companion-stream-peer.mjs';
import { enrollHost, control, stream, nextApplication, until, upgrade, http } from './companion-stream-peer-client.mjs';
import { write, observeClose, bounded } from './companion-stream-peer-io.mjs';
import { encodeStream } from './companion-protocol-codec.mjs';
import { requestHeader, pattern, uploadLength, RESPONSE_HEADER, RESPONSE_BODY_LENGTH } from './companion-stream-peer-schema.mjs';

function responseSlice(offset, length) {
  const result = Buffer.allocUnsafe(length);
  for (let index = 0; index < length; index++) {
    const position = offset + index;
    result[index] = position < RESPONSE_HEADER.length ? RESPONSE_HEADER[position] : ((position - RESPONSE_HEADER.length) * 7) % 253;
  }
  return result;
}
async function sendBody(connection, scenario, from, to) {
  for (let offset = from; offset < to; offset += 4096) await connection.ws.send('binary', pattern(offset, Math.min(4096, to - offset)));
}
async function readResponse(connection, onPrefix = async () => {}) {
  let received = 0, prefix = false;
  const hash = createHash('sha256');
  while (true) {
    const event = await nextApplication(connection);
    try {
      if (event.kind === 'binary') {
        const bytes = event.copyBytes();
        assert.deepEqual(bytes, responseSlice(received, bytes.length));
        hash.update(bytes); received += bytes.length;
        if (!prefix && received >= RESPONSE_HEADER.length + 4096) { prefix = true; await onPrefix(); }
      } else {
        assert.equal(event.kind, 'text');
        assert.equal(JSON.parse(event.copyBytes()).type, 'end_write');
        break;
      }
    } finally { event.release(); }
  }
  assert.equal(received, RESPONSE_HEADER.length + RESPONSE_BODY_LENGTH);
  await connection.ws.send('close', Buffer.from([3, 232]));
  const close = await nextApplication(connection);
  try { assert.equal(close.kind, 'close'); assert.equal(close.closeCode, 1000); }
  finally { close.release(); }
  await connection.ws.finish();
  return { received, hash: hash.digest('hex') };
}

test('real mTLS gated proxy streaming preserves both prefixes, actual request EOF, bytes and joined cleanup', { timeout: 20000 }, async t => {
  const peer = await startCompanionStreamPeer();
  const directory = peer.directory;
  let session, flow;
  let phase = 'enroll';
  try {
    assert.deepEqual(Object.keys(peer.metadata).sort(), ['enrollmentPort', 'gatewayDer', 'gatewayPin', 'webSocketPort']);
    const credential = await enrollHost(peer);
    phase = 'control';
    session = await control(peer, credential, 'gated');
    phase = 'stream';
    flow = await stream(peer, credential, session);
    phase = 'upload_prefix';
    await flow.ws.send('binary', requestHeader('gated'));
    await sendBody(flow, 'gated', 0, 4096);
    const prefix = await until(session.probe, value => value.fixture.uploadPrefixSeen);
    assert.equal(prefix.fixture.uploadBytesRead, requestHeader('gated').length + 4096);
    assert.equal(prefix.fixture.uploadEof, false);
    assert.equal(prefix.fixture.responseBytesWritten, 0);
    await sendBody(flow, 'gated', 4096, uploadLength('gated'));
    await flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: flow.id }));
    phase = 'response';
    const reply = await readResponse(flow, async () => {
      const state = await session.probe();
      assert.equal(state.fixture.uploadEof, true);
      assert.equal(state.fixture.responseTailReleased, false);
      assert.equal(state.fixture.responseBytesWritten, RESPONSE_HEADER.length + 4096);
      assert.equal((await session.command('release_response_tail')).status, 200);
    });
    const completed = await until(session.probe, value => value.stream?.phase === 'complete');
    phase = 'cleanup';
    assert.equal(completed.fixture.uploadVerified, true);
    assert.equal(completed.fixture.uploadSha256, 'f0989db67f7bd1ccd2f9e09ba4cbb9bbcf8702561403b9543c9e49fc5aa67c5c');
    assert.equal(reply.hash, '5207d6508c1de0bbbfa607ce5564279d6b967da7a91b0462be6fb13b95d8d756');
    assert.equal(completed.fixture.responseSha256, reply.hash);
    assert.equal(completed.fixture.responseBytesWritten, reply.received);
    assert.equal(completed.stream.client.eofEmitted, true);
    assert.equal(completed.stream.gateway.eofEmitted, true);
    assert.equal(completed.pool.streamLeases, 0);
    await session.cancel();
    const clean = await until(session.probe, value => value.cleanup.complete);
    assert.deepEqual(clean.pool, { sessionLeases: 0, streamLeases: 0, chargedBytes: 0 });
    assert.equal((await session.command('release_response_tail')).status, 403);
    const inert = await session.probe();
    assert.deepEqual(inert, clean);
    const diagnostic = JSON.stringify(inert);
    assert.equal(diagnostic.includes(session.token), false);
    assert.equal(diagnostic.includes(credential.deviceId), false);
    assert.equal(diagnostic.includes('fixture.invalid'), false);
  } catch (failure) {
    t.diagnostic(`Research failure phase: ${phase}`);
    if (session) { const state = await session.probe(); t.diagnostic(JSON.stringify({ stream: state.stream, fixture: state.fixture, io: state.io, cleanup: state.cleanup })); }
    throw failure;
  } finally {
    await flow?.ws.cancel(); await session?.cancel(); await peer.close();
  }
  assert.equal(fs.existsSync(directory), false);
  assert.equal(peer.snapshot().authenticatedSockets, 0);
  assert.equal(peer.snapshot().proxySockets, 0);
});

async function context(scenario, operation) {
  const peer = await startCompanionStreamPeer();
  let session, flow;
  try {
    const credential = await enrollHost(peer);
    session = await control(peer, credential, scenario);
    flow = await stream(peer, credential, session);
    await operation({ peer, credential, session, flow });
  } finally {
    await flow?.ws.cancel(); await session?.cancel(); await peer.close();
  }
}
async function blockedUpload(session, flow, scenario) {
  let done = false;
  const sending = (async () => {
    await flow.ws.send('binary', requestHeader(scenario));
    await sendBody(flow, scenario, 0, uploadLength(scenario));
    await flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: flow.id }));
    done = true;
  })();
  sending.catch(() => {});
  try {
    const deadline = performance.now() + 10000;
    const candidate = value => value.io.proxyWritePending && value.io.pendingIngressBytes === 4096 &&
      value.stream?.client.chargedBytes === 8192 && flow.ws.snapshot().pendingWriteCallbacks === 1 && !done;
    // Early write(false) can be transient while kernel/TLS buffers still admit data.
    // Require the SAME unfinished callbacks over a bounded observation window, not merely
    // a timer or a first backpressure flag. Total generated data still cannot exceed32MiB.
    while (performance.now() < deadline) {
      assert.equal(done, false, '32MiB fixture finished without observing stable blocked I/O');
      const before = await session.probe();
      if (candidate(before)) {
        const localCompleted = flow.ws.snapshot().completedWrites;
        await new Promise(resolve => setTimeout(resolve, 250));
        const after = await session.probe();
        if (candidate(after) && after.io.proxyWriteEntries === before.io.proxyWriteEntries &&
            flow.ws.snapshot().completedWrites === localCompleted) return { sending, blocked: after };
      } else await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.fail('No stable actual blocked callbacks observed within the bounded fixture');
  } catch (failure) { await flow.ws.cancel(); await Promise.allSettled([sending]); throw failure; }
}

test('real model-bound backpressure retains one ingress frame and resumes a 32MiB upload without loss or replay', { timeout: 40000 }, async () => {
  await context('backpressure', async ({ session, flow }) => {
    const { sending, blocked } = await blockedUpload(session, flow, 'backpressure');
    assert.equal(blocked.fixture.proxyReadPaused, true);
    assert.equal(blocked.fixture.uploadBytesRead, 0);
    assert.equal(blocked.stream.chargedFrames, 2);
    assert.equal(blocked.pool.chargedBytes, 8192);
    assert.equal((await session.command('resume_proxy_read')).status, 200);
    await bounded(sending, 20000, 'host_upload_timeout');
    const reply = await readResponse(flow);
    const completed = await until(session.probe, value => value.stream?.phase === 'complete');
    assert.equal(completed.fixture.uploadBytesRead, requestHeader('backpressure').length + uploadLength('backpressure'));
    assert.equal(completed.fixture.uploadVerified, true);
    assert.equal(completed.fixture.responseSha256, reply.hash);
    assert.ok(completed.io.resumedPendingCount > 0);
    assert.equal(completed.io.pendingIngressBytes, 0);
    assert.equal(completed.pool.chargedBytes, 0);
    await session.cancel();
    await until(session.probe, value => value.cleanup.complete);
  });
});

test('independent control cancellation closes actual blocked TLS/proxy writes and joins before releasing charges', { timeout: 20000 }, async () => {
  await context('cancel', async ({ session, flow }) => {
    const { sending } = await blockedUpload(session, flow, 'cancel');
    await session.cancel();
    await assert.rejects(sending);
    await flow.ws.cancel();
    const clean = await until(session.probe, value => value.cleanup.complete);
    assert.equal(clean.control.cause, 'cancelled');
    assert.equal(clean.stream.phase, 'cancelled');
    assert.equal(clean.stream.cause, 'cancelled');
    assert.ok(clean.io.retainedBytesAtAbort > 0);
    assert.equal(clean.io.retainedStreamLeasesAtAbort, 1);
    assert.equal(clean.io.pendingIngressBytes, 0);
    assert.equal(clean.cleanup.pendingCallbacks, 0);
    assert.deepEqual(clean.pool, { sessionLeases: 0, streamLeases: 0, chargedBytes: 0 });
    assert.equal(flow.ws.snapshot().pendingWriteCallbacks, 0);
    assert.equal(flow.ws.snapshot().transportClosed, true);
  });
});

test('actual 30–31 second expiry closes observed blocked writes with real deadline timing and joined zero resources', { timeout: 50000 }, async () => {
  const started = performance.now();
  await context('expiry', async ({ session, flow }) => {
    const initial = await session.probe();
    const lifetime = initial.timing.expiresUtcMillis - initial.timing.readyUtcMillis;
    assert.ok(lifetime >= 30000 && lifetime <= 31000);
    assert.equal(Date.parse(session.ready.expiresAt), initial.timing.expiresUtcMillis);
    const { sending } = await blockedUpload(session, flow, 'expiry');
    const expired = await until(session.probe, value => value.control.cause === 'session_expired', 35000);
    assert.ok(expired.timing.terminalUtcMillis >= expired.timing.expiresUtcMillis || expired.timing.terminalElapsedMillis >= lifetime);
    assert.ok(expired.timing.terminalElapsedMillis >= 29000);
    await assert.rejects(sending);
    await flow.ws.cancel(); await session.cancel();
    const clean = await until(session.probe, value => value.cleanup.complete);
    assert.equal(clean.stream.phase, 'failed');
    assert.equal(clean.stream.cause, 'session_expired');
    assert.ok(clean.io.retainedBytesAtAbort > 0);
    assert.equal(clean.io.retainedStreamLeasesAtAbort, 1);
    assert.equal(clean.cleanup.pendingCallbacks, 0);
    assert.deepEqual(clean.pool, { sessionLeases: 0, streamLeases: 0, chargedBytes: 0 });
  });
  assert.ok(performance.now() - started >= 30000);
});

test('wrong token/device and hostile upgrade policy cannot mutate an existing open owner that later completes', { timeout: 20000 }, async () => {
  await context('binding', async ({ peer, credential, session, flow }) => {
    const other = await enrollHost(peer, 'other');
    const wrong = session.token[0] === 'A' ? 'B' + session.token.slice(1) : 'A' + session.token.slice(1);
    assert.equal((await upgrade(peer, credential, '/companion/v1/streams', { token: wrong })).status, 403);
    assert.equal((await upgrade(peer, other, '/companion/v1/streams', { token: session.token })).status, 403);
    for (const extra of [['Origin: https://browser.invalid'], ['Cookie: x=y'], ['Authorization: ignored'],
      [`X-FreeKit-Session: ${session.token}`], ['Sec-WebSocket-Extensions: permessage-deflate'], ['Sec-WebSocket-Protocol: other']]) {
      assert.equal((await upgrade(peer, credential, '/companion/v1/streams', { token: session.token, extra })).status, 400);
    }
    assert.equal((await upgrade(peer, credential, '/companion/v1/streams?ignored=1', { token: session.token })).status, 404);
    for (const defect of [{ key: 'not-a-websocket-key' }, { key: null }, { version: '14' }]) {
      assert.equal((await upgrade(peer, credential, '/companion/v1/streams', { token: session.token, ...defect })).status, 400);
    }
    const preserved = await session.probe();
    assert.equal(preserved.streamOrdinal, 1); assert.equal(preserved.stream.phase, 'open');
    assert.equal(preserved.stream.streamLease, true); assert.equal(preserved.fixture.uploadBytesRead, 0);
    for (const body of ['{"command":"resume_proxy_read","command":"release_response_tail"}',
      ' {"command":"resume_proxy_read"}', '{"command":"arbitrary"}', '{"command":"resume_proxy_read"}\n']) {
      assert.equal((await http(peer, credential, 'POST', '/research/command', session.token, Buffer.from(body))).status, 400);
    }
    assert.equal((await http(peer, credential, 'GET', '/research/probe', wrong)).status, 403);
    assert.equal((await http(peer, other, 'GET', '/research/probe', session.token)).status, 403);
    assert.equal((await session.probe()).streamOrdinal, 1);
    await flow.ws.send('binary', requestHeader('binding'));
    await sendBody(flow, 'binding', 0, uploadLength('binding'));
    await flow.ws.send('text', encodeStream({ protocolVersion: 1, type: 'end_write', streamId: flow.id }));
    await readResponse(flow);
    await until(session.probe, value => value.stream?.phase === 'complete');
    await session.cancel(); await until(session.probe, value => value.cleanup.complete);
  });
});

test('pending authenticated upgrades retain both configured stream slots and refuse a third without mutation', { timeout: 15000 }, async () => {
  const peer = await startCompanionStreamPeer();
  let session;
  const pending = [];
  try {
    const credential = await enrollHost(peer); session = await control(peer, credential, 'binding');
    pending.push(await upgrade(peer, credential, '/companion/v1/streams', { token: session.token }));
    pending.push(await upgrade(peer, credential, '/companion/v1/streams', { token: session.token }));
    assert.equal((await upgrade(peer, credential, '/companion/v1/streams', { token: session.token })).status, 429);
    const occupied = await session.probe();
    assert.equal(occupied.streamOrdinal, 2);
    assert.equal(occupied.stream.phase, 'awaiting_open');
    assert.equal(occupied.control.streamLeases, 2);
    assert.equal(occupied.pool.streamLeases, 2);
    await session.cancel();
    await Promise.all(pending.map(connection => connection.ws.cancel()));
    const clean = await until(session.probe, value => value.cleanup.complete);
    assert.equal(clean.pool.streamLeases, 0);
    assert.equal(clean.pool.sessionLeases, 0);
  } finally { await Promise.all(pending.map(connection => connection.ws.cancel())); await session?.cancel(); await peer.close(); }
});

test('bounded upgrade-attempt cap refuses before allocating a phantom lease', { timeout: 30000 }, async () => {
  const peer = await startCompanionStreamPeer();
  let session;
  try {
    const credential = await enrollHost(peer); session = await control(peer, credential, 'malformed');
    for (let ordinal = 1; ordinal <= 64; ordinal++) {
      const connection = await upgrade(peer, credential, '/companion/v1/streams', { token: session.token });
      const closed = observeClose(connection.socket);
      await connection.ws.send('close', Buffer.from([3, 232]));
      await closed; await connection.ws.cancel();
      const failed = await until(session.probe, value => value.stream?.resourcesReleased);
      assert.equal(failed.streamOrdinal, ordinal); assert.equal(failed.pool.streamLeases, 0);
    }
    assert.equal((await upgrade(peer, credential, '/companion/v1/streams', { token: session.token })).status, 429);
    const bounded = await session.probe();
    assert.equal(bounded.streamOrdinal, 64); assert.equal(bounded.pool.streamLeases, 0);
    assert.equal(bounded.control.streamLeases, 0);
    await session.cancel(); await until(session.probe, value => value.cleanup.complete);
  } finally { await session?.cancel(); await peer.close(); }
});

test('missing client identity and a valid CA-signed but unregistered SPKI cannot allocate an owner', { timeout: 20000 }, async () => {
  const peer = await startCompanionStreamPeer();
  try {
    await assert.rejects(upgrade(peer, null, '/companion/v1/control', { scenario: 'binding' }));
    peer.command(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256',
      '-config', 'request.cnf', '-keyout', 'unregistered-key.pem', '-out', 'unregistered.csr.pem']);
    fs.chmodSync(path.join(peer.directory, 'unregistered-key.pem'), 0o600);
    peer.command(['ca', '-config', 'issuer.cnf', '-batch', '-notext', '-extensions', 'client', '-in', 'unregistered.csr.pem', '-out', 'unregistered.pem']);
    const leaf = new X509Certificate(fs.readFileSync(path.join(peer.directory, 'unregistered.pem')));
    assert.equal(leaf.verify(new X509Certificate(fs.readFileSync(path.join(peer.directory, 'ca.pem'))).publicKey), true);
    const unregistered = { cert: leaf.toString(), key: fs.readFileSync(path.join(peer.directory, 'unregistered-key.pem')) };
    // HTTP400 is received through successful TLS chain validation, then registry denial.
    assert.equal((await upgrade(peer, unregistered, '/companion/v1/control', { scenario: 'binding' })).status, 400);
    const state = await until(async () => peer.snapshot(), value => value.authenticatedSockets === 0);
    assert.equal(state.ownerRecords, 0);
    assert.equal(state.sessionLeases, 0);
    assert.equal(state.streamLeases, 0);
    assert.equal(state.proxySockets, 0);
  } finally { await peer.close(); }
});

test('actual malformed JSON, invalid framing and oversized headers fail before proxy bytes with sequential bounded cleanup', { timeout: 20000 }, async () => {
  const peer = await startCompanionStreamPeer();
  let session;
  try {
    const credential = await enrollHost(peer); session = await control(peer, credential, 'malformed');
    for (let ordinal = 1; ordinal <= 3; ordinal++) {
      const connection = ordinal === 1 ? await upgrade(peer, credential, '/companion/v1/streams', { token: session.token }) :
        await stream(peer, credential, session, `bad${ordinal}`);
      try {
        const receiving = assert.rejects(nextApplication(connection));
        if (ordinal === 1) await connection.ws.send('text', Buffer.from('{"protocolVersion":1,"type":"open","streamId":"a","streamId":"b"}'));
        else await write(connection.socket, ordinal === 2 ? Buffer.from([0xc2, 0x80]) : Buffer.from([0x82, 0xfe, 0x10, 0x01]));
        await receiving; await connection.ws.cancel();
        const failed = await until(session.probe, value => value.stream?.resourcesReleased);
        assert.equal(failed.streamOrdinal, ordinal);
        assert.equal(failed.stream.phase, 'failed');
        assert.equal(failed.stream.cause, ordinal === 1 ? 'invalid_message' : 'network_unreachable');
        assert.equal(failed.fixture.uploadBytesRead, 0);
        assert.equal(failed.fixture.responseBytesWritten, 0);
        assert.equal(failed.stream.streamLease, false);
        assert.equal(failed.pool.chargedBytes, 0);
      } finally { await connection.ws?.cancel(); }
    }
    await session.cancel(); await until(session.probe, value => value.cleanup.complete);
  } finally { await session?.cancel(); await peer.close(); }
});

test('real server transport close after upload prefix cannot complete a stream or pretend request EOF', { timeout: 20000 }, async () => {
  await context('premature', async ({ session, flow }) => {
    const receiving = assert.rejects(nextApplication(flow));
    await flow.ws.send('binary', requestHeader('premature'));
    await sendBody(flow, 'premature', 0, 4096);
    await receiving; await flow.ws.cancel();
    const failed = await until(session.probe, value => value.stream?.resourcesReleased);
    assert.equal(failed.fixture.uploadPrefixSeen, true);
    assert.equal(failed.fixture.uploadEof, false);
    assert.equal(failed.fixture.responseBytesWritten, 0);
    assert.equal(failed.stream.phase, 'failed');
    assert.equal(failed.stream.cause, 'network_unreachable');
    assert.equal(failed.io.retainedStreamLeasesAtAbort, 1);
    await session.cancel(); await until(session.probe, value => value.cleanup.complete);
  });
});
