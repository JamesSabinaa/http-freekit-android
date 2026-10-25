import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import httpClient from 'node:http';
import { createCaptureFixture, captureFixtureDigests } from './capture-fixture.mjs';
import { runDraftCommand } from '../transport-spike/draft-stream-command.mjs';

const ports = { http: 0, opaque: 0, udp: 0, quic: 0 };
const body = Buffer.from(Array.from({ length: 16421 }, (_, i) => (i * 31 + 7) & 255));
const http = Buffer.concat([Buffer.from('POST /capture-fixture HTTP/1.1\r\nHost: capture-fixture.invalid\r\nContent-Length: 16421\r\nConnection: close\r\n\r\n'), body]);
const digest = value => createHash('sha256').update(value).digest('hex');
const exchange = async (port, payload) => {
  const socket = net.connect(port, '127.0.0.1'); socket.on('error', () => {});
  try {
    socket.setTimeout(2000, () => socket.destroy(Error('test_exchange_deadline')));
    const chunks = [];
    socket.on('data', chunk => chunks.push(chunk));
    const closed = once(socket, 'close');
    await once(socket, 'connect'); socket.end(payload); await closed;
    return Buffer.concat(chunks);
  } finally { socket.destroy(); }
};
const packet = async (port, bytes) => {
  const socket = dgram.createSocket('udp4');
  let timer;
  try {
    const response = Promise.race([once(socket, 'message'), new Promise((_, reject) => { timer = setTimeout(() => reject(Error('test_packet_deadline')), 2000); })]);
    socket.send(bytes, port, '127.0.0.1');
    return (await response)[0];
  } finally { clearTimeout(timer); const closed = once(socket, 'close'); socket.close(); await closed; }
};

test('actual intercepted IPv4 HTTP/opaque and IPv6 roles preserve full bytes, EOF and reply digest', { timeout: 10000 }, async () => {
  const fixture = await createCaptureFixture({ ports });
  try {
    assert.equal(captureFixtureDigests.tcpReply, '05dfd86ee3ecc0267ceb6234e1955c1e8c80e34b6323b2b1c87c7d1d84042255');
    for (const [role, bytes] of [[1, http], [2, body], [3, http]]) {
      const response = await exchange(fixture.ports.intercepted, Buffer.concat([Buffer.from([role]), bytes]));
      assert.equal(response.length, 32787); assert.equal(digest(response), captureFixtureDigests.tcpReply);
    }
    const snap = fixture.snapshot();
    assert.equal(snap.interceptedHttp, 1); assert.equal(snap.interceptedOpaque, 1); assert.equal(snap.interceptedIpv6, 1);
    assert.equal(snap.directHttp, 0); assert.equal(snap.invalidRequests, 0);
  } finally {
    const closed = await fixture.close();
    assert.equal(closed.closed, true); assert.equal(closed.activeSockets, 0); assert.equal(closed.pendingCallbacks, 0); assert.equal(closed.timers, 0);
  }
});

test('direct TCP, UDP and real DNS-shaped packets are independently counted without an intercepted role', { timeout: 10000 }, async () => {
  const fixture = await createCaptureFixture({ ports });
  try {
    assert.equal(digest(await exchange(fixture.ports.http, http)), captureFixtureDigests.tcpReply);
    assert.equal(digest(await exchange(fixture.ports.opaque, body)), captureFixtureDigests.tcpReply);
    assert.equal(digest(await exchange(fixture.ports.direct, body)), captureFixtureDigests.tcpReply);
    const udp = Buffer.from(Array.from({ length: 256 }, (_, i) => (i * 13 + 5) & 255));
    assert.equal(captureFixtureDigests.udp, 'ca8c15a2b7d76a0dc5c39dc35deffcfc596d14194b5c09a7513acb1577e99dbe');
    assert.deepEqual(await packet(fixture.ports.udp, udp), udp);
    assert.deepEqual(await packet(fixture.ports.quic, udp), udp);
    const query = Buffer.from('435001000001000000000000076669787475726507696e76616c69640000010001', 'hex');
    const response = await packet(fixture.ports.udp, query);
    assert.equal(captureFixtureDigests.dns, 'ab8bd414e49bcfde5e1bcc7277d8947246a42dbd5802ee81db4cc4e90bddd8d3');
    assert.equal(response[2], 0x81); assert.equal(response[3], 0x80); assert.equal(digest(response), captureFixtureDigests.dns);
    const snap = fixture.snapshot();
    for (const key of ['directHttp', 'directOpaque', 'directTcp', 'udp', 'dns', 'udp443']) assert.equal(snap[key], 1);
    assert.equal(snap.interceptedHttp, 0);
  } finally { await fixture.close(); }
});

test('unknown role, changed byte and truncated body cannot increment a successful receiver counter', { timeout: 10000 }, async () => {
  const fixture = await createCaptureFixture({ ports });
  try {
    for (const bytes of [Buffer.from([99]), Buffer.concat([Buffer.from([1]), http.subarray(0, -1)]), Buffer.concat([Buffer.from([2]), body, Buffer.from([0])])]) {
      assert.equal((await exchange(fixture.ports.intercepted, bytes)).length, 0);
    }
    const snap = fixture.snapshot(); assert.equal(snap.invalidRequests, 3); assert.equal(snap.interceptedHttp, 0); assert.equal(snap.interceptedOpaque, 0);
  } finally { await fixture.close(); }
});

test('actual idle sockets join, and a late UDP bind collision leaves no child handles or listeners', { timeout: 15000 }, async () => {
  const fixture = await createCaptureFixture({ ports });
  const socket = net.connect(fixture.ports.intercepted, '127.0.0.1'); await once(socket, 'connect');
  const socketClosed = once(socket, 'close');
  const result = await fixture.close(); await socketClosed;
  assert.equal(result.activeSockets, 0); assert.equal(result.timers, 0); assert.equal(result.listeners, 0);
  const moduleUrl = new URL('./capture-fixture.mjs', import.meta.url).href;
  const script = `import dgram from 'node:dgram';import {once} from 'node:events';import {createCaptureFixture} from ${JSON.stringify(moduleUrl)};const s=dgram.createSocket('udp4');s.bind(0,'127.0.0.1');await once(s,'listening');try{await createCaptureFixture({ports:{http:0,opaque:0,udp:s.address().port,quic:0}});process.exitCode=4;}catch(e){if(e.message!=='capture_fixture_setup_failed')process.exitCode=5;}finally{const c=once(s,'close');s.close();await c;}`;
  const child = await runDraftCommand(process.execPath, ['--input-type=module', '-e', script], { timeoutMillis: 10000 });
  assert.equal(child.code, 0); assert.equal(child.closeObserved, true); assert.equal(child.processGroupClosed, true); assert.equal(child.reason, null);
});

test('finite held-response gate observes real request EOF and Stop closes the actual pending receiver', { timeout: 10000 }, async () => {
  const fixture = await createCaptureFixture({ ports });
  let socket;
  try {
    await new Promise((resolve, reject) => httpClient.get({ host: '127.0.0.1', port: fixture.ports.control, path: '/hold-next', agent: false }, response => {
      response.resume(); response.once('end', () => response.statusCode === 200 ? resolve() : reject(Error('hold_failed')));
    }).once('error', reject));
    socket = net.connect(fixture.ports.intercepted, '127.0.0.1'); await once(socket, 'connect');
    socket.end(Buffer.concat([Buffer.from([1]), http]));
    const started = performance.now();
    while (fixture.snapshot().heldConnections !== 1 && performance.now() - started < 2000) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(fixture.snapshot().heldConnections, 1); assert.equal(fixture.snapshot().interceptedHttp, 0);
    const closed = once(socket, 'close'); socket.destroy(); await closed;
  } finally { socket?.destroy(); assert.equal((await fixture.close()).heldConnections, 0); }
});
