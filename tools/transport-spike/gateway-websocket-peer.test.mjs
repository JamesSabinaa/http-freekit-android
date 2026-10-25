import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import tls from 'node:tls';
import { inspect } from 'node:util';
import { randomBytes, X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { gatewayPeerScenarios, startGatewayWebSocketPeer } from './gateway-websocket-peer.mjs';
import { headers, bounded, observeClose } from './companion-stream-peer-io.mjs';
import { ResearchWebSocket } from './research-websocket.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';

async function connect(peer) {
  const meta = peer.metadata(), certificate = new X509Certificate(Buffer.from(meta.gatewayCertificateDer, 'base64url'));
  const socket = tls.connect({ host: '127.0.0.1', port: meta.port, servername: meta.logicalName, ca: certificate.toString(), rejectUnauthorized: true });
  observeClose(socket); socket.on('error', () => {});
  try {
    await bounded(new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', reject); }), 5000);
    assert.equal(socket.authorized, true);
    const key = randomBytes(16).toString('base64');
    socket.write(`GET /companion/v1/control HTTP/1.1\r\nHost: ${meta.logicalName}:${meta.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    const response = await bounded(headers(socket), 5000);
    assert.match(response.toString(), /^HTTP\/1\.1 101 Switching Protocols\r\n/);
    return { socket, ws: new ResearchWebSocket(socket, { role: 'client', maxBinaryBytes: 65536 }) };
  } catch (failure) { socket.destroy(); await observeClose(socket); throw failure; }
}
const next = ws => bounded(ws.next(), 5000);
async function normalClose(ws) {
  await ws.send('close', Buffer.from([3, 232]));
  const event = await next(ws);
  try { assert.equal(event.kind, 'close'); assert.equal(event.closeCode, 1000); }
  finally { event.release(); }
}
function joined(snapshot) {
  for (const key of ['admissionClosed', 'listenerClosed', 'ownedChildrenJoined', 'privateDirectoryRemoved']) assert.equal(snapshot[key], true, key);
  for (const key of ['activeSockets','pendingCallbacks','pendingTimers','workers']) assert.equal(snapshot[key], 0, key);
}

test('independent scoped TLS echoes real text/binary, empty ping/pong and close before actual joined cleanup', { timeout: 20000 }, async () => {
  const peer = await startGatewayWebSocketPeer({ scenario: 'echo' }); let connection;
  try {
    const meta = peer.metadata();
    for (const text of [String(peer), JSON.stringify(peer), inspect(peer)]) {
      assert.equal(text.includes(meta.logicalName), false); assert.equal(text.includes(meta.gatewayCertificateDer), false);
    }
    connection = await connect(peer); const { ws } = connection;
    const text = Buffer.from('independent-backend-text'); await ws.send('text', text);
    let event = await next(ws); try { assert.equal(event.kind, 'text'); assert.deepEqual(event.copyBytes(), text); } finally { event.release(); }
    const binary = Buffer.from(Array.from({ length: 65536 }, (_, i) => (i * 19 + 5) & 255)); await ws.send('binary', binary);
    event = await next(ws); try { assert.equal(event.kind, 'binary'); assert.deepEqual(event.copyBytes(), binary); } finally { event.release(); }
    await ws.send('ping', Buffer.alloc(0));
    event = await next(ws); try { assert.equal(event.kind, 'pong'); assert.equal(event.copyBytes().length, 0); } finally { event.release(); }
    event = await next(ws); try { assert.equal(event.kind, 'ping'); assert.equal(event.copyBytes().toString(), 'probe'); await ws.send('pong', event.copyBytes()); } finally { event.release(); }
    await normalClose(ws);
  } finally { connection?.socket.destroy(); if (connection) await observeClose(connection.socket); joined(await peer.close()); }
  assert.deepEqual([peer.snapshot().upgrades,peer.snapshot().clientTextMessages,peer.snapshot().clientBinaryMessages,peer.snapshot().clientPongs,peer.snapshot().clientCloseObserved],[1,1,1,1,true]);
});

test('actual TLS fragmented messages preserve split UTF8 and binary bytes with two ping interleavings', { timeout: 15000 }, async () => {
  const peer = await startGatewayWebSocketPeer({ scenario: 'fragmented' }); let connection;
  try {
    connection = await connect(peer); let text, binary, pings = 0;
    while (!text || !binary || pings < 2) {
      const event = await next(connection.ws);
      try {
        if (event.kind === 'ping') { pings++; assert.equal(event.copyBytes().toString(),'probe'); await connection.ws.send('pong',event.copyBytes()); }
        else if (event.kind === 'text') text = event.copyBytes();
        else if (event.kind === 'binary') binary = event.copyBytes();
        else assert.fail('unexpected_fixture_event');
      } finally { event.release(); }
    }
    assert.equal(text.toString(),'fragmented-€-backend');
    assert.deepEqual(binary,Buffer.from(Array.from({length:4097},(_,i)=>(i*29+3)&255)));
    await normalClose(connection.ws);
  } finally { connection?.socket.destroy(); if(connection) await observeClose(connection.socket); joined(await peer.close()); }
  assert.equal(peer.snapshot().clientPongs,2);
});

test('a real masked-server violation is rejected and interrupted TLS ownership still joins', { timeout: 15000 }, async () => {
  const peer=await startGatewayWebSocketPeer({scenario:'bad-mask'});let connection;
  try { connection=await connect(peer);await assert.rejects(next(connection.ws)); }
  finally { connection?.socket.destroy();if(connection)await observeClose(connection.socket);joined(await peer.close()); }
});

test('actual private CLI emits only finite public metadata and joined release/stop records', { timeout: 20000 }, async () => {
  const result=await runDraftCommand(process.execPath,[fileURLToPath(new URL('./gateway-websocket-peer.mjs',import.meta.url)),'--scenario','held-read'],
    {timeoutMillis:15000,stdinBytes:Buffer.from('{"op":"release"}\n{"op":"stop"}\n')});
  assert.equal(result.code,0,result.stderr);assert.equal(result.closeObserved,true);assert.equal(result.processGroupClosed,true);
  const lines=result.output.trim().split('\n').map(line=>JSON.parse(line));
  assert.equal(lines.length,3);assert.deepEqual(lines.map(line=>line.event),['ready','released','closed']);
  assert.deepEqual(Object.keys(lines[0]).sort(),['event','format','gatewayCertificateDer','logicalName','port','revision']);
  joined(lines[2]);assert.equal(result.output.includes('PRIVATE KEY'),false);assert.equal(result.stderrBytes,0);
});

test('finite CLI/options reject supplied text and startup failure removes only its owned private directory', { timeout: 10000 }, async () => {
  assert.equal(gatewayPeerScenarios.length,15);
  const command=await runDraftCommand(process.execPath,[fileURLToPath(new URL('./gateway-websocket-peer.mjs',import.meta.url)),'--scenario','CANARY_private'],{timeoutMillis:5000});
  assert.equal(command.code,1);assert.equal(command.closeObserved,true);assert.equal(command.processGroupClosed,true);
  assert.equal((command.output+command.stderr).includes('CANARY'),false);
  const before=new Set(fs.readdirSync(os.tmpdir()).filter(name=>name.startsWith('freekit-gateway-ws-')));
  await assert.rejects(startGatewayWebSocketPeer({scenario:'echo',openssl:process.execPath}));
  const after=fs.readdirSync(os.tmpdir()).filter(name=>name.startsWith('freekit-gateway-ws-')&&!before.has(name));assert.deepEqual(after,[]);
});
