import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { ResearchWebSocket } from './research-websocket.mjs';
import { runResearchWebSocketPeer } from './research-websocket-peer.mjs';

function childPeer(t, args = []) {
  const child = spawn(process.execPath, [fileURLToPath(new URL('./research-websocket-peer.mjs', import.meta.url)), ...args],
    { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let stdout = '';
  let stderr = '';
  let readyDone;
  let readyReject;
  const ready = new Promise((done, reject) => { readyDone = done; readyReject = reject; });
  ready.catch(() => {});
  child.stdout.on('data', chunk => {
    stdout += chunk.toString('utf8');
    if (stdout.length > 128) { child.kill(); readyReject(Error('fixture_output_bound')); }
    const first = stdout.split('\n')[0];
    if (stdout.includes('\n')) {
      const match = /^READY ([1-9][0-9]{0,4})$/.exec(first);
      if (!match || Number(match[1]) > 65535) readyReject(Error('fixture_ready_invalid'));
      else readyDone(Number(match[1]));
    }
  });
  child.stderr.on('data', chunk => {
    stderr += chunk.toString('utf8');
    if (stderr.length > 128) child.kill();
  });
  const closed = new Promise((done, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { readyReject(Error('fixture_exited_before_ready')); done({ code, signal, stdout, stderr }); });
  });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill(); });
  return { child, ready, closed };
}
async function connect(port) {
  const socket = net.connect(port, '127.0.0.1');
  await once(socket, 'connect');
  return socket;
}
async function expect(owner, kind, expected) {
  const event = await owner.next();
  try { assert.equal(event.kind, kind); assert.deepEqual(event.copyBytes(), expected); }
  finally { event.release(); }
}

test('standalone peer completes the exact bounded framing exchange and exits after joined closure', { timeout: 15000 }, async t => {
  const process = childPeer(t);
  const port = await process.ready;
  const socket = await connect(port);
  const owner = new ResearchWebSocket(socket, { role: 'client' });
  try {
    await owner.send('text', Buffer.from('framing-probe'));
    await expect(owner, 'text', Buffer.from('framing-ready'));
    const refused = net.connect(port, '127.0.0.1');
    const [admissionFailure] = await once(refused, 'error');
    assert.equal(admissionFailure.code, 'ECONNREFUSED');
    refused.destroy();
    const pattern = Buffer.allocUnsafe(65536);
    for (let index = 0; index < pattern.length; index++) pattern[index] = index % 251;
    await owner.send('binary', pattern);
    await expect(owner, 'binary', pattern);
    await owner.send('ping', Buffer.from([7, 8]));
    await expect(owner, 'pong', Buffer.from([7, 8]));
    await owner.send('close', Buffer.from([3, 232]));
    await expect(owner, 'close', Buffer.from([3, 232]));
    await owner.finish();
    assert.deepEqual(await process.closed, { code: 0, signal: null, stdout: `READY ${port}\nCOMPLETE\n`, stderr: '' });
  } finally { await owner.cancel(); }
});

test('peer rejects a wrong payload without echoing its bytes and closes admission', { timeout: 15000 }, async t => {
  const process = childPeer(t);
  const port = await process.ready;
  const owner = new ResearchWebSocket(await connect(port), { role: 'client' });
  try {
    await owner.send('text', Buffer.from('PRIVATE_WRONG_PAYLOAD'));
    const result = await process.closed;
    assert.equal(result.code, 1);
    assert.equal(result.stdout, `READY ${port}\n`);
    assert.equal(result.stderr, 'FAILED research_websocket_peer\n');
    const refused = net.connect(port, '127.0.0.1');
    const [failure] = await once(refused, 'error');
    assert.equal(failure.code, 'ECONNREFUSED');
    refused.destroy();
  } finally { await owner.cancel(); }
});

test('peer rejects raw malformed unmasked input and premature EOF with fixed diagnostics', { timeout: 15000 }, async t => {
  for (const body of [Buffer.from([0x81, 0]), Buffer.from([0x81])]) {
    const process = childPeer(t);
    const port = await process.ready;
    const socket = await connect(port);
    socket.on('error', () => {});
    socket.end(body);
    const result = await process.closed;
    assert.equal(result.code, 1);
    assert.equal(result.stdout, `READY ${port}\n`);
    assert.equal(result.stderr, 'FAILED research_websocket_peer\n');
    socket.destroy();
  }
});

test('idle peer deadline fails, closes its listener/socket, and never reports completion', { timeout: 5000 }, async () => {
  let port;
  let client;
  let clientClosed;
  const run = runResearchWebSocketPeer({ timeoutMillis: 500, onReady: value => {
    port = value;
    client = net.connect(port, '127.0.0.1');
    client.on('error', () => {});
    clientClosed = new Promise(done => client.once('close', done));
  } });
  await assert.rejects(run, failure => failure.code === 'probe_timeout');
  await clientClosed;
  assert.equal(client.closed, true);
  const refused = net.connect(port, '127.0.0.1');
  const [failure] = await once(refused, 'error');
  assert.equal(failure.code, 'ECONNREFUSED'); refused.destroy();
});

test('CLI rejects extra arguments without binding a listener or leaking supplied material', { timeout: 5000 }, async t => {
  const process = childPeer(t, ['PRIVATE_ARGUMENT']);
  const result = await process.closed;
  assert.deepEqual(result, { code: 1, signal: null, stdout: '', stderr: 'FAILED research_websocket_peer\n' });
});
