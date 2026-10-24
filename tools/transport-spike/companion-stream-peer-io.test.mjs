import test from 'node:test';
import assert from 'node:assert/strict';
import { Duplex } from 'node:stream';
import net from 'node:net';
import { once } from 'node:events';
import { pull, endWrite, writerState, observeClose, bounded } from './companion-stream-peer-io.mjs';

test('real EOF remains observable after a fully half-closed TCP socket auto-destroys', { timeout: 5000 }, async () => {
  const server = net.createServer({ allowHalfOpen: true });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const accepted = once(server, 'connection');
  const client = net.connect(server.address().port, '127.0.0.1');
  const connected = once(client, 'connect');
  const clientClosed = observeClose(client);
  const [peer] = await accepted; await connected;
  const peerClosed = observeClose(peer);
  try {
    await endWrite(client);
    assert.equal(await pull(peer, 1), null);
    await endWrite(peer);
    assert.equal(await pull(client, 1), null);
    await clientClosed; await peerClosed;
    assert.equal(client.destroyed, true);
    assert.equal(await pull(client, 1), null);
  } finally { client.destroy(); peer.destroy(); await new Promise(done => server.close(done)); }
});

test('end callback remains charged and unjoined after transport close until its actual callback occurs', async () => {
  const socket = new Duplex({ read() {}, write(_bytes, _encoding, callback) { callback(); } });
  let callback;
  socket.end = done => { callback = done; return socket; };
  const state = writerState();
  const ending = assert.rejects(endWrite(socket, state), failure => failure.code === 'socket_end_failed');
  const closed = observeClose(socket); socket.destroy(); await closed; await ending;
  assert.equal(state.pending, 1);
  await assert.rejects(bounded(state.idle, 20), failure => failure.code === 'cleanup_incomplete');
  callback(); await state.idle;
  assert.equal(state.pending, 0);
});

test('repeated close observers share the admission-time event promise, not a later closed flag', async () => {
  let destroyDone;
  const socket = new Duplex({ read() {}, write(_bytes, _encoding, callback) { callback(); },
    destroy(_failure, callback) { destroyDone = callback; } });
  const first = observeClose(socket); let joined = false;
  first.then(() => { joined = true; });
  socket.destroy();
  assert.equal(observeClose(socket), first);
  await new Promise(done => setImmediate(done));
  assert.equal(joined, false);
  destroyDone(); await first;
  assert.equal(joined, true);
});
