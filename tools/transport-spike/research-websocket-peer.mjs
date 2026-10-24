// Single-connection loopback framing interoperability fixture. No HTTP upgrade/TLS/authentication.
import net from 'node:net';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { ResearchWebSocket, ResearchWebSocketError } from './research-websocket.mjs';

const failure = code => new ResearchWebSocketError(code);

export async function runResearchWebSocketPeer({ timeoutMillis = 10000, onReady = () => {} } = {}) {
  if (!Number.isInteger(timeoutMillis) || timeoutMillis < 100 || timeoutMillis > 10000 || typeof onReady !== 'function') {
    throw failure('invalid_configuration');
  }
  const absoluteEnd = performance.now() + timeoutMillis;
  const cleanupReserve = Math.min(1000, Math.floor(timeoutMillis / 4));
  const server = net.createServer({ pauseOnConnect: true });
  server.maxConnections = 1;
  let owner;
  let socket;
  let socketClosed;
  let admissionClosed;
  let exchangeTimer;
  let cleanupTimer;
  let aborted = false;
  let acceptReject;
  const closeAdmission = () => {
    if (admissionClosed === undefined && server.listening) {
      admissionClosed = new Promise((done, reject) => server.close(error => error ? reject(failure('probe_cleanup')) : done()));
      admissionClosed.catch(() => {});
    }
    return admissionClosed ?? Promise.resolve();
  };
  const accepted = new Promise((done, reject) => {
    acceptReject = reject;
    server.once('error', () => reject(failure('probe_setup')));
    server.once('connection', connected => {
      socket = connected;
      socket.on('error', () => {}); // Errors are translated by the owner; never print native details.
      socketClosed = new Promise(resolveClosed => socket.once('close', resolveClosed));
      closeAdmission(); // Stop admitting work immediately, not after the exchange.
      if (aborted) { socket.destroy(); reject(failure('probe_timeout')); }
      else done(socket);
    });
  });
  accepted.catch(() => {});
  const work = (async () => {
    await new Promise((done, reject) => {
      server.once('error', () => reject(failure('probe_setup')));
      server.listen({ host: '127.0.0.1', port: 0, exclusive: true, backlog: 1 }, done);
    });
    if (aborted) { closeAdmission(); throw failure('probe_timeout'); }
    onReady(server.address().port);
    owner = new ResearchWebSocket(await accepted, { role: 'server', cleanupTimeoutMillis: cleanupReserve });
    const expect = async (kind, expected) => {
      const event = await owner.next();
      try {
        if (event.kind !== kind || !event.copyBytes().equals(expected)) throw failure('probe_mismatch');
      } finally { event.release(); }
    };
    await expect('text', Buffer.from('framing-probe'));
    await owner.send('text', Buffer.from('framing-ready'));
    const pattern = Buffer.allocUnsafe(65536);
    for (let index = 0; index < pattern.length; index++) pattern[index] = index % 251;
    await expect('binary', pattern);
    await owner.send('binary', pattern);
    await expect('ping', Buffer.from([7, 8]));
    await owner.send('pong', Buffer.from([7, 8]));
    await expect('close', Buffer.from([3, 232]));
    await owner.send('close', Buffer.from([3, 232]));
    await owner.finish();
    await closeAdmission();
    const state = owner.snapshot();
    if (!state.transportClosed || state.pendingWriteCallbacks !== 0 || state.queuedWrites !== 0 || state.reading) {
      throw failure('probe_cleanup');
    }
  })();
  // Observe late rejection too when a deadline wins the race.
  work.catch(() => {});
  try {
    await Promise.race([work, new Promise((_, reject) => {
      exchangeTimer = setTimeout(() => {
        aborted = true;
        acceptReject(failure('probe_timeout'));
        reject(failure('probe_timeout'));
      }, Math.max(1, absoluteEnd - performance.now() - cleanupReserve));
    })]);
  } finally {
    clearTimeout(exchangeTimer);
    await Promise.race([(async () => {
      if (owner) await owner.cancel();
      else socket?.destroy();
      await closeAdmission();
      if (socketClosed) await socketClosed;
      await Promise.allSettled([work]);
    })(), new Promise((_, reject) => {
      cleanupTimer = setTimeout(() => reject(failure('probe_cleanup')), Math.max(1, absoluteEnd - performance.now()));
    })]).finally(() => clearTimeout(cleanupTimer));
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 2) throw failure('invalid_arguments');
    await runResearchWebSocketPeer({ onReady: port => process.stdout.write(`READY ${port}\n`) });
    process.stdout.write('COMPLETE\n');
  } catch {
    // Fixed diagnostic: no payload, close reason, endpoint, filesystem path, or native error.
    process.stderr.write('FAILED research_websocket_peer\n');
    process.exitCode = 1;
  }
}
