// Explicit local research binding. The desktop checkout is supplied by the caller;
// this imports its real maintained proxy implementation and never copies it.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { duplexPair } from 'node:stream';
import { inspect } from 'node:util';
import { HTTP_ORIGIN_PROXY_MODE, HTTP_ORIGIN_CAPABILITY } from './companion-http-origin.mjs';
import { observeClose, bounded, safeError } from './companion-stream-peer-io.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';

function ownCallbacks(socket) {
  const pending = new Set();
  // In-process duplex destruction may leave an unread public write callback
  // outstanding. Actual close cancels that owner with FAILURE, never a receipt.
  socket.once('close', () => { for (const finish of [...pending]) finish(safeError('desktop_transport_closed')); });
  for (const name of ['write', 'end']) {
    const original = socket[name];
    socket[name] = function (...args) {
      const index = args.length - 1, callback = args[index];
      if (typeof callback !== 'function') return original.apply(this, args);
      let settled = false;
      const finish = failure => { if (settled) return; settled = true; pending.delete(finish); callback(failure); };
      if (pending.size >= 16) throw safeError('desktop_transport_bound');
      pending.add(finish); args[index] = finish;
      if (socket.closed) { queueMicrotask(() => finish(safeError('desktop_transport_closed'))); return name === 'write' ? false : socket; }
      try { return original.apply(this, args); }
      catch { finish(safeError('desktop_transport_failed')); throw safeError('desktop_transport_failed'); }
    };
  }
  return () => pending.size;
}

export async function createDesktopOriginBackend({ desktopRoot, desktopCommit, authorizeDestination, onCapture = () => {} } = {}) {
  let ProxyServer;
  try {
    if (typeof desktopRoot !== 'string' || !path.isAbsolute(desktopRoot) || typeof desktopCommit !== 'string' || desktopCommit.length !== 40 || !/^[0-9a-f]{40}$/.test(desktopCommit) ||
        typeof authorizeDestination !== 'function' || typeof onCapture !== 'function') throw 0;
    const root = fs.realpathSync(desktopRoot), filename = fs.realpathSync(path.join(root, 'src/proxy/proxy-server.js'));
    if (!filename.startsWith(root + path.sep)) throw 0;
    const results = await Promise.all([['rev-parse', 'HEAD'], ['status', '--porcelain', '--untracked-files=no']].map(args =>
      runDraftCommand('git', args, { cwd: root, timeoutMillis: 5000, maxOutputBytes: 4096 })));
    if (results.some(result => result.code !== 0 || result.reason || !result.closeObserved || !result.processGroupClosed) ||
        results[0].output.toString('utf8').trim() !== desktopCommit || results[1].output.length !== 0) throw 0;
    ({ ProxyServer } = await import(pathToFileURL(filename).href));
    if (typeof ProxyServer !== 'function' || typeof ProxyServer.prototype.attachTrustedHttpOriginConnectStream !== 'function') throw 0;
  } catch { throw safeError('desktop_origin_configuration'); }
  let closing = false, closeTask, admitted = 0, settled = 0, captures = 0, clientEndWrites = 0;
  const proxy = new ProxyServer(null, { onRequest: value => { captures++; onCapture(value); } });
  const owners = new Set();
  const factory = context => {
    if (closing || context.proxyMode !== HTTP_ORIGIN_PROXY_MODE || !context.negotiatedCapabilities.includes(HTTP_ORIGIN_CAPABILITY) || context.admissionAllowed() !== true) throw safeError('desktop_origin_rejected');
    const [transport, peer] = duplexPair({ allowHalfOpen: true, readableHighWaterMark: 4096, writableHighWaterMark: 4096 });
    transport.on('error', () => {}); peer.on('error', () => {});
    peer.once('end', () => { clientEndWrites++; }); // Actual drained desktop-facing read EOF.
    const transportCallbacks = ownCallbacks(transport), peerCallbacks = ownCallbacks(peer);
    const transportClosed = observeClose(transport), peerClosed = observeClose(peer), abort = new AbortController();
    let attached = null, started = false, sealed = false, ownerClose, resolveStarted;
    const startSettled = new Promise(done => { resolveStarted = done; });
    const closed = Promise.all([transportClosed, peerClosed, startSettled]).then(async () => {
      if (attached) await attached.closed;
      if (transportCallbacks() || peerCallbacks()) throw safeError('cleanup_incomplete');
      owners.delete(owner); settled++;
    });
    const owner = Object.freeze({ transport, closed,
      async start() {
        if (started || sealed || closing || context.admissionAllowed() !== true) { resolveStarted(); throw safeError('desktop_origin_rejected'); }
        started = true;
        try {
          // Retain the actual desktop owner before any subsequent asynchronous work.
          attached = proxy.attachTrustedHttpOriginConnectStream(peer, { proxyMode: context.proxyMode,
            negotiatedCapabilities: [...context.negotiatedCapabilities], signal: abort.signal,
            authorizeDestination: endpoint => {
              if (sealed || closing || context.admissionAllowed() !== true) return false;
              let allowed; try { allowed = authorizeDestination(endpoint, context.grant); } catch { return false; }
              return allowed === true && !sealed && !closing && context.admissionAllowed() === true;
            } });
        } finally { resolveStarted(); }
      },
      close() {
        if (ownerClose) return ownerClose;
        // All admissions and I/O are interrupted before this method returns.
        sealed = true; abort.abort(); transport.destroy(); peer.destroy();
        if (!started) resolveStarted();
        let attachmentClose; try { attachmentClose = attached?.close(); } catch { attachmentClose = Promise.reject(safeError('cleanup_incomplete')); }
        ownerClose = Promise.all([attachmentClose, closed]).then(() => {});
        ownerClose.catch(() => {}); return ownerClose;
      } });
    // duplexPair destruction is local to one endpoint. Propagate either actual
    // close through this owner so silent desktop refusal also interrupts WSS I/O.
    peer.once('close', () => { owner.close().catch(() => {}); });
    transport.once('close', () => { owner.close().catch(() => {}); });
    admitted++; owners.add(owner); closed.catch(() => {});
    return owner;
  };
  const snapshot = () => Object.freeze({ closing, activeOwners: owners.size, admitted, settled, captures, clientEndWrites });
  return Object.freeze({ factory, snapshot,
    close() {
      if (closeTask) return closeTask;
      closing = true;
      const joins = [...owners].map(owner => owner.close());
      // Begin independent desktop teardown even when an injected owner cannot join.
      let stopping; try { stopping = proxy.stop(); } catch { stopping = Promise.reject(safeError('cleanup_incomplete')); }
      closeTask = bounded((async () => {
        const results = await Promise.allSettled([...joins, stopping]);
        if (results.some(result => result.status === 'rejected') || owners.size) throw safeError('cleanup_incomplete');
        return snapshot();
      })(), 7000);
      return closeTask;
    },
    toJSON: snapshot, [inspect.custom]: () => '[Desktop origin research backend]',
  });
}
