// Explicit local research binding. The desktop checkout is supplied by the caller;
// this imports its real maintained proxy implementation and never copies it.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { duplexPair } from 'node:stream';
import { inspect } from 'node:util';
import { X509Certificate } from 'node:crypto';
import { HTTP_ORIGIN_PROXY_MODE, HTTP_ORIGIN_CAPABILITY } from './companion-http-origin.mjs';
import { observeClose, bounded, safeError } from './companion-stream-peer-io.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';
import { validateCapabilities, TRAFFIC_CAPABILITIES } from './companion-protocol-codec.mjs';

export const C3_DESKTOP_COMMIT = '2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6';
export const C3_LOGICAL_HOST = 'capture-origin.invalid';
export const C3_CAPABILITIES = Object.freeze([HTTP_ORIGIN_CAPABILITY, 'tcp-https-connect']);
const c3Materials = new WeakSet();

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

async function desktopSource({ desktopRoot, desktopCommit, https = false }) {
  try {
    if (typeof desktopRoot !== 'string' || !path.isAbsolute(desktopRoot) || typeof desktopCommit !== 'string' || desktopCommit.length !== 40 || !/^[0-9a-f]{40}$/.test(desktopCommit) ||
        https && desktopCommit !== C3_DESKTOP_COMMIT) throw 0;
    const root = fs.realpathSync(desktopRoot), filename = fs.realpathSync(path.join(root, 'src/proxy/proxy-server.js'));
    if (!filename.startsWith(root + path.sep)) throw 0;
    const results = await Promise.all([['rev-parse', 'HEAD'], ['status', '--porcelain', '--untracked-files=no']].map(args =>
      runDraftCommand('git', args, { cwd: root, timeoutMillis: 5000, maxOutputBytes: 4096 })));
    if (results.some(result => result.code !== 0 || result.reason || !result.closeObserved || !result.processGroupClosed) ||
        results[0].output.toString('utf8').trim() !== desktopCommit || results[1].output.length !== 0) throw 0;
    const { ProxyServer } = await import(pathToFileURL(filename).href);
    if (typeof ProxyServer !== 'function' || typeof ProxyServer.prototype.attachTrustedHttpOriginConnectStream !== 'function') throw 0;
    if (!https) return { ProxyServer };
    const caFile = fs.realpathSync(path.join(root, 'src/proxy/certificate-authority.js'));
    if (!caFile.startsWith(root + path.sep) || typeof ProxyServer.prototype.attachTrustedHttpsConnectStream !== 'function') throw 0;
    const { CertificateAuthority } = await import(pathToFileURL(caFile).href);
    if (typeof CertificateAuthority !== 'function') throw 0;
    return { ProxyServer, CertificateAuthority };
  } catch { throw safeError('desktop_origin_configuration'); }
}

/** Actual desktop CA objects stay inside this private, owned research process. */
export async function createDesktopOriginAuthorities({ desktopRoot, desktopCommit, directory } = {}) {
  const { CertificateAuthority } = await desktopSource({ desktopRoot, desktopCommit, https: true });
  try {
    if (typeof directory !== 'string' || !path.isAbsolute(directory) || fs.realpathSync(directory) !== path.resolve(directory)) throw 0;
    const caDirectory = path.join(directory, 'desktop-interception'), originDirectory = path.join(directory, 'upstream-origin');
    fs.mkdirSync(caDirectory, { mode: 0o700 }); fs.mkdirSync(originDirectory, { mode: 0o700 });
    const logger = Object.freeze({ log() {}, warn() {} });
    const ca = new CertificateAuthority(caDirectory, { logger }), origin = new CertificateAuthority(originDirectory, { logger });
    const initialized = await Promise.allSettled([ca.initialize({ autoRenewExpiring: false }), origin.initialize({ autoRenewExpiring: false })]);
    if (initialized.some(result => result.status === 'rejected')) throw 0;
    const publicCa = new X509Certificate(fs.readFileSync(ca.caCertPath)), originCa = new X509Certificate(fs.readFileSync(origin.caCertPath));
    const tls = await origin.generateCertForHost(C3_LOGICAL_HOST), leaf = new X509Certificate(tls.cert);
    if (publicCa.raw.length > 4096 || publicCa.raw.equals(originCa.raw) || !publicCa.ca || !originCa.ca ||
        !leaf.verify(originCa.publicKey) || leaf.checkHost(C3_LOGICAL_HOST, { subject: 'never', wildcards: false }) !== C3_LOGICAL_HOST) throw 0;
    const material = Object.freeze({ certificateAuthority: ca, originCaPath: origin.caCertPath,
      interceptionCaCertificateDer: () => Buffer.from(publicCa.raw),
      originTlsOptions: () => ({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'] }),
      toJSON: () => '[Private desktop research authorities]', [inspect.custom]: () => '[Private desktop research authorities]' });
    c3Materials.add(material); return material;
  } catch { throw safeError('desktop_origin_configuration'); }
}

export async function createDesktopOriginBackend({ desktopRoot, desktopCommit, authorizeDestination, onCapture = () => {}, httpsMaterial } = {}) {
  if (typeof authorizeDestination !== 'function' || typeof onCapture !== 'function' ||
      httpsMaterial !== undefined && !c3Materials.has(httpsMaterial)) throw safeError('desktop_origin_configuration');
  const { ProxyServer } = await desktopSource({ desktopRoot, desktopCommit, https: httpsMaterial !== undefined });
  let closing = false, closeTask, admitted = 0, settled = 0, captures = 0, clientEndWrites = 0;
  let actualMode = null, actualCapabilities = Object.freeze([]);
  const captureIds = new Set(); // Bounded private identities; never appear in snapshots/logs.
  const proxy = new ProxyServer(httpsMaterial?.certificateAuthority ?? null, { onRequest: value => {
    if (typeof value?.id !== 'string' || value.id.length < 1 || value.id.length > 128 || /[^A-Za-z0-9_.-]/.test(value.id)) throw safeError('desktop_capture_invalid');
    if (value.protocol === 'ws-frame') {
      if (typeof value.parentId !== 'string' || !captureIds.has(value.parentId)) throw safeError('desktop_capture_invalid');
      onCapture(value); return;
    }
    if (!captureIds.has(value.id)) {
      if (captureIds.size >= 8) throw safeError('desktop_capture_bound');
      captureIds.add(value.id); captures++;
    }
    onCapture(value);
  } });
  if (httpsMaterial) proxy.setTrustedCAs([httpsMaterial.originCaPath], { logger: Object.freeze({ log() {} }) });
  const owners = new Set();
  const factory = context => {
    let capabilities;
    try {
      capabilities = Object.freeze(validateCapabilities(context.negotiatedCapabilities));
      const originMode = context.proxyMode === HTTP_ORIGIN_PROXY_MODE && capabilities.includes(HTTP_ORIGIN_CAPABILITY);
      const httpsMode = httpsMaterial !== undefined && context.proxyMode === undefined && capabilities.includes('tcp-https-connect');
      if (closing || !originMode && !httpsMode ||
          httpsMaterial !== undefined && capabilities.some(value => !C3_CAPABILITIES.includes(value)) ||
          capabilities.some(value => !TRAFFIC_CAPABILITIES.includes(value)) || context.admissionAllowed() !== true) throw 0;
    } catch { throw safeError('desktop_origin_rejected'); }
    const mode = context.proxyMode, grant = context.grant, admission = context.admissionAllowed;
    const admissionAllowed = () => { try { return admission.call(context) === true; } catch { return false; } };
    actualMode = mode ?? null; actualCapabilities = capabilities;
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
        if (started || sealed || closing || !admissionAllowed()) { resolveStarted(); throw safeError('desktop_origin_rejected'); }
        started = true;
        try {
          // Retain the actual desktop owner before any subsequent asynchronous work.
          const options = { negotiatedCapabilities: [...capabilities], signal: abort.signal,
            authorizeDestination: endpoint => {
              if (sealed || closing || !admissionAllowed()) return false;
              let allowed; try { allowed = authorizeDestination(endpoint, grant); } catch { return false; }
              return allowed === true && !sealed && !closing && admissionAllowed();
            } };
          attached = mode === HTTP_ORIGIN_PROXY_MODE
            ? proxy.attachTrustedHttpOriginConnectStream(peer, { ...options, proxyMode: mode })
            : proxy.attachTrustedHttpsConnectStream(peer, options);
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
  const snapshot = () => Object.freeze({ closing, activeOwners: owners.size, admitted, settled, captures, clientEndWrites,
    proxyMode: actualMode, negotiatedCapabilities: Object.freeze([...actualCapabilities]) });
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
