// Private, fixed-destination host research. No wire or desktop implementation.
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { duplexPair } from 'node:stream';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { observeClose as watchClose } from './companion-stream-peer-io.mjs';
import { referenceInterceptionProfile as P, ReferenceInterceptionError as Failure,
  referenceInterceptionResponse } from './reference-interception-contract.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const ack = Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n');
const parserOptions = { maxHeaderSize: P.maxHeaderBytes, insecureHTTPParser: false,
  requireHostHeader: true, highWaterMark: 4096 };

function boundedJoin(promise) {
  let timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(new Failure('cleanup_unjoined', false)), P.timeoutMillis); });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

// duplexPair cancellation is local. Settle outstanding public callbacks on an
// actual close with failure, never with a fabricated successful write receipt.
function ownCallbacks(socket) {
  const pending = new Set();
  socket.once('close', () => { for (const finish of [...pending]) finish(new Failure('backend_closed')); });
  for (const name of ['write', 'end']) {
    const original = socket[name];
    socket[name] = function (...args) {
      const callback = args.at(-1);
      if (typeof callback !== 'function') return original.apply(this, args);
      if (pending.size >= 16) throw new Failure('backend_failed');
      let settled = false;
      const finish = error => { if (settled) return; settled = true; pending.delete(finish); callback(error); };
      pending.add(finish); args[args.length - 1] = finish;
      if (socket.closed) { queueMicrotask(() => finish(new Failure('backend_closed'))); return name === 'write' ? false : socket; }
      try { return original.apply(this, args); }
      catch { finish(new Failure('backend_failed')); throw new Failure('backend_failed'); }
    };
  }
  return () => pending.size;
}

export async function startReferenceInterceptionBackend({ assets } = {}) {
  let originTls, interceptionTls, originCa;
  const clearKeys = () => { for (const options of [originTls, interceptionTls]) if (options?.key instanceof Uint8Array) options.key.fill(0); };
  try {
    originTls = assets.tlsOptions('origin'); interceptionTls = assets.tlsOptions('interception');
    originCa = assets.caPem('origin');
    if (assets.caDer('origin').equals(assets.caDer('interception'))) throw 0;
  } catch { clearKeys(); throw new Failure('assets_unavailable'); }
  let sealing = false, final = false, closing;
  const owners = new Set(), sockets = new Set(), rows = [], listeners = new Set();
  const originAdmissions = new Map(), accepted = new Map();
  const counters = { ownersCreated: 0, ownersClosed: 0, upstreamDials: 0,
    interceptedHttpRequests: 0, interceptedHttpsRequests: 0, upstreamHttpRequests: 0,
    upstreamHttpsRequests: 0, interceptionTlsHandshakes: 0, upstreamTlsHandshakes: 0, rejectedPrefaces: 0 };
  let activeRequests = 0;
  function track(socket) {
    if (sockets.has(socket)) return;
    sockets.add(socket); watchClose(socket);
    socket.on('error', () => {});
    socket.once('close', () => { sockets.delete(socket); });
  }
  function requestWork(req) {
    activeRequests++;
    let done = false;
    const finish = () => { if (!done) { done = true; activeRequests--; } };
    req.once('close', finish); return finish;
  }
  function readRequest(req, fail, complete) {
    const finish = requestWork(req), chunks = [];
    let bytes = 0, bad = false;
    const reject = () => { if (!bad) { bad = true; fail(); } };
    req.on('error', reject); req.on('aborted', reject);
    const seen = new Set();
    let headerBytes = Buffer.byteLength(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`) + 2;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i].toLowerCase();
      headerBytes += Buffer.byteLength(req.rawHeaders[i]) + Buffer.byteLength(req.rawHeaders[i + 1]) + 4;
      if (seen.has(name) || ['transfer-encoding', 'upgrade', 'trailer', 'expect'].includes(name)) bad = true;
      seen.add(name);
    }
    const length = req.headers['content-length'];
    if (req.method !== 'POST' || req.url !== P.path || req.httpVersion !== '1.1' ||
        req.headers.host !== P.hostname || !/^(0|[1-9][0-9]{0,3})$/.test(length ?? '') ||
        Number(length) > P.maxBodyBytes || headerBytes > P.maxHeaderBytes ||
        req.headers.connection && req.headers.connection.toLowerCase() !== 'close') bad = true;
    if (bad) { fail(); return; }
    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > Number(length) || bytes > P.maxBodyBytes) reject();
      else if (!bad) chunks.push(chunk);
    });
    req.once('end', () => {
      finish();
      if (bad) return;
      if (bytes !== Number(length) || req.rawTrailers.length) return reject();
      complete(Buffer.concat(chunks, bytes));
    });
  }
  function origin(mode) {
    const server = mode === 'http' ? http.createServer(parserOptions) :
      https.createServer({ ...originTls, ...parserOptions, SNICallback: (name, cb) =>
        name === P.hostname ? cb(null, tls.createSecureContext(originTls)) : cb(new Failure('upstream_failed')) });
    server.on('connection', socket => {
      track(socket);
      const key = socket.remotePort;
      accepted.set(key, socket);
      socket.once('close', () => { if (accepted.get(key) === socket) accepted.delete(key); });
      originAdmissions.get(key)?.own(socket);
    });
    server.on('secureConnection', socket => {
      track(socket);
      const admission = originAdmissions.get(socket.remotePort);
      admission?.own(socket);
      if (!admission?.live()) socket.destroy();
    });
    server.on('clientError', (_error, socket) => socket.destroy());
    server.on('tlsClientError', (_error, socket) => socket.destroy());
    server.on('request', (req, res) => {
      const fail = () => req.socket.destroy();
      const admission = originAdmissions.get(req.socket.remotePort);
      if (sealing || !admission?.live() || req.socket.referenceRequestSeen) return fail();
      admission.own(req.socket); admission.ownRequest(req);
      req.socket.referenceRequestSeen = true;
      readRequest(req, fail, body => {
        if (!admission.live()) return fail();
        const response = referenceInterceptionResponse(body);
        counters[mode === 'http' ? 'upstreamHttpRequests' : 'upstreamHttpsRequests']++;
        if (rows.length < P.maxOwners) rows.push(Object.freeze({ mode, requestBytes: body.length,
          responseBytes: response.length, requestSha256: digest(body), responseSha256: digest(response) }));
        res.writeHead(200, { 'Content-Length': response.length, 'Connection': 'close', 'Content-Type': 'application/octet-stream' });
        res.end(response);
      });
    });
    return server;
  }
  const httpOrigin = origin('http'), httpsOrigin = origin('https');
  async function listen(server) {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); listeners.add(server); resolve(); });
    });
  }
  try { await listen(httpOrigin); await listen(httpsOrigin); }
  catch {
    for (const socket of sockets) socket.destroy();
    await Promise.all([...listeners].map(server => new Promise(resolve => server.close(resolve))));
    clearKeys();
    throw new Failure('backend_failed');
  }
  function factory(context) {
    const admission = context?.admissionAllowed;
    const allowed = () => { try { return !sealing && admission.call(context) === true; } catch { return false; } };
    const capabilities = context?.negotiatedCapabilities;
    const mode = context?.proxyMode === 'http-origin-connect' && capabilities?.includes('tcp-http-origin-connect') ? 'http' :
      context?.proxyMode === undefined && capabilities?.includes('tcp-https-connect') ? 'https' : null;
    if (!mode || !Array.isArray(capabilities) || capabilities.some(c => !['tcp-http-origin-connect', 'tcp-https-connect'].includes(c))) throw new Failure('configuration');
    if (!allowed() || owners.size >= P.maxOwners) throw new Failure('admission_closed');
    const [transport, peer] = duplexPair({ allowHalfOpen: true, readableHighWaterMark: 4096, writableHighWaterMark: 4096 });
    const resources = new Set(), joins = [], operations = new Set();
    let started = false, stopped = false, timer, parser, preface = Buffer.alloc(0), parsed = false;
    function own(socket) {
      if (resources.has(socket)) return socket;
      resources.add(socket); socket.once('close', () => resources.delete(socket));
      track(socket); joins.push(watchClose(socket));
      if (stopped) socket.destroy();
      return socket;
    }
    function ownRequest(request) { joins.push(watchClose(request)); }
    own(transport); own(peer);
    const callbackCounts = [ownCallbacks(transport), ownCallbacks(peer)];
    let tlsWire, tlsSocket;
    let closeTask, settleStart;
    const startJoined = new Promise(resolve => { settleStart = resolve; });
    const stop = () => {
      stopped = true; clearTimeout(timer); settleStart();
      for (const operation of operations) operation.destroy?.(new Failure('backend_closed'));
      for (const socket of resources) socket.destroy(new Failure('backend_closed'));
    };
    const closed = (async () => {
      await startJoined;
      // New socket owners can only be acquired before stop or natural peer close.
      await Promise.all(joins.slice(0, 2));
      stop();
      await Promise.all(joins);
      await Promise.all([...operations].map(operation => operation instanceof Promise ? operation : watchClose(operation)));
      if (callbackCounts.some(count => count())) throw new Failure('cleanup_unjoined', false);
      owners.delete(owner); counters.ownersClosed++;
    })();
    closed.catch(() => {});
    transport.once('close', stop); peer.once('close', stop);
    function live() { return !stopped && allowed(); }
    function dispatch(body, res) {
      if (!live()) return stop();
      const upstream = mode === 'http' ? http : https;
      // Last synchronous admission immediately precedes the only dial site.
      if (!live()) return stop();
      counters.upstreamDials++;
      const request = upstream.request({ host: '127.0.0.1', port: (mode === 'http' ? httpOrigin : httpsOrigin).address().port,
        method: 'POST', path: P.path, agent: false, maxHeaderSize: P.maxHeaderBytes,
        headers: { Host: P.hostname, 'Content-Length': body.length, Connection: 'close' },
        ...(mode === 'https' ? { ca: originCa, rejectUnauthorized: true, servername: P.hostname,
          checkServerIdentity: tls.checkServerIdentity, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'] } : {}) });
      operations.add(request); watchClose(request);
      request.once('close', () => operations.delete(request));
      request.on('error', stop);
      request.on('socket', socket => {
        own(socket);
        socket.once('connect', () => {
          if (!live()) return stop();
          const key = socket.localPort, admission = { live, own, ownRequest };
          originAdmissions.set(key, admission);
          const incoming = accepted.get(key);
          if (incoming) own(incoming);
          socket.once('close', () => { if (originAdmissions.get(key) === admission) originAdmissions.delete(key); });
        });
        if (!live()) return stop();
        if (mode === 'https') socket.once('secureConnect', () => {
          if (!live() || !socket.authorized) return stop();
          counters.upstreamTlsHandshakes++;
        });
      });
      request.once('response', response => {
        if (!live() || response.statusCode !== 200 || response.headers['content-length'] !== '81') return stop();
        ownRequest(response);
        const finish = requestWork(response);
        let bytes = 0;
        response.on('data', chunk => { bytes += chunk.length; if (bytes > 81) stop(); });
        response.on('error', stop);
        response.once('end', () => { finish(); if (bytes !== 81) stop(); });
        res.writeHead(200, { 'Content-Length': 81, Connection: 'close', 'Content-Type': 'application/octet-stream' });
        response.pipe(res);
      });
      request.end(body);
    }
    function attach() {
      parser = mode === 'http' ? http.createServer(parserOptions) : https.createServer({ ...interceptionTls,
        ...parserOptions, allowHalfOpen: true, SNICallback: (name, cb) => name === P.hostname && live() ?
          cb(null, tls.createSecureContext(interceptionTls)) : cb(new Failure('admission_closed')) });
      // Node's HTTP server otherwise ends its writable side on upload EOF,
      // before an asynchronous origin reply. Keep its maintained parser and
      // enable its explicit HTTP half-open handling for this owned stream.
      parser.httpAllowHalfOpen = true;
      parser.on('clientError', stop); parser.on('tlsClientError', stop);
      parser.on('checkContinue', stop); parser.on('checkExpectation', stop);
      parser.on('upgrade', stop); parser.on('connect', stop);
      parser.on('secureConnection', socket => {
        own(socket);
        if (!live() || socket.servername !== P.hostname) return stop();
        // HTTP Connection: close normally uses destroySoon(), which tears down
        // TLS before the peer's close_notify. End only the real TLS write side;
        // the read side and the original deadline still own completion/abort.
        socket.destroySoon = () => { socket.end(); return socket; };
        socket.on('error', stop);
        socket.once('close', () => {
          if (stopped) return;
          if (!socket.readableEnded || !socket.writableFinished) return stop();
          // A complete TLS session is not the carrier upload END_WRITE. TLS
          // owns only its isolated pair endpoint, never the gateway's raw peer.
          peer.unpipe(tlsWire);
          peer.on('data', stop); // No ciphertext is legal after close_notify.
          if (peer.readableEnded) tlsWire.destroy();
          else peer.once('end', () => tlsWire.destroy());
          peer.resume();
        });
        counters.interceptionTlsHandshakes++;
      });
      let count = 0;
      parser.on('request', (req, res) => {
        if (!live() || ++count !== 1) return stop();
        ownRequest(req);
        counters[mode === 'http' ? 'interceptedHttpRequests' : 'interceptedHttpsRequests']++;
        readRequest(req, stop, body => {
          // Let the maintained parser reject coalesced extra transactions first.
          const work = new Promise(resolve => setImmediate(() => { if (live()) dispatch(body, res); else stop(); resolve(); }));
          operations.add(work); work.finally(() => operations.delete(work));
        });
      });
      // TLS owns an isolated maintained pair: its natural auto-destroy after
      // close_notify must not destroy the independently half-open raw carrier.
      // Each pipe forwards actual data/EOF with maintained backpressure.
      let input = peer;
      if (mode === 'https') {
        [tlsSocket, tlsWire] = duplexPair({ allowHalfOpen: true, readableHighWaterMark: 4096, writableHighWaterMark: 4096 });
        own(tlsSocket); own(tlsWire);
        callbackCounts.push(ownCallbacks(tlsSocket), ownCallbacks(tlsWire));
        tlsSocket.on('error', stop); tlsWire.on('error', stop);
        peer.pipe(tlsWire); tlsWire.pipe(peer);
        input = tlsSocket;
      }
      // Prevent a reentrant handshake before tls.connect installs verification.
      if (mode === 'https') input.cork();
      parser.emit('connection', input);
      if (mode === 'https') {
        const work = new Promise(resolve => setImmediate(() => { input.uncork(); resolve(); }));
        operations.add(work); work.finally(() => operations.delete(work));
      }
    }
    function receive(chunk) {
      const port = mode === 'http' ? P.httpPort : P.httpsPort;
      const expected = Buffer.from(`CONNECT ${P.address}:${port} HTTP/1.1\r\nHost: ${P.address}:${port}\r\n\r\n`);
      const needed = expected.length - preface.length, take = Math.min(needed, chunk.length);
      if (!chunk.subarray(0, take).equals(expected.subarray(preface.length, preface.length + take))) {
        counters.rejectedPrefaces++; return stop();
      }
      preface = Buffer.concat([preface, chunk.subarray(0, take)]);
      if (preface.length !== expected.length) return;
      parsed = true; peer.pause(); peer.removeListener('data', receive);
      if (!live()) return stop();
      if (chunk.length > take) peer.unshift(chunk.subarray(take));
      peer.write(ack, error => { if (error || !live()) return stop(); attach(); peer.resume(); });
    }
    const owner = Object.freeze({ transport, closed,
      async start() {
        if (started || !live()) { stop(); throw new Failure('admission_closed'); }
        started = true;
        timer = setTimeout(stop, P.timeoutMillis); timer.unref();
        peer.on('data', receive);
        peer.on('end', () => { if (!parsed && !stopped) { counters.rejectedPrefaces++; stop(); } });
        settleStart();
      },
      close() { if (!closeTask) { stop(); closeTask = boundedJoin(closed).then(() => {}); } return closeTask; },
    });
    owners.add(owner); counters.ownersCreated++;
    return owner;
  }
  const snapshot = () => Object.freeze({ ownersCreated: counters.ownersCreated, ownersClosed: counters.ownersClosed,
    activeOwners: owners.size, activeSockets: sockets.size, activeRequests, listeners: listeners.size,
    upstreamDials: counters.upstreamDials, interceptedHttpRequests: counters.interceptedHttpRequests,
    interceptedHttpsRequests: counters.interceptedHttpsRequests, upstreamHttpRequests: counters.upstreamHttpRequests,
    upstreamHttpsRequests: counters.upstreamHttpsRequests, interceptionTlsHandshakes: counters.interceptionTlsHandshakes,
    upstreamTlsHandshakes: counters.upstreamTlsHandshakes, rejectedPrefaces: counters.rejectedPrefaces, closed: final });
  return Object.freeze({ factory, snapshot, evidence: () => rows.map(row => ({ ...row })),
    close() {
      if (closing) return closing;
      sealing = true;
      closing = boundedJoin((async () => {
        const ownerJoins = [...owners].map(owner => owner.close());
        const socketJoins = [...sockets].map(socket => { const joined = watchClose(socket); socket.destroy(); return joined; });
        const listenerJoins = [...listeners].map(server => new Promise((resolve, reject) => server.close(error => {
          if (error) reject(new Failure('cleanup_unjoined', false)); else { listeners.delete(server); resolve(); }
        })));
        await Promise.all([...ownerJoins, ...socketJoins, ...listenerJoins]);
        if (owners.size || sockets.size || activeRequests) throw new Failure('cleanup_unjoined', false);
        clearKeys(); final = true; return snapshot();
      })());
      return closing;
    },
    toJSON: snapshot, [inspect.custom]: () => '[Private reference interception backend]',
  });
}
