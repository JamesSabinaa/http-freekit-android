import net from 'node:net';
import dgram from 'node:dgram';
import http from 'node:http';
import { createHash } from 'node:crypto';

const body = Buffer.from(Array.from({ length: 16421 }, (_, index) => (index * 31 + 7) & 255));
const reply = Buffer.from(Array.from({ length: 32787 }, (_, index) => (index * 17 + 11) & 255));
const httpBytes = Buffer.concat([Buffer.from(`POST /capture-fixture HTTP/1.1\r\nHost: capture-fixture.invalid\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]);
const udpBytes = Buffer.from(Array.from({ length: 256 }, (_, index) => (index * 13 + 5) & 255));
const dns = Buffer.from('435001000001000000000000076669787475726507696e76616c69640000010001', 'hex');
const dnsReply = Buffer.from(dns); dnsReply[2] = 0x81; dnsReply[3] = 0x80;
export const captureFixtureDigests = Object.freeze({ tcpReply: createHash('sha256').update(reply).digest('hex'),
  udp: createHash('sha256').update(udpBytes).digest('hex'), dns: createHash('sha256').update(dnsReply).digest('hex') });

/** Finite synthetic receivers. Never accepts a caller-selected target or forwards network data. */
export async function createCaptureFixture({ ports: requested = { http: 80, opaque: 443, udp: 53, quic: 443 } } = {}) {
  if (Object.keys(requested).sort().join(',') !== 'http,opaque,quic,udp' ||
      Object.values(requested).some(port => !Number.isInteger(port) || port < 0 || port > 65535)) throw Error('invalid_capture_ports');
  const counters = Object.fromEntries(['directHttp', 'directOpaque', 'directTcp', 'udp', 'dns', 'udp443',
    'interceptedHttp', 'interceptedOpaque', 'interceptedIpv6', 'uploadBytes', 'downloadBytes', 'invalidRequests', 'heldRequestsClosed', 'heldCloseRequests', 'tcpConnections', 'udpDatagrams',
    'deadlineCloseRequests', 'tcpErrorEvents', 'tcpResetErrors'].map(key => [key, 0]));
  const sockets = new Map(), timers = new Set(), socketTimers = new Map(), listeners = [];
  let pendingCallbacks = 0, closed = false, closing, holdNext = false;
  const held = new Set();
  let heldRecord = null, heldCloseRequested = false;
  const snapshot = () => Object.freeze({ ...counters, activeSockets: sockets.size, pendingCallbacks,
    timers: timers.size, listeners: closed ? 0 : listeners.length, heldConnections: held.size, closed });
  const expire = socket => {
    if (!socket.destroyed) { counters.deadlineCloseRequests++; socket.destroy(); }
  };
  const own = socket => {
    let resolveClosed;
    const joined = new Promise(resolve => { resolveClosed = resolve; });
    const timer = setTimeout(() => expire(socket), 5000); timers.add(timer); socketTimers.set(socket, timer);
    sockets.set(socket, joined);
    socket.on('error', error => {
      counters.tcpErrorEvents++;
      if (error?.code === 'ECONNRESET') counters.tcpResetErrors++;
    });
    socket.once('close', () => { const current = socketTimers.get(socket); clearTimeout(current); timers.delete(current); socketTimers.delete(socket); sockets.delete(socket); if (held.delete(socket)) counters.heldRequestsClosed++; resolveClosed(); });
    if (closing) socket.destroy();
    return joined;
  };
  const receive = (socket, kind) => {
    counters.tcpConnections++;
    own(socket);
    let received = Buffer.alloc(0), valid = false, writeCompleted = false, intentionallyHeld = false, expected;
    socket.on('data', chunk => {
      if (received.length + chunk.length > 18000) { counters.invalidRequests++; socket.destroy(); return; }
      received = Buffer.concat([received, chunk]);
    });
    socket.once('end', () => {
      let selected = kind;
      if (kind === 'intercepted') {
        selected = { 1: 'interceptedHttp', 2: 'interceptedOpaque', 3: 'interceptedIpv6' }[received[0]];
        received = received.subarray(1);
      }
      expected = ['directHttp', 'interceptedHttp', 'interceptedIpv6'].includes(selected) ? httpBytes : body;
      if (!selected || !received.equals(expected)) { counters.invalidRequests++; socket.destroy(); return; }
      valid = true;
      if (kind === 'intercepted' && holdNext) {
        holdNext = false; held.add(socket); intentionallyHeld = true;
        heldRecord = { socket, closed: sockets.get(socket) };
        const old = socketTimers.get(socket); clearTimeout(old); timers.delete(old);
        const timer = setTimeout(() => expire(socket), 60000); socketTimers.set(socket, timer); timers.add(timer);
        return;
      }
      pendingCallbacks++;
      socket.end(reply, error => {
        pendingCallbacks--;
        if (!error) { writeCompleted = true; counters[selected]++; counters.uploadBytes += received.length; counters.downloadBytes += reply.length; }
      });
    });
    socket.once('close', () => { if (valid && !writeCompleted && !intentionallyHeld && !closing) counters.invalidRequests++; });
  };
  const listen = server => new Promise((resolve, reject) => {
    const onError = () => {
      server.removeListener('listening', onListening);
      try { server.close(() => reject(Error('capture_listener_failed'))); }
      catch { reject(Error('capture_listener_failed')); }
    };
    const onListening = () => { server.removeListener('error', onError); server.on('error', () => {}); listeners.push(server); resolve(server.address().port); };
    server.once('error', onError); server.once('listening', onListening);
  });
  const tcp = async (kind, port) => {
    const server = net.createServer({ allowHalfOpen: true }, socket => receive(socket, kind));
    const ready = listen(server); server.listen(port, '127.0.0.1'); return ready;
  };
  const datagram = async (kind, port) => {
    const server = dgram.createSocket('udp4');
    server.on('message', (message, remote) => {
      counters.udpDatagrams++;
      let response, selected = kind;
      if (kind === 'udp') {
        if (message.equals(dns)) { response = dnsReply; selected = 'dns'; }
        else if (message.equals(udpBytes)) response = udpBytes;
      } else if (message.equals(udpBytes)) response = udpBytes;
      if (!response) { counters.invalidRequests++; return; }
      pendingCallbacks++;
      server.send(response, remote.port, remote.address, error => {
        pendingCallbacks--;
        if (!error) { counters[selected]++; counters.uploadBytes += message.length; counters.downloadBytes += response.length; }
      });
    });
    const ready = listen(server); server.bind(port, '127.0.0.1'); return ready;
  };
  const close = () => closing ??= (async () => {
    const serverJoins = listeners.map(server => new Promise((resolve, reject) => {
      try { server.close(error => error ? reject(Error('capture_listener_close_failed')) : resolve()); }
      catch { reject(Error('capture_listener_close_failed')); }
    }));
    const socketJoins = [...sockets.values()];
    for (const socket of sockets.keys()) socket.destroy();
    const results = await Promise.allSettled([...serverJoins, ...socketJoins]);
    closed = results.every(result => result.status === 'fulfilled') && sockets.size === 0 && timers.size === 0 && pendingCallbacks === 0;
    if (!closed) throw Error('capture_fixture_cleanup_failed');
    return snapshot();
  })();
  try {
    const ports = {};
    ports.http = await tcp('directHttp', requested.http);
    ports.opaque = await tcp('directOpaque', requested.opaque);
    ports.direct = await tcp('directTcp', 0);
    ports.intercepted = await tcp('intercepted', 0);
    ports.udp = await datagram('udp', requested.udp);
    ports.quic = await datagram('udp443', requested.quic);
    const sendSnapshot = response => {
      if (response.destroyed) return;
      const bytes = Buffer.from(JSON.stringify(snapshot()));
      response.setHeader('Content-Type', 'application/json'); response.setHeader('Content-Length', bytes.length); response.end(bytes);
    };
    const control = http.createServer((request, response) => {
      response.setHeader('Connection', 'close');
      if (request.method !== 'GET' || !['/snapshot', '/hold-next', '/close-held'].includes(request.url) || request.headers['transfer-encoding'] ||
          (request.headers['content-length'] !== undefined && request.headers['content-length'] !== '0')) {
        response.writeHead(400); response.end(); return;
      }
      if (request.url === '/hold-next') {
        if (holdNext || heldRecord || closing) { response.writeHead(409); response.end(); return; }
        holdNext = true;
      }
      if (request.url === '/close-held') {
        if (!heldRecord || heldCloseRequested || closing) {
          response.writeHead(409, { 'Content-Length': '0' }); response.end(); return;
        }
        heldCloseRequested = true; counters.heldCloseRequests++;
        // Explicit fixture cleanup, not evidence that a remote Stop closed its idle peer.
        if (!heldRecord.socket.destroyed) heldRecord.socket.destroy();
        heldRecord.closed.then(() => sendSnapshot(response));
        return;
      }
      sendSnapshot(response);
    });
    control.on('connection', own);
    const controlReady = listen(control); control.listen(0, '127.0.0.1'); ports.control = await controlReady;
    return Object.freeze({ ports: Object.freeze(ports), snapshot, close });
  } catch {
    try { await close(); } catch { throw Error('capture_fixture_cleanup_failed'); }
    throw Error('capture_fixture_setup_failed');
  }
}
