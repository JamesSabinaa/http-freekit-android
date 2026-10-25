// Independent finite TLS peer for the maintained JVM engine; no Android/authentication claim.
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { fileURLToPath } from 'node:url';
import { enrollmentFixtureAssets, EnrollmentFixtureError } from './companion-enrollment-https-assets.mjs';
import { ResearchWebSocket } from './research-websocket.mjs';
import { bounded, observeClose, write, writerState, endWrite } from './companion-stream-peer-io.mjs';

export const gatewayPeerScenarios = Object.freeze(['echo', 'fragmented', 'queued-input', 'held-read', 'bad-mask', 'bad-rsv',
  'bad-minimal16', 'bad-minimal64', 'oversized-frame', 'fragmented-byte-limit', 'empty-fragment-count129',
  'header-limit', 'bad-extension', 'bad-subprotocol', 'invalid-utf8', 'queued-text-close', 'local-close-eof']);
const FORMAT = 'http-freekit-gateway-ws-peer';
const fail = () => { throw new GatewayPeerError(); };
export class GatewayPeerError extends Error {
  constructor() { super('Gateway backend peer unavailable'); this.name = 'GatewayPeerError'; }
  toJSON() { return { error: 'gateway_peer_failed' }; }
  toString() { return 'GatewayPeerError(gateway_peer_failed)'; }
  [inspect.custom]() { return this.toString(); }
}
const frame = (opcode, payload = Buffer.alloc(0), fin = true) => {
  let header;
  if (payload.length < 126) header = Buffer.from([(fin ? 128 : 0) | opcode, payload.length]);
  else if (payload.length <= 65535) { header = Buffer.alloc(4); header[0] = (fin ? 128 : 0) | opcode; header[1] = 126; header.writeUInt16BE(payload.length, 2); }
  else { header = Buffer.alloc(10); header[0] = (fin ? 128 : 0) | opcode; header[1] = 127; header.writeBigUInt64BE(BigInt(payload.length), 2); }
  return Buffer.concat([header, payload]);
};
const pattern = (length, multiplier, add) => Buffer.from(Array.from({ length }, (_, i) => (i * multiplier + add) & 255));
const canonicalSession = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.exec(value)?.[0] === value &&
  Buffer.from(value, 'base64url').length === 32 && Buffer.from(value, 'base64url').toString('base64url') === value;

class GatewayPeer {
  #directory; #assets; #scenario; #server; #sockets = new Map(); #tasks = new Set(); #writers = new Set();
  #closing = false; #closed = false; #listenerClosed = false; #closeTask; #removed = false; #childrenJoined = false;
  #timer; #released = false; #release; #releaseWait; #ended; #finish;
  #upgrades = 0; #texts = 0; #binary = 0; #pongs = 0; #clientClose = false;
  constructor(directory, scenario) {
    this.#directory = directory; this.#scenario = scenario;
    this.#releaseWait = new Promise(resolve => { this.#release = resolve; });
    this.#ended = new Promise(resolve => { this.#finish = resolve; });
  }
  get ended() { return this.#ended; }
  async start(openssl) {
    try {
      this.#assets = await enrollmentFixtureAssets({ directory: this.#directory, mode: 'create', openssl, setupPort: 0, credentialPort: 0 });
      this.#childrenJoined = true; // Assets returns only after each real child close/group observation.
      this.#server = https.createServer({ ...this.#assets.tlsOptions(), maxHeaderSize: 4096, headersTimeout: 5000, requestTimeout: 5000 },
        request => request.socket.destroy());
      this.#server.maxConnections = 4; this.#server.maxHeadersCount = 32; this.#server.maxRequestsPerSocket = 1;
      this.#server.on('connection', socket => this.#own(socket));
      this.#server.on('secureConnection', socket => this.#own(socket));
      this.#server.on('tlsClientError', () => {}); this.#server.on('error', () => {});
      this.#server.once('close', () => { this.#listenerClosed = true; });
      this.#server.on('upgrade', (request, socket, head) => {
        this.#own(socket);
        if (this.#closing || this.#upgrades || !this.#upgradeAllowed(request) || head.length > 65536) { socket.destroy(); return; }
        this.#upgrades++; socket.setTimeout(0);
        const state = writerState(); this.#writers.add(state);
        this.#task(async () => {
          const accept = createHash('sha1').update(request.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
          let extra = '';
          if (this.#scenario === 'header-limit') extra = 'X-Test: ' + 'x'.repeat(4096) + '\r\n';
          if (this.#scenario === 'bad-extension') extra = 'Sec-WebSocket-Extensions: permessage-deflate\r\n';
          if (this.#scenario === 'bad-subprotocol') extra = 'Sec-WebSocket-Protocol: unrequested\r\n';
          await this.#write(socket, Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n' + extra + '\r\n'), state);
          if (['header-limit', 'bad-extension', 'bad-subprotocol'].includes(this.#scenario)) return;
          const ws = new ResearchWebSocket(socket, { role: 'server', initialBytes: head, maxBinaryBytes: 65536 });
          const serverCloseSent = await this.#initial(socket, state);
          if (['held-read', 'queued-input'].includes(this.#scenario)) { socket.pause(); await this.#releaseWait; }
          let pingSent = false;
          while (!this.#closing && !socket.destroyed) {
            const event = await ws.next();
            try {
              if (event.kind === 'close') {
                this.#clientClose = true;
                if (!serverCloseSent && this.#scenario !== 'local-close-eof') await this.#write(socket, frame(8, Buffer.from([3, 232])), state);
                await endWrite(socket, state); return;
              }
              if (event.kind === 'ping') {
                await this.#write(socket, frame(10, event.copyBytes()), state);
                if (this.#scenario === 'echo' && !pingSent) { pingSent = true; await this.#write(socket, frame(9, Buffer.from('probe')), state); }
              }
              else if (event.kind === 'pong') this.#pongs++;
              else if (event.kind === 'text' || event.kind === 'binary') {
                if (event.kind === 'text') this.#texts++; else this.#binary++;
                if (this.#scenario === 'echo') await this.#write(socket, frame(event.kind === 'text' ? 1 : 2, event.copyBytes()), state);
              }
            } finally { event.release(); }
          }
        });
      });
      await bounded(new Promise((resolve, reject) => {
        const error = () => { this.#server.removeListener('listening', ready); reject(new GatewayPeerError()); };
        const ready = () => { this.#server.removeListener('error', error); resolve(); };
        this.#server.once('error', error); this.#server.once('listening', ready); this.#server.listen(0, '127.0.0.1');
      }), 5000);
      this.#timer = setTimeout(() => { this.#timer = null; void this.close().catch(() => {}); }, 60000);
      return this;
    } catch (failure) {
      if (failure instanceof EnrollmentFixtureError && failure.joined === true) this.#childrenJoined = true;
      try { await this.close(); } catch {} fail();
    }
  }
  #own(socket) {
    if (this.#sockets.has(socket)) return;
    this.#sockets.set(socket, observeClose(socket)); socket.on('error', () => {});
    socket.once('close', () => this.#sockets.delete(socket));
    if (this.#closing || this.#sockets.size > 8) socket.destroy();
  }
  #task(operation) {
    const work = Promise.resolve().then(operation).catch(() => {});
    this.#tasks.add(work); work.finally(() => this.#tasks.delete(work));
  }
  #upgradeAllowed(request) {
    const key = request.headers['sec-websocket-key'], meta = this.metadata();
    const pathAllowed = request.url === '/companion/v1/control' ? request.headers['x-freekit-session'] === undefined :
      request.url === '/companion/v1/streams' && canonicalSession(request.headers['x-freekit-session']);
    return request.method === 'GET' && request.httpVersion === '1.1' && pathAllowed &&
      request.headers.host === meta.logicalName + ':' + meta.port && request.headers.upgrade?.toLowerCase() === 'websocket' &&
      request.headers.connection?.toLowerCase() === 'upgrade' && request.headers['sec-websocket-version'] === '13' &&
      request.headers.origin === undefined && request.headers['sec-websocket-extensions'] === undefined && request.headers['sec-websocket-protocol'] === undefined &&
      typeof key === 'string' && /^[A-Za-z0-9+/]{22}==$/.exec(key)?.[0] === key && Buffer.from(key, 'base64').length === 16 && Buffer.from(key, 'base64').toString('base64') === key;
  }
  async #write(socket, bytes, state) {
    for (let offset = 0; offset < bytes.length; offset += 8192) await write(socket, bytes.subarray(offset, offset + 8192), state);
  }
  async #initial(socket, state) {
    const send = (opcode, bytes, fin = true) => this.#write(socket, frame(opcode, bytes, fin), state);
    const ping = () => send(9, Buffer.from('probe'));
    const mode = this.#scenario;
    if (mode === 'queued-text-close') {
      await send(1, Buffer.from('queued-before-close'));
      await send(8, Buffer.from([3, 232]));
      return true;
    } else if (mode === 'fragmented') {
      const text = Buffer.from('fragmented-€-backend'), binary = pattern(4097, 29, 3);
      await send(1, text.subarray(0, 12), false); await ping(); await send(0, text.subarray(12, 14), false); await send(0, text.subarray(14));
      await send(2, binary.subarray(0, 1024), false); await ping(); await send(0, binary.subarray(1024, 1025), false); await send(0, binary.subarray(1025));
    } else if (mode === 'queued-input') {
      for (let message = 0; message < 3; message++) await send(2, pattern(65536, 17, message));
    } else if (mode === 'bad-mask') await this.#write(socket, Buffer.from([0x82, 0x81, 1, 2, 3, 4, 0x79]), state);
    else if (mode === 'bad-rsv') await this.#write(socket, Buffer.from([0xc2, 1, 0x78]), state);
    else if (mode === 'bad-minimal16') await this.#write(socket, Buffer.from([0x82, 126, 0, 1, 0x78]), state);
    else if (mode === 'bad-minimal64') await this.#write(socket, Buffer.from([0x82, 127, 0, 0, 0, 0, 0, 0, 0, 1, 0x78]), state);
    else if (mode === 'oversized-frame') { const header = Buffer.alloc(10); header[0] = 0x82; header[1] = 127; header.writeBigUInt64BE(65537n, 2); await this.#write(socket, header, state); }
    else if (mode === 'fragmented-byte-limit') { await send(2, pattern(65536, 17, 0), false); await send(0, Buffer.from([1])); }
    else if (mode === 'empty-fragment-count129') await this.#write(socket, Buffer.concat([frame(1, Buffer.alloc(0), false),
      ...Array.from({ length: 127 }, () => frame(0, Buffer.alloc(0), false)), frame(0)]), state);
    else if (mode === 'invalid-utf8') await send(1, Buffer.from([0xc0, 0xaf]));
  }
  metadata() {
    if (!this.#assets || !this.#server?.listening) fail();
    const material = this.#assets.metadata().material();
    return Object.freeze({ format: FORMAT, revision: 1, event: 'ready', port: this.#server.address().port,
      logicalName: material.logicalName, gatewayCertificateDer: material.gatewayCertificateDer });
  }
  release() { if (this.#closing || this.#released) fail(); this.#released = true; this.#release(); }
  snapshot() {
    return Object.freeze({ format: FORMAT, revision: 1, event: 'closed', admissionClosed: this.#closing, listenerClosed: this.#listenerClosed,
      activeSockets: this.#sockets.size, pendingCallbacks: [...this.#writers].reduce((n, state) => n + state.pending, 0),
      pendingTimers: this.#timer ? 1 : 0, workers: this.#tasks.size, ownedChildrenJoined: this.#childrenJoined,
      privateDirectoryRemoved: this.#removed, upgrades: this.#upgrades, clientTextMessages: this.#texts,
      clientBinaryMessages: this.#binary, clientPongs: this.#pongs, clientCloseObserved: this.#clientClose });
  }
  async close() {
    if (this.#closed) return this.snapshot();
    if (this.#closeTask) return this.#closeTask;
    this.#closing = true; clearTimeout(this.#timer); this.#timer = null; this.#release();
    this.#closeTask = (async () => {
      const closes = [...this.#sockets.values()]; for (const socket of this.#sockets.keys()) socket.destroy();
      const listener = this.#server ? new Promise(resolve => { this.#server.close(() => resolve()); }) : Promise.resolve();
      await bounded(Promise.all([...closes, listener, ...this.#tasks]), 5000);
      await bounded(Promise.all([...this.#writers].map(state => state.idle)), 5000);
      if (this.#sockets.size || this.#tasks.size || [...this.#writers].some(state => state.pending)) fail();
      if (this.#childrenJoined) {
        const actual = fs.realpathSync(this.#directory), temp = fs.realpathSync(os.tmpdir());
        if (actual !== path.resolve(this.#directory) || path.dirname(actual) !== temp || !path.basename(actual).startsWith('freekit-gateway-ws-')) fail();
        fs.rmSync(actual, { recursive: true, force: true }); this.#removed = !fs.existsSync(actual);
      }
      if (this.#server && !this.#listenerClosed) fail();
      if (!this.#removed || !this.#childrenJoined) fail();
      this.#closed = true; const result = this.snapshot(); this.#finish(result); return result;
    })();
    try { return await this.#closeTask; } catch { this.#closeTask = null; fail(); }
  }
  toString() { return '[Gateway WebSocket backend peer]'; }
  toJSON() { return '[Gateway WebSocket backend peer]'; }
  [inspect.custom]() { return this.toString(); }
}

export async function startGatewayWebSocketPeer({ scenario, openssl = process.env.OPENSSL_BIN ?? 'openssl' } = {}) {
  if (!gatewayPeerScenarios.includes(scenario)) fail();
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-gateway-ws-'))); fs.chmodSync(directory, 0o700);
  return new GatewayPeer(directory, scenario).start(openssl);
}

async function main(args) {
  let peer, failed = false, stopped = false;
  const emit = value => new Promise((resolve, reject) => { process.stdout.write(JSON.stringify(value) + '\n', error => error ? reject(new GatewayPeerError()) : resolve()); });
  const stop = () => { process.stdin.destroy(); if (peer) void peer.close().catch(() => { failed = true; }); };
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, stop);
  try {
    if (args.length !== 2 || args[0] !== '--scenario' || !gatewayPeerScenarios.includes(args[1])) fail();
    peer = await startGatewayWebSocketPeer({ scenario: args[1] }); await emit(peer.metadata());
    let pending = Buffer.alloc(0), total = 0, commands = 0;
    const operations = (async () => {
      for await (const chunk of process.stdin) {
        total += chunk.length; if (total > 8192 || chunk.some(byte => byte > 127)) fail();
        pending = Buffer.concat([pending, chunk]); if (pending.length > 1024 && !pending.includes(10)) fail();
        while (pending.includes(10)) {
          const at = pending.indexOf(10); if (at > 1024 || ++commands > 8) fail();
          const line = pending.subarray(0, at).toString('ascii'); pending = pending.subarray(at + 1);
          if (line === '{"op":"release"}') { peer.release(); await emit({ format: FORMAT, revision: 1, event: 'released' }); }
          else if (line === '{"op":"stop"}' && pending.length === 0) { stopped = true; return; }
          else fail();
        }
      }
      if (pending.length) fail();
    })();
    await Promise.race([operations, peer.ended.then(() => { if (!stopped) failed = true; stop(); })]);
  } catch { failed = true; }
  finally {
    process.stdin.destroy();
    for (const signal of ['SIGINT', 'SIGTERM']) process.off(signal, stop);
    if (peer) { try { await emit(await peer.close()); } catch { failed = true; } }
  }
  if (failed) { process.stderr.write('Gateway backend peer failed.\n'); process.exitCode = 1; }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main(process.argv.slice(2));
