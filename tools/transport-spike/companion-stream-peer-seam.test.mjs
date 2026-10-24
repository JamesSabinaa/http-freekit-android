import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import net from 'node:net';
import fs from 'node:fs';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { startPeer } from './android-peer.mjs';

test('optional authenticated factory stays private and concurrent closes join the same real cleanup', { timeout: 15000 }, async () => {
  let release;
  const gate = new Promise(done => { release = done; });
  let calls = 0;
  const peer = await startPeer({ authenticatedServerFactory: async ({ tls, authorize }) => {
    assert.equal(tls.requestCert, true); assert.equal(tls.rejectUnauthorized, true);
    assert.equal(Object.isFrozen(tls), true); assert.equal(typeof authorize, 'function');
    assert.equal(authorize({ authorized: false, getPeerX509Certificate: () => undefined }), false);
    const server = https.createServer(tls);
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    return { port: server.address().port, async close() {
      calls++; await gate; await new Promise(done => server.close(done));
    } };
  } });
  const directory = peer.directory;
  assert.deepEqual(Object.keys(peer.metadata).sort(), ['enrollmentPort', 'gatewayDer', 'gatewayPin', 'webSocketPort']);
  const first = peer.close(), second = peer.close();
  assert.equal(first, second);
  let joined = false; second.then(() => { joined = true; });
  await new Promise(done => setImmediate(done));
  assert.equal(joined, false); assert.equal(calls, 1);
  release(); await first;
  assert.equal(fs.existsSync(directory), false);
});

test('extension close failure still closes issuer listeners and removes owned key files, while preserving failure', { timeout: 15000 }, async () => {
  const peer = await startPeer({ authenticatedServerFactory: async ({ tls }) => {
    const server = https.createServer(tls);
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    return { port: server.address().port, async close() {
      await new Promise(done => server.close(done)); throw Error('synthetic_cleanup_failure');
    } };
  } });
  const directory = peer.directory;
  await assert.rejects(peer.close(), /authenticated_fixture_cleanup_failed/);
  assert.equal(fs.existsSync(directory), false);
  for (const port of [peer.metadata.enrollmentPort, peer.metadata.webSocketPort]) {
    const socket = net.connect(port, '127.0.0.1'); const [failure] = await once(socket, 'error');
    assert.equal(failure.code, 'ECONNREFUSED'); socket.destroy();
  }
});

test('invalid TLS factory startup closes its real proxy listener and issuer instead of keeping the process alive', { timeout: 15000 }, async () => {
  const issuer = new URL('./android-peer.mjs', import.meta.url).href;
  const module = new URL('./companion-stream-peer.mjs', import.meta.url).href;
  const source = `import{startPeer}from${JSON.stringify(issuer)};import{createCompanionStreamServer}from${JSON.stringify(module)};
    try{await startPeer({authenticatedServerFactory:context=>createCompanionStreamServer({...context,tls:{...context.tls,key:'invalid'}})});
      process.exitCode=2;}catch(error){if(error.code!=='stream_fixture_startup_failed')process.exitCode=3;}`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let bytes = 0;
  child.stdout.on('data', chunk => { bytes += chunk.length; if (bytes > 512) child.kill(); });
  child.stderr.on('data', chunk => { bytes += chunk.length; if (bytes > 512) child.kill(); });
  const timer = setTimeout(() => child.kill(), 10000);
  try {
    const [code, signal] = await once(child, 'close');
    assert.equal(signal, null, 'startup failure must naturally exit after closing all owned listeners');
    assert.equal(code, 0); assert.equal(bytes, 0);
  } finally { clearTimeout(timer); if (child.exitCode === null) child.kill(); }
});

test('an owner join failure cannot skip global listener cleanup or release unjoined model leases', { timeout: 15000 }, async () => {
  const peerModule = new URL('./companion-stream-peer.mjs', import.meta.url).href;
  const clientModule = new URL('./companion-stream-peer-client.mjs', import.meta.url).href;
  const framingModule = new URL('./research-websocket.mjs', import.meta.url).href;
  const source = `import fs from'node:fs';import{startCompanionStreamPeer}from${JSON.stringify(peerModule)};
    import{enrollHost,control,stream}from${JSON.stringify(clientModule)};import{ResearchWebSocket}from${JSON.stringify(framingModule)};
    const peer=await startCompanionStreamPeer();const dir=peer.directory;const cred=await enrollHost(peer);
    const ctl=await control(peer,cred,'binding');const flow=await stream(peer,cred,ctl);
    const original=ResearchWebSocket.prototype.cancel;
    ResearchWebSocket.prototype.cancel=function(){return this===ctl.ws||this===flow.ws?original.call(this):Promise.reject(Error('synthetic_join_failure'));};
    let failed=false;try{await peer.close();}catch(error){failed=error.message==='authenticated_fixture_cleanup_failed';}
    ResearchWebSocket.prototype.cancel=original;await ctl.ws.cancel();await flow.ws.cancel();await ctl.pump;
    const state=peer.snapshot();if(!failed||fs.existsSync(dir)||state.sessionLeases!==1||state.streamLeases!==1)process.exitCode=2;`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let bytes = 0;
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { bytes += chunk.length; if (bytes > 512) child.kill(); });
  const timer = setTimeout(() => child.kill(), 10000);
  try {
    const [code, signal] = await once(child, 'close');
    assert.equal(signal, null, 'a failed owner join must still attempt and finish independent listener/socket cleanup');
    assert.equal(code, 0); assert.equal(bytes, 0);
  } finally { clearTimeout(timer); if (child.exitCode === null) child.kill(); }
});
