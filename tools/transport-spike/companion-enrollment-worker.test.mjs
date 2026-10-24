import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { X509Certificate } from 'node:crypto';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';

const entry = fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url));
const temporaryRoot = fs.realpathSync(os.tmpdir());
const same = (left, right) => assert.equal(isDeepStrictEqual(left, right), true, 'Exact private material continuity');
function directory(t) {
  const value = fs.mkdtempSync(path.join(temporaryRoot, 'freekit-enrollment-worker-')); fs.chmodSync(value, 0o700);
  t.after(() => { assert(value.startsWith(temporaryRoot + path.sep)); fs.rmSync(value, { recursive: true, force: true }); }); return value;
}
function worker(t) {
  const child = fork(entry, [], { execArgv: ['--disable-warning=ExperimentalWarning'], stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true });
  let sequence = 0, output = 0, errors = 0, exit;
  const pending = new Map();
  // On Windows, parent-initiated IPC disconnect can omit ChildProcess's aggregate
  // close event even after exit and both pipes close. Join each actual component.
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  const stdoutClosed = new Promise(resolve => child.stdout.once('close', resolve));
  const stderrClosed = new Promise(resolve => child.stderr.once('close', resolve));
  const ipcClosed = new Promise(resolve => child.once('disconnect', resolve));
  const closed = Promise.all([exited, stdoutClosed, stderrClosed, ipcClosed]).then(([result]) => { exit = result; return result; });
  child.stdout.on('data', bytes => { output += bytes.length; }); child.stderr.on('data', bytes => { errors += bytes.length; });
  child.on('message', reply => { const callback = pending.get(reply.id); if (callback) { pending.delete(reply.id); callback(reply); } });
  async function request(op, args = {}, override = {}) {
    const id = ++sequence;
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(Error('Private worker response deadline')); }, 15000);
      pending.set(id, reply => { clearTimeout(timer); resolve(reply); });
    });
    child.send({ revision: 1, id, op, args, ...override }); return response;
  }
  async function command(op, args = {}) { const reply = await request(op, args); if (!reply.ok) throw Object.assign(Error('Private worker command refused'), { code: reply.code }); return reply.result; }
  async function join() {
    let timer;
    try { const result = await Promise.race([closed, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Worker closure deadline')), 5000); })]); assert.equal(output, 0); assert.equal(errors, 0); return result; }
    finally { clearTimeout(timer); }
  }
  t.after(async () => {
    if (!exit && child.connected) { try { await command('close'); } catch {} }
    if (!exit) { child.kill('SIGKILL'); await join(); }
  });
  return { child, request, command, join };
}
const start = (directory, mode = 'create', ports = {}) => ({ directory, mode, openssl: process.env.OPENSSL_BIN ?? 'openssl', setupPort: 0, credentialPort: 0, ...ports });
async function pair(metadata, invitation) {
  const device = createCryptoFixture(), body = Buffer.from(JSON.stringify({ protocolVersion: 1, type: 'pair', desktopId: metadata.desktopId,
    invitationId: invitation.invitationId, invitationSecret: invitation.invitationSecret, csrDer: device.csr().toString('base64url'), deviceName: 'Private worker fixture', capabilities: ['tcp-http'] }));
  return new Promise((resolve, reject) => {
    const request = https.request({ hostname: '127.0.0.1', port: metadata.setupPort, servername: metadata.logicalName, agent: false,
      ca: new X509Certificate(Buffer.from(metadata.gatewayCertificateDer, 'base64url')).toString(), method: 'POST', path: '/companion/v1/pair',
      headers: { host: `${metadata.logicalName}:${metadata.setupPort}`, 'content-type': 'application/json', 'content-length': body.length, connection: 'close' } }, reply => {
      const chunks = []; let count = 0;
      reply.on('data', bytes => { count += bytes.length; if (count > 16384) reply.destroy(); else chunks.push(bytes); }); reply.on('error', reject);
      reply.once('end', () => { assert.equal(reply.statusCode, 200); resolve(JSON.parse(Buffer.concat(chunks))); });
    }); request.on('error', reject); request.setTimeout(5000, () => request.destroy(Error('Worker HTTPS deadline'))); request.end(body);
  });
}
function closure(snapshot) {
  for (const key of ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined']) assert.equal(snapshot[key], true);
  for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']) assert.equal(snapshot[key], 0);
}

test('real fork signs through private operator RPC, joins naturally, then reopens exact identity/result/ports in a new process', { timeout: 20000 }, async t => {
  const d = directory(t), first = worker(t), metadata = await first.command('start', start(d)), invitation = await first.command('createInvitation');
  const waiting = first.command('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 5000 }), registered = await pair(metadata, invitation);
  same(await waiting, registered); const approved = await first.command('approve', { enrollmentId: registered.enrollmentId });
  assert.equal(approved.type, 'pair_approved'); same(await first.command('readResult', { enrollmentId: registered.enrollmentId }), approved);
  closure(await first.command('close')); same(await first.join(), { code: 0, signal: null });
  const second = worker(t), opened = await second.command('start', start(d, 'open', { setupPort: metadata.setupPort, credentialPort: metadata.credentialPort }));
  same(opened, metadata); same(await second.command('readResult', { enrollmentId: registered.enrollmentId }), approved);
  closure(await second.command('close')); same(await second.join(), { code: 0, signal: null });
});
test('malformed operation/arguments and oversized messages are static refusals without taking valid owner slots', { timeout: 15000 }, async t => {
  const d = directory(t), owner = worker(t);
  assert.equal((await owner.request('metadata')).code, 'pairing_unavailable');
  for (const [op, args, extra] of [['unknown', {}, {}], ['metadata', { extra: true }, {}], ['metadata', {}, { revision: 2 }], ['start', { ...start(d), directory: d + '\n' }, {}]]) {
    assert.equal((await owner.request(op, args, extra)).code, 'invalid_message');
  }
  assert.equal((await owner.request('metadata', { oversized: 'x'.repeat(16384) })).code, 'message_too_large');
  const metadata = await owner.command('start', start(d)); assert.equal(Object.keys(metadata).length, 8);
  assert.equal((await owner.request('start', start(d))).code, 'pairing_unavailable'); closure(await owner.command('close')); assert.equal((await owner.join()).code, 0);
});
test('three held business RPCs preserve the reserved close slot and every cancelled reply joins before closed acknowledgement', { timeout: 15000 }, async t => {
  const d = directory(t), owner = worker(t); await owner.command('start', start(d)); const invitation = await owner.command('createInvitation');
  const waiting = [0, 1, 2].map(() => owner.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 }));
  assert.equal((await owner.request('snapshot')).code, 'pairing_limit');
  const closed = await owner.command('close'); closure(closed);
  const replies = await Promise.all(waiting); assert(replies.every(reply => reply.ok === false && reply.code === 'pairing_unavailable'));
  assert.equal((await owner.join()).code, 0);
});
test('close received during real initialization waits owned children and emits only an actually closed acknowledgement', { timeout: 15000 }, async t => {
  const d = directory(t), owner = worker(t), initializing = owner.command('start', start(d));
  const closed = owner.command('close'); assert.equal(Object.keys(await initializing).length, 8); closure(await closed); assert.equal((await owner.join()).code, 0);
});
test('unexpected IPC disconnect closes live listeners and waiters, exits nonzero and releases the DB only after actual join', { timeout: 15000 }, async t => {
  const d = directory(t), owner = worker(t), metadata = await owner.command('start', start(d));
  owner.child.disconnect(); assert.equal((await owner.join()).code, 1);
  const reopened = worker(t); same(await reopened.command('start', start(d, 'open', { setupPort: metadata.setupPort, credentialPort: metadata.credentialPort })), metadata);
  closure(await reopened.command('close')); assert.equal((await reopened.join()).code, 0);
});
test('failed initialization never emits fabricated resource closure success', { timeout: 10000 }, async t => {
  const d = directory(t), owner = worker(t);
  const failed = await owner.request('start', start(d, 'open', { setupPort: 39001, credentialPort: 39002 })); assert.equal(failed.ok, false); assert.equal(failed.code, 'pairing_unavailable');
  const closed = await owner.request('close'); assert.equal(closed.ok, false); assert.equal(closed.code, 'pairing_unavailable'); assert.equal((await owner.join()).code, 1);
});
