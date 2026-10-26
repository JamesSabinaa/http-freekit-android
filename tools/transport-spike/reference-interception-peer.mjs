// Private host research composition. Not C5, desktop integration or production wire.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspect } from 'node:util';
import { pathToFileURL } from 'node:url';
import { createReferenceInterceptionAssets } from './reference-interception-assets.mjs';
import { startReferenceInterceptionBackend } from './reference-interception-backend.mjs';
import { startEnrollmentOriginFixture } from './companion-enrollment-origin.mjs';
import { enrollOriginCsr } from './companion-enrollment-origin-client.mjs';
import { bounded, write, writerState } from './companion-stream-peer-io.mjs';

const format = 'http-freekit-reference-interception-peer';
const capabilities = ['tcp-http-origin-connect', 'tcp-https-connect'];
const codes = new Set(['peer_configuration', 'peer_input', 'peer_unavailable', 'peer_enrollment',
  'peer_revocation', 'peer_cleanup', 'peer_watchdog', 'peer_output']);
class PeerError extends Error {
  constructor(code, joined = false, suppressed = []) {
    super('Private reference peer unavailable');
    this.name = 'ReferencePeerError';
    this.code = codes.has(code) ? code : 'peer_unavailable';
    this.joined = joined === true;
    Object.defineProperty(this, 'suppressed', { value: Object.freeze(suppressed) });
  }
  toJSON() { return { code: this.code, joined: this.joined }; }
  [inspect.custom]() { return this.toJSON(); }
}
const fail = (code, joined = true) => { throw new PeerError(code, joined); };
const sanitized = (error, code) => error instanceof PeerError ? error : new PeerError(code, error?.joined === true);
function publicCsr(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,5462}$/.test(value)) fail('peer_input');
  const bytes = Buffer.from(value, 'base64url');
  if (!bytes.length || bytes.length > 4096 || bytes.toString('base64url') !== value) fail('peer_input');
  return bytes;
}
function gatewayJoined(s) {
  return s.closed && s.admissionClosed && s.authorityClosed && s.storeClosed && s.listenersClosed && s.issuerChildrenJoined &&
    ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'workers', 'signerGroups', 'issuerJobs', 'acceptedSockets',
      'tlsSockets', 'bodyReaders', 'requestTasks', 'pendingWriteCallbacks', 'registrationWaiters', 'listeners'].every(k => s[k] === 0) &&
    ['sessionLeases', 'streamLeases', 'chargedBytes', 'ownerRecords', 'authenticatedSockets', 'proxySockets',
      'listeners', 'workers', 'timers', 'pendingCallbacks'].every(k => s.stream[k] === 0) &&
    s.issuer.commandsStarted === s.issuer.commandsClosed && s.issuer.commandsStarted === s.issuer.processGroupsClosed;
}

export async function startReferenceInterceptionPeer({ openssl = process.env.OPENSSL_BIN ?? 'openssl' } = {}) {
  if (typeof openssl !== 'string' || !openssl || openssl.length > 4096 || /[\0\r\n]/.test(openssl)) fail('peer_configuration');
  let parent, directory;
  try {
    parent = fs.realpathSync(os.tmpdir());
    directory = fs.mkdtempSync(path.join(parent, 'freekit-reference-peer-'));
    // mkdtemp creates the private mode before any material or child exists.
    if ((fs.statSync(directory).mode & 0o777) !== 0o700) fail('peer_configuration', false);
  } catch { fail('peer_configuration', directory === undefined); }
  let assets, backend, gateway, metadata, ca, enrollmentId;
  let sealed = false, enrolled = false, closeTask, startupUnjoined = false, privateDirectoryRemoved = false;
  const jobs = new Set();
  // Explicit private snapshots are defensive. Default object inspection is not IPC.
  const snapshot = () => {
    const probe = enrollmentId ? gateway?.inspectEnrollment(enrollmentId)?.probe : null;
    const stream = probe?.stream ? {
      phase: probe.stream.phase, resourcesReleased: probe.stream.resourcesReleased, streamLease: probe.stream.streamLease,
      clientEofEmitted: probe.stream.client.eofEmitted, gatewayEofEmitted: probe.stream.gateway.eofEmitted,
      chargedBytes: probe.control.chargedBytes, fixtureUploadBytesRead: probe.fixture.uploadBytesRead,
      fixtureResponseBytesWritten: probe.fixture.responseBytesWritten, cleanupComplete: probe.cleanup.complete,
    } : null;
    return structuredClone({ backend: backend?.snapshot() ?? null, assets: assets?.snapshot() ?? null,
      gateway: gateway?.snapshot() ?? null, stream, evidence: backend?.evidence() ?? [], privateDirectoryRemoved });
  };
  const available = () => { if (sealed || !gateway) fail('peer_unavailable'); };
  const close = () => {
    if (closeTask) return closeTask;
    sealed = true;
    closeTask = (async () => {
      const failures = [];
      let joined = !startupUnjoined;
      const attempt = async action => {
        try { await action(); } catch (error) { joined = false; failures.push(sanitized(error, 'peer_cleanup')); }
      };
      // Close the gateway first to seal issuer/registry publication; independently
      // close the backend even if the gateway failed. Do not destroy assets/users.
      const gatewayClose = gateway ? attempt(async () => {
        const state = await gateway.close(); if (!gatewayJoined(state)) fail('peer_cleanup', false);
      }) : Promise.resolve();
      const backendClose = backend ? attempt(async () => {
        const state = await backend.close();
        if (!state.closed || state.ownersCreated !== state.ownersClosed ||
            ['activeOwners', 'activeSockets', 'activeRequests', 'listeners'].some(k => state[k] !== 0)) fail('peer_cleanup', false);
      }) : Promise.resolve();
      await Promise.all([gatewayClose, backendClose]);
      await Promise.allSettled([...jobs]);
      if (assets && joined) await attempt(async () => {
        const state = await assets.close();
        if (!state.closed || state.commandsStarted !== state.commandsClosed || state.commandsStarted !== state.processGroupsClosed) fail('peer_cleanup', false);
      });
      if (joined) await attempt(async () => {
        if (path.dirname(directory) !== parent || !path.basename(directory).startsWith('freekit-reference-peer-') ||
            fs.realpathSync(directory) !== directory || fs.lstatSync(directory).isSymbolicLink()) fail('peer_cleanup', false);
        fs.rmSync(directory, { recursive: true });
        privateDirectoryRemoved = !fs.existsSync(directory);
        if (!privateDirectoryRemoved) fail('peer_cleanup', false);
      });
      if (!joined || failures.length) throw new PeerError('peer_cleanup', false, failures);
      return snapshot();
    })();
    return closeTask;
  };
  try {
    const assetDirectory = path.join(directory, 'assets'), enrollmentDirectory = path.join(directory, 'enrollment');
    for (const child of [assetDirectory, enrollmentDirectory]) fs.mkdirSync(child, { mode: 0o700 });
    assets = await createReferenceInterceptionAssets({ directory: assetDirectory, openssl });
    ca = assets.caDer('interception').toString('base64url');
    backend = await startReferenceInterceptionBackend({ assets });
    gateway = await startEnrollmentOriginFixture({ directory: enrollmentDirectory, mode: 'create', openssl,
      credentialLifetimeSeconds: 3600, trustedProxyFactory: backend.factory, supportedCapabilities: capabilities,
      interceptionCaCertificateDer: assets.caDer('interception') });
    metadata = gateway.metadata().material();
  } catch (error) {
    startupUnjoined = error?.joined !== true;
    let cleanup;
    try { await close(); } catch (failure) { cleanup = failure; }
    throw new PeerError('peer_unavailable', !startupUnjoined && !cleanup, cleanup ? [sanitized(cleanup, 'peer_cleanup')] : []);
  }
  return Object.freeze({
    ready() { return structuredClone({ metadata, interceptionCaDer: ca, nodeVersion: process.version, nodeOpenSsl: process.versions.openssl }); },
    enroll(csrDer) {
      available();
      if (enrolled || !(csrDer instanceof Uint8Array) || csrDer.length < 1 || csrDer.length > 4096) fail('peer_input');
      enrolled = true;
      const bytes = Buffer.from(csrDer);
      const task = (async () => {
        try {
          const approved = (await enrollOriginCsr(gateway, bytes, capabilities)).material();
          enrollmentId = approved.enrollmentId;
          if (sealed) fail('peer_unavailable');
          return { approved: structuredClone(approved) };
        } catch (error) { throw sanitized(error, 'peer_enrollment'); }
        finally { bytes.fill(0); }
      })();
      jobs.add(task); task.then(() => jobs.delete(task), () => jobs.delete(task));
      return task;
    },
    snapshot,
    revoke() {
      available(); if (!enrollmentId) fail('peer_revocation');
      try {
        const result = gateway.revoke(enrollmentId).material();
        if (result.type !== 'pair_ended' || result.code !== 'device_revoked') fail('peer_revocation');
        return { revoked: true };
      } catch (error) { throw sanitized(error, 'peer_revocation'); }
    },
    close, toJSON: () => '[Private reference interception peer]', [inspect.custom]: () => '[Private reference interception peer]',
  });
}

async function main() {
  let owner, startup, terminal = false, finishing, count = 0, total = 0, bytes = Buffer.alloc(0);
  let chain = Promise.resolve(), output = Promise.resolve(), completed;
  const completion = new Promise(resolve => { completed = resolve; });
  const writers = new Set();
  const emit = value => {
    const task = output.then(async () => {
      const encoded = Buffer.from(JSON.stringify({ format, revision: 1, ...value }) + '\n');
      if (encoded.length > 16384) fail('peer_output', false);
      const state = writerState(); writers.add(state);
      try {
        for (let at = 0; at < encoded.length; at += 8192) await bounded(write(process.stdout, encoded.subarray(at, at + 8192), state), 5000);
      }
      catch { process.stdout.destroy(); fail('peer_output', false); }
      finally {
        try { await bounded(state.idle, 5000); if (state.pending) fail('peer_output', false); }
        finally { if (!state.pending) writers.delete(state); }
      }
    });
    output = task.catch(() => {}); return task;
  };
  const stop = code => {
    if (finishing) return finishing;
    terminal = true; process.stdin.pause(); clearTimeout(watchdog);
    // Synchronous module admission seal, before joining the serialized command.
    let closure = owner?.close();
    closure?.catch(() => {});
    finishing = (async () => {
      let joined = true, snapshot, primary = code;
      try { if (!owner) owner = await startup; }
      catch (error) { joined = error?.joined === true; primary ??= 'peer_unavailable'; }
      if (!closure && owner) { closure = owner.close(); closure.catch(() => {}); }
      await chain;
      if (closure) try { snapshot = await closure; }
      catch (error) { joined = false; primary ??= 'peer_cleanup'; }
      await output;
      if (writers.size) { joined = false; primary ??= 'peer_output'; }
      try {
        await emit(primary ? { event: 'failed', code: primary, joined } : { event: 'closed', snapshot });
      } catch { joined = false; primary = 'peer_output'; }
      process.stdin.destroy();
      if (primary || !joined) process.exitCode = 1;
      completed();
    })();
    return finishing;
  };
  const watchdog = setTimeout(() => { void stop('peer_watchdog'); }, 180000);
  const onEnd = () => { void stop('peer_input'); };
  const onError = () => { void stop('peer_input'); };
  const onSignal = () => { void stop('peer_unavailable'); };
  const onOutputError = () => { void stop('peer_output'); };
  const onData = chunk => {
    if (terminal) return;
    total += chunk.length;
    if (total > 262144) { void stop('peer_input'); return; }
    // Bound each line, not each OS read: coalesced valid commands are legal.
    let at = 0;
    while (at < chunk.length) {
      if (terminal) return;
      const end = chunk.indexOf(10, at);
      const part = chunk.subarray(at, end < 0 ? chunk.length : end);
      if (part.some(byte => byte < 32 || byte > 126) || bytes.length + part.length > 8192) { void stop('peer_input'); return; }
      bytes = Buffer.concat([bytes, part]);
      if (end < 0) return;
      at = end + 1;
      const line = bytes.toString('ascii'); bytes = Buffer.alloc(0);
      let command;
      try {
        command = JSON.parse(line);
        if (!command || Array.isArray(command) || JSON.stringify(command) !== line || ++count > 64) fail('peer_input');
        const keys = Object.keys(command).join(',');
        if (command.op === 'enroll' && keys === 'op,csrDer') command.csrDer = publicCsr(command.csrDer);
        else if (keys !== 'op' || !['snapshot', 'revoke', 'stop'].includes(command.op)) fail('peer_input');
      } catch { void stop('peer_input'); return; }
      if (command.op === 'stop') { void stop(); return; }
      const operation = chain.then(async () => {
        await startup;
        if (terminal) return;
        let event;
        if (command.op === 'enroll') event = { event: 'enrolled', ...await owner.enroll(command.csrDer) };
        else if (command.op === 'snapshot') event = { event: 'snapshot', snapshot: owner.snapshot() };
        else event = { event: 'revoked', ...await owner.revoke() };
        if (!terminal) await emit(event);
      });
      // Do not have stop() await the catch that itself initiates stop().
      chain = operation.catch(() => {});
      operation.catch(error => { if (!terminal) void stop(sanitized(error, 'peer_unavailable').code); });
    }
  };
  process.stdin.on('data', onData); process.stdin.once('end', onEnd); process.stdin.once('error', onError);
  process.stdout.on('error', onOutputError);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, onSignal);
  try {
    if (process.argv.length !== 2) fail('peer_configuration');
    startup = startReferenceInterceptionPeer();
    owner = await startup;
    if (!terminal) await emit({ event: 'ready', ...owner.ready() });
  } catch (error) { await stop(sanitized(error, 'peer_unavailable').code); }
  // A real stop owns listener removal as well as gateway/process writes.
  await completion;
  process.stdin.removeListener('data', onData); process.stdin.removeListener('end', onEnd); process.stdin.removeListener('error', onError);
  process.stdout.removeListener('error', onOutputError);
  for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, onSignal);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
