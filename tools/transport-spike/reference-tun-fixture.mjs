// Private host research composition. Not C5, desktop integration or production wire.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspect } from 'node:util';
import { createReferenceInterceptionAssets } from './reference-interception-assets.mjs';
import { startReferenceInterceptionBackend } from './reference-interception-backend.mjs';
import { startEnrollmentOriginFixture } from './companion-enrollment-origin.mjs';

export const TUN_CODES = Object.freeze(['tun_configuration', 'tun_input', 'tun_unavailable', 'tun_enrollment', 'tun_closing', 'tun_cleanup', 'tun_watchdog', 'tun_output', 'tun_protocol', 'tun_timeout', 'tun_process']);
const capabilities = ['tcp-http-origin-connect', 'tcp-https-connect'];
export class ReferenceTunError extends Error {
  constructor(code, joined = false, suppressed = []) {
    super('Private reference TUN unavailable'); this.name = 'ReferenceTunError';
    this.code = TUN_CODES.includes(code) ? code : 'tun_unavailable'; this.joined = joined === true;
    Object.defineProperty(this, 'suppressed', { value: Object.freeze([...suppressed]) });
  }
  toJSON() { return { code: this.code, joined: this.joined }; }
  [inspect.custom]() { return this.toJSON(); }
}
const fail = (code, joined = true) => { throw new ReferenceTunError(code, joined); };
const sanitized = (error, code) => error instanceof ReferenceTunError ? error : new ReferenceTunError(code, error?.joined === true);
const identity = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
function gatewayJoined(s) {
  return s.closed && s.admissionClosed && s.authorityClosed && s.storeClosed && s.listenersClosed && s.issuerChildrenJoined &&
    ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'workers', 'signerGroups', 'issuerJobs', 'acceptedSockets',
      'tlsSockets', 'bodyReaders', 'requestTasks', 'pendingWriteCallbacks', 'registrationWaiters', 'listeners'].every(k => s[k] === 0) &&
    ['sessionLeases', 'streamLeases', 'chargedBytes', 'ownerRecords', 'authenticatedSockets', 'proxySockets',
      'listeners', 'workers', 'timers', 'pendingCallbacks'].every(k => s.stream[k] === 0) &&
    s.issuer.commandsStarted === s.issuer.commandsClosed && s.issuer.commandsStarted === s.issuer.processGroupsClosed;
}

export async function startReferenceTunFixture({ openssl = process.env.OPENSSL_BIN ?? 'openssl' } = {}) {
  if (typeof openssl !== 'string' || !openssl || openssl.length > 4096 || /[\0\r\n]/.test(openssl)) fail('tun_configuration');
  let parent, directory;
  try {
    parent = fs.realpathSync(os.tmpdir());
    directory = fs.mkdtempSync(path.join(parent, 'freekit-reference-tun-'));
    // mkdtemp creates the private mode before any material or child exists.
    if ((fs.statSync(directory).mode & 0o777) !== 0o700) fail('tun_configuration', false);
  } catch { fail('tun_configuration', directory === undefined); }
  let assets, backend, gateway, enrollmentId, invitationId;
  let sealed = false, invited = false, closeTask, startupUnjoined = false, operationUnjoined = false, privateDirectoryRemoved = false;
  const jobs = new Set();
  // Explicit private snapshots are defensive. Default object inspection is not IPC.
  const snapshot = () => {
    const probe = enrollmentId ? gateway?.inspectEnrollment(enrollmentId)?.probe : null;
    const stream = probe?.stream ? {
      phase: probe.stream.phase ?? null, resourcesReleased: probe.stream.resourcesReleased ?? null, streamLease: probe.stream.streamLease ?? null,
      clientEofEmitted: probe.stream.client?.eofEmitted ?? null, gatewayEofEmitted: probe.stream.gateway?.eofEmitted ?? null,
      chargedBytes: probe.control?.chargedBytes ?? null, fixtureUploadBytesRead: probe.fixture?.uploadBytesRead ?? null,
      fixtureResponseBytesWritten: probe.fixture?.responseBytesWritten ?? null, cleanupComplete: probe.cleanup?.complete ?? null,
    } : null;
    return structuredClone({ gateway: gateway?.snapshot() ?? null, backend: backend?.snapshot() ?? null,
      assets: assets?.snapshot() ?? null, stream, evidence: backend?.evidence() ?? [], privateDirectoryRemoved });
  };
  const available = () => { if (sealed || !gateway) fail('tun_unavailable'); };
  const close = () => {
    if (closeTask) return closeTask;
    sealed = true;
    closeTask = (async () => {
      const failures = [];
      let joined = !startupUnjoined;
      const attempt = async action => {
        try { await action(); } catch (error) { joined = false; failures.push(sanitized(error, 'tun_cleanup')); }
      };
      // Close the gateway first to seal issuer/registry publication; independently
      // close the backend even if the gateway failed. Do not destroy assets/users.
      const gatewayClose = gateway ? attempt(async () => {
        const state = await gateway.close(); if (!gatewayJoined(state)) fail('tun_cleanup', false);
      }) : Promise.resolve();
      const backendClose = backend ? attempt(async () => {
        const state = await backend.close();
        if (!state.closed || state.ownersCreated !== state.ownersClosed ||
            ['activeOwners', 'activeSockets', 'activeRequests', 'listeners'].some(k => state[k] !== 0)) fail('tun_cleanup', false);
      }) : Promise.resolve();
      await Promise.all([gatewayClose, backendClose]);
      await Promise.allSettled([...jobs]);
      if (operationUnjoined) { joined = false; failures.push(new ReferenceTunError('tun_enrollment',false)); }
      if (assets && joined) await attempt(async () => {
        const state = await assets.close();
        if (!state.closed || state.commandsStarted !== state.commandsClosed || state.commandsStarted !== state.processGroupsClosed) fail('tun_cleanup', false);
      });
      if (joined) await attempt(async () => {
        if (path.dirname(directory) !== parent || !path.basename(directory).startsWith('freekit-reference-tun-') ||
            fs.realpathSync(directory) !== directory || fs.lstatSync(directory).isSymbolicLink()) fail('tun_cleanup', false);
        fs.rmSync(directory, { recursive: true });
        privateDirectoryRemoved = !fs.existsSync(directory);
        if (!privateDirectoryRemoved) fail('tun_cleanup', false);
      });
      if (!joined || failures.length) throw new ReferenceTunError('tun_cleanup', false, failures);
      return snapshot();
    })();
    return closeTask;
  };
  try {
    const assetDirectory = path.join(directory, 'assets'), enrollmentDirectory = path.join(directory, 'enrollment');
    for (const child of [assetDirectory, enrollmentDirectory]) fs.mkdirSync(child, { mode: 0o700 });
    assets = await createReferenceInterceptionAssets({ directory: assetDirectory, openssl });
    backend = await startReferenceInterceptionBackend({ assets });
    gateway = await startEnrollmentOriginFixture({ directory: enrollmentDirectory, mode: 'create', openssl,
      credentialLifetimeSeconds: 3600, trustedProxyFactory: backend.factory, supportedCapabilities: capabilities,
      interceptionCaCertificateDer: assets.caDer('interception') });
  } catch (error) {
    startupUnjoined = error?.joined !== true;
    let cleanup;
    try { await close(); } catch (failure) { cleanup = failure; }
    throw new ReferenceTunError('tun_unavailable', !startupUnjoined && !cleanup, cleanup ? [sanitized(cleanup, 'tun_cleanup')] : []);
  }
  const checkEnrollment = id => { if (!identity(id) || !enrollmentId || id !== enrollmentId) fail('tun_input'); };
  const operation = action => {
    const task = (async () => {
      try { return await action(); }
      catch (error) {
        const failure = sanitized(error, 'tun_enrollment');
        if (!failure.joined) operationUnjoined = true;
        throw failure;
      }
    })();
    jobs.add(task); task.then(() => jobs.delete(task), () => jobs.delete(task)); return task;
  };
  return Object.freeze({
    metadata() { available(); return gateway.metadata(); },
    createInvitation() {
      available(); if (invited) fail('tun_input');
      const result = gateway.createInvitation(); invited = true; invitationId = result.material().invitationId; return result;
    },
    waitForRegistered(id, options) {
      available(); if (!identity(id) || id !== invitationId) fail('tun_input');
      return operation(async () => {
        const result = await gateway.waitForRegistered(id, options);
        enrollmentId = result.material().enrollmentId; return result;
      });
    },
    approve(id) { available(); checkEnrollment(id); return operation(() => gateway.approve(id)); },
    readResult(id) { available(); checkEnrollment(id); return gateway.readResult(id); },
    inspectEnrollment(id) { available(); checkEnrollment(id); return gateway.inspectEnrollment(id); },
    snapshot,
    close, toJSON: () => '[Private reference TUN fixture]', [inspect.custom]: () => '[Private reference TUN fixture]',
  });
}
