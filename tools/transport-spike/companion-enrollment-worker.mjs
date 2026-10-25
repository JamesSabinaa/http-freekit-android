// Private parent IPC only. No invitation/operator commands are served over HTTP.
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import path from 'node:path';

const codes = new Set(['invalid_message', 'message_too_large', 'unsupported_version', 'unsupported_capability', 'authentication_failed', 'invitation_expired', 'invitation_used', 'pairing_limit', 'pairing_unavailable']);
const schema = {
  start: ['directory', 'mode', 'openssl', 'setupPort', 'credentialPort'], metadata: [], createInvitation: [], interceptionCaEvidence: [],
  startAdversarial: ['directory', 'mode', 'openssl', 'setupPort', 'credentialPort'],
  startOrigin: ['desktopRoot', 'desktopCommit', 'openssl'], releaseOriginTail: [],
  startTunOrigin: ['desktopRoot', 'desktopCommit', 'openssl'],
  startStreaming: ['directory', 'mode', 'openssl', 'setupPort', 'credentialPort', 'streamPort', 'credentialLifetimeSeconds', 'sessionLifetimeMillis'],
  waitForRegistered: ['invitationId', 'timeoutMillis'], approve: ['enrollmentId'], reject: ['enrollmentId'], revoke: ['enrollmentId'],
  readResult: ['enrollmentId'], inspectEnrollment: ['enrollmentId'], dropNextApprovedStatus: [], snapshot: [], close: [],
};
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, fields) => object(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
const full = (value, expression) => typeof value === 'string' && expression.exec(value)?.[0] === value;
const text = value => typeof value === 'string' && value.length >= 1 && value.length <= 4096 && !/[\u0000\r\n]/.test(value);
function valid(message) {
  if (!exact(message, ['revision', 'id', 'op', 'args']) || message.revision !== 1 || !Number.isSafeInteger(message.id) || message.id < 1 ||
      !Object.hasOwn(schema, message.op) || !exact(message.args, schema[message.op])) return false;
  const args = message.args;
  if (['startOrigin', 'startTunOrigin'].includes(message.op)) return text(args.desktopRoot) && path.isAbsolute(args.desktopRoot) &&
    full(args.desktopCommit, /^[0-9a-f]{40}$/) && text(args.openssl);
  if (['start', 'startStreaming', 'startAdversarial'].includes(message.op)) {
    const streaming = message.op === 'startStreaming';
    const ports = [args.setupPort, args.credentialPort, ...(streaming ? [args.streamPort] : [])];
    if (!text(args.directory) || !text(args.openssl) || !['create', 'open'].includes(args.mode) ||
        !ports.every(port => Number.isInteger(port) && port >= (args.mode === 'create' ? 0 : 1) && port <= 65535) ||
        new Set(ports.filter(port => port !== 0)).size !== ports.filter(port => port !== 0).length) return false;
    if (message.op === 'startAdversarial') return args.mode === 'create';
    return !streaming || (args.mode === 'create' && Number.isInteger(args.credentialLifetimeSeconds) &&
      args.credentialLifetimeSeconds >= 60 && args.credentialLifetimeSeconds <= 7776000 &&
      Number.isInteger(args.sessionLifetimeMillis) && args.sessionLifetimeMillis >= 1000 && args.sessionLifetimeMillis <= 1800000);
  }
  if (message.op === 'waitForRegistered') return full(args.invitationId, /^[A-Za-z0-9_-]{1,128}$/) && Number.isInteger(args.timeoutMillis) && args.timeoutMillis >= 1 && args.timeoutMillis <= 10000;
  if (schema[message.op].includes('enrollmentId')) return full(args.enrollmentId, /^enr_[A-Za-z0-9_-]{43}$/) && Buffer.from(args.enrollmentId.slice(4), 'base64url').toString('base64url') === args.enrollmentId.slice(4);
  return true;
}

let fixture, starting, startAccepted = false, originFixture = false, plainHttpsFixture = false, closing = false, shutdown;
const pending = new Map(), sends = new Set();
function send(reply) {
  if (!process.connected || typeof process.send !== 'function' || sends.size >= 4) return Promise.reject(Error('private_ipc_unavailable'));
  try { if (Buffer.byteLength(JSON.stringify(reply)) > 16384) throw Error(); }
  catch { return Promise.reject(Error('private_ipc_unavailable')); }
  let resolveSend, rejectSend;
  const task = new Promise((resolve, reject) => { resolveSend = resolve; rejectSend = reject; }); sends.add(task);
  try { process.send(reply, error => { sends.delete(task); error ? rejectSend(Error('private_ipc_unavailable')) : resolveSend(); }); }
  catch { sends.delete(task); rejectSend(Error('private_ipc_unavailable')); }
  return task;
}
const failure = (id, code) => send({ revision: 1, id, ok: false, code });
function stopWithoutReply() {
  if (shutdown) return shutdown;
  closing = true;
  shutdown = (async () => {
    try { await starting?.catch(() => null); await fixture?.close(); await Promise.allSettled([...pending.values(), ...sends]); }
    finally { process.exitCode = 1; if (process.connected) process.disconnect(); }
  })();
  shutdown.catch(() => {}); return shutdown;
}
async function invoke(op, args) {
  if (['start', 'startStreaming', 'startAdversarial', 'startOrigin', 'startTunOrigin'].includes(op)) {
    startAccepted = true;
    originFixture = op === 'startOrigin' || op === 'startTunOrigin';
    plainHttpsFixture = op === 'start';
    starting = op === 'start' ? startEnrollmentHttpsFixture(args) : (async () => {
      if (op === 'startOrigin' || op === 'startTunOrigin') {
        const { startOriginGatewayFixture } = await import('./gateway-origin-fixture.mjs');
        return startOriginGatewayFixture(op === 'startTunOrigin' ? { ...args, profile: 'tun-http-h1', family: 'ipv4' } : args);
      }
      if (op === 'startStreaming') {
        const { startEnrollmentStreamFixture } = await import('./companion-enrollment-stream.mjs');
        return startEnrollmentStreamFixture(args);
      }
      const { startEnrollmentAdversarialFixture } = await import('./companion-enrollment-adversarial.mjs');
      return startEnrollmentAdversarialFixture(args);
    })();
    fixture = await starting;
    return fixture.metadata().material();
  }
  if (!fixture) throw Object.assign(Error(), { code: 'pairing_unavailable' });
  if (op === 'interceptionCaEvidence') {
    if (!plainHttpsFixture) throw Object.assign(Error(), { code: 'pairing_unavailable' });
    return fixture.interceptionCaEvidence().material();
  }
  if (op === 'releaseOriginTail') {
    if (!originFixture) throw Object.assign(Error(), { code: 'pairing_unavailable' });
    return fixture.releaseTail();
  }
  if (op === 'metadata') return fixture.metadata().material();
  if (op === 'createInvitation') return fixture.createInvitation().material();
  if (op === 'waitForRegistered') return (await fixture.waitForRegistered(args.invitationId, { timeoutMillis: args.timeoutMillis })).material();
  if (op === 'approve') return (await fixture.approve(args.enrollmentId)).material();
  if (['reject', 'revoke', 'readResult'].includes(op)) return fixture[op](args.enrollmentId).material();
  if (op === 'dropNextApprovedStatus') { fixture.dropNextApprovedStatus(); return { armed: true }; }
  if (op === 'inspectEnrollment') {
    if (typeof fixture.inspectEnrollment !== 'function') throw Object.assign(Error(), { code: 'pairing_unavailable' });
    return fixture.inspectEnrollment(args.enrollmentId);
  }
  return fixture.snapshot();
}
function receive(message) {
  const safeId = Number.isSafeInteger(message?.id) && message.id > 0 ? message.id : null;
  let size;
  try { size = Buffer.byteLength(JSON.stringify(message)); } catch { void stopWithoutReply(); return; }
  if (!safeId) { void stopWithoutReply(); return; }
  const refuse = code => { failure(safeId, code).catch(() => { void stopWithoutReply(); }); };
  if (size > 16384) { refuse('message_too_large'); return; }
  if (!valid(message)) { refuse('invalid_message'); return; }
  if (pending.has(safeId)) { refuse('invalid_message'); return; }
  const starts = ['start', 'startStreaming', 'startAdversarial', 'startOrigin', 'startTunOrigin'].includes(message.op);
  if (closing || (starts ? startAccepted : message.op !== 'close' && !startAccepted)) { refuse('pairing_unavailable'); return; }
  if (message.op !== 'close' && pending.size >= 3) { refuse('pairing_limit'); return; }
  if (message.op === 'close') closing = true;
  // Register before invoking any asynchronous owner; a refusal never deletes another request's slot.
  let resolveOwner;
  const owner = new Promise(resolve => { resolveOwner = resolve; }); pending.set(safeId, owner);
  void (async () => {
    let closeAcknowledged = false;
    try {
      let result;
      if (message.op === 'close') {
        await starting?.catch(() => null);
        if (!fixture) {
          // Invalid configuration never started any fixture/issuer. Close admission and
          // attest that distinct state; an attempted but failed start still cannot do so.
          if (startAccepted) throw Object.assign(Error(), { code: 'pairing_unavailable' });
          result = { initializationAttempted: false, closed: true,
            admissionClosed: true, listenersClosed: true, storeClosed: true, issuerChildrenJoined: true,
            activeSockets: 0, pendingCallbacks: 0, pendingTimers: 0, issuerJobs: 0, signerGroups: 0, workers: 0 };
        } else {
          result = await fixture.close();
          if (originFixture) result = originClosed(result);
        }
        await Promise.allSettled([...pending].filter(([id]) => id !== safeId).map(([, task]) => task));
        await Promise.allSettled([...sends]);
      } else result = await invoke(message.op, message.args);
      await send({ revision: 1, id: safeId, ok: true, result }); closeAcknowledged = message.op === 'close';
    } catch (error) {
      try { await failure(safeId, codes.has(error?.code) ? error.code : 'pairing_unavailable'); } catch { void stopWithoutReply(); }
    } finally {
      if (pending.get(safeId) === owner) pending.delete(safeId); resolveOwner();
      if (message.op === 'close') {
        process.exitCode = closeAcknowledged ? 0 : 1;
        if (process.connected) process.disconnect();
      }
    }
  })();
}
function originClosed(value) {
  const nested = value?.enrollment, backend = value?.backend;
  const counts = ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'workers'];
  if (!nested || !backend || value.privateDirectoryRemoved !== true || value.listenerClosed !== true ||
      backend.activeOwners !== 0 || backend.admitted !== backend.settled ||
      counts.some(key => !Number.isSafeInteger(value[key]) || value[key] < 0 || !Number.isSafeInteger(nested[key]) || nested[key] < 0)) {
    throw Object.assign(Error(), { code: 'pairing_unavailable' });
  }
  return { admissionClosed: value.admissionClosed === true && nested.admissionClosed === true && backend.closing === true,
    listenersClosed: value.listenerClosed === true && nested.listenersClosed === true,
    storeClosed: nested.storeClosed === true, issuerChildrenJoined: nested.issuerChildrenJoined === true,
    activeSockets: value.activeSockets + nested.activeSockets, pendingCallbacks: value.pendingCallbacks + nested.pendingCallbacks,
    pendingTimers: value.pendingTimers + nested.pendingTimers, workers: value.workers + nested.workers,
    issuerJobs: nested.issuerJobs, signerGroups: nested.signerGroups,
    privateDirectoryRemoved: value.privateDirectoryRemoved, gatewayStreamComplete: value.gatewayStreamComplete };
}
if (typeof process.send !== 'function') process.exitCode = 1;
else {
  process.on('message', receive);
  process.once('disconnect', () => { if (!closing) void stopWithoutReply(); });
}
