// Private parent IPC only. No invitation/operator commands are served over HTTP.
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';

const codes = new Set(['invalid_message', 'message_too_large', 'unsupported_version', 'unsupported_capability', 'authentication_failed', 'invitation_expired', 'invitation_used', 'pairing_limit', 'pairing_unavailable']);
const schema = {
  start: ['directory', 'mode', 'openssl', 'setupPort', 'credentialPort'], metadata: [], createInvitation: [],
  waitForRegistered: ['invitationId', 'timeoutMillis'], approve: ['enrollmentId'], reject: ['enrollmentId'], revoke: ['enrollmentId'],
  readResult: ['enrollmentId'], dropNextApprovedStatus: [], snapshot: [], close: [],
};
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, fields) => object(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
const full = (value, expression) => typeof value === 'string' && expression.exec(value)?.[0] === value;
const text = value => typeof value === 'string' && value.length >= 1 && value.length <= 4096 && !/[\u0000\r\n]/.test(value);
function valid(message) {
  if (!exact(message, ['revision', 'id', 'op', 'args']) || message.revision !== 1 || !Number.isSafeInteger(message.id) || message.id < 1 ||
      !Object.hasOwn(schema, message.op) || !exact(message.args, schema[message.op])) return false;
  const args = message.args;
  if (message.op === 'start') return text(args.directory) && text(args.openssl) && ['create', 'open'].includes(args.mode) &&
    [args.setupPort, args.credentialPort].every(port => Number.isInteger(port) && port >= (args.mode === 'create' ? 0 : 1) && port <= 65535) &&
    (args.setupPort === 0 || args.setupPort !== args.credentialPort);
  if (message.op === 'waitForRegistered') return full(args.invitationId, /^[A-Za-z0-9_-]{1,128}$/) && Number.isInteger(args.timeoutMillis) && args.timeoutMillis >= 1 && args.timeoutMillis <= 10000;
  if (schema[message.op].includes('enrollmentId')) return full(args.enrollmentId, /^enr_[A-Za-z0-9_-]{43}$/) && Buffer.from(args.enrollmentId.slice(4), 'base64url').toString('base64url') === args.enrollmentId.slice(4);
  return true;
}

let fixture, starting, startAccepted = false, closing = false, shutdown;
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
  if (op === 'start') {
    startAccepted = true;
    starting = startEnrollmentHttpsFixture(args); fixture = await starting;
    return fixture.metadata().material();
  }
  if (!fixture) throw Object.assign(Error(), { code: 'pairing_unavailable' });
  if (op === 'metadata') return fixture.metadata().material();
  if (op === 'createInvitation') return fixture.createInvitation().material();
  if (op === 'waitForRegistered') return (await fixture.waitForRegistered(args.invitationId, { timeoutMillis: args.timeoutMillis })).material();
  if (op === 'approve') return (await fixture.approve(args.enrollmentId)).material();
  if (['reject', 'revoke', 'readResult'].includes(op)) return fixture[op](args.enrollmentId).material();
  if (op === 'dropNextApprovedStatus') { fixture.dropNextApprovedStatus(); return { armed: true }; }
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
  if (closing || (message.op === 'start' ? startAccepted : !startAccepted)) { refuse('pairing_unavailable'); return; }
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
        if (!fixture) throw Object.assign(Error(), { code: 'pairing_unavailable' });
        result = await fixture.close();
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
if (typeof process.send !== 'function') process.exitCode = 1;
else {
  process.on('message', receive);
  process.once('disconnect', () => { if (!closing) void stopWithoutReply(); });
}
