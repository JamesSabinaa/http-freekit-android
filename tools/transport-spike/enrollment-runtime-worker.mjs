// Parent-only A22 private IPC owner. Never used as a phone-accessible operator surface.
import { fork, execFileSync } from 'node:child_process';
import path from 'node:path';
import { inspect } from 'node:util';

const OPS = new Set(['start', 'startStreaming', 'startAdversarial', 'startOrigin', 'releaseOriginTail', 'metadata', 'createInvitation', 'waitForRegistered', 'approve', 'reject',
  'revoke', 'readResult', 'inspectEnrollment', 'dropNextApprovedStatus', 'snapshot', 'close']);
const WIRE_ERRORS = new Set(['invalid_fixture_command', 'fixture_unavailable', 'fixture_timeout',
  'fixture_closing', 'fixture_cleanup_failed', 'invalid_message', 'message_too_large', 'unsupported_version',
  'unsupported_capability', 'authentication_failed', 'invitation_expired', 'invitation_used',
  'pairing_limit', 'pairing_unavailable']);
const CLOSED_FLAGS = ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined'];
const CLOSED_COUNTS = ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers'];
const values = new WeakMap();
export class EnrollmentWorkerError extends Error {
  constructor(code) { super('Enrollment worker unavailable'); this.code = code; }
  toJSON() { return { code: this.code }; }
  [inspect.custom]() { return 'EnrollmentWorkerError(' + this.code + ')'; }
}
const fail = code => { throw new EnrollmentWorkerError(code); };
function boundedCopy(value) {
  let budget = 0;
  function visit(input, depth) {
    if (depth > 8) fail('worker_protocol_failed');
    if (input === null || typeof input === 'boolean') return input;
    if (typeof input === 'number') {
      if (!Number.isSafeInteger(input)) fail('worker_protocol_failed');
      return input;
    }
    if (typeof input === 'string') {
      if (!input.isWellFormed() || input.length > 16384) fail('worker_protocol_failed');
      budget += Buffer.byteLength(JSON.stringify(input));
      if (budget > 16384) fail('worker_protocol_failed');
      return input;
    }
    if (!input || typeof input !== 'object') fail('worker_protocol_failed');
    if (Array.isArray(input)) {
      if (input.length > 64) fail('worker_protocol_failed');
      const output = [];
      for (let i = 0; i < input.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(i));
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('worker_protocol_failed');
        output.push(visit(descriptor.value, depth + 1));
      }
      return output;
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(input))) fail('worker_protocol_failed');
    const keys = Reflect.ownKeys(input);
    if (keys.length > 64) fail('worker_protocol_failed');
    const entries = [];
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (typeof key !== 'string' || !Object.hasOwn(descriptor, 'value')) fail('worker_protocol_failed');
      visit(key, depth + 1);
      entries.push([key, visit(descriptor.value, depth + 1)]);
    }
    return Object.fromEntries(entries);
  }
  const copied = visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(copied)) > 16384) fail('worker_protocol_failed');
  return copied;
}
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || !fields.every(key => Object.hasOwn(value, key))) fail('worker_protocol_failed');
}
class WorkerReply {
  constructor(value) { values.set(this, JSON.stringify(value)); Object.freeze(this); }
  material() { return JSON.parse(values.get(this)); }
  toString() { return 'EnrollmentWorkerReply([REDACTED])'; }
  toJSON() { return { kind: 'EnrollmentWorkerReply', redacted: true }; }
  [inspect.custom]() { return this.toString(); }
}
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function within(promise, milliseconds) {
  let timer;
  try { return await Promise.race([promise.then(() => true), new Promise(resolve => { timer = setTimeout(() => resolve(false), milliseconds); })]); }
  finally { clearTimeout(timer); }
}
function quiescent(value) {
  return value && CLOSED_FLAGS.every(key => value[key] === true) && CLOSED_COUNTS.every(key => value[key] === 0);
}

export class EnrollmentRuntimeWorker {
  #child; #pending = new Map(); #next = 1; #failure = null; #stopping = false; #closeTask;
  #closed = false; #groupClosed = false; #exitCode = null; #signal = null; #reason = null; #lastClosed = null;
  #joined;
  constructor({ entry, args = [], cwd, env = process.env }) {
    if (typeof entry !== 'string' || !path.isAbsolute(entry) || !Array.isArray(args) ||
        args.some(value => typeof value !== 'string' || value.length > 4096 || /[\0\r\n]/.test(value))) fail('worker_configuration_failed');
    let resolveJoined;
    this.#joined = new Promise(resolve => { resolveJoined = resolve; });
    this.#child = fork(entry, args, { cwd, env, execArgv: [], serialization: 'json',
      detached: process.platform !== 'win32', windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    this.#child.on('message', value => this.#message(value));
    this.#child.once('error', () => this.#unavailable('worker_spawn_failed'));
    this.#child.once('close', (code, signal) => {
      this.#closed = true; this.#exitCode = code; this.#signal = signal;
      for (const pending of this.#pending.values()) {
        clearTimeout(pending.timer);
        if (!pending.settled) pending.reject(new EnrollmentWorkerError('worker_exited'));
      }
      this.#pending.clear(); resolveJoined();
    });
  }
  get pid() { return this.#child.pid; } // Explicit owned-process access only; never a report identity.
  #unavailable(code) {
    this.#failure ??= code;
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      if (!pending.settled) { pending.settled = true; pending.reject(new EnrollmentWorkerError(code)); }
    }
  }
  #message(input) {
    try {
      const message = boundedCopy(input);
      if (message.ok === true) exact(message, ['revision', 'id', 'ok', 'result']);
      else if (message.ok === false) exact(message, ['revision', 'id', 'ok', 'code']);
      else fail('worker_protocol_failed');
      if (message.revision !== 1 || !Number.isSafeInteger(message.id) || message.id < 1) fail('worker_protocol_failed');
      const pending = this.#pending.get(message.id);
      if (!pending) fail('worker_protocol_failed');
      if (!message.ok && !WIRE_ERRORS.has(message.code)) fail('worker_protocol_failed');
      if (message.ok && (!message.result || typeof message.result !== 'object' || Array.isArray(message.result))) fail('worker_protocol_failed');
      clearTimeout(pending.timer); this.#pending.delete(message.id);
      if (pending.settled) return;
      pending.settled = true;
      if (message.ok) pending.resolve(new WorkerReply(message.result));
      else pending.reject(new EnrollmentWorkerError(message.code));
    } catch { this.#unavailable('worker_protocol_failed'); }
  }
  request(op, args = {}, { timeoutMillis = 15000 } = {}) {
    try {
      if (!OPS.has(op) || !Number.isInteger(timeoutMillis) || timeoutMillis < 1 || timeoutMillis > 120000) fail('worker_configuration_failed');
      if (this.#closed || !this.#child.connected) fail('worker_exited');
      if ((this.#stopping || this.#failure) && !['close', 'snapshot'].includes(op)) fail(this.#failure ?? 'worker_closing');
      // Three business slots leave one control slot for close during an in-flight approval.
      if (this.#pending.size >= (op === 'close' ? 4 : 3)) fail('worker_command_limit');
      if (this.#next >= Number.MAX_SAFE_INTEGER) fail('worker_command_limit');
      const message = boundedCopy({ revision: 1, id: this.#next++, op, args });
      if (!message.args || typeof message.args !== 'object' || Array.isArray(message.args)) fail('worker_configuration_failed');
      return new Promise((resolve, reject) => {
        const pending = { resolve, reject, settled: false, timer: null };
        this.#pending.set(message.id, pending);
        pending.timer = setTimeout(() => this.#unavailable('worker_timeout'), timeoutMillis);
        try { this.#child.send(message, error => { if (error) this.#unavailable('worker_send_failed'); }); }
        catch { this.#unavailable('worker_send_failed'); }
      });
    } catch (error) {
      return Promise.reject(error instanceof EnrollmentWorkerError ? error : new EnrollmentWorkerError('worker_configuration_failed'));
    }
  }
  #groupExists() {
    if (!this.#child.pid) return false;
    try { process.kill(-this.#child.pid, 0); return true; }
    catch (error) { if (error.code === 'ESRCH') return false; fail('worker_cleanup_failed'); }
  }
  async #joinGroup() {
    if (process.platform === 'win32') { this.#groupClosed = this.#closed; return; }
    const deadline = performance.now() + 5000;
    while (this.#groupExists() && performance.now() < deadline) await sleep(25);
    this.#groupClosed = !this.#groupExists();
    if (!this.#groupClosed) fail('worker_cleanup_failed');
  }
  async #stopQuiescent() {
    if (!quiescent(this.#lastClosed)) fail('worker_cleanup_failed');
    this.#reason = 'owned_child_timeout';
    if (process.platform === 'win32') {
      try { execFileSync('taskkill.exe', ['/PID', String(this.pid), '/T', '/F'], { timeout: 10000, stdio: 'ignore', windowsHide: true }); }
      catch { /* Actual close below decides whether the fast-exit race completed. */ }
    } else {
      try { process.kill(-this.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') fail('worker_cleanup_failed'); }
      if (!(await within(this.#joined, 2000))) {
        try { process.kill(-this.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') fail('worker_cleanup_failed'); }
      }
    }
    if (!(await within(this.#joined, 5000))) fail('worker_cleanup_failed');
  }
  close() {
    if (this.#closeTask) return this.#closeTask;
    this.#stopping = true;
    this.#closeTask = (async () => {
      let failed;
      try {
        if (!this.#closed) {
          const reply = await this.request('close', {}, { timeoutMillis: 20000 });
          this.#lastClosed = reply.material();
          if (!quiescent(this.#lastClosed)) fail('worker_cleanup_failed');
          if (!(await within(this.#joined, 5000))) await this.#stopQuiescent();
        }
        if (!this.#closed) fail('worker_cleanup_failed');
        await this.#joinGroup();
        if (!quiescent(this.#lastClosed) || this.#exitCode !== 0 || this.#signal !== null || this.#reason) fail('worker_cleanup_failed');
      } catch (error) { failed = error instanceof EnrollmentWorkerError ? error.code : 'worker_cleanup_failed'; }
      if (failed || this.#failure) fail(failed ?? this.#failure);
      return new WorkerReply(this.#lastClosed);
    })();
    return this.#closeTask;
  }
  closedSnapshot() { return this.#lastClosed === null ? null : new WorkerReply(this.#lastClosed); }
  commandObservation() {
    return Object.freeze({ code: this.#exitCode, signal: this.#signal, reason: this.#reason,
      closeObserved: this.#closed, processGroupClosed: this.#groupClosed });
  }
  toString() { return 'EnrollmentRuntimeWorker([REDACTED])'; }
  toJSON() { return { kind: 'EnrollmentRuntimeWorker', closed: this.#closed, pending: this.#pending.size }; }
  [inspect.custom]() { return this.toString(); }
}
