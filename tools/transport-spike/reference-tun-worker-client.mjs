// Parent owns only the fixed private child, its pipes and process group.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { FORMAT, validateRequest } from './reference-tun-worker.mjs';
import { ReferenceTunError, TUN_CODES } from './reference-tun-fixture.mjs';
import { bounded } from './companion-stream-peer-io.mjs';
const fail = code => { throw new ReferenceTunError(code); };
const copy = value => structuredClone(value);
// Pure private aggregation; process exit cannot prove removal of child-owned assets.
export function referenceTunStartupJoined(childCleanupJoined, state) {
  return childCleanupJoined === true && state.closeObserved === true && state.processGroupJoined === true &&
    state.stdinJoined === true && state.stdoutJoined === true && state.stderrJoined === true &&
    state.pendingWrites === 0 && state.pendingRequests === 0 && state.forced === false;
}
export async function startReferenceTunWorker({ openssl = process.env.OPENSSL_BIN ?? 'openssl' } = {}) {
  if (typeof openssl !== 'string' || !openssl || openssl.length > 4096 || /[\0\r\n]/.test(openssl)) fail('tun_configuration');
  const child = spawn(process.execPath, [fileURLToPath(new URL('./reference-tun-worker.mjs', import.meta.url))], {
    env: { ...process.env, OPENSSL_BIN: openssl }, detached: process.platform !== 'win32', windowsHide: true, stdio: ['pipe','pipe','pipe'],
  });
  let closed = false, code = null, signal = null, groupJoined = false, forced = false, failure = null, sealed = false;
  let next = 1, total = 0, bytes = Buffer.alloc(0), outputBytes = 0, stderrBytes = 0, stderr = '', readyResolve, readyReject, closeTask;
  let stdoutJoined = false, stderrJoined = false, stdinJoined = false, pendingWrites = 0, readySeen = false, childCleanupJoined = null;
  const ready = new Promise((resolve,reject) => { readyResolve = resolve; readyReject = reject; }); ready.catch(() => {});
  const pending = new Map(), writes = new Set();
  const rejectAll = problem => {
    failure ??= problem; readyReject(new ReferenceTunError(failure));
    for (const p of pending.values()) { clearTimeout(p.timer); p.reject(new ReferenceTunError(failure)); } pending.clear();
    if (!sealed) queueMicrotask(() => { void close().catch(() => {}); });
  };
  const joined = new Promise(resolve => { child.once('close', (c,s) => {
    closed = true; code = c; signal = s;
    if (!sealed || pending.size) rejectAll('tun_process'); resolve();
  }); });
  const stdinDone = new Promise(resolve => child.stdin.once('close', () => { stdinJoined = true; resolve(); }));
  const stdoutDone = new Promise(resolve => child.stdout.once('close', () => { stdoutJoined = true; resolve(); }));
  const stderrDone = new Promise(resolve => child.stderr.once('close', () => { stderrJoined = true; resolve(); }));
  child.once('error', () => rejectAll('tun_process'));
  child.stdin.on('error', () => rejectAll('tun_output'));
  child.stdout.on('error', () => rejectAll('tun_output')); child.stderr.on('error', () => rejectAll('tun_output'));
  child.stderr.on('data', chunk => {
    stderrBytes += chunk.length;
    if (stderrBytes > 4096) { rejectAll('tun_output'); return; }
    stderr += chunk.toString('utf8');
  });
  child.stdout.on('data', chunk => {
    outputBytes += chunk.length;
    if (outputBytes > 16384 * 130) { rejectAll('tun_protocol'); return; }
    let at = 0;
    while (at < chunk.length) {
      const end = chunk.indexOf(10, at), part = chunk.subarray(at,end < 0 ? chunk.length : end);
      if (part.some(b => b < 32 || b > 126) || bytes.length + part.length > 16383) { rejectAll('tun_protocol'); return; }
      bytes = Buffer.concat([bytes,part]); if (end < 0) return; at = end + 1;
      const line = bytes.toString('ascii'); bytes = Buffer.alloc(0);
      try {
        const v = JSON.parse(line);
        if (JSON.stringify(v) !== line || v.format !== FORMAT || v.revision !== 1) fail('tun_protocol');
        const keys = Object.keys(v).join(',');
        if (keys === 'format,revision,event' && v.event === 'ready' && !readySeen) { readySeen = true; readyResolve(); continue; }
        if (keys === 'format,revision,event,code,joined' && v.event === 'failed' && TUN_CODES.includes(v.code) && typeof v.joined === 'boolean') {
          // Negative cleanup evidence is sticky even if a later event claims true.
          childCleanupJoined = childCleanupJoined !== false && v.joined;
          rejectAll(v.code); continue;
        }
        if (!readySeen || !Number.isInteger(v.id) || !pending.has(v.id)) fail('tun_protocol');
        if (v.ok === true) { if (keys !== 'format,revision,id,ok,result') fail('tun_protocol'); }
        else if (v.ok === false) {
          if (keys !== 'format,revision,id,ok,code,joined' || !TUN_CODES.includes(v.code) || typeof v.joined !== 'boolean') fail('tun_protocol');
        } else fail('tun_protocol');
        const p = pending.get(v.id); clearTimeout(p.timer); pending.delete(v.id);
        if (v.ok) p.resolve(copy(v.result)); else p.reject(new ReferenceTunError(v.code,v.joined));
      } catch { rejectAll('tun_protocol'); return; }
    }
  });
  const request = (op,args = {}) => {
    try {
      if ((sealed && op !== 'close') || closed || (failure && op !== 'close')) fail(failure ?? 'tun_closing');
      if (pending.size >= (op === 'close' ? 3 : 2)) fail('tun_input');
      if (Object.hasOwn(args,'id') && typeof args.id !== 'string') fail('tun_input');
      if (Object.hasOwn(args,'timeoutMillis') && !Number.isInteger(args.timeoutMillis)) fail('tun_input');
      const line = JSON.stringify({ format: FORMAT, revision: 1, id: next, op, args });
      validateRequest(line,next);
      if (Buffer.byteLength(line) + 1 > 8192 || total + Buffer.byteLength(line) + 1 > 262144) fail('tun_input');
      const id = next++; total += Buffer.byteLength(line) + 1;
      const promise = new Promise((resolve,reject) => {
        const timer = setTimeout(() => rejectAll('tun_timeout'), op === 'close' ? 25000 : 20000);
        pending.set(id,{resolve,reject,timer});
      });
      const write = new Promise(resolve => {
        pendingWrites++;
        child.stdin.write(line + '\n', error => { pendingWrites--; if (error) rejectAll('tun_output'); resolve(); });
      }); writes.add(write); write.then(() => writes.delete(write));
      return promise;
    } catch (e) { return Promise.reject(e instanceof ReferenceTunError ? e : new ReferenceTunError('tun_input')); }
  };
  const groupExists = () => {
    if (!child.pid) return false;
    if (process.platform === 'win32') return !closed;
    try { process.kill(-child.pid,0); return true; } catch (e) { if (e.code === 'ESRCH') return false; fail('tun_cleanup'); }
  };
  const kill = sig => { try { if (child.pid) process.kill(process.platform === 'win32' ? child.pid : -child.pid,sig); } catch (e) { if (e.code !== 'ESRCH') fail('tun_cleanup'); } };
  const processSnapshot = () => ({ closeObserved: closed, exitCode: code, signal, processGroupJoined: groupJoined,
    stdoutJoined, stderrJoined, stdinJoined, pendingWrites, pendingRequests: pending.size, forced, failure });
  const close = () => {
    if (closeTask) return closeTask; sealed = true;
    closeTask = (async () => {
      let result;
      const failures = failure ? [new ReferenceTunError(failure)] : [];
      const retain = e => failures.push(e instanceof ReferenceTunError ? e : new ReferenceTunError('tun_cleanup'));
      const attempt = async action => { try { await action(); } catch (e) { retain(e); } };
      await attempt(async () => { if (!closed) result = await request('close'); });
      try { await bounded(joined, 5000); } catch {
        forced = true; retain(new ReferenceTunError('tun_process'));
        await attempt(async () => kill('SIGTERM'));
        try { await bounded(joined,2000); } catch {
          await attempt(async () => kill('SIGKILL'));
          await attempt(() => bounded(joined,5000));
        }
      }
      // An exited leader is not proof its owned group has disappeared.
      await attempt(async () => {
        if (groupExists()) { forced = true; retain(new ReferenceTunError('tun_process')); kill('SIGKILL'); }
        const deadline = performance.now() + 5000;
        while (groupExists() && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve,25));
        groupJoined = !groupExists();
      });
      await Promise.all([stdinDone,stdoutDone,stderrDone,...writes].map(p => attempt(() => bounded(p,5000))));
      // Only Node's known SQLite experimental warning is permitted, not TLS warnings.
      const known = /^\(node:\d+\) ExperimentalWarning: SQLite is an experimental feature and might change at any time\n(?:\(Use `node --trace-warnings \.\.\.` to show where the warning was created\)\n)?$/;
      if (stderr && !known.test(stderr)) retain(new ReferenceTunError('tun_output'));
      if (bytes.length || pendingWrites || !groupJoined || code !== 0 || signal || forced || !result?.privateDirectoryRemoved) retain(new ReferenceTunError('tun_cleanup'));
      if (failure && !failures.some(e => e.code === failure)) retain(new ReferenceTunError(failure));
      if (failures.length) throw new ReferenceTunError(failures[0].code,false,failures.slice(1));
      return copy(result);
    })(); return closeTask;
  };
  try { await bounded(ready,25000); } catch (e) {
    let secondary;
    try { await close(); } catch (cleanup) { secondary = new ReferenceTunError(TUN_CODES.includes(cleanup?.code) ? cleanup.code : 'tun_cleanup',false); }
    throw new ReferenceTunError(TUN_CODES.includes(e?.code) ? e.code : 'tun_timeout',
      referenceTunStartupJoined(childCleanupJoined,processSnapshot()), secondary ? [secondary] : []);
  }
  return Object.freeze({
    metadata: () => request('metadata'), createInvitation: () => request('createInvitation'),
    waitForRegistered: (id,{timeoutMillis = 10000} = {}) => request('waitForRegistered',{id,timeoutMillis}),
    approve: id => request('approve',{id}), readResult: id => request('readResult',{id}),
    inspectEnrollment: id => request('inspectEnrollment',{id}), snapshot: () => request('snapshot'), close, processSnapshot,
    toJSON: () => '[Private reference TUN worker]', [inspect.custom]: () => '[Private reference TUN worker]',
  });
}
