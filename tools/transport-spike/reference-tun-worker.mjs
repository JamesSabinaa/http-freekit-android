// PRIVATE JSONL child; never a mobile management interface.
import { pathToFileURL } from 'node:url';
import { startReferenceTunFixture, ReferenceTunError, TUN_CODES } from './reference-tun-fixture.mjs';
import { bounded, write, writerState } from './companion-stream-peer-io.mjs';
export const FORMAT = 'http-freekit-reference-tun-worker';
export function validateRequest(line, expected) {
  let v;
  try { v = JSON.parse(line); } catch { throw new ReferenceTunError('tun_input'); }
  const bad = () => { throw new ReferenceTunError('tun_input'); };
  if (!v || JSON.stringify(v) !== line || Object.keys(v).join(',') !== 'format,revision,id,op,args' ||
      v.format !== FORMAT || v.revision !== 1 || v.id !== expected || expected > 128 || !v.args ||
      Array.isArray(v.args) || typeof v.args !== 'object') bad();
  const keys = Object.keys(v.args).join(',');
  if (['metadata','createInvitation','snapshot','close'].includes(v.op)) { if (keys) bad(); }
  else if (['approve','readResult','inspectEnrollment','waitForRegistered'].includes(v.op)) {
    if (keys !== (v.op === 'waitForRegistered' ? 'id,timeoutMillis' : 'id') ||
        typeof v.args.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(v.args.id)) bad();
    if (v.op === 'waitForRegistered' && (!Number.isInteger(v.args.timeoutMillis) || v.args.timeoutMillis < 1 || v.args.timeoutMillis > 10000)) bad();
  } else bad();
  if (expected === 128 && v.op !== 'close') bad();
  return v;
}
const material = v => v?.material instanceof Function ? v.material() : v;
async function main() {
  let owner, startup, terminal = false, finishing, count = 0, total = 0, bytes = Buffer.alloc(0), output = Promise.resolve();
  const jobs = new Set(), writers = new Set(); let complete; const completion = new Promise(resolve => { complete = resolve; });
  const emit = value => {
    const task = output.then(async () => {
      const data = Buffer.from(JSON.stringify({ format: FORMAT, revision: 1, ...value }) + '\n');
      if (data.length > 16384) throw new ReferenceTunError('tun_output');
      const state = writerState(); writers.add(state);
      try {
        for (let at = 0; at < data.length; at += 8192) await bounded(write(process.stdout,data.subarray(at,at + 8192),state),5000);
      }
      catch { process.stdout.destroy(); throw new ReferenceTunError('tun_output'); }
      finally {
        try { await bounded(state.idle,5000); if (state.pending) throw new ReferenceTunError('tun_output'); }
        finally { if (!state.pending) writers.delete(state); }
      }
    }); output = task.catch(() => {}); return task;
  };
  const stop = (code, id) => {
    if (finishing) return finishing;
    terminal = true; process.stdin.pause(); clearTimeout(watchdog);
    let closure = owner?.close(); closure?.catch(() => {});
    finishing = (async () => {
      let joined = true, result;
      try { owner ??= await startup; } catch (e) { joined = e?.joined === true; code ??= 'tun_unavailable'; }
      if (owner && !closure) { closure = owner.close(); closure.catch(() => {}); }
      if (closure) try { result = await closure; } catch { joined = false; code ??= 'tun_cleanup'; }
      await Promise.allSettled([...jobs]); await output;
      if (writers.size) { joined = false; code ??= 'tun_output'; }
      try { await emit(id ? (code ? { id, ok: false, code, joined } : { id, ok: true, result }) : { event: 'failed', code: code ?? 'tun_input', joined }); }
      catch { code = 'tun_output'; }
      process.stdin.destroy(); if (code) process.exitCode = 1; complete();
    })(); return finishing;
  };
  const watchdog = setTimeout(() => { void stop('tun_watchdog'); }, 360000);
  const onData = chunk => {
    if (terminal) return; total += chunk.length;
    if (total > 262144) { void stop('tun_input'); return; }
    let at = 0;
    while (at < chunk.length && !terminal) {
      const end = chunk.indexOf(10, at), part = chunk.subarray(at, end < 0 ? chunk.length : end);
      if (part.some(b => b < 32 || b > 126) || bytes.length + part.length > 8192) { void stop('tun_input'); return; }
      bytes = Buffer.concat([bytes, part]); if (end < 0) return; at = end + 1;
      let command;
      try { command = validateRequest(bytes.toString('ascii'), ++count); } catch { void stop('tun_input'); return; }
      bytes = Buffer.alloc(0);
      if (command.op === 'close') { void stop(undefined, command.id); return; }
      if (jobs.size >= 2) { void stop('tun_input'); return; }
      const task = (async () => {
        await startup;
        if (terminal) { await emit({ id: command.id, ok: false, code: 'tun_closing', joined: true }); return; }
        try {
          const a = command.args;
          const value = command.op === 'waitForRegistered' ? await owner.waitForRegistered(a.id, { timeoutMillis: a.timeoutMillis }) :
            await owner[command.op](...('id' in a ? [a.id] : []));
          await emit({ id: command.id, ok: true, result: material(value) });
        } catch (e) {
          await emit({ id: command.id, ok: false, code: TUN_CODES.includes(e?.code) ? e.code : 'tun_enrollment', joined: e?.joined === true });
        }
      })(); jobs.add(task); task.then(() => jobs.delete(task), () => { jobs.delete(task); void stop('tun_output'); });
    }
  };
  const inputError = () => { void stop('tun_input'); }, outputError = () => { void stop('tun_output'); }, signal = () => { void stop('tun_process'); };
  process.stdin.on('data', onData); process.stdin.once('end', inputError); process.stdin.once('error', inputError);
  process.stdout.on('error', outputError); process.once('SIGINT', signal); process.once('SIGTERM', signal);
  try {
    if (process.argv.length !== 2) throw new ReferenceTunError('tun_configuration');
    startup = startReferenceTunFixture(); owner = await startup; if (!terminal) await emit({ event: 'ready' });
  } catch (e) { await stop(TUN_CODES.includes(e?.code) ? e.code : 'tun_unavailable'); }
  await completion;
  process.stdin.removeListener('data', onData); process.stdin.removeListener('end', inputError); process.stdin.removeListener('error', inputError);
  process.stdout.removeListener('error', outputError); process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
