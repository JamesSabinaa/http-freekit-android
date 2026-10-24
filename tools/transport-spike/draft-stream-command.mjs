import { spawn, execFileSync } from 'node:child_process';

/** One owned command; captured bytes are explicit, bounded, non-enumerable access only. */
export async function runDraftCommand(command, args, { cwd, env = process.env, timeoutMillis = 10000,
  maxOutputBytes = 256 * 1024, abortSignal, stdinBytes, onStdoutChunk } = {}) {
  if (typeof command !== 'string' || !command || !Array.isArray(args) || args.some(value => typeof value !== 'string') ||
      !Number.isInteger(timeoutMillis) || timeoutMillis < 1 || timeoutMillis > 900000 ||
      !Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > 256 * 1024 ||
      (stdinBytes !== undefined && (!(stdinBytes instanceof Uint8Array) || stdinBytes.byteLength > 16384)) ||
      (onStdoutChunk !== undefined && typeof onStdoutChunk !== 'function')) throw Error('invalid_command_configuration');
  if (abortSignal?.aborted) throw Error('research_run_cancelled');
  // Copy bounded private input before any await; it never enters argv/env/default diagnostics.
  const input = stdinBytes === undefined ? null : Buffer.from(stdinBytes);
  const child = spawn(command, args, { cwd, env, windowsHide: true, detached: process.platform !== 'win32',
    stdio: [input === null ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
  let reason = null, spawnError = null, closedObserved = false, processGroupClosed = process.platform === 'win32', stopPromise, timer;
  let inputFinished = input === null, inputClosed = input === null, inputError = false, resolveInputClosed;
  const inputClose = input === null ? Promise.resolve(true) : new Promise(resolve => { resolveInputClosed = resolve; });
  let outputBytes = 0, retained = 0, stderrBytes = 0;
  const stdout = [], stderr = [];
  let resolveClosed, resolveStopFailure;
  const closed = new Promise(resolve => { resolveClosed = resolve; });
  const stopFailure = new Promise(resolve => { resolveStopFailure = resolve; });
  child.once('error', failure => { spawnError = ['ENOENT', 'EACCES', 'ENOEXEC'].includes(failure.code) ? failure.code : 'SPAWN_ERROR'; });
  child.once('close', () => { closedObserved = true; clearTimeout(timer); resolveClosed(true); });
  const waitClosed = async milliseconds => {
    let deadline;
    try { return await Promise.race([closed, new Promise(resolve => { deadline = setTimeout(() => resolve(false), milliseconds); })]); }
    finally { clearTimeout(deadline); }
  };
  const groupExists = () => {
    try { process.kill(-child.pid, 0); return true; }
    catch (failure) { if (failure.code === 'ESRCH') return false; throw Error('owned_child_cleanup_failed'); }
  };
  const closeProcessGroup = async force => {
    if (process.platform === 'win32') return;
    if (!child.pid) { processGroupClosed = true; return; }
    if (groupExists()) {
      // A leader can close while a same-group descendant ignores TERM and owns no pipes.
      try { process.kill(-child.pid, force ? 'SIGKILL' : 'SIGTERM'); }
      catch (failure) { if (failure.code !== 'ESRCH') throw Error('owned_child_cleanup_failed'); }
      let deadline = performance.now() + (force ? 5000 : 2000);
      while (groupExists() && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 25));
      if (groupExists() && !force) return closeProcessGroup(true);
      if (groupExists()) throw Error('owned_child_cleanup_failed');
    }
    processGroupClosed = true;
  };
  const stop = why => {
    if (closedObserved) return closed;
    reason ??= why;
    if (stopPromise) return stopPromise;
    stopPromise = (async () => {
      if (child.pid) {
        if (process.platform === 'win32') {
          try { execFileSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { timeout: 10000, stdio: 'ignore', windowsHide: true }); }
          catch {
            // A fast child may have exited while synchronous taskkill blocked delivery of its
            // close event. Yield and observe actual closure before declaring cleanup failure.
            if (!(await waitClosed(5000))) throw Error('owned_child_cleanup_failed');
          }
        } else {
          try { process.kill(-child.pid, 'SIGTERM'); } catch (failure) { if (failure.code !== 'ESRCH') throw Error('owned_child_cleanup_failed'); }
          await waitClosed(2000);
          await closeProcessGroup(true);
        }
      }
      if (!(await waitClosed(5000))) throw Error('owned_child_cleanup_failed');
    })().catch(() => { reason = 'owned_child_cleanup_failed'; resolveStopFailure(false); });
    return stopPromise;
  };
  const capture = (data, isStdout) => {
    outputBytes += data.length;
    if (isStdout && retained < maxOutputBytes) {
      const keep = data.subarray(0, maxOutputBytes - retained); stdout.push(keep); retained += keep.length;
    }
    if (!isStdout && stderrBytes < 16 * 1024 + 1) {
      const keep = data.subarray(0, 16 * 1024 + 1 - stderrBytes); stderr.push(keep); stderrBytes += keep.length;
    }
    if (outputBytes > maxOutputBytes) void stop('instrumentation_output_limit');
    if (isStdout && reason === null && onStdoutChunk) {
      try {
        // Observers must synchronously parse bounded chunks; asynchronous owners belong to the driver.
        const returned = onStdoutChunk(Buffer.from(data));
        if (returned !== undefined) {
          if (returned && typeof returned.then === 'function') Promise.resolve(returned).catch(() => {});
          throw Error();
        }
      } catch { void stop('owned_child_observer_failed'); }
    }
  };
  child.stdout.on('data', data => capture(data, true));
  child.stderr.on('data', data => capture(data, false));
  if (input !== null) {
    child.stdin.once('finish', () => { inputFinished = true; });
    child.stdin.once('close', () => { inputClosed = true; resolveInputClosed(true); });
    child.stdin.on('error', () => { inputError = true; void stop('owned_child_input_failed'); });
    child.stdin.end(input);
  }
  const abort = () => { void stop('research_run_cancelled'); };
  abortSignal?.addEventListener('abort', abort, { once: true });
  timer = setTimeout(() => { void stop('owned_child_timeout'); }, timeoutMillis);
  try {
    await Promise.race([closed, stopFailure]);
    if (stopPromise) await stopPromise;
    if (closedObserved && !stopPromise) {
      try { await closeProcessGroup(false); }
      catch { reason = 'owned_child_cleanup_failed'; }
    }
  } finally {
    clearTimeout(timer); abortSignal?.removeEventListener('abort', abort);
    if (input !== null) {
      let inputTimer;
      child.stdin.destroy();
      try {
        await Promise.race([inputClose,
          new Promise(resolve => { inputTimer = setTimeout(() => resolve(false), 1000); })]);
      } finally { clearTimeout(inputTimer); input.fill(0); }
      if (!inputClosed) reason = 'owned_child_cleanup_failed';
      else if (inputError || !inputFinished) reason ??= 'owned_child_input_failed';
    }
  }
  if (spawnError !== null) reason ??= 'owned_child_spawn_failed';
  return Object.freeze(Object.defineProperties({ code: child.exitCode, signal: child.signalCode, reason, spawnError,
    closeObserved: closedObserved, processGroupClosed, outputBytes, stderrBytes,
    ...(input === null ? {} : { inputBytes: input.length, inputFinished, inputClosed }) }, {
    output: { value: Buffer.concat(stdout).toString('utf8') }, stderr: { value: Buffer.concat(stderr) },
  }));
}
