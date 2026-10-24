// Bounded investigation of source 277939d: no Android/Conscrypt/ADB performance claim.
// Credentials enter the Java process through stdin only. Reports whitelist fixed counters.
import { spawn, spawnSync } from 'node:child_process';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { startCompanionStreamPeer } from './companion-stream-peer.mjs';
import { control, enrollHost, until } from './companion-stream-peer-client.mjs';
import { logicalName } from './android-peer.mjs';
import { bounded, safeError } from './companion-stream-peer-io.mjs';

export const pressureProfiles = Object.freeze([
  Object.freeze({ requestedBufferBytes: 1024, packetization: 'split', localPair: false }),
  Object.freeze({ requestedBufferBytes: 1024, packetization: 'combined', localPair: false }),
  Object.freeze({ requestedBufferBytes: 65536, packetization: 'split', localPair: false }),
  Object.freeze({ requestedBufferBytes: 1024, packetization: 'split', localPair: true }),
]);
export const pressureReportPath = 'build/reports/draft-stream-pressure/pressure.json';
const source = fileURLToPath(new URL('./companion-stream-peer-pressure-client.java', import.meta.url));
const pause = () => new Promise(done => setTimeout(done, 150));
const fail = () => { throw safeError('pressure_probe_failed'); };
const number = value => { const n = Number(value); if (!Number.isSafeInteger(n) || n < 0 || n > 32 * 1024 * 1024 + 8192) fail(); return n; };
function config(peer, credential, session, requestedBufferBytes, combined, localPair) {
  const integers = (...values) => { const bytes = Buffer.alloc(values.length * 4); values.forEach((v, i) => bytes.writeUInt32BE(v, i * 4)); return bytes; };
  const blob = value => Buffer.concat([integers(value.length), value]);
  return Buffer.concat([integers(1, peer.metadata.webSocketPort, requestedBufferBytes, combined ? 1 : 0, localPair ? 1 : 0),
    ...[Buffer.from(logicalName), Buffer.from(peer.metadata.gatewayDer, 'base64url'), new X509Certificate(credential.cert).raw,
      createPrivateKey(credential.key).export({ format: 'der', type: 'pkcs8' }), Buffer.from(session.token)].map(blob)]);
}
function ownedJava(java, directory) {
  const child = spawn(java, ['-cp', directory, 'CompanionStreamPressure'], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let ended = false, code, signal, stdout = '', outputBytes = 0, errorBytes = 0, waiter;
  const lines = [];
  const close = new Promise(done => child.once('close', (exit, termination) => { ended = true; code = exit; signal = termination; waiter?.(); done(); }));
  child.on('error', () => { waiter?.(); }); child.stdin.on('error', () => {});
  child.stdout.on('data', value => {
    outputBytes += value.length;
    if (outputBytes > 32768) { child.kill(); return; }
    stdout += value.toString('ascii');
    while (stdout.includes('\n')) {
      const position = stdout.indexOf('\n'), line = stdout.slice(0, position).replace(/\r$/, ''); stdout = stdout.slice(position + 1);
      if (line.length > 256 || lines.length >= 2) { child.kill(); return; }
      lines.push(line); waiter?.();
    }
  });
  child.stderr.on('data', value => { errorBytes += value.length; if (errorBytes > 8192) child.kill(); });
  const next = async () => bounded((async () => {
    while (lines.length === 0) {
      if (ended) fail();
      await new Promise(done => { waiter = done; }); waiter = undefined;
    }
    const line = lines.shift();
    if (/^ERROR (config|credential|connect|handshake|upgrade|ready|local|stream|stop)$/.test(line)) throw safeError(`pressure_java_${line.slice(6)}_failed`);
    return line;
  })(), 7000, 'pressure_probe_failed');
  function state(line, kind) {
    const match = new RegExp(`^${kind} ([0-9]+) ([0-9]+) ([0-9]+) (true|false) (true|false) ([0-9]+) (true|false) (true|false)$`).exec(line);
    if (!match) fail();
    const [writeEntries, writeCompletions, completedBytes] = match.slice(1, 4).map(number);
    if (writeCompletions > writeEntries || writeEntries - writeCompletions > 1) fail();
    return { writeEntries, writeCompletions, completedBytes, writerActive: match[4] === 'true', writerFailed: match[5] === 'true',
      producerBytesWritten: number(match[6]), producerActive: match[7] === 'true', producerFailed: match[8] === 'true' };
  }
  return {
    start: async bytes => {
      child.stdin.write(bytes);
      const match = /^READY ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)$/.exec(await next()); if (!match) fail();
      return { actualSendBufferBytes: number(match[1]), actualReceiveBufferBytes: number(match[2]),
        applicationSendBufferBytes: number(match[3]), applicationReceiveBufferBytes: number(match[4]),
        bridgeSendBufferBytes: number(match[5]), bridgeReceiveBufferBytes: number(match[6]) };
    },
    snapshot: async () => { child.stdin.write(Buffer.from([1])); return state(await next(), 'STATE'); },
    stop: async () => {
      if (ended) fail();
      child.stdin.write(Buffer.from([2])); child.stdin.end();
      const result = state(await next(), 'STOPPED');
      await bounded(close, 7000, 'pressure_probe_failed');
      if (code !== 0 || signal !== null || result.writerActive || result.producerActive || errorBytes !== 0 || stdout.trim() || lines.length) fail();
      return { ...result, writerJoined: true, producerJoined: true, processJoined: true };
    },
    abort: async () => {
      if (!ended) { child.kill(); await bounded(close, 7000, 'pressure_probe_failed'); }
    },
  };
}
function peerState(value) {
  const io = value.io;
  return { proxyWriteEntries: io.proxyWriteEntries, proxyWriteCompletions: io.proxyWriteCompletions,
    proxyWritePending: io.proxyWritePending, pendingIngressBytes: io.pendingIngressBytes,
    backpressureCount: io.backpressureCount, chargedBytes: value.control.chargedBytes,
    proxyReadPaused: value.fixture.proxyReadPaused, uploadBytesRead: value.fixture.uploadBytesRead };
}
export async function runPressureProbe({ java, javac, requestedBufferBytes = 1024, packetization = 'split', localPair = false } = {}) {
  if (!java || !javac || ![1024, 65536].includes(requestedBufferBytes) || !['split', 'combined'].includes(packetization) || typeof localPair !== 'boolean') fail();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-pressure-'));
  if (path.dirname(directory) !== path.resolve(os.tmpdir()) || !path.basename(directory).startsWith('freekit-pressure-')) fail();
  let peer, session, process, stopped;
  try {
    const compiled = spawnSync(javac, ['-encoding', 'UTF-8', '-d', directory, source], { timeout: 15000, maxBuffer: 8192, windowsHide: true });
    if (compiled.status !== 0 || compiled.signal || compiled.error) fail();
    peer = await startCompanionStreamPeer();
    const credential = await enrollHost(peer, 'pressure');
    session = await control(peer, credential, 'backpressure');
    process = ownedJava(java, directory);
    const actualBuffers = await process.start(config(peer, credential, session, requestedBufferBytes, packetization === 'combined', localPair));
    const origin = performance.now(), end = origin + 15000;
    let candidate = 0, candidateSince = 0, javaCandidate = 0, javaSince = 0;
    let observed = false, javaWriterObserved = false, samples = 0, latestJava, latestPeer;
    let maxCompletedBytes = 0, maxProxyWriteEntries = 0;
    while (performance.now() < end) {
      latestJava = await process.snapshot(); latestPeer = peerState(await session.probe()); samples++;
      if (latestJava.writerFailed || latestJava.producerFailed || samples > 128) fail();
      maxCompletedBytes = Math.max(maxCompletedBytes, latestJava.completedBytes);
      maxProxyWriteEntries = Math.max(maxProxyWriteEntries, latestPeer.proxyWriteEntries);
      const pending = latestPeer.proxyReadPaused && latestPeer.proxyWritePending &&
        latestPeer.proxyWriteEntries > latestPeer.proxyWriteCompletions && latestPeer.pendingIngressBytes > 0 &&
        latestPeer.pendingIngressBytes <= 4096 && latestPeer.backpressureCount > 0 && latestPeer.chargedBytes > 0 && latestPeer.chargedBytes <= 16384;
      if (!pending || candidate !== latestPeer.proxyWriteEntries) { candidate = latestPeer.proxyWriteEntries; candidateSince = performance.now(); }
      const javaPending = latestJava.writerActive && latestJava.writeEntries > latestJava.writeCompletions;
      if (!javaPending || javaCandidate !== latestJava.writeEntries) { javaCandidate = latestJava.writeEntries; javaSince = performance.now(); }
      observed = pending && performance.now() <= end && performance.now() - candidateSince >= 250;
      javaWriterObserved = javaPending && performance.now() <= end && performance.now() - javaSince >= 250;
      if (observed && javaWriterObserved) break;
      await pause();
    }
    const elapsedMillis = Math.round(performance.now() - origin);
    stopped = await process.stop();
    await session.cancel();
    const cleanup = await until(session.probe, value => value.cleanup.complete);
    const result = { requestedBufferBytes, packetization, localPair, ...actualBuffers, observedWithinBudget: observed, javaWriterObserved,
      observationBudgetMillis: 15000, elapsedMillis, samples, maxCompletedBytes, maxProxyWriteEntries,
      java: latestJava, shutdown: stopped, peer: latestPeer,
      cleanup: { complete: cleanup.cleanup.complete, workers: cleanup.cleanup.workers, timers: cleanup.cleanup.timers,
        pendingCallbacks: cleanup.cleanup.pendingCallbacks, sessionLeases: cleanup.pool.sessionLeases,
        streamLeases: cleanup.pool.streamLeases, chargedBytes: cleanup.pool.chargedBytes } };
    await peer.close(); peer = null;
    return result;
  } finally {
    const failures = [];
    if (process && !stopped) { try { await process.abort(); } catch { failures.push(true); } }
    if (peer) { try { await peer.close(); } catch { failures.push(true); } }
    if (session) { try { await bounded(session.pump, 7000, 'pressure_probe_failed'); } catch { failures.push(true); } }
    try { fs.rmSync(directory, { recursive: true, force: true }); } catch { failures.push(true); }
    if (failures.length) fail();
  }
}

export async function pressureMain(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node tools/transport-spike/companion-stream-peer-pressure.mjs');
    console.log('Writes bounded diagnostic JSON to build/reports/draft-stream-pressure/pressure.json.');
    return;
  }
  if (args.length !== 0) throw safeError('invalid_pressure_probe_arguments');
  // Remove an older report before setup, so a failed run cannot leave stale success.
  fs.rmSync(pressureReportPath, { force: true });
  const javaHome = process.env.PRESSURE_JAVA_HOME || process.env.JAVA_HOME;
  const executable = name => javaHome ? path.join(javaHome, 'bin', `${name}${process.platform === 'win32' ? '.exe' : ''}`) : name;
  const version = spawnSync(executable('java'), ['-version'], { timeout: 5000, maxBuffer: 4096, windowsHide: true });
  const javaVersion = /^(?:openjdk|java) version "([0-9][0-9A-Za-z._+-]{0,63})"/m.exec(version.stderr?.toString('utf8') ?? '')?.[1];
  if (version.status !== 0 || !javaVersion) fail();
  const revision = spawnSync('git', ['rev-parse', 'HEAD'], { timeout: 5000, maxBuffer: 256, windowsHide: true });
  const sourceCommit = revision.stdout?.toString('ascii').trim();
  const dirty = spawnSync('git', ['status', '--porcelain', '--untracked-files=normal'], { timeout: 5000, maxBuffer: 8192, windowsHide: true });
  if (revision.status !== 0 || !/^[a-f0-9]{40}$/.test(sourceCommit ?? '') || dirty.status !== 0) fail();
  const results = [];
  for (const profile of pressureProfiles) results.push(await runPressureProbe({ ...profile, java: executable('java'), javac: executable('javac') }));
  const report = { format: 'http-freekit-a20-pressure', revision: 1, baseSourceCommit: '277939d72d2d5ad33bc0f5be1e636d5fbe17ca3c',
    sourceCommit, sourceDirty: dirty.stdout.length !== 0, nodeVersion: process.version, javaVersion, platform: process.platform,
    limitations: ['software_key', 'host_jsse', 'no_conscrypt', 'no_adb', 'no_android_client_model', 'no_android_kernel'], results };
  const rendered = JSON.stringify(report, null, 2) + '\n';
  if (Buffer.byteLength(rendered) > 32768) fail();
  fs.mkdirSync(path.dirname(pressureReportPath), { recursive: true });
  fs.writeFileSync(pressureReportPath, rendered, { mode: 0o600 });
  console.log(`PRESSURE COMPLETE profiles=${results.length} observed=${results.filter(value => value.observedWithinBudget).length}`);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  pressureMain().catch(() => { console.error('pressure_probe_failed'); process.exitCode = 1; });
}
