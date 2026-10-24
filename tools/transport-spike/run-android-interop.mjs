// Public fixture inputs only. Raw instrumentation output is bounded, parsed, and never uploaded.
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { measureFixtureClock, startPeer } from './android-peer.mjs';
import { releaseOwnedReversePorts, reserveFixtureReversePorts } from './reverse-mappings.mjs';
import { MAX_ADB_DIAGNOSTIC_BYTES, MAX_INSTRUMENTATION_BYTES, adbPublicVersion, commandDiagnostic, parseInstrumentation, readAdbServerLog, researchClass, resultHtml, resultXml, snapshotAdbServerLog } from './instrumentation-results.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const moduleBuild = path.join(root, 'tools/transport-spike/android/build');
const xmlDirectory = path.join(moduleBuild, 'outputs/androidTest-results/connected/debug');
const htmlDirectory = path.join(moduleBuild, 'reports/androidTests/connected/debug');
const testPackage = 'com.httpfreekit.interop.test';
const component = `${testPackage}/androidx.test.runner.AndroidJUnitRunner`;
const options = { adb: process.env.ANDROID_HOME ? path.join(process.env.ANDROID_HOME, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb') : 'adb', openssl: process.env.OPENSSL_BIN ?? 'openssl' };
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index];
  if (!['--serial', '--adb', '--openssl'].includes(name) || !process.argv[index + 1]) throw Error('Expected --serial SERIAL [--adb PATH] [--openssl PATH]');
  options[name.slice(2)] = process.argv[index + 1];
}
if (!options.serial || !/^[A-Za-z0-9_.:-]{1,128}$/.test(options.serial)) throw Error('An explicit adb --serial is required');
const adb = (args, timeout = 10000) => execFileSync(options.adb, ['-s', options.serial, ...args], {
  timeout, maxBuffer: 65536, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
}).trim();
const diagnostics = {};
function recordDiagnostic(prefix, value) {
  for (const [key, item] of Object.entries(value)) diagnostics[prefix + key[0].toUpperCase() + key.slice(1)] = item;
}
function probe(args, timeout = 10000) {
  try { return { ok: true, output: adb(args, timeout), diagnostic: commandDiagnostic({ code: 0 }) }; }
  catch (failure) {
    return { ok: false, output: '', diagnostic: commandDiagnostic({ code: failure.status, signal: failure.signal,
      stderr: failure.stderr, spawnError: typeof failure.code === 'string' ? failure.code : null }) };
  }
}
let child;
let childStopped;
let peerPromise;
let peer;
let installed = false;
let stopping = false;
let cleanupPromise;
const mappings = [];

async function stopChild() {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  if (childStopped) return childStopped;
  childStopped = (async () => {
    if (process.platform === 'win32') {
      try { execFileSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { timeout: 10000, stdio: 'ignore', windowsHide: true }); }
      catch { if (child.exitCode === null && child.signalCode === null) throw Error('owned_child_cleanup_failed'); }
    } else {
      try { process.kill(-child.pid, 'SIGTERM'); } catch (failure) { if (failure.code !== 'ESRCH') throw failure; }
      await new Promise(resolve => {
        const onExit = () => { clearTimeout(timer); resolve(); };
        const timer = setTimeout(() => { child.removeListener('exit', onExit); resolve(); }, 3000);
        child.once('exit', onExit);
      });
      try { process.kill(-child.pid, 'SIGKILL'); } catch (failure) { if (failure.code !== 'ESRCH') throw failure; }
    }
  })();
  return childStopped;
}
function run(command, args, timeout, capture = false) {
  childStopped = undefined;
  return new Promise(resolve => {
    const chunks = [];
    const stderrChunks = [];
    let bytes = 0;
    let stderrBytes = 0;
    let reason;
    child = spawn(command, args, { cwd: root, env: { ...process.env, ANDROID_SERIAL: options.serial },
      stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit', detached: process.platform !== 'win32', windowsHide: true });
    const endAfterStop = () => stopChild().then(
      () => resolve({ code: child.exitCode, signal: child.signalCode, output: Buffer.concat(chunks).toString('utf8'), stderr: Buffer.concat(stderrChunks), reason }),
      () => resolve({ code: child.exitCode, signal: child.signalCode, output: Buffer.concat(chunks).toString('utf8'), stderr: Buffer.concat(stderrChunks), reason: 'owned_child_cleanup_failed' }),
    );
    const deadline = setTimeout(() => { reason = 'owned_child_timeout'; endAfterStop(); }, timeout);
    if (capture) for (const [stream, retain] of [[child.stdout, true], [child.stderr, false]]) stream.on('data', data => {
      bytes += data.length;
      if (!retain && stderrBytes < MAX_ADB_DIAGNOSTIC_BYTES + 1) {
        const kept = data.subarray(0, MAX_ADB_DIAGNOSTIC_BYTES + 1 - stderrBytes);
        stderrChunks.push(kept); stderrBytes += kept.length;
      }
      if (bytes > MAX_INSTRUMENTATION_BYTES) { reason = 'instrumentation_output_limit'; endAfterStop(); }
      else if (retain) chunks.push(data);
    });
    child.once('error', failure => { clearTimeout(deadline); resolve({ code: null, signal: null, output: '', stderr: '', spawnError: failure.code, reason: 'owned_child_start_failed' }); });
    child.once('close', (code, signal) => { clearTimeout(deadline); resolve({ code, signal, output: Buffer.concat(chunks).toString('utf8'), stderr: Buffer.concat(stderrChunks), reason }); });
  });
}
function cleanup() {
  if (cleanupPromise) return cleanupPromise;
  cleanupPromise = (async () => {
    const failures = [];
    try { await stopChild(); } catch { failures.push('owned_child_cleanup_failed'); }
    if (installed) {
      try { adb(['shell', 'am', 'force-stop', testPackage]); adb(['uninstall', testPackage], 60000); }
      catch { failures.push('research_test_package_cleanup_failed'); }
    }
    failures.push(...releaseOwnedReversePorts(adb, mappings));
    try { await (peer ?? await peerPromise?.catch(() => null))?.close(); } catch { failures.push('ephemeral_peer_cleanup_failed'); }
    if (failures.length) throw Error(failures.join(', '));
  })();
  return cleanupPromise;
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  stopping = true; process.exitCode = 1;
  cleanup().catch(() => { console.error('Research cancellation cleanup failed.'); });
});
function ensureRunning() { if (stopping) throw Error('research_run_cancelled'); }
function writeReports(result) {
  result.diagnostics = diagnostics;
  for (const directory of [xmlDirectory, htmlDirectory]) fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(xmlDirectory, 'TEST-android-node-research.xml'), resultXml(result));
  fs.writeFileSync(path.join(htmlDirectory, 'index.html'), resultHtml(result));
}
// Remove only these two fixed generated report directories; never delete a computed external path.
for (const directory of [xmlDirectory, htmlDirectory]) {
  if (!path.resolve(directory).startsWith(path.resolve(moduleBuild) + path.sep)) throw Error('Invalid generated report location');
  fs.rmSync(directory, { recursive: true, force: true });
}
let result;
try {
  const version = probe(['version']);
  recordDiagnostic('versionQuery', version.diagnostic);
  Object.assign(diagnostics, adbPublicVersion(version.output));
  const daemonStatus = probe(['server-status']);
  recordDiagnostic('daemonStatusQuery', daemonStatus.diagnostic);
  diagnostics.adbDaemonVersion = adbPublicVersion(daemonStatus.output).adbDaemonVersion;
  const initialState = probe(['get-state']);
  recordDiagnostic('initialDeviceQuery', initialState.diagnostic);
  if (!initialState.ok || initialState.output !== 'device') throw Error('selected_device_unavailable');
  const buildArgs = ['--no-daemon', '--console=plain', ':transport-interop:assembleDebugAndroidTest'];
  const build = await run(process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : './gradlew',
    process.platform === 'win32' ? ['/d', '/s', '/c', `gradlew.bat ${buildArgs.join(' ')}`] : buildArgs, 15 * 60 * 1000);
  if (build.code !== 0 || build.reason) throw Error(build.reason ?? 'research_apk_build_failed');
  ensureRunning();
  const apkDirectory = path.join(moduleBuild, 'outputs/apk/androidTest/debug');
  const metadata = JSON.parse(fs.readFileSync(path.join(apkDirectory, 'output-metadata.json'), 'utf8'));
  if (metadata.applicationId !== testPackage || metadata.elements?.length !== 1 ||
      !/^[A-Za-z0-9_.-]+\.apk$/.test(metadata.elements[0].outputFile)) throw Error('unexpected_research_apk_metadata');
  if (adb(['install', '-r', '-t', path.join(apkDirectory, metadata.elements[0].outputFile)], 60000).split(/\r?\n/).at(-1) !== 'Success') throw Error('research_apk_install_failed');
  installed = true;
  if (!adb(['shell', 'pm', 'list', 'instrumentation']).split('\n').some(line => line.startsWith(`instrumentation:${component} `))) throw Error('research_runner_not_registered');
  console.log('Research APK installed before fixture startup and reverse allocation.');
  ensureRunning();
  const hostBeforeClockProbe = Date.now();
  const deviceClock = probe(['shell', 'date', '+%s'], 5000);
  const hostAfterClockProbe = Date.now();
  recordDiagnostic('deviceClockQuery', deviceClock.diagnostic);
  if (!deviceClock.ok) throw Error('device_clock_probe_failed');
  Object.assign(diagnostics, measureFixtureClock(deviceClock.output, hostBeforeClockProbe, hostAfterClockProbe));
  if (diagnostics.fixtureClockStatus !== 'within_bound') throw Error('research_clock_' + diagnostics.fixtureClockStatus);
  peerPromise = startPeer({ openssl: options.openssl });
  peer = await peerPromise;
  recordDiagnostic('certificateValidity', peer.validity);
  ensureRunning();
  const publicInputs = { ...peer.metadata };
  Object.assign(publicInputs, reserveFixtureReversePorts(adb, peer.metadata, mappings));
  const args = ['-s', options.serial, 'shell', 'am', 'instrument', '-w', '-r', '-e', 'class', researchClass];
  for (const [name, value] of Object.entries(publicInputs)) {
    if (!/^[A-Za-z0-9_-]+$/.test(String(value))) throw Error('invalid_public_fixture_input');
    args.push('-e', name, String(value));
  }
  args.push(component);
  console.log('Running explicit research instrumentation; waiting for four exact start/end pairs.');
  const serverLogBaseline = snapshotAdbServerLog(process.env.ANDROID_ADB_LOG_PATH);
  const instrument = await run(options.adb, args, 180000, true);
  // Read the private log before a recovery probe can start another daemon or append new messages.
  recordDiagnostic('serverLog', readAdbServerLog(serverLogBaseline));
  recordDiagnostic('instrumentation', commandDiagnostic(instrument));
  result = parseInstrumentation(instrument.output, { exitCode: instrument.code, signal: instrument.signal, transportError: instrument.reason });
  const selectedState = probe(['get-state']);
  recordDiagnostic('selectedDeviceQuery', selectedState.diagnostic);
  diagnostics.selectedDeviceState = selectedState.ok ? ['device', 'offline', 'unauthorized', 'unknown'].includes(selectedState.output) ? selectedState.output : 'unexpected_state' : 'query_failed';
  if (!selectedState.ok || selectedState.output !== 'device') { result.problems.push('selected_device_unavailable_after_instrumentation'); result.ok = false; }
  const reverseState = probe(['reverse', '--list']);
  recordDiagnostic('reverseQuery', reverseState.diagnostic);
  if (reverseState.ok) {
    const remaining = reverseState.output.split(/\r?\n/).map(line => line.trim().split(/\s+/).slice(-2));
    if (mappings.some(mapping => !remaining.some(([device, host]) => device === `tcp:${mapping.devicePort}` && host === `tcp:${mapping.hostPort}`))) {
      result.problems.push('owned_reverse_mapping_lost_during_instrumentation'); result.ok = false;
    }
  } else { result.problems.push('reverse_mapping_state_unavailable'); result.ok = false; }
  console.log(`ADB channel diagnostics: ${JSON.stringify(diagnostics)}`);
  writeReports(result);
  console.log(`Research instrumentation: ${result.started} started, ${result.completed} completed; ${result.ok ? 'passed' : 'failed'}.`);
  for (const value of result.cases) if (value.state !== 'passed') console.error(`${value.name}: ${value.state}\n${value.detail}`);
  if (!result.ok) throw Error(result.problems.join(', ') || 'research_assertion_failed');
} catch (failure) {
  const category = failure.status !== undefined || failure.code ? 'host_setup_command_failed' : /^[a-z0-9_, ]{1,256}$/.test(failure.message) ? failure.message : 'host_setup_failed';
  if (!result) { result = parseInstrumentation('', { exitCode: 1, transportError: category }); writeReports(result); }
  console.error(`Android-to-Node research failed: ${result.problems.join(', ') || 'research_assertion_failed'}`);
  process.exitCode = 1;
} finally {
  try { await cleanup(); } catch (failure) {
    console.error(failure.message); process.exitCode = 1;
    if (result) { result.problems.push(failure.message); result.ok = false; writeReports(result); }
  }
}
