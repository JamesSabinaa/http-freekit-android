// Separate seven-case research driver. Reports are written only after real selective cleanup.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDraftCommand } from './draft-stream-command.mjs';
import { reserveFixtureReversePorts } from './reverse-mappings.mjs';
import { adbPublicVersion, commandDiagnostic, readAdbServerLog, snapshotAdbServerLog } from './instrumentation-results.mjs';
import { draftSetupCode, draftStreamingClass, draftStreamingHtml, draftStreamingXml,
  measureDraftStreamingClock, parseDraftStreamingInstrumentation } from './draft-stream-results.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const moduleBuild = path.join(root, 'tools/transport-spike/android/build');
const xmlFile = path.join(moduleBuild, 'outputs/androidTest-results/draft-streaming/debug/TEST-draft-stream-research.xml');
const htmlFile = path.join(moduleBuild, 'reports/androidTests/draft-streaming/debug/index.html');
const testPackage = 'com.httpfreekit.interop.test';
const component = `${testPackage}/androidx.test.runner.AndroidJUnitRunner`;

export function draftStreamingOptions(args, env = process.env) {
  const options = { adb: env.ANDROID_HOME ? path.join(env.ANDROID_HOME, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb') : 'adb',
    openssl: env.OPENSSL_BIN ?? 'openssl' };
  const seen = new Set();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index], value = args[index + 1];
    if (!['--serial', '--adb', '--openssl'].includes(name) || seen.has(name) || typeof value !== 'string' ||
        !value || value.length > 4096 || /[\u0000\r\n]/.test(value)) throw Error('invalid_research_arguments');
    seen.add(name); options[name.slice(2)] = value;
  }
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(options.serial ?? '')) throw Error('explicit_research_serial_required');
  for (const value of [options.adb, options.openssl]) {
    if (typeof value !== 'string' || !value || value.length > 4096 || /[\u0000\r\n]/.test(value)) throw Error('invalid_research_arguments');
  }
  return Object.freeze(options);
}

export function containsOwnedMappings(output, mappings) {
  const rows = String(output).split(/\r?\n/).map(line => line.trim().split(/\s+/).slice(-2));
  return mappings.length === 2 && mappings.every(mapping => rows.some(([device, host]) =>
    device === `tcp:${mapping.devicePort}` && host === `tcp:${mapping.hostPort}`));
}

export async function runDraftStreaming(options) {
  const diagnostics = { cleanupStatus: 'incomplete', cleanupPeerClosed: false, cleanupOwnedChildClosed: true,
    cleanupReverseMappingsVerified: false, ownedReverseMappingsPresent: false };
  const record = (prefix, values) => {
    for (const [name, value] of Object.entries(values)) diagnostics[prefix + name[0].toUpperCase() + name.slice(1)] = value;
  };
  const controller = new AbortController();
  const stop = () => controller.abort();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, stop);
  const ensureRunning = () => { if (controller.signal.aborted) throw Error('research_run_cancelled'); };
  const command = async (executable, args, timeoutMillis = 10000, cleanup = false) => {
    const result = await runDraftCommand(executable, args, { cwd: root, timeoutMillis,
      env: { ...process.env, ANDROID_SERIAL: options.serial }, abortSignal: cleanup ? undefined : controller.signal });
    diagnostics.cleanupOwnedChildClosed &&= result.closeObserved && result.processGroupClosed;
    return result;
  };
  const adb = (args, timeout = 10000) => execFileSync(options.adb, ['-s', options.serial, ...args], {
    timeout, maxBuffer: 65536, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  }).trim();
  const probe = (args, timeout) => {
    try { return { ok: true, output: adb(args, timeout), diagnostic: commandDiagnostic({ code: 0 }) }; }
    catch (failure) { return { ok: false, output: '', diagnostic: commandDiagnostic({ code: failure.status, signal: failure.signal,
      stderr: failure.stderr, spawnError: typeof failure.code === 'string' ? failure.code : null }) }; }
  };
  const mappings = [];
  let peer, peerPromise, packageInstallAttempted = false, result;
  const fail = code => { if (!result.problems.includes(code)) result.problems.push(code); result.ok = false; };
  try {
    const source = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 10000 }).trim();
    diagnostics.sourceCommit = /^[a-f0-9]{40}$/.test(source) ? source : 'unavailable';
    diagnostics.sourceDirty = execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 10000 }).trim() !== '';
    const version = probe(['version']); record('versionQuery', version.diagnostic); Object.assign(diagnostics, adbPublicVersion(version.output));
    const daemon = probe(['server-status']); record('daemonStatusQuery', daemon.diagnostic);
    diagnostics.adbDaemonVersion = adbPublicVersion(daemon.output).adbDaemonVersion;
    const initial = probe(['get-state']); record('initialDeviceQuery', initial.diagnostic);
    if (!initial.ok || initial.output !== 'device') throw Error('selected_device_unavailable');
    ensureRunning();
    const buildArgs = ['--no-daemon', '--console=plain', ':transport-interop:assembleDebugAndroidTest'];
    const build = await command(process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : './gradlew',
      process.platform === 'win32' ? ['/d', '/s', '/c', `gradlew.bat ${buildArgs.join(' ')}`] : buildArgs, 900000);
    record('build', commandDiagnostic(build));
    if (build.code !== 0 || build.reason) throw Error(build.reason ?? 'research_apk_build_failed');
    ensureRunning();
    const apkDirectory = path.join(moduleBuild, 'outputs/apk/androidTest/debug');
    const metadata = JSON.parse(fs.readFileSync(path.join(apkDirectory, 'output-metadata.json'), 'utf8'));
    if (metadata.applicationId !== testPackage || metadata.elements?.length !== 1 ||
        !/^[A-Za-z0-9_.-]+\.apk$/.test(metadata.elements[0].outputFile)) throw Error('unexpected_research_apk_metadata');
    packageInstallAttempted = true;
    const install = await command(options.adb, ['-s', options.serial, 'install', '-r', '-t', path.join(apkDirectory, metadata.elements[0].outputFile)], 60000);
    record('install', commandDiagnostic(install));
    if (install.code !== 0 || install.reason || install.output.trim().split(/\r?\n/).at(-1) !== 'Success') throw Error(install.reason ?? 'research_apk_install_failed');
    if (!adb(['shell', 'pm', 'list', 'instrumentation']).split('\n').some(line => line.startsWith(`instrumentation:${component} `))) throw Error('research_runner_not_registered');
    ensureRunning();
    const before = Date.now(), clock = probe(['shell', 'date', '+%s'], 5000), after = Date.now();
    record('deviceClockQuery', clock.diagnostic);
    if (!clock.ok) throw Error('device_clock_probe_failed');
    Object.assign(diagnostics, measureDraftStreamingClock(clock.output, before, after));
    if (diagnostics.draftClockStatus !== 'within_bound') throw Error('draft_clock_outside_bound');
    const { startCompanionStreamPeer } = await import('./companion-stream-peer.mjs');
    ensureRunning();
    peerPromise = startCompanionStreamPeer({ openssl: options.openssl });
    peer = await peerPromise; record('certificateValidity', peer.validity); ensureRunning();
    const publicInputs = { gatewayDer: peer.metadata.gatewayDer, gatewayPin: peer.metadata.gatewayPin,
      ...reserveFixtureReversePorts(adb, peer.metadata, mappings) };
    const args = ['-s', options.serial, 'shell', 'am', 'instrument', '-w', '-r', '-e', 'class', draftStreamingClass];
    for (const [name, value] of Object.entries(publicInputs)) {
      if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,16384}$/.test(value)) throw Error('invalid_public_fixture_input');
      args.push('-e', name, value);
    }
    args.push(component);
    console.log('Running draft streaming research; requiring seven actual start/end pairs.');
    const log = snapshotAdbServerLog(process.env.ANDROID_ADB_LOG_PATH);
    const instrument = await command(options.adb, args, 720000);
    record('serverLog', readAdbServerLog(log)); record('instrumentation', commandDiagnostic(instrument));
    result = parseDraftStreamingInstrumentation(instrument.output, { exitCode: instrument.code, signal: instrument.signal, transportError: instrument.reason });
    const state = probe(['get-state']); record('selectedDeviceQuery', state.diagnostic);
    diagnostics.selectedDeviceState = state.ok && ['device', 'offline', 'unauthorized', 'unknown'].includes(state.output) ? state.output : 'query_failed';
    if (diagnostics.selectedDeviceState !== 'device') fail('selected_device_unavailable_after_instrumentation');
    const reverse = probe(['reverse', '--list']); record('reverseQuery', reverse.diagnostic);
    diagnostics.ownedReverseMappingsPresent = reverse.ok && containsOwnedMappings(reverse.output, mappings);
    if (!diagnostics.ownedReverseMappingsPresent) fail('owned_reverse_mapping_lost_during_instrumentation');
  } catch (failure) {
    const code = draftSetupCode(failure.message);
    if (!result) result = parseDraftStreamingInstrumentation('', { exitCode: 1, transportError: code });
    else fail(code);
  } finally {
    // The asynchronous command runner has already observed close and joined its stop operation.
    // Attempt every independent cleanup even after failure; only actual observations can pass.
    const failures = [];
    // Even an interrupted install can have installed the package before its reply was lost.
    if (packageInstallAttempted) {
      for (const [label, args, timeout] of [
        ['cleanupTestPackageForceStop', ['shell', 'am', 'force-stop', testPackage], 10000],
        ['cleanupTestPackageUninstall', ['uninstall', testPackage], 60000],
      ]) {
        try {
          const closed = await command(options.adb, ['-s', options.serial, ...args], timeout, true);
          record(label, commandDiagnostic(closed));
          if (closed.code !== 0 || closed.reason || (label.endsWith('Uninstall') && closed.output.trim() !== 'Success')) failures.push('research_test_package_cleanup_failed');
        } catch { failures.push('research_test_package_cleanup_failed'); }
      }
    }
    const owned = mappings.splice(0), exitCodes = [];
    for (const mapping of [...owned].reverse()) {
      const removed = probe(['reverse', '--remove', `tcp:${mapping.devicePort}`]);
      exitCodes.push(removed.ok ? 0 : removed.diagnostic.exitCode);
      if (!removed.ok) failures.push('owned_reverse_mapping_cleanup_failed');
    }
    diagnostics.cleanupReverseRemovalExitCodes = JSON.stringify(exitCodes);
    if (owned.length) {
      const remaining = probe(['reverse', '--list']); record('cleanupReverseQuery', remaining.diagnostic);
      const rows = remaining.output.split(/\r?\n/).map(line => line.trim().split(/\s+/).slice(-2));
      diagnostics.cleanupReverseMappingsVerified = remaining.ok && owned.every(mapping => !rows.some(([device]) => device === `tcp:${mapping.devicePort}`));
      if (!diagnostics.cleanupReverseMappingsVerified) failures.push('owned_reverse_mapping_cleanup_unverified');
    }
    try { if (peer ??= await peerPromise?.catch(() => null)) { await peer.close(); diagnostics.cleanupPeerClosed = true; } }
    catch { failures.push('ephemeral_peer_cleanup_failed'); }
    if (!diagnostics.cleanupOwnedChildClosed) failures.push('owned_child_cleanup_failed');
    if (controller.signal.aborted) failures.push('research_run_cancelled');
    for (const code of new Set(failures)) fail(code);
    if (failures.length === 0) diagnostics.cleanupStatus = 'complete';
    if (result.ok && (diagnostics.cleanupStatus !== 'complete' || !diagnostics.cleanupPeerClosed ||
        !diagnostics.cleanupOwnedChildClosed || !diagnostics.cleanupReverseMappingsVerified ||
        diagnostics.cleanupReverseRemovalExitCodes !== '[0,0]' || diagnostics.cleanupTestPackageForceStopExitCode !== 0 ||
        diagnostics.cleanupTestPackageUninstallExitCode !== 0)) fail('research_completion_cleanup_unverified');
    result.diagnostics = diagnostics;
    for (const file of [xmlFile, htmlFile]) fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(xmlFile, draftStreamingXml(result)); fs.writeFileSync(htmlFile, draftStreamingHtml(result));
    for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, stop);
  }
  console.log(`Draft streaming research: ${result.started} started, ${result.completed} completed; ${result.ok ? 'passed' : 'failed'}; cleanup ${diagnostics.cleanupStatus}.`);
  if (!result.ok) console.error(`Research failure categories: ${result.problems.join(', ') || 'research_assertion_failed'}`);
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { if (!(await runDraftStreaming(draftStreamingOptions(process.argv.slice(2)))).ok) process.exitCode = 1; }
  catch { console.error('Draft streaming research driver failed; inspect the bounded report when available.'); process.exitCode = 1; }
}
