// Shared owned device/process operations for the finite enrollment research suites.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDraftCommand } from './draft-stream-command.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const enrollmentPackage = 'com.httpfreekit.interop.test';
export const enrollmentComponent = enrollmentPackage + '/androidx.test.runner.AndroidJUnitRunner';
export const enrollmentPassed = value => value.code === 0 && value.signal === null && value.reason === null && value.closeObserved && value.processGroupClosed;
export const enrollmentShellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";
const CLOSED_KEYS = ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined',
  'activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers'];
export const enrollmentClosedProjection = snapshot => snapshot === null ? null : Object.fromEntries(CLOSED_KEYS.map(key => [key, snapshot[key]]));
const requirePass = (value, stage) => { if (!enrollmentPassed(value)) throw Error(stage); return value; };

export async function registerEnrollmentReverses(adb, metadata, owned) {
  if (Object.hasOwn(metadata, 'webSocketPort') && Object.hasOwn(metadata, 'adversarialPeerPort')) throw Error('enrollment_fixture_failed');
  const ports = [metadata.setupPort, metadata.credentialPort,
    ...(Object.hasOwn(metadata, 'webSocketPort') ? [metadata.webSocketPort] : []),
    ...(Object.hasOwn(metadata, 'adversarialPeerPort') ? [metadata.adversarialPeerPort] : [])];
  if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535) || new Set(ports).size !== ports.length) throw Error('enrollment_fixture_failed');
  for (const port of ports) {
    const result = await adb(['reverse', '--no-rebind', 'tcp:' + port, 'tcp:' + port]);
    if (result.code === 0) owned.push({ devicePort: port, hostPort: port });
    requirePass(result, 'enrollment_fixture_failed');
    if (!['', String(port)].includes(result.output.trim())) throw Error('enrollment_fixture_failed');
  }
}

export function enrollmentOwnedReversesAbsent(result, owned) {
  if (!enrollmentPassed(result) || result.stderrBytes !== 0 || typeof result.output !== 'string' ||
      /[^\x09\x0a\x0d\x20-\x7e]/.test(result.output)) return false;
  const text = result.output.trim();
  if (!text) return true;
  const lines = text.split(/\r?\n/);
  if (lines.length > 128) return false;
  const socketName = value => {
    if (/^tcp:[1-9][0-9]{0,4}$/.exec(value)?.[0] === value) return Number(value.slice(4)) <= 65535;
    return /^(?:localabstract|localreserved|localfilesystem):[!-~]{1,1024}$/.exec(value)?.[0] === value;
  };
  const deviceSockets = [];
  for (const line of lines) {
    const fields = line.trim().split(/[ \t]+/);
    if (fields.length !== 2 && fields.length !== 3) return false;
    if (fields.length === 3 && /^[A-Za-z0-9_.:-]{1,128}$/.exec(fields[0])?.[0] !== fields[0]) return false;
    const [device, host] = fields.slice(-2);
    if (!socketName(device) || !socketName(host)) return false;
    deviceSockets.push(device);
  }
  return owned.every(mapping => !deviceSockets.includes('tcp:' + mapping.devicePort));
}

export function createEnrollmentHost(options) {
  const controller = new AbortController(), commands = [];
  const abort = () => controller.abort();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, abort);
  const command = async (executable, args, timeoutMillis = 10000, extras = {}, cleanup = false) => {
    const result = await runDraftCommand(executable, args, { cwd: ROOT,
      env: { ...process.env, ANDROID_SERIAL: options.serial }, timeoutMillis,
      abortSignal: cleanup ? undefined : controller.signal, ...extras });
    commands.push(result); return result;
  };
  const adb = (args, timeout = 10000, extras = {}, cleanup = false) => command(options.adb, ['-s', options.serial, ...args], timeout, extras, cleanup);
  const state = async (cleanup = false) => {
    const value = await adb(['get-state'], 10000, {}, cleanup);
    return enrollmentPassed(value) && value.stderrBytes === 0 && value.output.trim() === 'device' ? 'device' : 'unavailable';
  };
  const host = { controller, abort, commands, command, adb, state, installAttempted: false,
    dispose() { for (const signal of ['SIGINT', 'SIGTERM']) process.off(signal, abort); },
    async presence() {
      const script = '/system/bin/pidof ' + enrollmentPackage + ' >/dev/null; status=$?; ' +
        'if [ "$status" -eq 0 ]; then echo ENROLLMENT_PRESENT; elif [ "$status" -eq 1 ]; then echo ENROLLMENT_ABSENT; else exit "$status"; fi';
      const result = await adb(['shell', '-T', 'sh', '-c', enrollmentShellQuote(script)]);
      const marker = enrollmentPassed(result) && result.stderrBytes === 0 ? result.output.trim() : '';
      return { result, value: marker === 'ENROLLMENT_PRESENT' ? 'present' : marker === 'ENROLLMENT_ABSENT' ? 'absent' : 'unknown' };
    },
    async prepare(report) {
      let stage = 'host_setup_failed';
      try {
        const source = requirePass(await command('git', ['rev-parse', 'HEAD']), stage).output.trim();
        const dirty = requirePass(await command('git', ['status', '--porcelain', '--untracked-files=no']), stage).output.trim() !== '';
        if (!/^[0-9a-f]{40}$/.test(source)) throw Error();
        report.source = { commit: source, trackedDirty: dirty };
        if (dirty) { stage = 'source_not_clean'; throw Error(); }
        stage = 'selected_device_unavailable';
        if (await state() !== 'device') throw Error();
        const api = Number(requirePass(await adb(['shell', 'getprop', 'ro.build.version.sdk']), stage).output.trim());
        if (![26, 37].includes(api)) throw Error();
        report.api = api;
        stage = 'device_clock_probe_failed';
        const before = Date.now(), measured = await adb(['shell', 'date', '+%s'], 5000), after = Date.now();
        if (!enrollmentPassed(measured) || !/^[0-9]{10}$/.test(measured.output.trim())) throw Error();
        const seconds = Number(measured.output.trim());
        report.clock = { deviceEpochSeconds: seconds, hostBeforeMillis: before, hostAfterMillis: after,
          lowerBoundMillis: seconds * 1000 - after, upperBoundMillis: seconds * 1000 + 999 - before, roundTripMillis: after - before };
        if (after < before || after - before > 2000 || report.clock.lowerBoundMillis < -2000 || report.clock.upperBoundMillis > 2000) {
          stage = 'enrollment_clock_outside_bound'; throw Error();
        }
        stage = 'research_apk_build_failed';
        const args = ['--no-daemon', '--console=plain', ':transport-interop:assembleDebugAndroidTest'];
        requirePass(await command(process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : './gradlew',
          process.platform === 'win32' ? ['/d', '/s', '/c', 'gradlew.bat ' + args.join(' ')] : args, 900000), stage);
        stage = 'unexpected_research_apk_metadata';
        const directory = path.join(ROOT, 'tools/transport-spike/android/build/outputs/apk/androidTest/debug');
        const metadataPath = path.join(directory, 'output-metadata.json');
        if (fs.statSync(metadataPath).size > 65536) throw Error();
        const apk = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
        if (apk.applicationId !== enrollmentPackage || apk.elements?.length !== 1 || !/^[A-Za-z0-9_.-]+\.apk$/.test(apk.elements[0].outputFile)) throw Error();
        const existing = requirePass(await adb(['shell', 'pm', 'list', 'packages', enrollmentPackage]), stage);
        if (existing.stderrBytes || existing.output.trim() !== '') throw Error();
        stage = 'research_apk_install_failed'; host.installAttempted = true;
        const installed = requirePass(await adb(['install', '-t', path.join(directory, apk.elements[0].outputFile)], 60000), stage);
        if (installed.output.trim().split(/\r?\n/).at(-1) !== 'Success') throw Error();
        stage = 'research_runner_not_registered';
        const runners = requirePass(await adb(['shell', 'pm', 'list', 'instrumentation', enrollmentPackage]), stage).output.split(/\r?\n/);
        if (!runners.some(line => line.startsWith('instrumentation:' + enrollmentComponent + ' '))) throw Error();
      } catch { throw Error(stage); }
    },
    async cleanupPackage(observation) {
      const result = { forceStopCommand: null, uninstallCommand: null, uninstallConfirmed: false, failed: false };
      if (!host.installAttempted) return result;
      try { const stopped = await adb(['shell', 'am', 'force-stop', enrollmentPackage], 10000, {}, true);
        result.forceStopCommand = observation(stopped); if (!enrollmentPassed(stopped)) result.failed = true; }
      catch { result.failed = true; }
      try { const removed = await adb(['uninstall', enrollmentPackage], 60000, {}, true);
        result.uninstallCommand = observation(removed); result.uninstallConfirmed = enrollmentPassed(removed) && removed.output.trim() === 'Success';
        if (!result.uninstallConfirmed) result.failed = true; }
      catch { result.failed = true; }
      return result;
    },
  };
  return host;
}

export async function cleanupEnrollmentResources(host, { workers, mappings, directory, tasks = [], commandStart = 0 }, observation) {
  const result = { workerClosed: null, workerCommand: null, reverseRemovalExitCodes: [], ownedReversesAbsent: false,
    privateDirectoryRemoved: false, ownedCommandsClosed: false, ownedCommandGroupsClosed: false, failed: false };
  for (const mapping of [...mappings].reverse()) {
    try { const removed = await host.adb(['reverse', '--remove', 'tcp:' + mapping.devicePort], 10000, {}, true);
      result.reverseRemovalExitCodes.push(removed.code === null ? 255 : removed.code); if (!enrollmentPassed(removed)) result.failed = true; }
    catch { result.reverseRemovalExitCodes.push(255); result.failed = true; }
  }
  if (mappings.length) {
    try { result.ownedReversesAbsent = enrollmentOwnedReversesAbsent(await host.adb(['reverse', '--list'], 10000, {}, true), mappings);
      if (!result.ownedReversesAbsent) result.failed = true; }
    catch { result.failed = true; }
  }
  for (const worker of workers) { try { await worker.close(); } catch { result.failed = true; } }
  await Promise.allSettled(tasks.filter(Boolean));
  const last = workers.at(-1);
  if (last) { result.workerClosed = enrollmentClosedProjection(last.closedSnapshot()?.material() ?? null); result.workerCommand = observation(last.commandObservation()); }
  result.ownedCommandsClosed = host.commands.slice(commandStart).every(value => value.closeObserved);
  result.ownedCommandGroupsClosed = host.commands.slice(commandStart).every(value => value.processGroupClosed);
  if (!result.ownedCommandsClosed || !result.ownedCommandGroupsClosed) result.failed = true;
  if (directory && workers.every(worker => worker.commandObservation().closeObserved && worker.commandObservation().processGroupClosed && worker.closedSnapshot()?.material().storeClosed === true)) {
    try {
      const resolved = path.resolve(directory), temporary = fs.realpathSync(os.tmpdir());
      if (path.dirname(resolved) !== temporary || !path.basename(resolved).startsWith('freekit-enrollment-runtime-') || fs.realpathSync(resolved) !== resolved) throw Error();
      fs.rmSync(resolved, { recursive: true, force: true }); result.privateDirectoryRemoved = !fs.existsSync(resolved);
    } catch { result.failed = true; }
  }
  return result;
}
