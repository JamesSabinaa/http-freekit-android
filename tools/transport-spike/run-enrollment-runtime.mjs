// A22a driver: private input, host-only approval, real package/worker restart, selective cleanup.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { runDraftCommand } from './draft-stream-command.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { encodeEnrollment, enrollmentMessage } from './companion-enrollment-codec.mjs';
import { expectedEnrollmentMethods, enrollmentRuntimeClass, enrollmentReportPaths,
  createEnrollmentInvocationParser, createEnrollmentRuntimeReport, verifyEnrollmentRuntime,
  enrollmentRuntimeXml, enrollmentRuntimeHtml, enrollmentCommandObservation,
  enrollmentRuntimeProblem } from './enrollment-runtime-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const PACKAGE = 'com.httpfreekit.interop.test';
const COMPONENT = PACKAGE + '/androidx.test.runner.AndroidJUnitRunner';
const PRIVATE_INPUT = 'no_backup/draft-enrollment-research/input-v1.bin';
const CLOSED_KEYS = ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined',
  'activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers'];
const passed = value => value.code === 0 && value.signal === null && value.reason === null && value.closeObserved && value.processGroupClosed;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const approvedHash = value => sha(encodeEnrollment(enrollmentMessage('status_response', value)));
const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";
const closedProjection = snapshot => snapshot === null ? null :
  Object.fromEntries(CLOSED_KEYS.map(key => [key, snapshot[key]]));
function requirePass(value, code) { if (!passed(value)) throw Error(code); return value; }

export async function registerEnrollmentReverses(adb, metadata, owned) {
  const ports = [metadata.setupPort, metadata.credentialPort];
  if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535) || ports[0] === ports[1]) throw Error('enrollment_fixture_failed');
  for (const port of ports) {
    const result = await adb(['reverse', '--no-rebind', 'tcp:' + port, 'tcp:' + port]);
    // An observed exit0 already owns the registration even if a later pipe/group check fails.
    if (result.code === 0) owned.push({ devicePort: port, hostPort: port });
    requirePass(result, 'enrollment_fixture_failed');
    if (!['', String(port)].includes(result.output.trim())) throw Error('enrollment_fixture_failed');
  }
}
export function enrollmentOwnedReversesAbsent(result, owned) {
  if (!passed(result) || result.stderrBytes !== 0 || typeof result.output !== 'string') return false;
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

export function enrollmentRuntimeOptions(args, env = process.env) {
  const options = { adb: env.ANDROID_HOME ? path.join(env.ANDROID_HOME, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb') : 'adb',
    openssl: env.OPENSSL_BIN ?? 'openssl' };
  const seen = new Set();
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i], value = args[i + 1];
    if (!['--serial', '--adb', '--openssl'].includes(name) || seen.has(name) || typeof value !== 'string' ||
        !value || value.length > 4096 || /[\0\r\n]/.test(value)) throw Error('invalid_enrollment_arguments');
    seen.add(name); options[name.slice(2)] = value;
  }
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(options.serial ?? '')) throw Error('explicit_enrollment_serial_required');
  return Object.freeze(options);
}

export async function runEnrollmentRuntime(options) {
  const report = { format: 'http-freekit-a22a-runtime', revision: 1, source: null, api: null, clock: null,
    invocations: expectedEnrollmentMethods.map(method => createEnrollmentInvocationParser(method).finish()),
    input: null, approval: null, stop: null, restart: null, cleanup: null, problems: [] };
  const problem = code => {
    const safe = enrollmentRuntimeProblem(code);
    if (!report.problems.includes(safe) && report.problems.length < 16) report.problems.push(safe);
  };
  const controller = new AbortController();
  const abort = () => controller.abort();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, abort);
  const commands = [], workers = [], mappings = [];
  let worker, directory, installAttempted = false, approvalTask, stage = 'host_setup_failed';
  let initialMetadata, registration, approvedBefore;
  const command = async (executable, args, timeoutMillis = 10000, extras = {}, cleanup = false) => {
    const result = await runDraftCommand(executable, args, { cwd: ROOT,
      env: { ...process.env, ANDROID_SERIAL: options.serial }, timeoutMillis,
      abortSignal: cleanup ? undefined : controller.signal, ...extras });
    commands.push(result); return result;
  };
  const adb = (args, timeout = 10000, extras = {}, cleanup = false) =>
    command(options.adb, ['-s', options.serial, ...args], timeout, extras, cleanup);
  const state = async (cleanup = false) => {
    const value = await adb(['get-state'], 10000, {}, cleanup);
    return passed(value) && value.stderrBytes === 0 && value.output.trim() === 'device' ? 'device' : 'unavailable';
  };
  const presence = async () => {
    const script = '/system/bin/pidof ' + PACKAGE + ' >/dev/null; status=$?; ' +
      'if [ "$status" -eq 0 ]; then echo ENROLLMENT_PRESENT; elif [ "$status" -eq 1 ]; then echo ENROLLMENT_ABSENT; else exit "$status"; fi';
    const result = await adb(['shell', '-T', 'sh', '-c', shellQuote(script)]);
    const marker = passed(result) && result.stderrBytes === 0 ? result.output.trim() : '';
    return { result, value: marker === 'ENROLLMENT_PRESENT' ? 'present' : marker === 'ENROLLMENT_ABSENT' ? 'absent' : 'unknown' };
  };
  const spawnWorker = async (mode, setupPort = 0, credentialPort = 0) => {
    const owner = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)), cwd: ROOT });
    workers.push(owner); worker = owner;
    return (await owner.request('start', { directory, mode, openssl: options.openssl, setupPort, credentialPort }, { timeoutMillis: 60000 })).material();
  };
  async function invoke(method, onPhase) {
    let live = true;
    const parser = createEnrollmentInvocationParser(method, { onPhase(phase) {
      if (!live) throw Error('phase_after_command_close');
      if (onPhase) onPhase(phase);
    } });
    let result;
    try {
      result = await adb(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class',
        enrollmentRuntimeClass + '#' + method, COMPONENT], method === expectedEnrollmentMethods[0] ? 240000 : 120000,
      { onStdoutChunk(chunk) { parser.push(chunk); } });
    } finally { live = false; }
    const parsed = parser.finish(result);
    report.invocations[expectedEnrollmentMethods.indexOf(method)] = parsed;
    if (parsed.state !== 'passed') throw Error('enrollment_invocation_failed');
  }
  try {
    const source = requirePass(await command('git', ['rev-parse', 'HEAD']), 'host_setup_failed').output.trim();
    const dirty = requirePass(await command('git', ['status', '--porcelain', '--untracked-files=no']), 'host_setup_failed').output.trim() !== '';
    if (!/^[0-9a-f]{40}$/.test(source)) throw Error('host_setup_failed');
    report.source = { commit: source, trackedDirty: dirty };
    if (dirty) throw Error('source_not_clean');
    stage = 'selected_device_unavailable';
    if (await state() !== 'device') throw Error(stage);
    const api = Number(requirePass(await adb(['shell', 'getprop', 'ro.build.version.sdk']), stage).output.trim());
    if (![26, 37].includes(api)) throw Error(stage);
    report.api = api;
    stage = 'device_clock_probe_failed';
    const before = Date.now(), measured = await adb(['shell', 'date', '+%s'], 5000), after = Date.now();
    if (!passed(measured) || !/^[0-9]{10}$/.test(measured.output.trim())) throw Error(stage);
    const seconds = Number(measured.output.trim());
    report.clock = { deviceEpochSeconds: seconds, hostBeforeMillis: before, hostAfterMillis: after,
      lowerBoundMillis: seconds * 1000 - after, upperBoundMillis: seconds * 1000 + 999 - before, roundTripMillis: after - before };
    if (after < before || after - before > 2000 || report.clock.lowerBoundMillis < -2000 || report.clock.upperBoundMillis > 2000) throw Error('enrollment_clock_outside_bound');
    stage = 'research_apk_build_failed';
    const buildArgs = ['--no-daemon', '--console=plain', ':transport-interop:assembleDebugAndroidTest'];
    const build = await command(process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : './gradlew',
      process.platform === 'win32' ? ['/d', '/s', '/c', 'gradlew.bat ' + buildArgs.join(' ')] : buildArgs, 900000);
    requirePass(build, stage);
    stage = 'unexpected_research_apk_metadata';
    const apkDirectory = path.join(ROOT, 'tools/transport-spike/android/build/outputs/apk/androidTest/debug');
    const metadataPath = path.join(apkDirectory, 'output-metadata.json');
    if (fs.statSync(metadataPath).size > 65536) throw Error(stage);
    const apk = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    if (apk.applicationId !== PACKAGE || apk.elements?.length !== 1 || !/^[A-Za-z0-9_.-]+\.apk$/.test(apk.elements[0].outputFile)) throw Error(stage);
    // This standalone research run never replaces an existing package/data owner.
    const existing = requirePass(await adb(['shell', 'pm', 'list', 'packages', PACKAGE]), stage);
    if (existing.stderrBytes || existing.output.trim() !== '') throw Error(stage);
    stage = 'research_apk_install_failed'; installAttempted = true;
    const install = requirePass(await adb(['install', '-t', path.join(apkDirectory, apk.elements[0].outputFile)], 60000), stage);
    if (install.output.trim().split(/\r?\n/).at(-1) !== 'Success') throw Error(stage);
    stage = 'research_runner_not_registered';
    const runners = requirePass(await adb(['shell', 'pm', 'list', 'instrumentation', PACKAGE]), stage).output.split(/\r?\n/);
    if (!runners.some(line => line.startsWith('instrumentation:' + COMPONENT + ' '))) throw Error(stage);
    stage = 'enrollment_fixture_failed';
    const temporary = fs.realpathSync(os.tmpdir());
    directory = fs.mkdtempSync(path.join(temporary, 'freekit-enrollment-runtime-')); fs.chmodSync(directory, 0o700);
    initialMetadata = await spawnWorker('create');
    const invitation = (await worker.request('createInvitation')).material();
    await registerEnrollmentReverses(adb, initialMetadata, mappings);
    stage = 'enrollment_input_failed';
    const input = encodeEnrollmentRuntimeInput(initialMetadata, invitation);
    const script = 'umask 077; mkdir -p no_backup/draft-enrollment-research && chmod 700 no_backup/draft-enrollment-research && ' +
      'cat > ' + PRIVATE_INPUT + ' && chmod 600 ' + PRIVATE_INPUT;
    let sent;
    try { sent = await adb(['shell', '-T', 'run-as', PACKAGE, 'sh', '-c', shellQuote(script)], 10000, { stdinBytes: input }); }
    finally { input.fill(0); }
    report.input = { byteCount: input.length, inputBytes: sent.inputBytes ?? 0, inputFinished: sent.inputFinished === true,
      inputClosed: sent.inputClosed === true, command: enrollmentCommandObservation(sent), inputAbsentAfterPrepare: false };
    requirePass(sent, stage);
    report.approval = { liveAwaitingPhaseObserved: false, dropArmAcknowledged: false, requestedAfterArm: false,
      completed: false, actualApprovedResponseDrops: 0, approvedResponsesAfterDrop: 0, reopenedApprovedResponses: 0 };
    stage = 'enrollment_invocation_failed';
    await invoke(expectedEnrollmentMethods[0], phase => {
      if (phase !== 'awaiting-host-approval') return;
      if (approvalTask) throw Error('duplicate_approval_phase');
      report.approval.liveAwaitingPhaseObserved = true;
      approvalTask = (async () => {
        registration = (await worker.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 })).material();
        const armed = (await worker.request('dropNextApprovedStatus')).material();
        if (armed.armed !== true) throw Error('enrollment_approval_failed');
        report.approval.dropArmAcknowledged = true; report.approval.requestedAfterArm = true;
        approvedBefore = (await worker.request('approve', { enrollmentId: registration.enrollmentId })).material();
        if (approvedBefore.type !== 'pair_approved') throw Error('enrollment_approval_failed');
        report.approval.completed = true;
      })().catch(() => { problem('enrollment_approval_failed'); controller.abort(); });
    });
    await approvalTask;
    if (!report.approval.completed || !approvedBefore) throw Error('enrollment_approval_failed');
    const absent = requirePass(await adb(['shell', '-T', 'run-as', PACKAGE, 'sh', '-c',
      shellQuote('test ! -e ' + PRIVATE_INPUT + ' && echo ENROLLMENT_INPUT_ABSENT')]), 'enrollment_input_failed');
    report.input.inputAbsentAfterPrepare = absent.output.trim() === 'ENROLLMENT_INPUT_ABSENT';
    if (!report.input.inputAbsentAfterPrepare) throw Error('enrollment_input_failed');
    stage = 'enrollment_stop_failed';
    const deviceBefore = await state(), presenceBefore = await presence();
    const stopped = await adb(['shell', 'am', 'force-stop', PACKAGE]);
    const presenceAfter = await presence(), deviceAfter = await state();
    report.stop = { forceStopCommand: enrollmentCommandObservation(stopped), deviceBefore, deviceAfter,
      presenceBefore: presenceBefore.value, presenceAfter: presenceAfter.value, absenceQueryExitCode: presenceAfter.result.code,
      absenceMarkerVerified: presenceAfter.value === 'absent' && passed(presenceAfter.result) };
    if (!passed(stopped) || deviceBefore !== 'device' || deviceAfter !== 'device' ||
        presenceBefore.value === 'unknown' || presenceAfter.value !== 'absent') throw Error(stage);
    stage = 'enrollment_restart_failed';
    const initialClosed = (await worker.close()).material();
    report.approval.actualApprovedResponseDrops = initialClosed.droppedApprovedResponses;
    report.approval.approvedResponsesAfterDrop = initialClosed.approvedResponsesDeliveredAfterDrop;
    const initialCommand = enrollmentCommandObservation(worker.commandObservation());
    report.restart = { initialWorkerClosed: closedProjection(initialClosed), initialWorkerCommand: initialCommand, opened: false, continuity: null };
    const reopened = await spawnWorker('open', initialMetadata.setupPort, initialMetadata.credentialPort);
    const approvedAfter = (await worker.request('readResult', { enrollmentId: registration.enrollmentId })).material();
    report.restart.opened = true;
    report.restart.continuity = {
      setupPortBefore: initialMetadata.setupPort, setupPortAfter: reopened.setupPort,
      credentialPortBefore: initialMetadata.credentialPort, credentialPortAfter: reopened.credentialPort,
      gatewayCertificateSha256Before: sha(Buffer.from(initialMetadata.gatewayCertificateDer, 'base64url')),
      gatewayCertificateSha256After: sha(Buffer.from(reopened.gatewayCertificateDer, 'base64url')),
      enrollmentAuthoritySha256Before: sha(Buffer.from(initialMetadata.enrollmentAuthorityDer, 'base64url')),
      enrollmentAuthoritySha256After: sha(Buffer.from(reopened.enrollmentAuthorityDer, 'base64url')),
      approvedResultSha256Before: approvedHash(approvedBefore), approvedResultSha256After: approvedHash(approvedAfter) };
    stage = 'enrollment_invocation_failed';
    await invoke(expectedEnrollmentMethods[1]);
    const finalSnapshot = (await worker.request('snapshot')).material();
    report.approval.reopenedApprovedResponses = finalSnapshot.approvedResponsesDelivered;
  } catch (error) {
    problem(typeof error?.message === 'string' && enrollmentRuntimeProblem(error.message) !== 'host_setup_failed' ? error.message : stage);
  } finally {
    // Close signing/worker owners before awaiting scheduled operator tasks; close can cancel them.
    const cleanup = { forceStopCommand: null, uninstallCommand: null, uninstallConfirmed: false,
      reverseRemovalExitCodes: [], ownedReversesAbsent: false, finalWorkerClosed: null, finalWorkerCommand: null,
      ownedCommandsClosed: false, ownedCommandGroupsClosed: false, privateDirectoryRemoved: false };
    if (installAttempted) {
      try { const result = await adb(['shell', 'am', 'force-stop', PACKAGE], 10000, {}, true); cleanup.forceStopCommand = enrollmentCommandObservation(result); if (!passed(result)) problem('enrollment_cleanup_failed'); }
      catch { problem('enrollment_cleanup_failed'); }
      try {
        const result = await adb(['uninstall', PACKAGE], 60000, {}, true); cleanup.uninstallCommand = enrollmentCommandObservation(result);
        cleanup.uninstallConfirmed = passed(result) && result.output.trim() === 'Success';
        if (!cleanup.uninstallConfirmed) problem('enrollment_cleanup_failed');
      } catch { problem('enrollment_cleanup_failed'); }
    }
    for (const mapping of [...mappings].reverse()) {
      try {
        const result = await adb(['reverse', '--remove', 'tcp:' + mapping.devicePort], 10000, {}, true);
        cleanup.reverseRemovalExitCodes.push(result.code === null ? 255 : result.code);
        if (!passed(result)) problem('enrollment_cleanup_failed');
      } catch { cleanup.reverseRemovalExitCodes.push(255); problem('enrollment_cleanup_failed'); }
    }
    if (mappings.length) {
      try {
        const result = await adb(['reverse', '--list'], 10000, {}, true);
        cleanup.ownedReversesAbsent = enrollmentOwnedReversesAbsent(result, mappings);
        if (!cleanup.ownedReversesAbsent) problem('enrollment_cleanup_failed');
      } catch { problem('enrollment_cleanup_failed'); }
    }
    for (const owner of workers) {
      try { await owner.close(); } catch { problem('enrollment_cleanup_failed'); }
    }
    if (approvalTask) await approvalTask.catch(() => {});
    if (worker) {
      cleanup.finalWorkerClosed = closedProjection(worker.closedSnapshot()?.material() ?? null);
      cleanup.finalWorkerCommand = enrollmentCommandObservation(worker.commandObservation());
    }
    cleanup.ownedCommandsClosed = commands.every(value => value.closeObserved);
    cleanup.ownedCommandGroupsClosed = commands.every(value => value.processGroupClosed);
    if (!cleanup.ownedCommandsClosed || !cleanup.ownedCommandGroupsClosed) problem('enrollment_cleanup_failed');
    if (directory && workers.every(value => value.commandObservation().closeObserved &&
        value.commandObservation().processGroupClosed && value.closedSnapshot()?.material().storeClosed === true)) {
      try {
        const resolved = path.resolve(directory), temp = fs.realpathSync(os.tmpdir());
        if (path.dirname(resolved) !== temp || !path.basename(resolved).startsWith('freekit-enrollment-runtime-')) throw Error();
        fs.rmSync(resolved, { recursive: true, force: true }); cleanup.privateDirectoryRemoved = !fs.existsSync(resolved);
      } catch { problem('enrollment_cleanup_failed'); }
    }
    report.cleanup = cleanup;
    if (controller.signal.aborted) problem('research_run_cancelled');
    for (const signal of ['SIGINT', 'SIGTERM']) process.off(signal, abort);
  }
  const final = createEnrollmentRuntimeReport(report);
  for (const [name, text] of [['runtime', JSON.stringify(final, null, 2) + '\n'], ['xml', enrollmentRuntimeXml(final)], ['html', enrollmentRuntimeHtml(final)]]) {
    const filename = path.join(ROOT, enrollmentReportPaths[name]); fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, text);
  }
  let ok = false;
  try { verifyEnrollmentRuntime(final, { source: final.source?.commit, api: final.api }); ok = true; } catch {}
  console.log('Enrollment research: ' + final.invocations.reduce((n, value) => n + value.actualStarted, 0) + ' started, ' +
    final.invocations.reduce((n, value) => n + value.actualCompleted, 0) + ' completed; ' + (ok ? 'passed' : 'failed') + '.');
  if (!ok) console.error('Enrollment failure categories: ' + (final.problems.join(', ') || 'enrollment_invocation_failed'));
  return { ok, report: final };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { if (!(await runEnrollmentRuntime(enrollmentRuntimeOptions(process.argv.slice(2)))).ok) process.exitCode = 1; }
  catch { console.error('Enrollment runtime driver failed; inspect bounded reports when available.'); process.exitCode = 1; }
}
