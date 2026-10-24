// A22a driver: private input, host-only approval, real package/worker restart, selective cleanup.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createEnrollmentHost, cleanupEnrollmentResources, enrollmentPassed as passed,
  enrollmentClosedProjection as closedProjection, enrollmentShellQuote as shellQuote,
  registerEnrollmentReverses, enrollmentOwnedReversesAbsent } from './enrollment-runtime-host.mjs';
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
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const approvedHash = value => sha(encodeEnrollment(enrollmentMessage('status_response', value)));
function requirePass(value, code) { if (!passed(value)) throw Error(code); return value; }

export { registerEnrollmentReverses, enrollmentOwnedReversesAbsent };

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
  const host = createEnrollmentHost(options);
  const { controller, adb, state, presence } = host;
  const workers = [], mappings = [];
  let worker, directory, approvalTask, stage = 'host_setup_failed';
  let initialMetadata, registration, approvedBefore;
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
    await host.prepare(report);
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
    const { failed: packageFailed, ...packageCleanup } = await host.cleanupPackage(enrollmentCommandObservation);
    const { failed: resourcesFailed, workerClosed, workerCommand, ...resourcesCleanup } =
      await cleanupEnrollmentResources(host, { workers, mappings, directory, tasks: [approvalTask] }, enrollmentCommandObservation);
    if (packageFailed || resourcesFailed) problem('enrollment_cleanup_failed');
    report.cleanup = { ...packageCleanup, ...resourcesCleanup, finalWorkerClosed: workerClosed, finalWorkerCommand: workerCommand };
    if (controller.signal.aborted) problem('research_run_cancelled');
    host.dispose();
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
