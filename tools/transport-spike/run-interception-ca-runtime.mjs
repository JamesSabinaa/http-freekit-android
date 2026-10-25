// Fixed A22a/A23 driver: private enrollment, same-worker CA continuity, selective cleanup.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createEnrollmentHost, cleanupEnrollmentResources, enrollmentPassed as passed,
  enrollmentClosedProjection as closedProjection, enrollmentShellQuote as shellQuote,
  registerEnrollmentReverses } from './enrollment-runtime-host.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { encodeEnrollment, enrollmentMessage } from './companion-enrollment-codec.mjs';
import { expectedEnrollmentMethods, enrollmentRuntimeClass, enrollmentReportPaths,
  createEnrollmentInvocationParser, createEnrollmentRuntimeReport, verifyEnrollmentRuntime,
  enrollmentRuntimeXml, enrollmentRuntimeHtml, enrollmentCommandObservation,
  enrollmentRuntimeProblem } from './enrollment-runtime-results.mjs';
import { interceptionCaRuntimeClass, interceptionCaRuntimeMethod } from './interception-ca-runtime-descriptor.mjs';
import { interceptionCaRuntimeReportPaths, interceptionCaMethods, createInterceptionCaInvocationParser,
  createInterceptionCaRuntimeReport, verifyInterceptionCaRuntimeReport,
  interceptionCaRuntimeXml, interceptionCaRuntimeHtml } from './interception-ca-runtime-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const PACKAGE = 'com.httpfreekit.interop.test';
const COMPONENT = PACKAGE + '/androidx.test.runner.AndroidJUnitRunner';
const PRIVATE_INPUT = 'no_backup/draft-enrollment-research/input-v1.bin';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const approvedHash = value => sha(encodeEnrollment(enrollmentMessage('status_response', value)));
function requirePass(value, code) { if (!passed(value)) throw Error(code); return value; }

// Parse only the installed self-instrumenting APK's requested-permissions section.
export function ownedCaPermissionDeclared(output) {
  if (typeof output !== 'string' || Buffer.byteLength(output) > 262144) return false;
  const owned = /^\s*Package \[com\.httpfreekit\.interop\.test\] \([^\r\n]*\):?\s*$/gm;
  const match = owned.exec(output);
  if (!match || owned.exec(output)) return false;
  const nextPackage = /^\s*Package \[/gm;
  nextPackage.lastIndex = match.index + match[0].length;
  const next = nextPackage.exec(output);
  const packageSection = output.slice(match.index + match[0].length, next?.index ?? output.length);
  const section = /^\s*requested permissions:\s*\r?\n((?:^[ \t]+android\.permission\.[A-Z_]+(?:\s*\r?\n|$))*)/im.exec(packageSection);
  return !!section && /^[ \t]+android\.permission\.ACCESS_LOCAL_NETWORK[ \t]*$/m.test(section[1]);
}

export async function runInterceptionCaRuntime(options) {
  const caSuite = options.suite === 'a23';
  const report = { format: caSuite ? 'http-freekit-a23-runtime' : 'http-freekit-a22a-runtime', revision: 1, source: null, api: null, clock: null,
    invocations: caSuite ? [createEnrollmentInvocationParser(expectedEnrollmentMethods[0]).finish(), createInterceptionCaInvocationParser().finish(), createEnrollmentInvocationParser(expectedEnrollmentMethods[1]).finish()]
      : expectedEnrollmentMethods.map(method => createEnrollmentInvocationParser(method).finish()),
    input: null, approval: null, stop: null, restart: null, cleanup: null, problems: [], ...(caSuite ? { ca: null, permission: null } : {}) };
  const problem = code => {
    const safe = enrollmentRuntimeProblem(code);
    if (!report.problems.includes(safe) && report.problems.length < 16) report.problems.push(safe);
  };
  const host = createEnrollmentHost(options);
  const { controller, adb, state, presence } = host;
  const workers = [], mappings = [];
  let worker, directory, approvalTask, stage = 'host_setup_failed';
  let initialMetadata, registration, approvedBefore, liveApproval = false;
  const approvalAllowed = () => liveApproval && !controller.signal.aborted;
  const spawnWorker = async (mode, setupPort = 0, credentialPort = 0) => {
    const owner = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)), cwd: ROOT });
    workers.push(owner); worker = owner;
    return (await owner.request('start', { directory, mode, openssl: options.openssl, setupPort, credentialPort }, { timeoutMillis: 60000 })).material();
  };
  async function invoke(method, onPhase) {
    let live = true;
    const parser = method === interceptionCaRuntimeMethod ? createInterceptionCaInvocationParser(phase => {
      if (!live) throw Error('phase_after_command_close');
      if (onPhase) onPhase(phase);
    }) : createEnrollmentInvocationParser(method, { onPhase(phase) {
      if (!live) throw Error('phase_after_command_close');
      if (onPhase) onPhase(phase);
    } });
    let result;
    try {
      result = await adb(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class',
        (method === interceptionCaRuntimeMethod ? interceptionCaRuntimeClass : enrollmentRuntimeClass) + '#' + method, COMPONENT], method === expectedEnrollmentMethods[0] ? 240000 : 120000,
      { onStdoutChunk(chunk) { parser.push(chunk); } });
    } finally { live = false; if (method === expectedEnrollmentMethods[0]) liveApproval = false; }
    const parsed = parser.finish(result);
    report.invocations[(caSuite ? interceptionCaMethods : expectedEnrollmentMethods).indexOf(method)] = parsed;
    if (parsed.state !== 'passed') throw Error('enrollment_invocation_failed');
  }
  try {
    await host.prepare(report);
    if (caSuite) {
      report.permission = { mode: report.api === 37 ? 'owned_ci_grant' : 'not_required', declared: false, grantCommand: null, readbackCommand: null, readbackGranted: false };
      if (report.api === 37) {
        stage = 'enrollment_fixture_failed';
        const declared = requirePass(await adb(['shell', 'pm', 'dump', PACKAGE]), stage);
        report.permission.declared = declared.stderrBytes === 0 && ownedCaPermissionDeclared(declared.output);
        if (!report.permission.declared) throw Error(stage);
        const grant = await adb(['shell', 'pm', 'grant', '--user', '0', PACKAGE, 'android.permission.ACCESS_LOCAL_NETWORK']);
        report.permission.grantCommand = enrollmentCommandObservation(grant);
        requirePass(grant, stage);
        const readback = await adb(['shell', 'cmd', 'package', 'check-permission', 'android.permission.ACCESS_LOCAL_NETWORK', PACKAGE, '0']);
        report.permission.readbackCommand = enrollmentCommandObservation(readback);
        report.permission.readbackGranted = passed(readback) && readback.stderrBytes === 0 && readback.output.trim() === 'granted';
        if (!report.permission.readbackGranted) throw Error(stage);
      }
    }
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
      liveApproval = true;
      approvalTask = (async () => {
        registration = (await worker.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 })).material();
        if (!approvalAllowed()) throw Error('enrollment_approval_failed');
        const armed = (await worker.request('dropNextApprovedStatus')).material();
        if (!approvalAllowed() || armed.armed !== true) throw Error('enrollment_approval_failed');
        report.approval.dropArmAcknowledged = true;
        if (!approvalAllowed()) throw Error('enrollment_approval_failed');
        report.approval.requestedAfterArm = true;
        approvedBefore = (await worker.request('approve', { enrollmentId: registration.enrollmentId })).material();
        if (approvedBefore.type !== 'pair_approved') throw Error('enrollment_approval_failed');
        report.approval.completed = true;
      })().catch(() => { problem('enrollment_approval_failed'); controller.abort(); });
    });
    await approvalTask;
    if (!report.approval.completed || !approvedBefore) throw Error('enrollment_approval_failed');
    let caBefore;
    if (caSuite) {
      stage = 'enrollment_fixture_failed';
      caBefore = (await worker.request('interceptionCaEvidence')).material();
      if (caBefore.certificateSha256 !== approvedBefore.interceptionCaCertificateSha256 ||
          caBefore.certificateSha256 !== initialMetadata.interceptionCaCertificateSha256) throw Error(stage);
    }
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
    if (caSuite) {
      const caAfter = (await worker.request('interceptionCaEvidence')).material();
      report.ca = { beforeBytes: caBefore.certificateBytes, afterBytes: caAfter.certificateBytes,
        beforeMatchesApproval: caBefore.certificateSha256 === approvedBefore.interceptionCaCertificateSha256,
        afterMatchesApproval: caAfter.certificateSha256 === approvedAfter.interceptionCaCertificateSha256,
        beforeMatchesMetadata: caBefore.certificateSha256 === initialMetadata.interceptionCaCertificateSha256,
        afterMatchesMetadata: caAfter.certificateSha256 === reopened.interceptionCaCertificateSha256,
        digestUnchanged: caBefore.certificateSha256 === caAfter.certificateSha256,
        bytesUnchanged: caBefore.certificateBytes === caAfter.certificateBytes };
      if (!report.ca.afterMatchesApproval || !report.ca.afterMatchesMetadata || !report.ca.digestUnchanged || !report.ca.bytesUnchanged) throw Error(stage);
      await invoke(interceptionCaRuntimeMethod);
    }
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
  const final = caSuite ? createInterceptionCaRuntimeReport(report) : createEnrollmentRuntimeReport(report);
  const paths = caSuite ? interceptionCaRuntimeReportPaths : enrollmentReportPaths;
  const renderXml = caSuite ? interceptionCaRuntimeXml : enrollmentRuntimeXml;
  const renderHtml = caSuite ? interceptionCaRuntimeHtml : enrollmentRuntimeHtml;
  for (const [name, text] of [['runtime', JSON.stringify(final, null, 2) + '\n'], ['xml', renderXml(final)], ['html', renderHtml(final)]]) {
    const filename = path.join(ROOT, paths[name]); fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, text);
  }
  let ok = false;
  try {
    (caSuite ? verifyInterceptionCaRuntimeReport : verifyEnrollmentRuntime)(final, { source: final.source?.commit, api: final.api }); ok = true;
  } catch {}
  console.log('Enrollment research: ' + final.invocations.reduce((n, value) => n + value.actualStarted, 0) + ' started, ' +
    final.invocations.reduce((n, value) => n + value.actualCompleted, 0) + ' completed; ' + (ok ? 'passed' : 'failed') + '.');
  if (!ok) console.error('Enrollment failure categories: ' + (final.problems.join(', ') || 'enrollment_invocation_failed'));
  return { ok, report: final };
}
