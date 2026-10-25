// One finite C2 Android method; all device/process/private-input ownership is shared.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEnrollmentHost, cleanupEnrollmentResources, enrollmentPassed as passed,
  enrollmentPackage, enrollmentComponent, enrollmentShellQuote, registerEnrollmentReverses } from './enrollment-runtime-host.mjs';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';
import { enrollmentCommandObservation, enrollmentRuntimeProblem } from './enrollment-runtime-results.mjs';
import { enrollmentMessage } from './companion-enrollment-codec.mjs';
import { captureFactoryClass, captureFactoryMethod, captureFactoryReportPaths, createCaptureFactoryInvocationParser,
  createCaptureFactoryReport, verifyCaptureFactoryReport, captureFactoryRuntimeXml, captureFactoryRuntimeHtml } from './capture-factory-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const INPUT = 'no_backup/draft-enrollment-research/input-v1.bin';
const ensure = (condition, code) => { if (!condition) throw Error(code); };

export async function runCaptureFactoryRuntime(options) {
  const report = { format: 'http-freekit-capture-factory-runtime', revision: 1, source: null, api: null, clock: null,
    invocation: createCaptureFactoryInvocationParser().finish(), input: null, approval: null, host: null, resources: null, cleanup: null, problems: [] };
  const host = createEnrollmentHost(options), workers = [], mappings = [], tasks = [];
  let worker, metadata, invitation, registration, registrationTask, approvalTask, releaseTask, stage = 'host_setup_failed';
  const problem = code => { const safe = enrollmentRuntimeProblem(code); if (!report.problems.includes(safe) && report.problems.length < 16) report.problems.push(safe); };
  const tracked = operation => {
    const task = operation().catch(() => { problem('enrollment_invocation_failed'); host.abort(); return null; }); tasks.push(task); return task;
  };
  try {
    await host.prepare(report);
    stage = 'enrollment_fixture_failed';
    worker = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)), cwd: ROOT }); workers.push(worker);
    metadata = (await worker.request('startOrigin', { desktopRoot: options.desktopRoot, desktopCommit: options.desktopCommit, openssl: options.openssl }, { timeoutMillis: 60000 })).material();
    invitation = (await worker.request('createInvitation')).material();
    const initial = (await worker.request('snapshot')).material();
    ensure(Number.isSafeInteger(initial.enrollment?.issuer?.commandsStarted), stage);
    report.approval = { livePhaseObserved: false, requested: false, completed: false, approvedResponsesDelivered: 0, actualApprovedResponseDrops: 0,
      issuerCommandsBefore: initial.enrollment.issuer.commandsStarted, issuerCommandsAfter: null, issuerJobsAfter: null };
    report.host = { desktopCommit: options.desktopCommit, registered: false, liveReleasePhaseObserved: false,
      releaseRequested: false, releaseCompleted: false, gatewayStreamComplete: false, origin: null, backend: null };
    await registerEnrollmentReverses(host.adb, metadata, mappings);
    stage = 'enrollment_input_failed';
    const { webSocketPort, ...baseMetadata } = metadata;
    const input = encodeEnrollmentRuntimeInput(baseMetadata, invitation); let sent;
    try { sent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote(
      'umask 077; mkdir -p no_backup/draft-enrollment-research && chmod 700 no_backup/draft-enrollment-research && cat > ' + INPUT + ' && chmod 600 ' + INPUT)],
    10000, { stdinBytes: input }); } finally { input.fill(0); }
    report.input = { byteCount: input.length, inputBytes: sent.inputBytes ?? 0, inputFinished: sent.inputFinished === true,
      inputClosed: sent.inputClosed === true, command: enrollmentCommandObservation(sent), inputAbsentAfterMethod: false };
    ensure(passed(sent), stage);
    stage = 'enrollment_invocation_failed';
    let invocationLive = true, commandResult;
    const parser = createCaptureFactoryInvocationParser({ onPhase(phase) {
      ensure(invocationLive && !host.controller.signal.aborted, 'phase_after_command_close');
      if (phase === 'strict-csr-reserved') {
        ensure(!registrationTask, stage);
        registrationTask = tracked(async () => {
          registration = (await worker.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 })).material();
          enrollmentMessage('pair_response', registration);
          ensure(registration.type === 'pair_registered' && registration.desktopId === metadata.desktopId && registration.invitationId === invitation.invitationId, stage);
          report.host.registered = true; return true;
        });
      } else if (phase === 'awaiting-host-approval') {
        ensure(registrationTask && !approvalTask, 'enrollment_approval_failed'); report.approval.livePhaseObserved = true;
        approvalTask = tracked(async () => {
          ensure(await registrationTask, 'enrollment_approval_failed'); report.approval.requested = true;
          const approved = (await worker.request('approve', { enrollmentId: registration.enrollmentId })).material();
          enrollmentMessage('status_response', approved);
          ensure(approved.type === 'pair_approved' && approved.desktopId === metadata.desktopId && approved.enrollmentId === registration.enrollmentId &&
            approved.enrollmentAuthorityDer === metadata.enrollmentAuthorityDer && approved.capabilities.length === 1 && approved.capabilities[0] === 'tcp-http-origin-connect', 'enrollment_approval_failed');
          report.approval.completed = true; return true;
        });
      } else if (phase === 'application-output-shut') {
        ensure(approvalTask && !releaseTask, stage); report.host.liveReleasePhaseObserved = true;
        releaseTask = tracked(async () => {
          ensure(await approvalTask, stage); report.host.releaseRequested = true;
          // The child also requires actual decoded/applied/drained END_WRITE.
          const released = (await worker.request('releaseOriginTail', {}, { timeoutMillis: 10000 })).material();
          ensure(released.origin?.clientEndWriteApplied === true && released.origin.tailReleased === true, stage);
          report.host.releaseCompleted = true; return true;
        });
      }
    } });
    try {
      commandResult = await host.adb(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', captureFactoryClass + '#' + captureFactoryMethod,
        '-e', 'webSocketPort', String(webSocketPort), enrollmentComponent], 240000, { onStdoutChunk(chunk) { parser.push(chunk); } });
    } finally { invocationLive = false; report.invocation = parser.finish(commandResult); }
    ensure(report.invocation.state === 'passed', stage);
    ensure(await registrationTask, stage); ensure(await approvalTask, 'enrollment_approval_failed'); ensure(await releaseTask, stage);
    const deadline = performance.now() + 5000; let snapshot;
    while (true) {
      ensure(!host.controller.signal.aborted, stage); snapshot = (await worker.request('snapshot')).material();
      if (snapshot.gatewayStreamComplete === true && snapshot.backend?.activeOwners === 0) break;
      ensure(performance.now() < deadline, stage); await new Promise(done => setTimeout(done, 20));
    }
    report.host.gatewayStreamComplete = snapshot.gatewayStreamComplete;
    report.host.origin = snapshot.origin; report.host.backend = snapshot.backend;
    report.approval.approvedResponsesDelivered = snapshot.enrollment.approvedResponsesDelivered;
    report.approval.actualApprovedResponseDrops = snapshot.enrollment.droppedApprovedResponses;
    report.approval.issuerCommandsAfter = snapshot.enrollment.issuer.commandsStarted; report.approval.issuerJobsAfter = snapshot.enrollment.issuerJobs;
    const absent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote('test ! -e ' + INPUT + ' && echo FACTORY_INPUT_ABSENT')]);
    report.input.inputAbsentAfterMethod = passed(absent) && absent.stderrBytes === 0 && absent.output.trim() === 'FACTORY_INPUT_ABSENT';
    ensure(report.input.inputAbsentAfterMethod, 'enrollment_input_failed');
  } catch (error) {
    const code = typeof error?.message === 'string' && enrollmentRuntimeProblem(error.message) !== 'host_setup_failed' ? error.message : stage;
    problem(code);
  } finally {
    if (workers.length || mappings.length || tasks.length) {
      const { failed, ...resources } = await cleanupEnrollmentResources(host, { workers, mappings, tasks }, enrollmentCommandObservation);
      const closed = worker?.closedSnapshot()?.material();
      resources.privateDirectoryRemoved = closed?.privateDirectoryRemoved === true; resources.gatewayStreamComplete = closed?.gatewayStreamComplete === true;
      report.resources = resources;
      if (failed || !resources.privateDirectoryRemoved) problem('enrollment_cleanup_failed');
    }
    const { failed: packageFailed, ...cleanup } = await host.cleanupPackage(enrollmentCommandObservation);
    report.cleanup = { ...cleanup, ownedCommandsClosed: host.commands.every(value => value.closeObserved), ownedCommandGroupsClosed: host.commands.every(value => value.processGroupClosed) };
    if (packageFailed || !report.cleanup.ownedCommandsClosed || !report.cleanup.ownedCommandGroupsClosed) problem('enrollment_cleanup_failed');
    if (host.controller.signal.aborted) problem('research_run_cancelled'); host.dispose();
  }
  const final = createCaptureFactoryReport(report);
  for (const [name, text] of [['runtime', JSON.stringify(final, null, 2) + '\n'], ['xml', captureFactoryRuntimeXml(final)], ['html', captureFactoryRuntimeHtml(final)]]) {
    const filename = path.join(ROOT, captureFactoryReportPaths[name]); fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, text);
  }
  let ok = false; try { verifyCaptureFactoryReport(final, { source: final.source?.commit, api: final.api, desktopCommit: options.desktopCommit }); ok = true; } catch {}
  console.log(`Capture factory research: ${final.invocation.actualStarted} started, ${final.invocation.actualCompleted} completed; ${ok ? 'passed' : 'failed'}.`);
  if (!ok) console.error('Capture factory failure categories: ' + (final.problems.join(', ') || 'enrollment_invocation_failed'));
  return { ok, report: final };
}
