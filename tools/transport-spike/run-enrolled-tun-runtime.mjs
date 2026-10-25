// One finite C5 method; existing enrollment owners retain device/worker/process cleanup.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEnrollmentHost, cleanupEnrollmentResources, enrollmentPassed as passed,
  enrollmentPackage, enrollmentComponent, enrollmentShellQuote, registerEnrollmentReverses } from './enrollment-runtime-host.mjs';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';
import { enrollmentCommandObservation, enrollmentRuntimeProblem, enrollmentRuntimeValidation as V } from './enrollment-runtime-results.mjs';
import { enrollmentMessage } from './companion-enrollment-codec.mjs';
import { createEnrolledTunAliasOwner, publishEnrolledTunAcknowledgment } from './enrolled-tun-host.mjs';
import { enrolledTunClass, enrolledTunMethod, enrolledTunPayload, enrolledTunAcknowledgment, enrolledTunDesktopCommit, enrolledTunReportPaths,
  createEnrolledTunInvocationParser, createEnrolledTunReport, verifyEnrolledTunReport, projectEnrolledTunHostSnapshot,
  enrolledTunHostComplete, enrolledTunRuntimeXml, enrolledTunRuntimeHtml } from './enrolled-tun-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const INPUT = 'no_backup/draft-enrollment-research/input-v1.bin';
const ensure = (condition, code = 'enrollment_invocation_failed') => { if (!condition) throw Error(code); };
const absentScript = `set -eu
test ! -e ${INPUT}
test ! -L ${INPUT}
test ! -e ${enrolledTunAcknowledgment.path}
test ! -L ${enrolledTunAcknowledgment.path}
test ! -e no_backup/draft-enrollment-research/.tun-complete-v1.pending
test ! -L no_backup/draft-enrollment-research/.tun-complete-v1.pending
echo TUN_INPUT_AND_GATE_ABSENT`;
const packageAbsenceScript = `set -eu
packages="$(pm list packages ${enrollmentPackage})"
test -z "$packages"
if /system/bin/pidof ${enrollmentPackage} >/dev/null; then exit 1; else status=$?; test "$status" -eq 1; fi
echo TUN_INTEROP_ABSENT`;

// Dependency overrides are for finite owner/phase tests; the CLI always uses actual owners.
export async function runEnrolledTunRuntime(options, dependencies = {}) {
  const report = { format: 'http-freekit-enrolled-tun-runtime', revision: 1, source: null, api: null, clock: null,
    invocation: createEnrolledTunInvocationParser().finish(), input: null, approval: null, host: null,
    alias: null, ack: null, apkSetup: null, resources: null, cleanup: null, problems: [] };
  const host = (dependencies.createHost ?? createEnrollmentHost)(options), workers = [], mappings = [], tasks = [];
  const alias = (dependencies.createAlias ?? createEnrolledTunAliasOwner)(host.command, { platform: dependencies.platform ?? process.platform });
  report.alias = alias.snapshot();
  let worker, packages, metadata, invitation, registration, registrationTask, approvalTask, releaseTask, completionTask, stage = 'host_setup_failed';
  let invocationLive = false;
  const problem = code => { const safe = enrollmentRuntimeProblem(code); if (!report.problems.includes(safe) && report.problems.length < 16) report.problems.push(safe); };
  const live = () => ensure(invocationLive && !host.controller.signal.aborted, 'enrollment_invocation_failed');
  const tracked = operation => {
    const task = operation().catch(() => { problem('enrollment_invocation_failed'); host.abort(); return null; }); tasks.push(task); return task;
  };
  try {
    ensure(options.desktopCommit === enrolledTunDesktopCommit, 'enrollment_fixture_failed');
    // Unsupported hosts refuse before source/device/alias commands, without pretending to run Linux setup.
    if (report.alias.platform !== 'linux') await alias.prepare();
    await host.prepare(report);
    stage = 'research_apk_install_failed';
    const createPackages = dependencies.createPackages ?? (await import('./enrolled-tun-packages.mjs')).createEnrolledTunPackageOwner;
    packages = createPackages(host); await packages.prepare(report.api); report.apkSetup = packages.snapshot();
    stage = 'enrollment_fixture_failed'; await alias.prepare(); report.alias = alias.snapshot();
    worker = dependencies.createWorker ? dependencies.createWorker() : new EnrollmentRuntimeWorker({
      entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)), cwd: ROOT }); workers.push(worker);
    metadata = (await worker.request('startTunOrigin', { desktopRoot: options.desktopRoot, desktopCommit: options.desktopCommit, openssl: options.openssl }, { timeoutMillis: 60000 })).material();
    invitation = (await worker.request('createInvitation')).material();
    const initial = (await worker.request('snapshot')).material(); ensure(Number.isSafeInteger(initial.enrollment?.issuer?.commandsStarted), stage);
    report.approval = { livePhaseObserved: false, requested: false, completed: false, approvedResponsesDelivered: 0, actualApprovedResponseDrops: 0,
      issuerCommandsBefore: initial.enrollment.issuer.commandsStarted, issuerCommandsAfter: null, issuerJobsAfter: null };
    report.host = { desktopCommit: options.desktopCommit, registered: false, liveReleasePhaseObserved: false, releaseRequested: false, releaseCompleted: false,
      liveCompletionPhaseObserved: false, gatewayStreamComplete: false, completeObservedBeforeAck: false, androidAckPhaseObserved: false,
      profile: null, family: null, origin: null, backend: null };
    await registerEnrollmentReverses(host.adb, metadata, mappings);
    stage = 'enrollment_input_failed';
    const { webSocketPort, ...baseMetadata } = metadata, input = encodeEnrollmentRuntimeInput(baseMetadata, invitation); let sent;
    try { sent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote(
      'umask 077; mkdir -p no_backup/draft-enrollment-research && chmod 700 no_backup/draft-enrollment-research && cat > ' + INPUT + ' && chmod 600 ' + INPUT)],
    10000, { stdinBytes: input }); } finally { input.fill(0); }
    report.input = { byteCount: input.length, inputBytes: sent.inputBytes ?? 0, inputFinished: sent.inputFinished === true,
      inputClosed: sent.inputClosed === true, command: enrollmentCommandObservation(sent), inputAbsentAfterMethod: false };
    ensure(passed(sent) && sent.stderrBytes === 0 && sent.inputBytes === input.length && sent.inputFinished && sent.inputClosed, stage);
    stage = 'enrollment_invocation_failed'; invocationLive = true; let commandResult;
    const parser = createEnrolledTunInvocationParser({ onPhase(phase) {
      live();
      if (phase === 'strict-csr-reserved') {
        ensure(!registrationTask);
        registrationTask = tracked(async () => {
          registration = (await worker.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 })).material();
          enrollmentMessage('pair_response', registration); live();
          ensure(registration.type === 'pair_registered' && registration.desktopId === metadata.desktopId && registration.invitationId === invitation.invitationId);
          report.host.registered = true; return true;
        });
      } else if (phase === 'awaiting-host-approval') {
        ensure(registrationTask && !approvalTask, 'enrollment_approval_failed'); report.approval.livePhaseObserved = true;
        approvalTask = tracked(async () => {
          ensure(await registrationTask, 'enrollment_approval_failed'); live(); report.approval.requested = true;
          const approved = (await worker.request('approve', { enrollmentId: registration.enrollmentId })).material();
          enrollmentMessage('status_response', approved);
          ensure(approved.type === 'pair_approved' && approved.desktopId === metadata.desktopId && approved.enrollmentId === registration.enrollmentId &&
            approved.enrollmentAuthorityDer === metadata.enrollmentAuthorityDer && JSON.stringify(approved.capabilities) === JSON.stringify(enrolledTunPayload.gatewayCapabilities), 'enrollment_approval_failed');
          report.approval.completed = true; return true;
        });
      } else if (phase === 'http-command-started') {
        ensure(approvalTask && !releaseTask); report.host.liveReleasePhaseObserved = true;
        releaseTask = tracked(async () => {
          ensure(await approvalTask); live(); report.host.releaseRequested = true;
          const released = (await worker.request('releaseOriginTail', {}, { timeoutMillis: 20000 })).material();
          ensure(released.origin?.clientEndWriteApplied === true && released.origin.tailReleased === true); report.host.releaseCompleted = true; return true;
        });
      } else if (phase === 'local-stream-drained') {
        ensure(releaseTask && !completionTask); report.host.liveCompletionPhaseObserved = true;
        completionTask = tracked(async () => {
          ensure(await releaseTask); live(); const deadline = performance.now() + 5000; let snapshot;
          while (true) {
            live(); const remaining = Math.floor(deadline - performance.now()); ensure(remaining > 0);
            const observed = (await worker.request('snapshot', {}, { timeoutMillis: Math.min(1000, remaining) })).material();
            live(); ensure(performance.now() <= deadline);
            if (enrolledTunHostComplete(observed)) { snapshot = observed; break; }
            ensure(performance.now() < deadline); await new Promise(done => setTimeout(done, 20));
          }
          Object.assign(report.host, projectEnrolledTunHostSnapshot(snapshot));
          report.approval.approvedResponsesDelivered = snapshot.enrollment.approvedResponsesDelivered;
          report.approval.actualApprovedResponseDrops = snapshot.enrollment.droppedApprovedResponses;
          report.approval.issuerCommandsAfter = snapshot.enrollment.issuer.commandsStarted; report.approval.issuerJobsAfter = snapshot.enrollment.issuerJobs;
          live(); report.host.completeObservedBeforeAck = true;
          report.ack = { ...await (dependencies.publishAcknowledgment ?? publishEnrolledTunAcknowledgment)(host), absentAfterMethod: false };
          ensure(report.ack.published); return true;
        });
      } else if (phase === 'gateway-complete-acknowledged') {
        // Android can consume the atomically renamed file before the ADB publication receipt resolves.
        ensure(completionTask && report.host.completeObservedBeforeAck); report.host.androidAckPhaseObserved = true;
      }
    } });
    try {
      commandResult = await host.adb(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', enrolledTunClass + '#' + enrolledTunMethod,
        '-e', 'webSocketPort', String(webSocketPort), enrollmentComponent], 300000, { onStdoutChunk(chunk) { parser.push(chunk); } });
    } finally { invocationLive = false; report.invocation = parser.finish(commandResult); }
    ensure(report.invocation.state === 'passed');
    ensure(await registrationTask); ensure(await approvalTask, 'enrollment_approval_failed'); ensure(await releaseTask); ensure(await completionTask);
    const absent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote(absentScript)]);
    const filesAbsent = passed(absent) && absent.stderrBytes === 0 && absent.output.trim() === 'TUN_INPUT_AND_GATE_ABSENT';
    report.input.inputAbsentAfterMethod = filesAbsent; report.ack.absentAfterMethod = filesAbsent; ensure(filesAbsent, 'enrollment_input_failed');
  } catch (error) {
    const code = typeof error?.message === 'string' && enrollmentRuntimeProblem(error.message) !== 'host_setup_failed' ? error.message : stage; problem(code);
  } finally {
    invocationLive = false;
    if (workers.length || mappings.length || tasks.length) {
      try {
        const { failed, ...resources } = await cleanupEnrollmentResources(host, { workers, mappings, tasks }, enrollmentCommandObservation);
        const closed = worker?.closedSnapshot()?.material(); resources.privateDirectoryRemoved = closed?.privateDirectoryRemoved === true; resources.gatewayStreamComplete = closed?.gatewayStreamComplete === true;
        report.resources = resources; if (failed || !resources.privateDirectoryRemoved) problem('enrollment_cleanup_failed');
      } catch { problem('enrollment_cleanup_failed'); }
    }
    if (packages) {
      try { const result = await packages.cleanup(); if (result.failed) problem('enrollment_cleanup_failed'); }
      catch { problem('enrollment_cleanup_failed'); }
      report.apkSetup = packages.snapshot();
    }
    const { failed: packageFailed, ...cleanup } = await host.cleanupPackage(enrollmentCommandObservation);
    report.cleanup = { ...cleanup, packageAbsentAfterCleanup: false, ownedCommandsClosed: false, ownedCommandGroupsClosed: false };
    if (host.installAttempted) {
      try { const absent = await host.adb(['shell', '-T', 'sh', '-c', enrollmentShellQuote(packageAbsenceScript)], 10000, {}, true);
        report.cleanup.packageAbsentAfterCleanup = passed(absent) && absent.stderrBytes === 0 && absent.output.trim() === 'TUN_INTEROP_ABSENT'; }
      catch { problem('enrollment_cleanup_failed'); }
    }
    const fixtureJoined = workers.length === 0 || V.workerPassed(report.resources?.workerClosed ?? null) && V.commandPassed(report.resources?.workerCommand ?? null);
    try { await alias.remove({ fixtureJoined }); } catch { problem('enrollment_cleanup_failed'); } report.alias = alias.snapshot();
    report.cleanup.ownedCommandsClosed = host.commands.every(value => value.closeObserved);
    report.cleanup.ownedCommandGroupsClosed = host.commands.every(value => value.processGroupClosed);
    if (packageFailed || host.installAttempted && !report.cleanup.packageAbsentAfterCleanup || !report.cleanup.ownedCommandsClosed || !report.cleanup.ownedCommandGroupsClosed) problem('enrollment_cleanup_failed');
    if (host.controller.signal.aborted) problem('research_run_cancelled'); host.dispose();
  }
  const final = createEnrolledTunReport(report);
  if (dependencies.writeReports !== false) for (const [name, text] of [['runtime', JSON.stringify(final, null, 2) + '\n'], ['xml', enrolledTunRuntimeXml(final)], ['html', enrolledTunRuntimeHtml(final)]]) {
    const filename = path.join(ROOT, enrolledTunReportPaths[name]); fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, text);
  }
  let ok = false; try { verifyEnrolledTunReport(final, { source: final.source?.commit, api: final.api, desktopCommit: options.desktopCommit }); ok = true; } catch {}
  console.log(`Enrolled TUN research: ${final.invocation.actualStarted} started, ${final.invocation.actualCompleted} completed; ${ok ? 'passed' : 'failed'}.`);
  if (!ok) console.error('Enrolled TUN failure categories: ' + (final.problems.join(', ') || 'enrollment_invocation_failed'));
  return { ok, report: final };
}
