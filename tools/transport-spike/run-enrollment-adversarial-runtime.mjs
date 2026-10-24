// Four finite Android enrollment checks, using the existing owned device/worker lifecycle.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { createEnrollmentHost, cleanupEnrollmentResources, enrollmentPassed as passed,
  enrollmentPackage, enrollmentComponent, enrollmentShellQuote, registerEnrollmentReverses } from './enrollment-runtime-host.mjs';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';
import { enrollmentCommandObservation, enrollmentRuntimeProblem } from './enrollment-runtime-results.mjs';
import { enrollmentMessage } from './companion-enrollment-codec.mjs';
import { enrollmentAdversarialClass as adversarialEnrollmentClass, enrollmentAdversarialCases as adversarialEnrollmentCases,
  enrollmentAdversarialReportPaths as adversarialEnrollmentReportPaths,
  createEnrollmentAdversarialInvocationParser as createAdversarialEnrollmentInvocationParser,
  createEnrollmentAdversarialReport as createAdversarialEnrollmentReport, verifyEnrollmentAdversarialReport as verifyAdversarialEnrollmentReport,
  enrollmentAdversarialRuntimeXml as adversarialEnrollmentRuntimeXml, enrollmentAdversarialRuntimeHtml as adversarialEnrollmentRuntimeHtml } from './enrollment-runtime-adversarial-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const INPUT = 'no_backup/draft-enrollment-research/input-v1.bin';
const TLS_METHOD = 'wrongGatewayPeerFailsTlsWithoutEnrollmentMutation';
const CANCEL_METHOD = 'pendingCancellationRejectsLateApprovalWithoutSavingCredential';
const APPROVED_METHOD = 'publishedCancellationRevokesSavedCredential';
const ensure = (condition, stage) => { if (!condition) throw Error(stage); };
function problem(list, code) { const safe = enrollmentRuntimeProblem(code); if (!list.includes(safe) && list.length < 16) list.push(safe); }
function counts(value) {
  const result = { dispatches: value.dispatches, issuerCommands: value.issuer?.commandsStarted, issuerJobs: value.issuerJobs };
  ensure(Object.values(result).every(number => Number.isSafeInteger(number) && number >= 0), 'enrollment_fixture_failed');
  return result;
}

export async function runEnrollmentAdversarialRuntime(options) {
  const report = { format: 'http-freekit-a22c-runtime', revision: 1, source: null, api: null, clock: null,
    scenarios: adversarialEnrollmentCases.map(({ method, scenario }) => ({ method, scenario,
      invocation: createAdversarialEnrollmentInvocationParser(method).finish(), input: null, approval: null,
      host: null, cleanup: null, problems: [] })), cleanup: null, problems: [] };
  const host = createEnrollmentHost(options);
  let stage = 'host_setup_failed';
  try {
    await host.prepare(report);
    for (const [index, descriptor] of adversarialEnrollmentCases.entries()) {
      const item = report.scenarios[index], workers = [], mappings = [], tasks = [], commandStart = host.commands.length;
      let directory, worker, metadata, invitation, registration, registrationTask, approvalTask, lateApprovalTask;
      let methodPassed = false;
      const tracked = operation => {
        const task = operation().catch(() => { problem(item.problems, 'enrollment_invocation_failed'); host.abort(); return null; });
        tasks.push(task); return task;
      };
      try {
        stage = 'enrollment_fixture_failed';
        directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'freekit-enrollment-runtime-')); fs.chmodSync(directory, 0o700);
        worker = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)), cwd: ROOT }); workers.push(worker);
        const tls = descriptor.method === TLS_METHOD, published = descriptor.method === APPROVED_METHOD;
        metadata = (await worker.request(tls ? 'startAdversarial' : 'start', { directory, mode: 'create', openssl: options.openssl,
          setupPort: 0, credentialPort: 0 }, { timeoutMillis: 60000 })).material();
        invitation = (await worker.request('createInvitation')).material();
        const before = counts((await worker.request('snapshot')).material());
        item.host = { registered: false, result: null, resultAfterMethod: false, dispatchesBefore: before.dispatches, dispatchesAfter: null,
          issuerCommandsBefore: before.issuerCommands, issuerCommandsAfter: null, issuerJobsAfter: null,
          lateApproval: descriptor.method === CANCEL_METHOD ? { livePhaseObserved: false, requested: false, completed: false, error: null, resultAfterAttempt: null } : null,
          alternateTls: null };
        await registerEnrollmentReverses(host.adb, metadata, mappings);
        stage = 'enrollment_input_failed';
        const { adversarialPeerPort, ...baseMetadata } = metadata;
        const input = encodeEnrollmentRuntimeInput(tls ? baseMetadata : metadata, invitation);
        let sent;
        try { sent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote(
          'umask 077; mkdir -p no_backup/draft-enrollment-research && chmod 700 no_backup/draft-enrollment-research && cat > ' + INPUT + ' && chmod 600 ' + INPUT)],
        10000, { stdinBytes: input }); } finally { input.fill(0); }
        item.input = { byteCount: input.length, inputBytes: sent.inputBytes ?? 0, inputFinished: sent.inputFinished === true,
          inputClosed: sent.inputClosed === true, command: enrollmentCommandObservation(sent), inputAbsentAfterPrepare: false };
        ensure(passed(sent), stage);
        if (published) item.approval = { liveAwaitingPhaseObserved: false, requested: false, completed: false,
          approvedResponsesDelivered: 0, actualApprovedResponseDrops: 0, issuerCommandsAfterApproval: null, credentialExpiresUtcMillis: null };
        stage = 'enrollment_invocation_failed';
        let invocationLive = true, result;
        const parser = createAdversarialEnrollmentInvocationParser(descriptor.method, { onPhase(phase) {
          ensure(invocationLive && !host.controller.signal.aborted, 'phase_after_command_close');
          if (phase === 'strict-csr-reserved') {
            ensure(!registrationTask, stage);
            registrationTask = tracked(async () => {
              registration = (await worker.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 })).material();
              enrollmentMessage('pair_response', registration);
              ensure(registration.type === 'pair_registered' && registration.desktopId === metadata.desktopId &&
                registration.invitationId === invitation.invitationId, 'enrollment_invocation_failed');
              item.host.registered = true; return registration;
            });
          } else if (phase === 'awaiting-host-approval') {
            ensure(published && registrationTask && !approvalTask, 'enrollment_approval_failed');
            item.approval.liveAwaitingPhaseObserved = true;
            approvalTask = tracked(async () => {
              ensure(await registrationTask, 'enrollment_approval_failed');
              item.approval.requested = true;
              const approved = (await worker.request('approve', { enrollmentId: registration.enrollmentId })).material();
              ensure(approved.type === 'pair_approved' && approved.desktopId === metadata.desktopId &&
                approved.enrollmentId === registration.enrollmentId && approved.enrollmentAuthorityDer === metadata.enrollmentAuthorityDer, 'enrollment_approval_failed');
              enrollmentMessage('status_response', approved);
              const leaf = Buffer.from(approved.clientCertificateDer, 'base64url'), certificate = new X509Certificate(leaf);
              const expires = Date.parse(certificate.validTo);
              ensure(certificate.raw.equals(leaf) && Number.isSafeInteger(expires) && expires === Date.parse(approved.credentialExpiresAt), 'enrollment_approval_failed');
              item.approval.credentialExpiresUtcMillis = expires;
              item.approval.issuerCommandsAfterApproval = counts((await worker.request('snapshot')).material()).issuerCommands;
              item.approval.completed = true; return true;
            });
          } else if (phase === 'awaiting-late-approval') {
            ensure(descriptor.method === CANCEL_METHOD && registrationTask && !lateApprovalTask, stage);
            item.host.lateApproval.livePhaseObserved = true;
            lateApprovalTask = tracked(async () => {
              ensure(await registrationTask, 'enrollment_invocation_failed');
              item.host.lateApproval.requested = true;
              try { await worker.request('approve', { enrollmentId: registration.enrollmentId }); throw Error('enrollment_invocation_failed'); }
              catch (error) { ensure(error?.code === 'invitation_used', 'enrollment_invocation_failed'); item.host.lateApproval.error = 'invitation_used'; }
              item.host.lateApproval.completed = true;
              const ended = (await worker.request('readResult', { enrollmentId: registration.enrollmentId })).material();
              enrollmentMessage('status_response', ended);
              ensure(ended.type === 'pair_ended' && ended.code === 'pairing_cancelled' &&
                ended.desktopId === registration.desktopId && ended.enrollmentId === registration.enrollmentId, 'enrollment_invocation_failed');
              item.host.lateApproval.resultAfterAttempt = 'cancelled'; return true;
            });
          }
        } });
        try {
          result = await host.adb(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', adversarialEnrollmentClass + '#' + descriptor.method,
            ...(tls ? ['-e', 'adversarialPeerPort', String(adversarialPeerPort)] : []), enrollmentComponent],
          240000, { onStdoutChunk(chunk) { parser.push(chunk); } });
        } finally { invocationLive = false; item.invocation = parser.finish(result); }
        ensure(item.invocation.state === 'passed', stage);
        ensure(await registrationTask, stage);
        if (published) ensure(await approvalTask, 'enrollment_approval_failed');
        if (descriptor.method === CANCEL_METHOD) ensure(await lateApprovalTask, stage);
        const current = (await worker.request('readResult', { enrollmentId: registration.enrollmentId })).material();
        enrollmentMessage('status_response', current);
        ensure(current.desktopId === registration.desktopId && current.enrollmentId === registration.enrollmentId &&
          (current.type !== 'pair_pending' || current.reservationExpiresAt === registration.reservationExpiresAt), stage);
        ensure(current.type === 'pair_pending' || (current.type === 'pair_ended' && current.code === 'pairing_cancelled'), stage);
        item.host.result = current.type === 'pair_pending' ? 'pending' : 'cancelled'; item.host.resultAfterMethod = true;
        const snapshot = (await worker.request('snapshot')).material(), after = counts(snapshot);
        item.host.dispatchesAfter = after.dispatches; item.host.issuerCommandsAfter = after.issuerCommands; item.host.issuerJobsAfter = after.issuerJobs;
        if (tls) item.host.alternateTls = snapshot.alternateTls;
        if (published) { item.approval.approvedResponsesDelivered = snapshot.approvedResponsesDelivered; item.approval.actualApprovedResponseDrops = snapshot.droppedApprovedResponses; }
        const absent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote('test ! -e ' + INPUT + ' && echo ADVERSARIAL_INPUT_ABSENT')]);
        item.input.inputAbsentAfterPrepare = passed(absent) && absent.stderrBytes === 0 && absent.output.trim() === 'ADVERSARIAL_INPUT_ABSENT';
        ensure(item.input.inputAbsentAfterPrepare, 'enrollment_input_failed'); methodPassed = true;
      } catch (error) {
        const code = typeof error?.message === 'string' && enrollmentRuntimeProblem(error.message) !== 'host_setup_failed' ? error.message : stage;
        problem(item.problems, code);
      } finally {
        const { failed, ...cleanup } = await cleanupEnrollmentResources(host, { workers, mappings, directory, tasks, commandStart }, enrollmentCommandObservation);
        item.cleanup = cleanup; if (failed) problem(item.problems, 'enrollment_cleanup_failed');
      }
      if (!methodPassed || item.problems.length || host.controller.signal.aborted) break;
    }
  } catch (error) {
    const code = typeof error?.message === 'string' && enrollmentRuntimeProblem(error.message) !== 'host_setup_failed' ? error.message : stage;
    problem(report.problems, code);
  } finally {
    const { failed, ...cleanup } = await host.cleanupPackage(enrollmentCommandObservation);
    report.cleanup = { ...cleanup, ownedCommandsClosed: host.commands.every(value => value.closeObserved),
      ownedCommandGroupsClosed: host.commands.every(value => value.processGroupClosed) };
    if (failed || !report.cleanup.ownedCommandsClosed || !report.cleanup.ownedCommandGroupsClosed) problem(report.problems, 'enrollment_cleanup_failed');
    if (host.controller.signal.aborted) problem(report.problems, 'research_run_cancelled'); host.dispose();
  }
  const final = createAdversarialEnrollmentReport(report);
  for (const [name, text] of [['runtime', JSON.stringify(final, null, 2) + '\n'], ['xml', adversarialEnrollmentRuntimeXml(final)], ['html', adversarialEnrollmentRuntimeHtml(final)]]) {
    const filename = path.join(ROOT, adversarialEnrollmentReportPaths[name]); fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, text);
  }
  let ok = false;
  try { verifyAdversarialEnrollmentReport(final, { source: final.source?.commit, api: final.api }); ok = true; } catch {}
  console.log('Adversarial enrollment research: ' + final.scenarios.reduce((count, value) => count + value.invocation.actualStarted, 0) + ' started, ' +
    final.scenarios.reduce((count, value) => count + value.invocation.actualCompleted, 0) + ' completed; ' + (ok ? 'passed' : 'failed') + '.');
  if (!ok) console.error('Adversarial enrollment failure categories: ' + (final.problems.join(', ') || 'enrollment_invocation_failed'));
  return { ok, report: final };
}
