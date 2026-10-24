// A22b finite suite. Shared host owns device/process setup and cleanup; no production entry point.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createEnrollmentHost, cleanupEnrollmentResources, enrollmentPassed as passed,
  enrollmentPackage, enrollmentComponent, enrollmentShellQuote, registerEnrollmentReverses } from './enrollment-runtime-host.mjs';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { encodeEnrolledStreamInput } from './enrollment-runtime-stream-input.mjs';
import { enrollmentCommandObservation, enrollmentRuntimeProblem } from './enrollment-runtime-results.mjs';
import { enrolledStreamingClass, enrolledStreamingCases, enrolledStreamingReportPaths,
  createEnrolledStreamingInvocationParser, projectEnrolledHostSnapshot, createEnrolledStreamingReport,
  verifyEnrolledStreamingReport, enrolledStreamingRuntimeXml, enrolledStreamingRuntimeHtml } from './enrollment-runtime-stream-results.mjs';
import { enrollmentMessage } from './companion-enrollment-codec.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const INPUT = 'no_backup/draft-enrollment-research/stream-input-v1.bin';
const inactive = value => ['closed', 'failed'].includes(value);
const ensure = (condition, stage) => { if (!condition) throw Error(stage); };
function problem(list, code) { const safe = enrollmentRuntimeProblem(code); if (!list.includes(safe) && list.length < 16) list.push(safe); }
function pending(value) {
  return value && value.available && value.grantValid && value.controlPhase === 'active' &&
    ['open', 'half_closed'].includes(value.streamPhase) && value.sessionLease && value.streamLeases === 1 &&
    value.chargedBytes > 0 && value.chargedBytes <= 8192 && value.chargedFrames > 0 && value.chargedFrames <= 4 &&
    value.proxyReadPaused && value.proxyWritePending && value.pendingIngressBytes === 4096 &&
    value.proxyWriteEntries > value.proxyWriteCompletions;
}

export async function runEnrolledStreamRuntime(options) {
  const report = { format: 'http-freekit-a22b-runtime', revision: 1, source: null, api: null, clock: null,
    scenarios: enrolledStreamingCases.map(({ method, scenario }) => ({ method, scenario,
      invocation: createEnrolledStreamingInvocationParser(method).finish(), input: null, approval: null,
      profile: null, host: null, cleanup: null, problems: [] })), cleanup: null, problems: [] };
  const host = createEnrollmentHost(options), origin = process.hrtime.bigint();
  const nanos = () => Number(process.hrtime.bigint() - origin);
  let stage = 'host_setup_failed';
  try {
    await host.prepare(report);
    for (const [index, descriptor] of enrolledStreamingCases.entries()) {
      const item = report.scenarios[index], workers = [], mappings = [], tasks = [];
      const commandStart = host.commands.length;
      let directory, worker, metadata, invitation, registration, approved, approvalTask, proofTask, revokeTask;
      let caseLive = true, methodPassed = false;
      const failTask = code => { problem(item.problems, code); host.abort(); };
      const tracked = (operation, code) => {
        const task = operation().catch(() => { failTask(code); return null; }); tasks.push(task); return task;
      };
      const inspect = async () => {
        ensure(registration, 'enrollment_invocation_failed');
        const callStartedNanos = nanos();
        const value = (await worker.request('inspectEnrollment', { enrollmentId: registration.enrollmentId })).material();
        return projectEnrolledHostSnapshot(value, { callStartedNanos, callReceivedNanos: nanos() });
      };
      const collectProxyProof = async () => {
        const until = nanos() + 10000000000;
        let first = null;
        while (caseLive && !host.controller.signal.aborted && nanos() < until) {
          const sample = await inspect();
          if (!pending(sample)) first = null;
          else {
            if (!first || first.proxyWriteEntries !== sample.proxyWriteEntries || first.proxyWriteCompletions !== sample.proxyWriteCompletions) first = sample;
            else if (sample.callStartedNanos - first.callReceivedNanos >= 250000000) {
              item.host.blockedFirst = first; item.host.blockedLast = sample; return true;
            }
          }
          await delay(25, undefined, { signal: host.controller.signal });
        }
        throw Error('enrollment_invocation_failed');
      };
      const startRevoke = () => {
        ensure(proofTask && !revokeTask, 'enrollment_invocation_failed');
        revokeTask = tracked(async () => {
          ensure(await proofTask, 'enrollment_invocation_failed');
          ensure(caseLive && !host.controller.signal.aborted, 'research_run_cancelled');
          const ended = (await worker.request('revoke', { enrollmentId: registration.enrollmentId })).material();
          ensure(ended.type === 'pair_ended' && ended.code === 'device_revoked', 'enrollment_invocation_failed');
          item.host.revokeAcknowledged = true; item.host.credentialStatus = 'revoked'; item.host.credentialStatusObservedUtcMillis = Date.now();
        }, 'enrollment_invocation_failed');
      };
      try {
        stage = 'enrollment_fixture_failed';
        directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'freekit-enrollment-runtime-')); fs.chmodSync(directory, 0o700);
        worker = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)), cwd: ROOT }); workers.push(worker);
        metadata = (await worker.request('startStreaming', { directory, mode: 'create', openssl: options.openssl,
          setupPort: 0, credentialPort: 0, streamPort: 0, credentialLifetimeSeconds: descriptor.credentialLifetimeSeconds,
          sessionLifetimeMillis: descriptor.sessionLifetimeMillis }, { timeoutMillis: 60000 })).material();
        invitation = (await worker.request('createInvitation')).material();
        await registerEnrollmentReverses(host.adb, metadata, mappings);
        stage = 'enrollment_input_failed';
        const input = encodeEnrolledStreamInput(metadata, invitation, descriptor.inputScenario);
        let sent;
        try { sent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote(
          'umask 077; mkdir -p no_backup/draft-enrollment-research && chmod 700 no_backup/draft-enrollment-research && cat > ' + INPUT + ' && chmod 600 ' + INPUT)],
        10000, { stdinBytes: input }); } finally { input.fill(0); }
        item.input = { byteCount: input.length, inputBytes: sent.inputBytes ?? 0, inputFinished: sent.inputFinished === true,
          inputClosed: sent.inputClosed === true, command: enrollmentCommandObservation(sent), inputAbsentAfterPrepare: false };
        ensure(passed(sent), stage);
        item.approval = { liveAwaitingPhaseObserved: false, requested: false, completed: false, approvedResponsesDelivered: 0, actualApprovedResponseDrops: 0 };
        item.host = { awaitingPhaseObserved: false, blockedFirst: null, blockedLast: null, terminal: null, revokeAcknowledged: false,
          credentialStatus: null, credentialStatusObservedUtcMillis: null, credentialStatusAfterMethod: false };
        stage = 'enrollment_invocation_failed';
        let invocationLive = true, result;
        const parser = createEnrolledStreamingInvocationParser(descriptor.method, { onPhase(phase) {
          ensure(invocationLive && !host.controller.signal.aborted, 'phase_after_command_close');
          if (phase === 'awaiting-host-approval') {
            ensure(!approvalTask, 'enrollment_approval_failed'); item.approval.liveAwaitingPhaseObserved = true;
            approvalTask = tracked(async () => {
              registration = (await worker.request('waitForRegistered', { invitationId: invitation.invitationId, timeoutMillis: 10000 })).material();
              item.approval.requested = true;
              approved = (await worker.request('approve', { enrollmentId: registration.enrollmentId })).material();
              ensure(approved.type === 'pair_approved', 'enrollment_approval_failed'); enrollmentMessage('status_response', approved);
              item.approval.completed = true;
              const profile = { credentialLifetimeSeconds: descriptor.credentialLifetimeSeconds, sessionLifetimeMillis: descriptor.sessionLifetimeMillis,
                credentialExpiresUtcMillis: Date.parse(approved.credentialExpiresAt), gatewayExpiresUtcMillis: Date.parse(new X509Certificate(Buffer.from(metadata.gatewayCertificateDer, 'base64url')).validTo),
                anchorExpiresUtcMillis: Date.parse(new X509Certificate(Buffer.from(approved.enrollmentAuthorityDer, 'base64url')).validTo) };
              ensure(Object.values(profile).every(Number.isSafeInteger) && approved.enrollmentAuthorityDer === metadata.enrollmentAuthorityDer &&
                approved.desktopId === metadata.desktopId && approved.enrollmentId === registration.enrollmentId &&
                profile.credentialExpiresUtcMillis === Date.parse(new X509Certificate(Buffer.from(approved.clientCertificateDer, 'base64url')).validTo), 'enrollment_approval_failed');
              item.profile = profile;
            }, 'enrollment_approval_failed');
          } else if (phase === 'bounded-stream-ready') {
            ensure(!proofTask, 'enrollment_invocation_failed'); proofTask = tracked(collectProxyProof, 'enrollment_invocation_failed');
          } else if (phase === descriptor.phases[7]) {
            item.host.awaitingPhaseObserved = true;
            if (descriptor.scenario === 'revocation') startRevoke();
          }
        } });
        try {
          result = await host.adb(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', enrolledStreamingClass + '#' + descriptor.method, enrollmentComponent],
            240000, { onStdoutChunk(chunk) { parser.push(chunk); } });
        } finally { invocationLive = false; item.invocation = parser.finish(result); }
        ensure(item.invocation.state === 'passed', stage);
        await approvalTask; ensure(item.approval.completed && approved && item.profile, 'enrollment_approval_failed');
        ensure(await proofTask, stage); if (revokeTask) await revokeTask;
        const absent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote('test ! -e ' + INPUT + ' && echo ENROLLED_INPUT_ABSENT')]);
        item.input.inputAbsentAfterPrepare = passed(absent) && absent.stderrBytes === 0 && absent.output.trim() === 'ENROLLED_INPUT_ABSENT';
        ensure(item.input.inputAbsentAfterPrepare, 'enrollment_input_failed');
        if (descriptor.scenario !== 'revocation') {
          if (descriptor.scenario === 'credential_expiry') {
            const until = nanos() + 5000000000;
            while (Date.now() < item.profile.credentialExpiresUtcMillis && nanos() < until) await delay(25, undefined, { signal: host.controller.signal });
            ensure(Date.now() >= item.profile.credentialExpiresUtcMillis, stage);
          }
          const current = (await worker.request('readResult', { enrollmentId: registration.enrollmentId })).material();
          if (descriptor.scenario === 'credential_expiry') {
            ensure(current.type === 'pair_ended' && current.code === 'credential_expired', stage);
            item.host.credentialStatus = 'credential_expired'; item.host.credentialStatusAfterMethod = true;
          } else {
            ensure(current.type === 'pair_approved' && current.clientCertificateDer === approved.clientCertificateDer && current.deviceId === approved.deviceId, stage);
            item.host.credentialStatus = 'active';
          }
          item.host.credentialStatusObservedUtcMillis = Date.now();
        }
        const until = nanos() + 5000000000;
        do {
          item.host.terminal = await inspect();
          if (item.host.terminal?.cleanupComplete && item.host.terminal.ownerResourcesReleased && inactive(item.host.terminal.controlPhase)) break;
          await delay(25, undefined, { signal: host.controller.signal });
        } while (nanos() < until);
        ensure(item.host.terminal?.cleanupComplete && item.host.terminal.ownerResourcesReleased, stage);
        const snapshot = (await worker.request('snapshot')).material();
        item.approval.approvedResponsesDelivered = snapshot.approvedResponsesDelivered;
        item.approval.actualApprovedResponseDrops = snapshot.droppedApprovedResponses;
        methodPassed = true;
      } catch (error) {
        const code = typeof error?.message === 'string' && enrollmentRuntimeProblem(error.message) !== 'host_setup_failed' ? error.message : stage;
        problem(item.problems, code);
      } finally {
        caseLive = false;
        const { failed, ...cleanup } = await cleanupEnrollmentResources(host, { workers, mappings, directory, tasks, commandStart }, enrollmentCommandObservation);
        item.cleanup = cleanup;
        if (failed) problem(item.problems, 'enrollment_cleanup_failed');
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
    if (host.controller.signal.aborted) problem(report.problems, 'research_run_cancelled');
    host.dispose();
  }
  const final = createEnrolledStreamingReport(report);
  for (const [name, text] of [['runtime', JSON.stringify(final, null, 2) + '\n'], ['xml', enrolledStreamingRuntimeXml(final)], ['html', enrolledStreamingRuntimeHtml(final)]]) {
    const filename = path.join(ROOT, enrolledStreamingReportPaths[name]); fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, text);
  }
  let ok = false;
  try { verifyEnrolledStreamingReport(final, { source: final.source?.commit, api: final.api }); ok = true; } catch {}
  console.log('Enrolled streaming research: ' + final.scenarios.reduce((count, value) => count + value.invocation.actualStarted, 0) + ' started, ' +
    final.scenarios.reduce((count, value) => count + value.invocation.actualCompleted, 0) + ' completed; ' + (ok ? 'passed' : 'failed') + '.');
  if (!ok) console.error('Enrolled streaming failure categories: ' + (final.problems.join(', ') || 'enrollment_invocation_failed'));
  return { ok, report: final };
}
