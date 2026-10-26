// Independent finite reference fixture research; never invokes C5/desktop workers.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createEnrollmentHost, enrollmentPassed as passed, enrollmentPackage, enrollmentComponent,
  enrollmentShellQuote as quote, registerEnrollmentReverses, enrollmentOwnedReversesAbsent, enrollmentClosedProjection } from './enrollment-runtime-host.mjs';
import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';
import { enrollmentMessage } from './companion-enrollment-codec.mjs';
import { enrollmentCommandObservation as commandObservation, enrollmentRuntimeValidation as V } from './enrollment-runtime-results.mjs';
import { referenceTunClass, referenceTunMethods, referenceTunAcknowledgment as gate, referenceTunReportPaths,
  referenceTunReportFormat, referenceTunPayload, referenceTunProblems, createReferenceTunInvocationParser,
  projectReferenceTunHost, referenceTunHostComplete, referenceTunProcessJoined, createReferenceTunReport, verifyReferenceTunReport,
  referenceTunRuntimeXml, referenceTunRuntimeHtml } from './reference-tun-results.mjs';
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const INPUT = 'no_backup/draft-enrollment-research/input-v1.bin';
const ensure = (condition, code = 'enrollment_invocation_failed') => { if (!condition) throw Error(code); };
export const referenceTunGateScript = `set -eu
umask 077
directory=no_backup/draft-enrollment-research
temporary="$directory/.reference-tun-complete-v1.pending"
destination="$directory/reference-tun-complete-v1.bin"
created=false
cleanup() {
  status=$?
  trap - EXIT
  if [ "$created" = true ]; then
    if rm -f "$temporary"; then :; elif [ "$status" -eq 0 ]; then status=1; fi
  fi
  exit "$status"
}
trap cleanup EXIT
test -d "$directory"
test ! -L "$directory"
test ! -e "$temporary"
test ! -L "$temporary"
test ! -e "$destination"
test ! -L "$destination"
set -C
exec 3>"$temporary"
created=true
cat >&3
exec 3>&-
chmod 600 "$temporary"
test ! -e "$destination"
test ! -L "$destination"
mv -n "$temporary" "$destination"
test ! -e "$temporary"
test ! -L "$temporary"
created=false
echo REFERENCE_TUN_GATE_PUBLISHED
`;
export async function publishReferenceTunAcknowledgment(host) {
  const bytes = Buffer.from(gate.bytes, 'ascii');
  try {
    const result = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', quote(referenceTunGateScript)], 10000, { stdinBytes: bytes });
    return { byteCount: bytes.length, inputBytes: result.inputBytes ?? 0, inputFinished: result.inputFinished === true,
      inputClosed: result.inputClosed === true, command: commandObservation(result),
      published: passed(result) && result.stderrBytes === 0 && result.output.trim() === 'REFERENCE_TUN_GATE_PUBLISHED' &&
        result.inputBytes === bytes.length && result.inputFinished === true && result.inputClosed === true };
  } finally { bytes.fill(0); }
}
const absentScript = `set -eu
${[INPUT, gate.path, gate.pendingPath].map(file => `test ! -e ${file}\ntest ! -L ${file}`).join('\n')}
echo REFERENCE_TUN_INPUT_AND_GATE_ABSENT`;
const packageAbsenceScript = `set -eu
packages="$(pm list packages ${enrollmentPackage})"
test -z "$packages"
if /system/bin/pidof ${enrollmentPackage} >/dev/null; then exit 1; else status=$?; test "$status" -eq 1; fi
echo REFERENCE_TUN_INTEROP_ABSENT`;
function closedOwners(snapshot) {
  const backend = snapshot?.backend, assets = snapshot?.assets, gateway = snapshot?.gateway;
  return { gatewayJoined: gateway?.closed === true && ['admissionClosed', 'authorityClosed', 'storeClosed', 'listenersClosed', 'issuerChildrenJoined'].every(key => gateway[key] === true) &&
      ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'workers', 'signerGroups', 'issuerJobs', 'acceptedSockets', 'tlsSockets', 'bodyReaders', 'requestTasks',
        'pendingWriteCallbacks', 'registrationWaiters', 'listeners'].every(key => gateway[key] === 0) &&
      ['sessionLeases', 'streamLeases', 'chargedBytes', 'ownerRecords', 'authenticatedSockets', 'proxySockets', 'listeners', 'workers', 'timers', 'pendingCallbacks'].every(key => gateway.stream?.[key] === 0) &&
      Number.isSafeInteger(gateway.issuer?.commandsStarted) && gateway.issuer.commandsStarted === gateway.issuer.commandsClosed && gateway.issuer.commandsStarted === gateway.issuer.processGroupsClosed,
    backendJoined: backend?.closed === true && Number.isSafeInteger(backend.ownersCreated) && backend.ownersCreated === backend.ownersClosed &&
      ['activeOwners', 'activeSockets', 'activeRequests', 'listeners'].every(key => backend[key] === 0),
    assetsJoined: assets?.closed === true && Number.isSafeInteger(assets.commandsStarted) && assets.commandsStarted === assets.commandsClosed && assets.commandsStarted === assets.processGroupsClosed };
}
async function runMethod(host, method, item, options, dependencies, problem) {
  const mappings = [], tasks = []; let worker, registrationTask, approvalTask, completionTask, registration, invitation, metadata;
  let liveInvocation = false, stage = 'enrollment_fixture_failed';
  const live = () => ensure(liveInvocation && !host.controller.signal.aborted);
  const tracked = operation => { const task = operation().catch(() => { problem('enrollment_invocation_failed'); host.abort(); return false; }); tasks.push(task); return task; };
  try {
    const createWorker = dependencies.createWorker ?? (await import('./reference-tun-worker-client.mjs')).startReferenceTunWorker;
    worker = await createWorker({ openssl: options.openssl });
    metadata = await worker.metadata(); invitation = await worker.createInvitation();
    ensure(metadata && invitation, stage);
    await registerEnrollmentReverses(host.adb, metadata, mappings);
    stage = 'enrollment_input_failed';
    const { webSocketPort, ...baseMetadata } = metadata, input = encodeEnrollmentRuntimeInput(baseMetadata, invitation); let sent;
    try {
      sent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', quote(
        'umask 077; mkdir -p no_backup/draft-enrollment-research && chmod 700 no_backup/draft-enrollment-research && set -C && cat > ' + INPUT + ' && chmod 600 ' + INPUT)], 10000, { stdinBytes: input });
    } finally { input.fill(0); }
    item.input = { byteCount: input.length, inputBytes: sent.inputBytes ?? 0, inputFinished: sent.inputFinished === true,
      inputClosed: sent.inputClosed === true, command: commandObservation(sent), inputAbsentAfterMethod: false };
    ensure(passed(sent) && sent.stderrBytes === 0 && sent.inputBytes === input.length && sent.inputFinished && sent.inputClosed, stage);
    item.approval = { registered: false, livePhaseObserved: false, requested: false, completed: false };
    item.host = { completion: projectReferenceTunHost(null, null, method), livePhaseObserved: false, completeObservedBeforeAck: false, androidAckPhaseObserved: false };
    stage = 'enrollment_invocation_failed'; liveInvocation = true; let commandResult;
    const parser = createReferenceTunInvocationParser(method, { onPhase(phase) {
      live();
      if (phase === 'strict-csr-reserved') {
        ensure(!registrationTask);
        registrationTask = tracked(async () => {
          registration = await worker.waitForRegistered(invitation.invitationId, { timeoutMillis: 10000 }); live();
          enrollmentMessage('pair_response', registration);
          ensure(registration.type === 'pair_registered' && registration.desktopId === metadata.desktopId && registration.invitationId === invitation.invitationId);
          item.approval.registered = true; return true;
        });
      } else if (phase === 'awaiting-host-approval') {
        ensure(registrationTask && !approvalTask, 'enrollment_approval_failed'); item.approval.livePhaseObserved = true;
        approvalTask = tracked(async () => {
          ensure(await registrationTask); live(); item.approval.requested = true;
          const approved = await worker.approve(registration.enrollmentId); live(); enrollmentMessage('status_response', approved);
          ensure(approved.type === 'pair_approved' && approved.desktopId === metadata.desktopId && approved.enrollmentId === registration.enrollmentId &&
            approved.enrollmentAuthorityDer === metadata.enrollmentAuthorityDer && JSON.stringify(approved.capabilities) === JSON.stringify(referenceTunPayload.gatewayCapabilities), 'enrollment_approval_failed');
          item.approval.completed = true; return true;
        });
      } else if (phase === 'local-stream-drained') {
        ensure(approvalTask && !completionTask); item.host.livePhaseObserved = true;
        completionTask = tracked(async () => {
          ensure(await approvalTask); live(); const deadline = performance.now() + 5000;
          // At most ~250 bounded snapshots, but parent admits127 business calls total;
          // cap at40 comparisons (80requests) inside the independent5s deadline.
          for (let attempt = 0; attempt < 40; attempt++) {
            live(); ensure(performance.now() < deadline);
            const snapshot = await worker.snapshot(), inspection = await worker.inspectEnrollment(registration.enrollmentId);
            live(); ensure(performance.now() <= deadline);
            item.host.completion = projectReferenceTunHost(snapshot, inspection, method);
            if (referenceTunHostComplete(item.host.completion, method)) {
              live(); item.host.completeObservedBeforeAck = true;
              item.ack = { ...await (dependencies.publishAcknowledgment ?? publishReferenceTunAcknowledgment)(host), absentAfterMethod: false };
              ensure(item.ack.published); return true;
            }
            await new Promise(done => setTimeout(done, 20));
          }
          throw Error('enrollment_invocation_failed');
        });
      } else if (phase === 'gateway-complete-acknowledged') {
        ensure(completionTask && item.host.completeObservedBeforeAck); item.host.androidAckPhaseObserved = true;
      }
    } });
    try {
      commandResult = await host.adb(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', referenceTunClass + '#' + method,
        '-e', 'webSocketPort', String(webSocketPort), enrollmentComponent], 300000, { onStdoutChunk(chunk) { parser.push(chunk); } });
    } finally { liveInvocation = false; item.invocation = parser.finish(commandResult); }
    ensure(item.invocation.state === 'passed'); ensure(await registrationTask); ensure(await approvalTask); ensure(await completionTask);
    const absent = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', quote(absentScript)]);
    const filesAbsent = passed(absent) && absent.stderrBytes === 0 && absent.output.trim() === 'REFERENCE_TUN_INPUT_AND_GATE_ABSENT';
    item.input.inputAbsentAfterMethod = filesAbsent; item.ack.absentAfterMethod = filesAbsent; ensure(filesAbsent, 'enrollment_input_failed');
  } catch (error) { problem(referenceTunProblems.includes(error?.message) ? error.message : stage); }
  finally {
    liveInvocation = false;
    const resources = { gateway: null, process: null, reverseCommands: [], ownedReversesAbsent: false, privateDirectoryRemoved: false,
      gatewayJoined: false, backendJoined: false, assetsJoined: false, ownedCommandsClosed: false, ownedCommandGroupsClosed: false };
    for (const mapping of [...mappings].reverse()) {
      try { const removed = await host.adb(['reverse', '--remove', 'tcp:' + mapping.devicePort], 10000, {}, true);
        resources.reverseCommands.push(commandObservation(removed)); if (!passed(removed)) problem('enrollment_cleanup_failed'); }
      catch { resources.reverseCommands.push(null); problem('enrollment_cleanup_failed'); }
    }
    if (mappings.length) try { resources.ownedReversesAbsent = enrollmentOwnedReversesAbsent(await host.adb(['reverse', '--list'], 10000, {}, true), mappings); }
    catch { problem('enrollment_cleanup_failed'); }
    if (worker) {
      try { const closed = await worker.close(); resources.gateway = enrollmentClosedProjection(closed.gateway ?? null);
        resources.privateDirectoryRemoved = closed.privateDirectoryRemoved === true; Object.assign(resources, closedOwners(closed)); }
      catch { problem('enrollment_cleanup_failed'); }
      try { resources.process = worker.processSnapshot(); if (!referenceTunProcessJoined(resources.process)) problem('enrollment_cleanup_failed'); }
      catch { problem('enrollment_cleanup_failed'); }
    }
    await Promise.allSettled(tasks);
    resources.ownedCommandsClosed = host.commands.every(command => command.closeObserved);
    resources.ownedCommandGroupsClosed = host.commands.every(command => command.processGroupClosed);
    item.resources = resources;
    if (worker && (!V.workerPassed(resources.gateway) || !resources.ownedReversesAbsent || !resources.privateDirectoryRemoved || !resources.gatewayJoined || !resources.backendJoined || !resources.assetsJoined) ||
      !resources.ownedCommandsClosed || !resources.ownedCommandGroupsClosed) problem('enrollment_cleanup_failed');
  }
}
export async function runReferenceTunRuntime(options, dependencies = {}) {
  const report = { format: referenceTunReportFormat, revision: 1, source: null, api: null, clock: null,
    methods: referenceTunMethods.map(method => ({ invocation: createReferenceTunInvocationParser(method).finish(), input: null, approval: null, host: null, ack: null, resources: null })),
    apkSetup: null, cleanup: null, problems: [] };
  const host = (dependencies.createHost ?? createEnrollmentHost)(options); let packages, stage = 'host_setup_failed';
  const problem = code => { const safe = referenceTunProblems.includes(code) ? code : 'host_setup_failed'; if (!report.problems.includes(safe) && report.problems.length < 16) report.problems.push(safe); };
  try {
    await host.prepare(report); stage = 'research_apk_install_failed';
    const createPackages = dependencies.createPackages ?? (await import('./enrolled-tun-packages.mjs')).createEnrolledTunPackageOwner;
    packages = createPackages(host); await packages.prepare(report.api); report.apkSetup = packages.snapshot();
    for (let index = 0; index < referenceTunMethods.length; index++) {
      if (report.problems.length || host.controller.signal.aborted) break;
      await runMethod(host, referenceTunMethods[index], report.methods[index], options, dependencies, problem);
    }
  } catch (error) { problem(referenceTunProblems.includes(error?.message) ? error.message : stage); }
  finally {
    if (packages) {
      try { if ((await packages.cleanup()).failed) problem('enrollment_cleanup_failed'); } catch { problem('enrollment_cleanup_failed'); }
      report.apkSetup = packages.snapshot();
    }
    try {
      const { failed, ...cleanup } = await host.cleanupPackage(commandObservation);
      report.cleanup = { ...cleanup, packageAbsentAfterCleanup: false, ownedCommandsClosed: false, ownedCommandGroupsClosed: false };
      if (failed) problem('enrollment_cleanup_failed');
      if (host.installAttempted) {
        try { const absent = await host.adb(['shell', '-T', 'sh', '-c', quote(packageAbsenceScript)], 10000, {}, true);
          report.cleanup.packageAbsentAfterCleanup = passed(absent) && absent.stderrBytes === 0 && absent.output.trim() === 'REFERENCE_TUN_INTEROP_ABSENT'; }
        catch { problem('enrollment_cleanup_failed'); }
      }
      report.cleanup.ownedCommandsClosed = host.commands.every(command => command.closeObserved);
      report.cleanup.ownedCommandGroupsClosed = host.commands.every(command => command.processGroupClosed);
      if (host.installAttempted && !report.cleanup.packageAbsentAfterCleanup || !report.cleanup.ownedCommandsClosed || !report.cleanup.ownedCommandGroupsClosed) problem('enrollment_cleanup_failed');
    } catch { problem('enrollment_cleanup_failed'); }
    if (host.controller.signal.aborted) problem('research_run_cancelled'); host.dispose();
  }
  const final = createReferenceTunReport(report);
  if (dependencies.writeReports !== false) for (const [name, text] of [['runtime', JSON.stringify(final, null, 2) + '\n'], ['xml', referenceTunRuntimeXml(final)], ['html', referenceTunRuntimeHtml(final)]]) {
    const filename = path.join(ROOT, referenceTunReportPaths[name]); fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, text);
  }
  let ok = false; try { verifyReferenceTunReport(final, { source: final.source?.commit, api: final.api }); ok = true; } catch { /* failed report remains available */ }
  if (dependencies.quiet !== true) console.log(`Reference TUN research: ${final.methods.reduce((sum, item) => sum + item.invocation.actualStarted, 0)} started; ${ok ? 'passed' : 'failed'}.`);
  return { ok, report: final };
}
export function parseReferenceTunArguments(args) {
  const options = { adb: process.env.ADB_BIN ?? 'adb', serial: process.env.ANDROID_SERIAL ?? '', openssl: process.env.OPENSSL_BIN ?? 'openssl' };
  const seen = new Set();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index], value = args[index + 1];
    ensure(['--adb', '--serial', '--openssl'].includes(key) && !seen.has(key) && typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\0\r\n]/.test(value), 'host_setup_failed');
    seen.add(key); options[key.slice(2)] = value;
  }
  ensure(/^[A-Za-z0-9_.:-]{1,128}$/.test(options.serial), 'selected_device_unavailable'); return Object.freeze(options);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { const result = await runReferenceTunRuntime(parseReferenceTunArguments(process.argv.slice(2))); if (!result.ok) process.exitCode = 1; }
  catch { console.error('Reference TUN research unavailable'); process.exitCode = 1; }
}
