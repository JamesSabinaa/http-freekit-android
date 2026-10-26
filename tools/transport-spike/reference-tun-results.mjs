import { enrollmentRuntimeValidation as V, enrollmentCommandObservation, EnrollmentRuntimeError, enrollmentRuntimeLimits } from './enrollment-runtime-results.mjs';
import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';
import * as D from './reference-tun-descriptor.mjs';
export * from './reference-tun-descriptor.mjs';
const fail = code => { throw new EnrollmentRuntimeError(code); };
const name = key => key[0].toLowerCase() + key.slice(1);
export function validateReferenceTunObservation(value, method) {
  V.enumeration(method, D.referenceTunMethods);
  V.exact(value, Object.keys(D.referenceTunObservationTypes).map(name));
  for (const [suffix, type] of Object.entries(D.referenceTunObservationTypes)) {
    const item = value[name(suffix)];
    if (['true', 'false', 'https'].includes(type)) {
      V.boolean(item);
      if (item !== (type === 'true' || type === 'https' && method === D.referenceTunMethods[1])) fail('invalid_observation');
    } else {
      V.integer(item, 0, 131072);
      if (type === 'guard' ? item < 2 : item !== ({ version: 1, zero: 0, one: 1, responseBytes: 81 })[type]) fail('invalid_observation');
    }
  }
  if (value.protectAttempts !== value.protectSuccesses || value.bindAttempts !== value.bindSuccesses || value.protectAttempts !== value.bindAttempts) fail('invalid_observation');
}
export function decodeReferenceTunObservation(bundle, method) {
  V.exact(bundle, Object.keys(D.referenceTunObservationTypes).map(key => D.referenceTunPrefix + key));
  const value = {};
  for (const [key, type] of Object.entries(D.referenceTunObservationTypes)) {
    const raw = bundle[D.referenceTunPrefix + key];
    if (['true', 'false', 'https'].includes(type)) {
      if (!['true', 'false'].includes(raw)) fail('invalid_observation');
      value[name(key)] = raw === 'true';
    } else {
      if (typeof raw !== 'string' || !/^(?:0|[1-9][0-9]{0,5})$/.test(raw)) fail('invalid_observation');
      value[name(key)] = Number(raw);
    }
  }
  validateReferenceTunObservation(value, method); return V.copyFreeze(value);
}
// Digests stay private: public reports contain equality booleans only.
import { createHash } from 'node:crypto';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const requestDigest = digest(Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 31 + 7) & 255)));
const responseDigest = digest(Buffer.from('reference-origin:' + requestDigest, 'ascii'));
const hostBooleans = ['streamResourcesReleased', 'clientEofEmitted', 'gatewayEofEmitted', 'webSocketClosed', 'close1000Acknowledged',
  'streamLease', 'sessionLease', 'requestMatched', 'responseMatched', 'originModeMatched'];
const hostCounts = ['chargedBytes', 'controlChargedBytes', 'chargedFrames', 'streamLeases', 'pendingIngressBytes', 'activeOwners', 'activeSockets', 'activeRequests', 'ownersCreated',
  'ownersClosed', 'upstreamDials', 'interceptedHttpRequests', 'interceptedHttpsRequests', 'upstreamHttpRequests', 'upstreamHttpsRequests',
  'interceptionTlsHandshakes', 'upstreamTlsHandshakes', 'rejectedPrefaces', 'requestBytes', 'responseBytes'];
const hostKeys = ['phase', ...hostBooleans, ...hostCounts];
export function projectReferenceTunHost(snapshot, inspection, method) {
  V.enumeration(method, D.referenceTunMethods);
  const stream = snapshot?.stream, probe = inspection?.probe, backend = snapshot?.backend;
  const row = snapshot?.evidence?.length === 1 ? snapshot.evidence[0] : null;
  const value = { phase: stream?.phase ?? null,
    streamResourcesReleased: stream?.resourcesReleased ?? null,
    clientEofEmitted: stream?.clientEofEmitted ?? null, gatewayEofEmitted: stream?.gatewayEofEmitted ?? null,
    webSocketClosed: probe?.stream?.webSocketClosed ?? null,
    // Existing gateway resourcesClosed permits complete ONLY after real1000 acknowledgement.
    close1000Acknowledged: typeof stream?.phase === 'string' && typeof probe?.stream?.phase === 'string' && typeof probe.stream.webSocketClosed === 'boolean' ?
      stream.phase === 'complete' && probe.stream.phase === 'complete' && probe.stream.webSocketClosed : null,
    streamLease: stream?.streamLease ?? null, sessionLease: probe?.control?.sessionLease ?? null,
    chargedBytes: stream?.chargedBytes ?? null, controlChargedBytes: probe?.control?.chargedBytes ?? null,
    chargedFrames: probe?.stream?.chargedFrames ?? null, streamLeases: probe?.control?.streamLeases ?? null,
    pendingIngressBytes: probe?.io?.pendingIngressBytes ?? null,
    requestMatched: typeof row?.requestSha256 === 'string' ? row.requestSha256 === requestDigest : null,
    responseMatched: typeof row?.responseSha256 === 'string' ? row.responseSha256 === responseDigest : null,
    originModeMatched: typeof row?.mode === 'string' ? row.mode === (method === D.referenceTunMethods[0] ? 'http' : 'https') : null,
    requestBytes: row?.requestBytes ?? null, responseBytes: row?.responseBytes ?? null,
  };
  for (const key of hostCounts) if (!Object.hasOwn(value, key)) value[key] = backend?.[key] ?? null;
  validateHost(value); return V.copyFreeze(value);
}
function validateHost(value) {
  V.exact(value, hostKeys);
  V.enumeration(value.phase, [null, 'opening', 'open', 'closing', 'complete', 'failed', 'cancelled']);
  for (const key of hostBooleans) if (value[key] !== null) V.boolean(value[key]);
  for (const key of hostCounts) if (value[key] !== null) V.integer(value[key], 0, 33570816);
}
export function referenceTunHostComplete(value, method) {
  try { validateHost(value); V.enumeration(method, D.referenceTunMethods); } catch { return false; }
  const https = method === D.referenceTunMethods[1];
  return value.phase === 'complete' && hostBooleans.every(key => value[key] === (key !== 'streamLease')) &&
    ['chargedBytes', 'controlChargedBytes', 'chargedFrames', 'streamLeases', 'pendingIngressBytes', 'activeOwners', 'activeSockets', 'activeRequests', 'rejectedPrefaces'].every(key => value[key] === 0) &&
    ['ownersCreated', 'ownersClosed', 'upstreamDials'].every(key => value[key] === 1) &&
    ['interceptedHttpRequests', 'upstreamHttpRequests'].every(key => value[key] === (https ? 0 : 1)) &&
    ['interceptedHttpsRequests', 'upstreamHttpsRequests', 'interceptionTlsHandshakes', 'upstreamTlsHandshakes'].every(key => value[key] === (https ? 1 : 0)) &&
    value.requestBytes === 4096 && value.responseBytes === 81;
}
const processKeys = ['closeObserved', 'exitCode', 'signal', 'processGroupJoined', 'stdoutJoined', 'stderrJoined', 'stdinJoined', 'pendingWrites', 'pendingRequests', 'forced', 'failure'];
export function validateReferenceTunProcess(value) {
  V.exact(value, processKeys);
  for (const key of ['closeObserved', 'processGroupJoined', 'stdoutJoined', 'stderrJoined', 'stdinJoined', 'forced']) V.boolean(value[key]);
  for (const key of ['pendingWrites', 'pendingRequests']) V.integer(value[key], 0, 128);
  if (value.exitCode !== null) V.integer(value.exitCode, 0, 255);
  V.enumeration(value.signal, [null, 'SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGILL', 'SIGTRAP', 'SIGABRT', 'SIGBUS', 'SIGFPE', 'SIGKILL', 'SIGSEGV', 'SIGPIPE', 'SIGALRM', 'SIGTERM']);
  V.enumeration(value.failure, [null, 'tun_configuration', 'tun_input', 'tun_unavailable', 'tun_enrollment', 'tun_cleanup', 'tun_watchdog', 'tun_output', 'tun_protocol', 'tun_process', 'tun_closing', 'tun_timeout']);
}
export function referenceTunProcessJoined(value) {
  try { validateReferenceTunProcess(value); } catch { return false; }
  return ['closeObserved', 'processGroupJoined', 'stdoutJoined', 'stderrJoined', 'stdinJoined'].every(key => value[key]) &&
    value.exitCode === 0 && value.signal === null && value.failure === null && !value.forced && value.pendingWrites === 0 && value.pendingRequests === 0;
}
export const referenceTunProblems = Object.freeze(['host_setup_failed', 'selected_device_unavailable', 'research_apk_build_failed', 'research_apk_install_failed',
  'unexpected_research_apk_metadata', 'research_runner_not_registered', 'source_not_clean', 'device_clock_probe_failed', 'enrollment_clock_outside_bound',
  'enrollment_input_failed', 'enrollment_fixture_failed', 'enrollment_approval_failed', 'enrollment_invocation_failed', 'enrollment_cleanup_failed', 'research_run_cancelled']);
const invocationProblems = new Set(['instrumentation_output_limit', 'instrumentation_line_limit', 'invalid_instrumentation_utf8',
  'invalid_status_bundle', 'status_field_limit', 'duplicate_status_field', 'status_after_terminal', 'unexpected_test_identity',
  'unexpected_declared_test_count', 'duplicate_test_start', 'test_end_without_start', 'invalid_phase', 'phase_callback_failed', 'phase_after_command_close',
  'unknown_test_result_code', 'test_skip_or_assumption', 'failure_with_success', 'instrumentation_failure', 'unterminated_status_bundle',
  'missing_terminal_result', 'incomplete_test_execution', 'incomplete_phase_execution', 'instrumentation_command_failed', 'invalid_observation',
  'incomplete_observation', 'observation_after_command_close']);
function codeList(value, allowed) {
  if (!Array.isArray(value) || value.length > 16 || new Set(value).size !== value.length || value.some(code => !allowed.has(code))) fail('invalid_runtime_report');
}
export function validateReferenceTunInvocation(value, method) {
  V.exact(value, ['method', 'state', 'actualStarted', 'actualCompleted', 'terminalCount', 'terminalCode', 'phases', 'command', 'problems', 'failureType', 'frames', 'observation', 'failure']);
  if (value.method !== method) fail('invalid_runtime_report');
  V.enumeration(method, D.referenceTunMethods); V.enumeration(value.state, ['passed', 'failed', 'not_started', 'incomplete']);
  for (const key of ['actualStarted', 'actualCompleted', 'terminalCount']) V.integer(value[key], 0, 16);
  if (value.terminalCode !== null) V.integer(value.terminalCode, -2147483648, 2147483647);
  if ((value.terminalCount === 0) !== (value.terminalCode === null)) fail('invalid_runtime_report');
  if (!Array.isArray(value.phases) || value.phases.length > D.referenceTunPhases.length || value.phases.some((phase, i) => phase !== D.referenceTunPhases[i])) fail('invalid_runtime_report');
  if (value.command !== null) V.validateCommand(value.command);
  codeList(value.problems, invocationProblems); V.enumeration(value.failureType, [null, 'Other']);
  if (!Array.isArray(value.frames) || value.frames.length !== 0) fail('invalid_runtime_report');
  if (value.failure !== null) {
    V.exact(value.failure, ['phase', 'type', 'category', 'cleanup']); V.enumeration(value.failure.phase, D.referenceTunPhases);
    V.enumeration(value.failure.type, D.referenceTunFailureTypes); V.enumeration(value.failure.category, D.referenceTunFailureCategories); V.boolean(value.failure.cleanup);
  }
  if (value.observation !== null) { validateReferenceTunObservation(value.observation, method); if (value.phases.length !== D.referenceTunPhases.length) fail('invalid_runtime_report'); }
  if (value.state === 'passed' && (value.actualStarted !== 1 || value.actualCompleted !== 1 || value.terminalCount !== 1 || value.terminalCode !== -1 ||
    value.phases.length !== D.referenceTunPhases.length || !V.commandPassed(value.command) || value.problems.length || value.observation === null || value.failure !== null || value.failureType !== null)) fail('invalid_runtime_report');
  if (value.state === 'not_started' && (value.actualStarted || value.actualCompleted || value.phases.length)) fail('invalid_runtime_report');
}
const packageFlags = ['initiallyAbsent', 'installAttempted', 'installed', 'uninstallConfirmed', 'absentAfterCleanup'];
const permissions = ['interopLocalNetwork', 'trafficLocalNetwork', 'interopNotification'];
function validatePackages(value) {
  V.exact(value, ['sameSigner', 'controlTrafficGranted', 'packages', 'permissions']); V.boolean(value.sameSigner); V.boolean(value.controlTrafficGranted);
  if (!Array.isArray(value.packages) || value.packages.length !== 2) fail('invalid_runtime_report');
  value.packages.forEach((item, index) => {
    V.exact(item, ['package', ...packageFlags, 'installCommand', 'forceStopCommand', 'uninstallCommand']);
    if (item.package !== ['com.httpfreekit.capturetest', 'com.httpfreekit.capturetraffic'][index]) fail('invalid_runtime_report');
    for (const key of packageFlags) V.boolean(item[key]);
    for (const key of ['installCommand', 'forceStopCommand', 'uninstallCommand']) if (item[key] !== null) V.validateCommand(item[key]);
  });
  V.exact(value.permissions, ['mode', ...permissions]); V.enumeration(value.permissions.mode, [null, 'not_required', 'owned_ci_grant']);
  for (const key of permissions) if (value.permissions[key] !== null) V.validateCommand(value.permissions[key]);
}
function validateTransfer(value, ack = false) {
  V.exact(value, ['byteCount', 'inputBytes', 'inputFinished', 'inputClosed', 'command', ...(ack ? ['published', 'absentAfterMethod'] : ['inputAbsentAfterMethod'])]);
  V.integer(value.byteCount, 1, ack ? 128 : 16384); V.integer(value.inputBytes, 0, ack ? 128 : 16384); V.validateCommand(value.command);
  for (const key of ['inputFinished', 'inputClosed', ...(ack ? ['published', 'absentAfterMethod'] : ['inputAbsentAfterMethod'])]) V.boolean(value[key]);
}
function validateReport(value) {
  V.exact(value, ['format', 'revision', 'source', 'api', 'clock', 'methods', 'apkSetup', 'cleanup', 'problems']);
  if (value.format !== D.referenceTunReportFormat || value.revision !== 1) fail('invalid_runtime_report');
  if (value.source !== null) { V.exact(value.source, ['commit', 'trackedDirty']); V.commit(value.source.commit); V.boolean(value.source.trackedDirty); }
  if (value.api !== null) V.enumeration(value.api, [26, 37]); if (value.clock !== null) V.validateClock(value.clock);
  codeList(value.problems, new Set(referenceTunProblems));
  if (!Array.isArray(value.methods) || value.methods.length !== 2) fail('invalid_runtime_report');
  value.methods.forEach((item, index) => {
    V.exact(item, ['invocation', 'input', 'approval', 'host', 'ack', 'resources']);
    validateReferenceTunInvocation(item.invocation, D.referenceTunMethods[index]);
    if (item.input !== null) validateTransfer(item.input);
    if (item.ack !== null) validateTransfer(item.ack, true);
    if (item.approval !== null) { V.exact(item.approval, ['registered', 'livePhaseObserved', 'requested', 'completed']); for (const flag of Object.keys(item.approval)) V.boolean(item.approval[flag]); }
    if (item.host !== null) { V.exact(item.host, ['completion', 'livePhaseObserved', 'completeObservedBeforeAck', 'androidAckPhaseObserved']); validateHost(item.host.completion); for (const key of ['livePhaseObserved', 'completeObservedBeforeAck', 'androidAckPhaseObserved']) V.boolean(item.host[key]); }
    if (item.resources !== null) {
      V.exact(item.resources, ['gateway', 'process', 'reverseCommands', 'ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayJoined', 'backendJoined', 'assetsJoined', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
      if (item.resources.gateway !== null) V.validateWorker(item.resources.gateway);
      if (item.resources.process !== null) validateReferenceTunProcess(item.resources.process);
      if (!Array.isArray(item.resources.reverseCommands) || item.resources.reverseCommands.length > 3) fail('invalid_runtime_report');
      for (const command of item.resources.reverseCommands) if (command !== null) V.validateCommand(command);
      for (const key of ['ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayJoined', 'backendJoined', 'assetsJoined', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']) V.boolean(item.resources[key]);
    }
  });
  if (value.apkSetup !== null) validatePackages(value.apkSetup);
  if (value.cleanup !== null) {
    V.exact(value.cleanup, ['forceStopCommand', 'uninstallCommand', 'uninstallConfirmed', 'packageAbsentAfterCleanup', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
    for (const key of ['forceStopCommand', 'uninstallCommand']) if (value.cleanup[key] !== null) V.validateCommand(value.cleanup[key]);
    for (const key of ['uninstallConfirmed', 'packageAbsentAfterCleanup', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']) V.boolean(value.cleanup[key]);
  }
}
export function createReferenceTunReport(value) {
  try { validateReport(value); return V.copyFreeze(value); } catch { fail('invalid_runtime_report'); }
}
export function decodeReferenceTunReport(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > enrollmentRuntimeLimits.runtime) fail('runtime_report_limit');
  let value; try { value = parseEnrollmentJson(bytes); } catch { fail('invalid_runtime_report'); }
  return createReferenceTunReport(value);
}
export function verifyReferenceTunReport(value, { source, api }) {
  const report = createReferenceTunReport(value); V.commit(source); V.enumeration(api, [26, 37]);
  if (report.source?.commit !== source || report.source.trackedDirty || report.api !== api) fail('runtime_source_mismatch');
  if (!V.clockPassed(report.clock)) fail('runtime_clock_failed');
  if (report.problems.length) fail('runtime_invocation_failed');
  for (const [index, item] of report.methods.entries()) {
    if (item.invocation.state !== 'passed') fail('runtime_invocation_failed');
    const transferPassed = (v, ack) => v && v.inputBytes === v.byteCount && v.inputFinished && v.inputClosed && V.commandPassed(v.command) &&
      (ack ? v.published && v.absentAfterMethod && v.byteCount === Buffer.byteLength(D.referenceTunAcknowledgment.bytes) : v.inputAbsentAfterMethod);
    if (!transferPassed(item.input, false)) fail('runtime_input_failed');
    if (!item.approval || !Object.values(item.approval).every(value => value === true)) fail('runtime_approval_failed');
    if (!item.host || !item.host.livePhaseObserved || !item.host.completeObservedBeforeAck || !item.host.androidAckPhaseObserved || !referenceTunHostComplete(item.host.completion, D.referenceTunMethods[index])) fail('runtime_reference_tun_host_failed');
    if (!transferPassed(item.ack, true)) fail('runtime_reference_tun_ack_failed');
    const r = item.resources;
    if (!r || !V.workerPassed(r.gateway) || !referenceTunProcessJoined(r.process) || r.reverseCommands.length !== 3 || !r.reverseCommands.every(V.commandPassed) ||
      !['ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayJoined', 'backendJoined', 'assetsJoined', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => r[key])) fail('runtime_cleanup_failed');
  }
  const packages = report.apkSetup;
  if (!packages || !packages.sameSigner || !packages.controlTrafficGranted || packages.packages.some(item => !packageFlags.every(key => item[key]) ||
    !['installCommand', 'forceStopCommand', 'uninstallCommand'].every(key => V.commandPassed(item[key]))) ||
    (api === 26 ? packages.permissions.mode !== 'not_required' || permissions.some(key => packages.permissions[key] !== null) :
      packages.permissions.mode !== 'owned_ci_grant' || permissions.some(key => !V.commandPassed(packages.permissions[key])))) fail('runtime_reference_tun_packages_failed');
  if (!report.cleanup || !V.commandPassed(report.cleanup.forceStopCommand) || !V.commandPassed(report.cleanup.uninstallCommand) ||
    !['uninstallConfirmed', 'packageAbsentAfterCleanup', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => report.cleanup[key])) fail('runtime_cleanup_failed');
  return Object.freeze({ methods: 2, actualStarted: 2, actualCompleted: 2, source, api });
}
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);
const render = text => { if (Buffer.byteLength(text) > enrollmentRuntimeLimits.rendered) fail('rendered_report_limit'); return text; };
export function referenceTunRuntimeXml(value) {
  const report = createReferenceTunReport(value), invocations = report.methods.map(item => item.invocation);
  return render('<?xml version="1.0" encoding="UTF-8"?>\n' + `<testsuite name="${D.referenceTunClass}" tests="2" failures="${invocations.filter(item => item.state === 'failed').length}" errors="${invocations.filter(item => !['passed', 'failed'].includes(item.state)).length}" skipped="0">\n` +
    invocations.map(item => `<testcase classname="${D.referenceTunClass}" name="${item.method}" time="0">${item.state === 'passed' ? '' : `<${item.state === 'failed' ? 'failure' : 'error'} message="Reference TUN method did not pass">${escape(item.problems.join(', ') + (item.failure ? '\n' + JSON.stringify(item.failure) : ''))}</${item.state === 'failed' ? 'failure' : 'error'}>`}</testcase>`).join('\n') + '\n</testsuite>\n');
}
export function referenceTunRuntimeHtml(value) { return render('<!doctype html><html lang="en"><meta charset="utf-8"><title>Reference TUN research</title><body><pre>' + escape(JSON.stringify(createReferenceTunReport(value), null, 2)) + '</pre></body></html>\n'); }
function finiteFailure(raw) {
  for (const line of raw.split('\n')) {
    const match = /^(?:java\.lang\.AssertionError: )?Reference TUN research failed at ([a-z-]+) type=([A-Za-z]+) category=([a-z_]+) cleanup=(true|false)$/.exec(line);
    if (match && D.referenceTunPhases.includes(match[1]) && D.referenceTunFailureTypes.includes(match[2]) && D.referenceTunFailureCategories.includes(match[3]))
      return { phase: match[1], type: match[2], category: match[3], cleanup: match[4] === 'true' };
  }
  return null;
}

export function createReferenceTunInvocationParser(method, { onPhase } = {}) {
  const descriptor = { className: D.referenceTunClass, methods: D.referenceTunMethods, prefix: D.referenceTunPrefix, cap: 80, decodeObservation: decodeReferenceTunObservation, observationPhase: () => D.referenceTunPhases.length }, requiredPhases = D.referenceTunPhases;
  if (!descriptor.methods.includes(method) || (onPhase !== undefined && typeof onPhase !== 'function')) fail('invalid_parser_configuration');
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let bytes = 0, line = '', pending = Object.create(null), lastKey, active = false, starts = 0, ends = 0;
  let terminalCount = 0, terminalCode = null, completedState, failureType = null, frames = [], finished = false, broken = false, observation = null, safeFailure = null;
  const phases = [], problems = [];
  const problem = code => { if (!problems.includes(code) && problems.length < 16) problems.push(code); };
  const stop = code => { problem(code); broken = true; fail(code); };
  function consume(text) {
    if (text.startsWith('INSTRUMENTATION_STATUS: ')) {
      if (terminalCount) problem('status_after_terminal');
      const match = /^INSTRUMENTATION_STATUS: ([A-Za-z0-9_]{1,80})=(.*)$/.exec(text);
      if (!match) { problem('invalid_status_bundle'); return; }
      const [, key, value] = match;
      if (Object.hasOwn(pending, key)) problem('duplicate_status_field');
      if (Object.keys(pending).length >= descriptor.cap && !Object.hasOwn(pending, key)) { stop('status_field_limit'); }
      pending[key] = value; lastKey = key; return;
    }
    let match = /^INSTRUMENTATION_STATUS_CODE: (-?(?:0|[1-9][0-9]{0,9}))$/.exec(text);
    if (match) {
      if (terminalCount) problem('status_after_terminal');
      const code = Number(match[1]);
      if (code < -2147483648 || code > 2147483647) stop('invalid_status_bundle');
      if (code === 2) {
        // finish runs after child/stdio closure. A residual line is diagnostic input,
        // never authority to start approval work after the observed command ended.
        if (finished) { problem('phase_after_command_close'); pending = Object.create(null); lastKey = undefined; return; }
        const phase = pending[descriptor.prefix + 'Phase'];
        if (!active || Object.keys(pending).length !== 2 || pending[descriptor.prefix + 'Version'] !== '1' || phase !== requiredPhases[phases.length] || problems.length ||
            (descriptor.decodeObservation && phases.length === descriptor.observationPhase(method) && observation === null)) stop('invalid_phase');
        phases.push(phase);
        pending = Object.create(null); lastKey = undefined;
        if (onPhase) {
          try {
            const returned = onPhase(phase);
            if (returned !== undefined) {
              if (returned instanceof Promise) void returned.catch(() => {});
              stop('phase_callback_failed');
            }
          }
          catch { stop('phase_callback_failed'); }
        }
        return;
      }
      if (descriptor.decodeObservation && code === 3) {
        if (finished) { problem('observation_after_command_close'); pending = Object.create(null); lastKey = undefined; return; }
        if (!active || phases.length !== descriptor.observationPhase(method) || observation !== null || problems.length) stop('invalid_observation');
        try { observation = descriptor.decodeObservation(pending, method); } catch { stop('invalid_observation'); }
        pending = Object.create(null); lastKey = undefined; return;
      }
      const allowed = new Set(['class', 'test', 'numtests', 'current', 'id', 'stream', 'stack']);
      if (Object.keys(pending).some(key => !allowed.has(key))) problem('invalid_status_bundle');
      if (pending.class !== descriptor.className || pending.test !== method) {
        problem('unexpected_test_identity'); pending = Object.create(null); lastKey = undefined; return;
      }
      if (pending.numtests !== '1' || (pending.current !== undefined && pending.current !== '1')) problem('unexpected_declared_test_count');
      if (code === 1) {
        if (starts === 16) stop('status_field_limit'); starts++;
        if (active || starts !== 1 || ends) problem('duplicate_test_start');
        else active = true;
        if (pending.stack) problem('invalid_status_bundle');
      } else {
        if (ends === 16) stop('status_field_limit'); ends++;
        if (!active || ends !== 1) problem('test_end_without_start');
        active = false; completedState = code === 0 ? 'passed' : 'failed';
        if (![0, -1, -2, -3, -4].includes(code)) problem('unknown_test_result_code');
        if (code === -3 || code === -4) problem('test_skip_or_assumption');
        if (pending.stack) {
          failureType = 'Other'; safeFailure ??= finiteFailure(pending.stack);

          if (code === 0) problem('failure_with_success');
        }
      }
      pending = Object.create(null); lastKey = undefined; return;
    }
    match = /^INSTRUMENTATION_CODE: (-?(?:0|[1-9][0-9]{0,9}))$/.exec(text);
    if (match) {
      if (Object.keys(pending).length) problem('unterminated_status_bundle');
      if (terminalCount === 16 || Number(match[1]) < -2147483648 || Number(match[1]) > 2147483647) stop('invalid_status_bundle');
      terminalCount++; terminalCode = Number(match[1]); lastKey = undefined; return;
    }
    if (/^INSTRUMENTATION_(?:FAILED|ABORTED):/.test(text) || /^INSTRUMENTATION_RESULT: (?:shortMsg|longMsg)=/.test(text)) {
      problem('instrumentation_failure'); lastKey = undefined; return;
    }
    if (text.startsWith('INSTRUMENTATION_')) {
      if (!text.startsWith('INSTRUMENTATION_RESULT: stream=')) problem('invalid_status_bundle');
      lastKey = undefined; return;
    }
    if (lastKey !== 'stack') {
      const found = finiteFailure(text);
      if (found || /Reference TUN research failed at /.test(text)) { safeFailure ??= found; problem('instrumentation_failure'); }
    }
    if (lastKey === 'stack') {
      if (Buffer.byteLength(pending.stack + '\n' + text) > 8192) stop('instrumentation_line_limit');
      pending.stack += '\n' + text;
    }
  }
  function consumeText(text) {
    if (text.includes('\uFEFF') || text.includes('\0')) stop('invalid_instrumentation_utf8');
    for (const part of text.split(/(?<=\n)/)) {
      line += part;
      if (Buffer.byteLength(line) > enrollmentRuntimeLimits.line) stop('instrumentation_line_limit');
      if (line.endsWith('\n')) { consume(line.slice(0, -1).replace(/\r$/, '')); line = ''; }
    }
  }
  return Object.freeze({
    push(chunk) {
      if (finished || broken) fail('parser_closed');
      if (!(chunk instanceof Uint8Array)) stop('invalid_instrumentation_utf8');
      const copied = Buffer.from(chunk); bytes += copied.length;
      if (bytes > enrollmentRuntimeLimits.output) stop('instrumentation_output_limit');
      let text; try { text = decoder.decode(copied, { stream: true }); } catch { stop('invalid_instrumentation_utf8'); }
      consumeText(text);
    },
    finish(commandResult = null) {
      if (finished) fail('parser_closed'); finished = true;
      if (!broken) {
        let text; try { text = decoder.decode(); } catch { problem('invalid_instrumentation_utf8'); broken = true; }
        if (!broken) {
          try { consumeText(text); if (line) consume(line.replace(/\r$/, '')); } catch { /* fixed problem already recorded */ }
        }
      }
      if (Object.keys(pending).length) problem('unterminated_status_bundle');
      if (terminalCount !== 1 || terminalCode !== -1) problem('missing_terminal_result');
      if (starts !== 1 || ends !== 1 || active) problem('incomplete_test_execution');
      if (phases.length !== requiredPhases.length) problem('incomplete_phase_execution');
      if (descriptor.decodeObservation && observation === null) problem('incomplete_observation');
      const command = commandResult === null ? null : enrollmentCommandObservation(commandResult);
      if (!V.commandPassed(command)) problem('instrumentation_command_failed');
      const state = starts === 0 && ends === 0 ? 'not_started' : completedState === 'failed' ? 'failed'
        : completedState === 'passed' && problems.length === 0 ? 'passed' : 'incomplete';
      // Invalid unmatched events remain explicit errors; counters are actual observations, not repaired claims.
      return V.copyFreeze({ method, state, actualStarted: starts, actualCompleted: ends, terminalCount, terminalCode, phases, command, problems, failureType, frames,
        ...(descriptor.decodeObservation ? { observation } : {}), failure: safeFailure });
    },
  });
}
