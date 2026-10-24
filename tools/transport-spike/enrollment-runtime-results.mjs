// A22a adapter only. Never retain raw command output or provider messages.
import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';

export const enrollmentRuntimeClass = 'com.httpfreekit.interop.DraftEnrollmentInteropTest';
export const expectedEnrollmentMethods = Object.freeze(['prepareApprovedCredentialForRestart', 'reopenApprovedCredentialAfterRestart']);
export const enrollmentPhases = Object.freeze(Object.fromEntries(expectedEnrollmentMethods.map((method, index) => [method, Object.freeze(index === 0
  ? ['input-consumed', 'strict-csr-reserved', 'pending-proof-observed', 'awaiting-host-approval', 'approved-result-validated', 'credential-persisted', 'prepare-resources-closed']
  : ['reopen-key-and-record-validated', 'reopen-mtls-authorized', 'reopen-resources-closed'])])));
export const enrollmentReportPaths = Object.freeze({
  runtime: 'tools/transport-spike/android/build/outputs/androidTest-results/enrollment-runtime/debug/runtime.json',
  xml: 'tools/transport-spike/android/build/outputs/androidTest-results/enrollment-runtime/debug/TEST-enrollment-research.xml',
  html: 'tools/transport-spike/android/build/reports/androidTests/enrollment-runtime/debug/index.html',
  host: 'build/reports/enrollment-runtime/host-cleanup.json',
});
export const enrollmentRuntimeLimits = Object.freeze({ output: 262144, line: 8192, runtime: 65536, host: 16384, rendered: 131072 });
const signals = new Set(['SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGILL', 'SIGTRAP', 'SIGABRT', 'SIGBUS', 'SIGFPE', 'SIGKILL', 'SIGSEGV', 'SIGPIPE', 'SIGALRM', 'SIGTERM']);
const commandReasons = new Set(['owned_child_timeout', 'owned_child_cleanup_failed', 'owned_child_spawn_failed',
  'owned_child_input_failed', 'owned_child_observer_failed', 'instrumentation_output_limit', 'research_run_cancelled']);
const parserCodes = new Set(['instrumentation_output_limit', 'instrumentation_line_limit', 'invalid_instrumentation_utf8',
  'invalid_status_bundle', 'status_field_limit', 'duplicate_status_field', 'status_after_terminal', 'unexpected_test_identity',
  'unexpected_declared_test_count', 'duplicate_test_start', 'test_end_without_start', 'invalid_phase', 'phase_callback_failed',
  'unknown_test_result_code', 'test_skip_or_assumption', 'failure_with_success', 'instrumentation_failure',
  'unterminated_status_bundle', 'missing_terminal_result', 'incomplete_test_execution', 'incomplete_phase_execution',
  'instrumentation_command_failed']);
const driverCodes = new Set(['host_setup_failed', 'selected_device_unavailable', 'research_apk_build_failed', 'research_apk_install_failed',
  'unexpected_research_apk_metadata', 'research_runner_not_registered', 'source_not_clean', 'device_clock_probe_failed',
  'enrollment_clock_outside_bound', 'enrollment_input_failed', 'enrollment_fixture_failed', 'enrollment_approval_failed',
  'enrollment_invocation_failed', 'enrollment_stop_failed', 'enrollment_restart_failed', 'enrollment_cleanup_failed', ...commandReasons]);
const failures = new Set(['AssertionError', 'IllegalStateException', 'IllegalArgumentException', 'IOException', 'EOFException',
  'SocketException', 'SocketTimeoutException', 'SSLException', 'SSLHandshakeException', 'SSLPeerUnverifiedException',
  'InterruptedException', 'CertificateException', 'JSONException', 'other_exception']);
export class EnrollmentRuntimeError extends Error { constructor(code = 'invalid_runtime_report') { super(code); this.name = 'EnrollmentRuntimeError'; this.code = code; } }
const fail = code => { throw new EnrollmentRuntimeError(code); };
export const enrollmentRuntimeProblem = code => driverCodes.has(code) ? code : 'host_setup_failed';
const exact = (value, fields) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length ||
      fields.some(key => !Object.hasOwn(value, key))) fail('invalid_runtime_report');
};
const integer = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < min || value > max) fail('invalid_runtime_report');
};
const boolean = value => { if (typeof value !== 'boolean') fail('invalid_runtime_report'); };
const enumeration = (value, allowed) => { if (!allowed.includes(value)) fail('invalid_runtime_report'); };
const hash = value => { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('invalid_runtime_report'); };
const commit = value => { if (typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) fail('invalid_runtime_report'); };
const codeList = (value, allowed) => {
  if (!Array.isArray(value) || value.length > 16 || new Set(value).size !== value.length || value.some(code => typeof code !== 'string' || !allowed.has(code))) fail('invalid_runtime_report');
};
const copyFreeze = value => {
  if (value && typeof value === 'object') {
    const copied = Array.isArray(value) ? value.map(copyFreeze) : Object.fromEntries(Object.entries(value).map(([key, field]) => [key, copyFreeze(field)]));
    return Object.freeze(copied);
  }
  return value;
};
function validateCommand(value) {
  exact(value, ['exitCode', 'signal', 'reason', 'closeObserved', 'processGroupClosed']);
  if (value.exitCode !== null) integer(value.exitCode, 0, 255);
  if (value.signal !== null && !signals.has(value.signal)) fail('invalid_runtime_report');
  if (value.reason !== null && !commandReasons.has(value.reason)) fail('invalid_runtime_report');
  boolean(value.closeObserved); boolean(value.processGroupClosed);
}
export function enrollmentCommandObservation(result) {
  const command = { exitCode: result.code ?? result.exitCode ?? null, signal: result.signal ?? null, reason: result.reason ?? null,
    closeObserved: result.closeObserved, processGroupClosed: result.processGroupClosed };
  validateCommand(command); return copyFreeze(command);
}
const commandPassed = value => value !== null && value.exitCode === 0 && value.signal === null && value.reason === null && value.closeObserved && value.processGroupClosed;
function sanitizeFailure(raw) {
  let failureType = null; const frames = [];
  for (const line of raw.split('\n')) {
    const type = /^(?:java\.lang\.|java\.io\.|java\.net\.|javax\.net\.ssl\.|java\.security\.cert\.|org\.json\.|org\.junit\.)?([A-Za-z]+)(?::|$)/.exec(line);
    if (failureType === null && type) failureType = failures.has(type[1]) ? type[1] : 'other_exception';
    const frame = /^\s*at (com\.httpfreekit\.interop\.(DraftEnrollment[A-Za-z0-9_$]{0,80}))\.([A-Za-z0-9_$<>]{1,80})\((DraftEnrollment[A-Za-z0-9_]{0,80}\.kt):([1-9][0-9]{0,5})\)$/.exec(line.replace(/\r$/, ''));
    if (frame && frame[2].split('$')[0] + '.kt' === frame[4] && frames.length < 16) frames.push({ className: frame[1], method: frame[3], file: frame[4], line: Number(frame[5]) });
  }
  return { failureType, frames };
}
function validateFrames(value) {
  if (!Array.isArray(value) || value.length > 16) fail('invalid_runtime_report');
  for (const frame of value) {
    exact(frame, ['className', 'method', 'file', 'line']);
    if (typeof frame.className !== 'string' || !/^com\.httpfreekit\.interop\.DraftEnrollment[A-Za-z0-9_$]{0,80}$/.test(frame.className) ||
        typeof frame.method !== 'string' || !/^[A-Za-z0-9_$<>]{1,80}$/.test(frame.method) ||
        frame.file !== frame.className.slice('com.httpfreekit.interop.'.length).split('$')[0] + '.kt') fail('invalid_runtime_report');
    integer(frame.line, 1, 999999);
  }
}
function validateInvocation(value, method) {
  exact(value, ['method', 'state', 'actualStarted', 'actualCompleted', 'terminalCount', 'terminalCode', 'phases', 'command', 'problems', 'failureType', 'frames']);
  if (value.method !== method) fail('invalid_runtime_report');
  enumeration(value.state, ['passed', 'failed', 'incomplete', 'not_started']);
  for (const field of ['actualStarted', 'actualCompleted', 'terminalCount']) integer(value[field], 0, 16);
  if (value.terminalCode !== null) integer(value.terminalCode, -2147483648, 2147483647);
  if (!Array.isArray(value.phases) || value.phases.length > enrollmentPhases[method].length ||
      value.phases.some((phase, index) => phase !== enrollmentPhases[method][index])) fail('invalid_runtime_report');
  if (value.command !== null) validateCommand(value.command);
  codeList(value.problems, parserCodes);
  if (value.failureType !== null && !failures.has(value.failureType)) fail('invalid_runtime_report');
  validateFrames(value.frames);
  if ((value.terminalCount === 0) !== (value.terminalCode === null)) fail('invalid_runtime_report');
  if (value.state === 'passed' && (value.actualStarted !== 1 || value.actualCompleted !== 1 || value.terminalCount !== 1 ||
      value.terminalCode !== -1 || value.phases.length !== enrollmentPhases[method].length || !commandPassed(value.command) ||
      value.problems.length || value.failureType !== null || value.frames.length)) fail('invalid_runtime_report');
  if (value.state === 'not_started' && (value.actualStarted || value.actualCompleted || value.phases.length)) fail('invalid_runtime_report');
}

/** Strict streaming UTF-8 parser. push may throw only a fixed category so an observer can stop the owned child. */
export function createEnrollmentInvocationParser(method, { onPhase } = {}) {
  if (!expectedEnrollmentMethods.includes(method) || (onPhase !== undefined && typeof onPhase !== 'function')) fail('invalid_parser_configuration');
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let bytes = 0, line = '', pending = Object.create(null), lastKey, active = false, starts = 0, ends = 0;
  let terminalCount = 0, terminalCode = null, completedState, failureType = null, frames = [], finished = false, broken = false;
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
      if (Object.keys(pending).length >= 16 && !Object.hasOwn(pending, key)) { stop('status_field_limit'); }
      pending[key] = value; lastKey = key; return;
    }
    let match = /^INSTRUMENTATION_STATUS_CODE: (-?(?:0|[1-9][0-9]{0,9}))$/.exec(text);
    if (match) {
      if (terminalCount) problem('status_after_terminal');
      const code = Number(match[1]);
      if (code < -2147483648 || code > 2147483647) stop('invalid_status_bundle');
      if (code === 2) {
        const phase = pending.draftEnrollmentPhase;
        if (!active || Object.keys(pending).length !== 2 || pending.draftEnrollmentVersion !== '1' || phase !== enrollmentPhases[method][phases.length] || problems.length) stop('invalid_phase');
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
      const allowed = new Set(['class', 'test', 'numtests', 'current', 'id', 'stream', 'stack']);
      if (Object.keys(pending).some(key => !allowed.has(key))) problem('invalid_status_bundle');
      if (pending.class !== enrollmentRuntimeClass || pending.test !== method) {
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
          ({ failureType, frames } = sanitizeFailure(pending.stack));
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
      if (phases.length !== enrollmentPhases[method].length) problem('incomplete_phase_execution');
      const command = commandResult === null ? null : enrollmentCommandObservation(commandResult);
      if (!commandPassed(command)) problem('instrumentation_command_failed');
      const state = starts === 0 && ends === 0 ? 'not_started' : completedState === 'failed' ? 'failed'
        : completedState === 'passed' && problems.length === 0 ? 'passed' : 'incomplete';
      // Invalid unmatched events remain explicit errors; counters are actual observations, not repaired claims.
      return copyFreeze({ method, state, actualStarted: starts, actualCompleted: ends, terminalCount, terminalCode, phases, command, problems, failureType, frames });
    },
  });
}
export function parseEnrollmentInvocation(output, { method, ...commandResult }) {
  const parser = createEnrollmentInvocationParser(method);
  try { parser.push(typeof output === 'string' ? Buffer.from(output) : output); } catch (error) { if (!(error instanceof EnrollmentRuntimeError)) throw error; }
  return parser.finish(commandResult);
}

function validateWorker(value) {
  exact(value, ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined', 'activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']);
  for (const key of ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined']) boolean(value[key]);
  for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']) integer(value[key], 0, 32);
}
const workerPassed = value => value !== null && ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined'].every(key => value[key]) &&
  ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers'].every(key => value[key] === 0);
function validateContinuity(value) {
  const roles = ['setupPort', 'credentialPort', 'gatewayCertificateSha256', 'enrollmentAuthoritySha256', 'approvedResultSha256'];
  exact(value, roles.flatMap(role => [role + 'Before', role + 'After']));
  for (const role of roles) for (const side of ['Before', 'After']) role.endsWith('Port') ? integer(value[role + side], 1, 65535) : hash(value[role + side]);
}
const continuityPassed = value => ['setupPort', 'credentialPort', 'gatewayCertificateSha256', 'enrollmentAuthoritySha256', 'approvedResultSha256'].every(role => value[role + 'Before'] === value[role + 'After']) && value.setupPortBefore !== value.credentialPortBefore;
function validateClock(value) {
  exact(value, ['deviceEpochSeconds', 'hostBeforeMillis', 'hostAfterMillis', 'lowerBoundMillis', 'upperBoundMillis', 'roundTripMillis']);
  integer(value.deviceEpochSeconds, 946684800, 4102444800);
  for (const key of ['hostBeforeMillis', 'hostAfterMillis']) integer(value[key], 946684800000, 4102444800000);
  for (const key of ['lowerBoundMillis', 'upperBoundMillis']) integer(value[key], -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);
  integer(value.roundTripMillis, 0, Number.MAX_SAFE_INTEGER);
}
function clockPassed(value) {
  return value !== null && value.lowerBoundMillis === value.deviceEpochSeconds * 1000 - value.hostAfterMillis &&
    value.upperBoundMillis === value.deviceEpochSeconds * 1000 + 999 - value.hostBeforeMillis &&
    value.roundTripMillis === value.hostAfterMillis - value.hostBeforeMillis && value.roundTripMillis <= 2000 &&
    value.lowerBoundMillis >= -2000 && value.upperBoundMillis <= 2000;
}
function validateRuntime(value) {
  exact(value, ['format', 'revision', 'source', 'api', 'clock', 'invocations', 'input', 'approval', 'stop', 'restart', 'cleanup', 'problems']);
  if (value.format !== 'http-freekit-a22a-runtime' || value.revision !== 1) fail('invalid_runtime_report');
  if (value.source !== null) { exact(value.source, ['commit', 'trackedDirty']); commit(value.source.commit); boolean(value.source.trackedDirty); }
  if (value.api !== null) enumeration(value.api, [26, 37]);
  if (value.clock !== null) validateClock(value.clock);
  if (!Array.isArray(value.invocations) || value.invocations.length !== 2) fail('invalid_runtime_report');
  value.invocations.forEach((invocation, index) => validateInvocation(invocation, expectedEnrollmentMethods[index]));
  codeList(value.problems, driverCodes);
  if (value.input !== null) {
    exact(value.input, ['byteCount', 'inputBytes', 'inputFinished', 'inputClosed', 'command', 'inputAbsentAfterPrepare']);
    integer(value.input.byteCount, 1, 16384); integer(value.input.inputBytes, 0, 16384); validateCommand(value.input.command);
    for (const key of ['inputFinished', 'inputClosed', 'inputAbsentAfterPrepare']) boolean(value.input[key]);
  }
  if (value.approval !== null) {
    exact(value.approval, ['liveAwaitingPhaseObserved', 'dropArmAcknowledged', 'requestedAfterArm', 'completed', 'actualApprovedResponseDrops', 'approvedResponsesAfterDrop', 'reopenedApprovedResponses']);
    for (const key of ['liveAwaitingPhaseObserved', 'dropArmAcknowledged', 'requestedAfterArm', 'completed']) boolean(value.approval[key]);
    for (const key of ['actualApprovedResponseDrops', 'approvedResponsesAfterDrop', 'reopenedApprovedResponses']) integer(value.approval[key], 0, 32);
  }
  if (value.stop !== null) {
    exact(value.stop, ['forceStopCommand', 'deviceBefore', 'deviceAfter', 'presenceBefore', 'presenceAfter', 'absenceQueryExitCode', 'absenceMarkerVerified']);
    validateCommand(value.stop.forceStopCommand);
    for (const key of ['deviceBefore', 'deviceAfter']) enumeration(value.stop[key], ['device', 'offline', 'unavailable']);
    for (const key of ['presenceBefore', 'presenceAfter']) enumeration(value.stop[key], ['present', 'absent', 'unknown']);
    if (value.stop.absenceQueryExitCode !== null) integer(value.stop.absenceQueryExitCode, 0, 255);
    boolean(value.stop.absenceMarkerVerified);
  }
  if (value.restart !== null) {
    exact(value.restart, ['initialWorkerClosed', 'initialWorkerCommand', 'opened', 'continuity']);
    if (value.restart.initialWorkerClosed !== null) validateWorker(value.restart.initialWorkerClosed);
    if (value.restart.initialWorkerCommand !== null) validateCommand(value.restart.initialWorkerCommand);
    boolean(value.restart.opened); if (value.restart.continuity !== null) validateContinuity(value.restart.continuity);
  }
  if (value.cleanup !== null) {
    exact(value.cleanup, ['forceStopCommand', 'uninstallCommand', 'uninstallConfirmed', 'reverseRemovalExitCodes', 'ownedReversesAbsent', 'finalWorkerClosed', 'finalWorkerCommand', 'ownedCommandsClosed', 'ownedCommandGroupsClosed', 'privateDirectoryRemoved']);
    for (const key of ['forceStopCommand', 'uninstallCommand', 'finalWorkerCommand']) if (value.cleanup[key] !== null) validateCommand(value.cleanup[key]);
    for (const key of ['uninstallConfirmed', 'ownedReversesAbsent', 'ownedCommandsClosed', 'ownedCommandGroupsClosed', 'privateDirectoryRemoved']) boolean(value.cleanup[key]);
    if (!Array.isArray(value.cleanup.reverseRemovalExitCodes) || value.cleanup.reverseRemovalExitCodes.length > 2) fail('invalid_runtime_report');
    for (const code of value.cleanup.reverseRemovalExitCodes) integer(code, 0, 255);
    if (value.cleanup.finalWorkerClosed !== null) validateWorker(value.cleanup.finalWorkerClosed);
  }
}
export function createEnrollmentRuntimeReport(observations) { validateRuntime(observations); return copyFreeze(observations); }
export function decodeEnrollmentRuntime(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > enrollmentRuntimeLimits.runtime) fail('runtime_report_limit');
  let value; try { value = parseEnrollmentJson(bytes); } catch { fail('invalid_runtime_report'); }
  return createEnrollmentRuntimeReport(value);
}
export function verifyEnrollmentRuntime(report, { source, api }) {
  validateRuntime(report); commit(source); enumeration(api, [26, 37]);
  if (report.source?.commit !== source || report.source.trackedDirty || report.api !== api) fail('runtime_source_mismatch');
  if (!clockPassed(report.clock)) fail('runtime_clock_failed');
  if (report.problems.length || report.invocations.some(value => value.state !== 'passed')) fail('runtime_invocation_failed');
  const { input, approval, stop, restart, cleanup } = report;
  if (!input || input.inputBytes !== input.byteCount || !input.inputFinished || !input.inputClosed || !input.inputAbsentAfterPrepare || !commandPassed(input.command)) fail('runtime_input_failed');
  if (!approval || !approval.liveAwaitingPhaseObserved || !approval.dropArmAcknowledged || !approval.requestedAfterArm || !approval.completed || approval.actualApprovedResponseDrops !== 1 || approval.approvedResponsesAfterDrop < 1 || approval.reopenedApprovedResponses < 1) fail('runtime_approval_failed');
  if (!stop || !commandPassed(stop.forceStopCommand) || stop.deviceBefore !== 'device' || stop.deviceAfter !== 'device' || stop.presenceBefore === 'unknown' || stop.presenceAfter !== 'absent' || stop.absenceQueryExitCode !== 0 || !stop.absenceMarkerVerified) fail('runtime_stop_failed');
  if (!restart || !workerPassed(restart.initialWorkerClosed) || !commandPassed(restart.initialWorkerCommand) || !restart.opened || !restart.continuity || !continuityPassed(restart.continuity)) fail('runtime_restart_failed');
  if (!cleanup || !['forceStopCommand', 'uninstallCommand', 'finalWorkerCommand'].every(key => commandPassed(cleanup[key])) || !workerPassed(cleanup.finalWorkerClosed) ||
      !['uninstallConfirmed', 'ownedReversesAbsent', 'ownedCommandsClosed', 'ownedCommandGroupsClosed', 'privateDirectoryRemoved'].every(key => cleanup[key]) ||
      cleanup.reverseRemovalExitCodes.length !== 2 || cleanup.reverseRemovalExitCodes.some(code => code !== 0)) fail('runtime_cleanup_failed');
  return Object.freeze({ methods: 2, actualStarted: 2, actualCompleted: 2, api, source });
}
export function decodeEnrollmentHostCleanup(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > enrollmentRuntimeLimits.host) fail('host_report_limit');
  let value; try { value = parseEnrollmentJson(bytes); } catch { fail('invalid_host_report'); }
  exact(value, ['format', 'revision', 'sourceCommit', 'api', 'driverExitCode', 'emulatorStarted', 'stopAttempted', 'stopExitCode', 'terminationObserved', 'joinObserved', 'emulatorExitCode']);
  if (value.format !== 'http-freekit-a22a-host-cleanup' || value.revision !== 1) fail('invalid_host_report');
  commit(value.sourceCommit); enumeration(value.api, [26, 37]);
  for (const key of ['driverExitCode', 'stopExitCode', 'emulatorExitCode']) if (value[key] !== null) integer(value[key], 0, 255);
  for (const key of ['emulatorStarted', 'stopAttempted', 'terminationObserved', 'joinObserved']) boolean(value[key]);
  return copyFreeze(value);
}
export function verifyEnrollmentHostCleanup(value, { source, api }) {
  const report = decodeEnrollmentHostCleanup(Buffer.from(JSON.stringify(value)));
  if (report.sourceCommit !== source || report.api !== api || report.driverExitCode !== 0 ||
      !report.emulatorStarted || !report.stopAttempted || !report.terminationObserved || !report.joinObserved || report.emulatorExitCode === null) fail('host_cleanup_failed');
  return Object.freeze({ emulatorJoined: true });
}
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);
function rendered(text) { if (Buffer.byteLength(text) > enrollmentRuntimeLimits.rendered) fail('rendered_report_limit'); return text; }
export function enrollmentRuntimeXml(report) {
  validateRuntime(report);
  const rows = report.invocations.map(value => {
    const detail = value.problems.join(', ') + (value.failureType ? '\n' + value.failureType : '') + value.frames.map(frame => `\nat ${frame.className}.${frame.method}(${frame.file}:${frame.line})`).join('');
    const result = value.state === 'passed' ? '' : value.state === 'failed' ? `<failure message="Enrollment assertion failed">${escape(detail)}</failure>` : `<error message="Enrollment method did not complete">${escape(detail)}</error>`;
    return `<testcase classname="${enrollmentRuntimeClass}" name="${value.method}" time="0">${result}</testcase>`;
  });
  return rendered(`<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="${enrollmentRuntimeClass}" tests="2" failures="${report.invocations.filter(value => value.state === 'failed').length}" errors="${report.invocations.filter(value => !['passed', 'failed'].includes(value.state)).length}" skipped="0">\n${rows.join('\n')}\n<system-out>${escape(report.problems.join(', ') || 'Method observations only; final runtime and emulator cleanup JSON are required.')}</system-out>\n</testsuite>\n`);
}
export function enrollmentRuntimeHtml(report) {
  validateRuntime(report);
  return rendered('<!doctype html><html lang="en"><meta charset="utf-8"><title>Enrollment research results</title><body><h1>A22a method and host observations</h1><pre>' + escape(JSON.stringify(report, null, 2)) + '</pre></body></html>\n');
}
