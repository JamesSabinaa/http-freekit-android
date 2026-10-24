import { EnrollmentRuntimeError, enrollmentRuntimeValidation as V, createEnrollmentSuiteInvocationParser, enrollmentRuntimeLimits } from './enrollment-runtime-results.mjs';
import { enrolledStreamingClass, enrolledStreamingCases, expectedEnrolledStreamingMethods } from './enrollment-runtime-stream-descriptor.mjs';
import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';
export { enrolledStreamingClass, enrolledStreamingCases, expectedEnrolledStreamingMethods, enrolledStreamingScenarios,
  enrolledStreamingPhases, enrolledStreamingReportPaths, enrolledObservationSuffixes } from './enrollment-runtime-stream-descriptor.mjs';
const UTC_MIN = 946684800000, UTC_MAX = 4102444800000, COUNT_MAX = 33570816;
const causes = [null, 'cancelled', 'unsupported_version', 'unsupported_capability', 'authentication_failed', 'device_revoked',
  'proxy_unavailable', 'session_limit', 'stream_limit', 'invalid_message', 'network_unreachable', 'session_expired', 'desktop_stopped', 'message_too_large'];
const controlPhases = ['awaiting_hello', 'awaiting_ready', 'active', 'closed', 'failed'];
const streamPhases = ['awaiting_open', 'awaiting_ready', 'open', 'half_closed', 'draining', 'closing', 'complete', 'cancelled', 'failed'];
const inspectorKeys = ['revision', 'found', 'available', 'credentialExpiresUtcMillis', 'gatewayExpiresUtcMillis', 'sessionPolicyMillis',
  'grantValid', 'invalidationCause', 'revalidations', 'controlsAdmitted', 'applicationWriteAdmissions', 'writesAfterInvalidation', 'terminalNotification', 'probe'];
export const enrolledHostSnapshotKeys = Object.freeze(('available grantValid credentialExpiresUtcMillis gatewayExpiresUtcMillis sessionPolicyMillis ' +
  'invalidationCause revalidations controlsAdmitted applicationWriteAdmissions writesAfterInvalidation controlPhase controlCause sessionLease streamLeases ' +
  'chargedBytes streamPhase streamCause chargedFrames proxyWriteEntries proxyWriteCompletions proxyWritePending pendingIngressBytes proxyReadPaused ' +
  'readyUtcMillis expiresUtcMillis terminalUtcMillis terminalElapsedMillis ownerResourcesReleased cleanupComplete workers timers pendingCallbacks ' +
  'terminalNotification callStartedNanos callReceivedNanos').split(' '));
const utc = value => V.integer(value, UTC_MIN, UTC_MAX);
function notification(value) {
  V.exact(value, ['attempted', 'completed', 'aborted']);
  for (const key of ['attempted', 'completed', 'aborted']) V.boolean(value[key]);
  if ((!value.attempted && (value.completed || value.aborted)) || (value.completed && value.aborted)) throw Error();
}
function validateSnapshot(value) {
  V.exact(value, enrolledHostSnapshotKeys);
  for (const key of ['available', 'grantValid', 'sessionLease', 'proxyWritePending', 'proxyReadPaused', 'ownerResourcesReleased', 'cleanupComplete']) V.boolean(value[key]);
  for (const key of ['credentialExpiresUtcMillis', 'gatewayExpiresUtcMillis', 'readyUtcMillis', 'expiresUtcMillis']) utc(value[key]);
  V.enumeration(value.sessionPolicyMillis, [15000, 120000]);
  V.enumeration(value.invalidationCause, [null, 'device_revoked', 'session_expired', 'network_unreachable']);
  V.enumeration(value.controlPhase, controlPhases); V.enumeration(value.controlCause, causes);
  V.enumeration(value.streamPhase, [null, ...streamPhases]); V.enumeration(value.streamCause, causes);
  for (const key of ['revalidations', 'applicationWriteAdmissions', 'writesAfterInvalidation', 'proxyWriteEntries', 'proxyWriteCompletions']) V.integer(value[key], 0, COUNT_MAX);
  V.integer(value.controlsAdmitted, 0, 8); V.integer(value.streamLeases, 0, 2); V.integer(value.chargedBytes, 0, 16384);
  V.integer(value.chargedFrames, 0, 4); V.integer(value.pendingIngressBytes, 0, 4096);
  for (const key of ['workers', 'timers', 'pendingCallbacks']) V.integer(value[key], 0, 64);
  for (const key of ['callStartedNanos', 'callReceivedNanos']) V.integer(value[key], 0, 3600000000000);
  if (value.callStartedNanos > value.callReceivedNanos || value.proxyWriteCompletions > value.proxyWriteEntries ||
      value.writesAfterInvalidation > value.applicationWriteAdmissions || (value.terminalUtcMillis === null) !== (value.terminalElapsedMillis === null)) throw Error();
  if (value.terminalUtcMillis !== null) { utc(value.terminalUtcMillis); V.integer(value.terminalElapsedMillis, 0, 180000); }
  if (value.streamPhase === null && (value.streamCause !== null || value.chargedFrames)) throw Error();
  notification(value.terminalNotification);
}
export function createEnrolledHostSnapshot(value) {
  try { validateSnapshot(value); return V.copyFreeze(value); }
  catch { throw new EnrollmentRuntimeError('invalid_enrolled_host_observation'); }
}
/** Fresh inert original-owner projection only; raw IPC data and global pool state never escape. */
export function projectEnrolledHostSnapshot(inspect, { callStartedNanos, callReceivedNanos }) {
  try {
    V.exact(inspect, inspectorKeys); if (inspect.revision !== 1) throw Error();
    for (const key of ['found', 'available', 'grantValid']) V.boolean(inspect[key]);
    utc(inspect.gatewayExpiresUtcMillis); V.enumeration(inspect.sessionPolicyMillis, [15000, 120000]);
    V.enumeration(inspect.invalidationCause, [null, 'device_revoked', 'session_expired', 'network_unreachable']);
    for (const key of ['revalidations', 'controlsAdmitted', 'applicationWriteAdmissions', 'writesAfterInvalidation']) V.integer(inspect[key], 0, key === 'controlsAdmitted' ? 8 : COUNT_MAX);
    notification(inspect.terminalNotification);
    V.integer(callStartedNanos, 0, 3600000000000); V.integer(callReceivedNanos, callStartedNanos, 3600000000000);
    if (!inspect.found) {
      if (inspect.credentialExpiresUtcMillis !== null || inspect.grantValid || inspect.invalidationCause !== null || inspect.probe !== null ||
          ['revalidations', 'controlsAdmitted', 'applicationWriteAdmissions', 'writesAfterInvalidation'].some(key => inspect[key] !== 0) ||
          Object.values(inspect.terminalNotification).some(Boolean)) throw Error();
      return null;
    }
    utc(inspect.credentialExpiresUtcMillis);
    if (inspect.probe === null) return null;
    const p = inspect.probe;
    V.exact(p, ['revision', 'scenario', 'streamOrdinal', 'control', 'stream', 'pool', 'fixture', 'io', 'cleanup', 'timing']);
    if (p.revision !== 1) throw Error();
    V.enumeration(p.scenario, ['gated', 'backpressure', 'cancel', 'expiry', 'binding', 'malformed', 'premature']); V.integer(p.streamOrdinal, 0, 64);
    V.exact(p.control, ['phase', 'cause', 'sessionLease', 'webSocketClosed', 'resourcesReleased', 'historyCount', 'streamLeases', 'chargedBytes']);
    V.exact(p.pool, ['sessionLeases', 'streamLeases', 'chargedBytes']);
    for (const key of ['sessionLeases', 'streamLeases', 'chargedBytes']) V.integer(p.pool[key], 0, 65536);
    V.exact(p.fixture, ['proxyReadPaused', 'uploadBytesRead', 'uploadPrefixSeen', 'uploadEof', 'uploadVerified', 'uploadSha256', 'responseBytesWritten',
      'responsePrefixWritten', 'responseTailReleased', 'responseEof', 'responseSha256']);
    V.exact(p.io, ['proxyWriteEntries', 'proxyWriteCompletions', 'proxyWritePending', 'wsWriteEntries', 'wsWriteCompletions', 'wsWritePending', 'pendingIngressBytes',
      'backpressureCount', 'resumedPendingCount', 'retainedBytesAtAbort', 'retainedFramesAtAbort', 'retainedStreamLeasesAtAbort']);
    V.exact(p.cleanup, ['controlClosed', 'streamClosed', 'proxyClosed', 'fixtureClosed', 'workers', 'timers', 'pendingCallbacks', 'complete']);
    V.exact(p.timing, ['readyUtcMillis', 'expiresUtcMillis', 'terminalUtcMillis', 'terminalElapsedMillis']);
    if (p.stream !== null) {
      V.exact(p.stream, ['phase', 'cause', 'streamLease', 'webSocketClosed', 'resourcesReleased', 'chargedFrames', 'client', 'gateway']);
      for (const direction of ['client', 'gateway']) {
        V.exact(p.stream[direction], ['sealed', 'eofEmitted', 'chargedBytes']);
        V.boolean(p.stream[direction].sealed); V.boolean(p.stream[direction].eofEmitted); V.integer(p.stream[direction].chargedBytes, 0, 8192);
      }
      for (const key of ['streamLease', 'webSocketClosed', 'resourcesReleased']) V.boolean(p.stream[key]);
    }
    V.boolean(p.control.webSocketClosed); V.boolean(p.control.resourcesReleased); V.integer(p.control.historyCount, 0, 64);
    // Only the selected projection is retained. Unselected public diagnostics are checked for primitive bounds too.
    for (const key of ['uploadPrefixSeen', 'uploadEof', 'uploadVerified', 'responsePrefixWritten', 'responseTailReleased', 'responseEof']) V.boolean(p.fixture[key]);
    for (const key of ['uploadBytesRead', 'responseBytesWritten']) V.integer(p.fixture[key], 0, COUNT_MAX);
    for (const key of ['uploadSha256', 'responseSha256']) if (p.fixture[key] !== null) V.hash(p.fixture[key]);
    V.boolean(p.io.wsWritePending);
    for (const key of ['wsWriteEntries', 'wsWriteCompletions', 'backpressureCount', 'resumedPendingCount']) V.integer(p.io[key], 0, COUNT_MAX);
    V.integer(p.io.retainedBytesAtAbort, 0, 16384); V.integer(p.io.retainedFramesAtAbort, 0, 8); V.integer(p.io.retainedStreamLeasesAtAbort, 0, 2);
    for (const key of ['controlClosed', 'streamClosed', 'proxyClosed', 'fixtureClosed']) V.boolean(p.cleanup[key]);
    return createEnrolledHostSnapshot({ available: inspect.available, grantValid: inspect.grantValid,
      credentialExpiresUtcMillis: inspect.credentialExpiresUtcMillis, gatewayExpiresUtcMillis: inspect.gatewayExpiresUtcMillis, sessionPolicyMillis: inspect.sessionPolicyMillis,
      invalidationCause: inspect.invalidationCause, revalidations: inspect.revalidations, controlsAdmitted: inspect.controlsAdmitted,
      applicationWriteAdmissions: inspect.applicationWriteAdmissions, writesAfterInvalidation: inspect.writesAfterInvalidation,
      controlPhase: p.control.phase, controlCause: p.control.cause, sessionLease: p.control.sessionLease, streamLeases: p.control.streamLeases, chargedBytes: p.control.chargedBytes,
      streamPhase: p.stream?.phase ?? null, streamCause: p.stream?.cause ?? null, chargedFrames: p.stream?.chargedFrames ?? 0,
      proxyWriteEntries: p.io.proxyWriteEntries, proxyWriteCompletions: p.io.proxyWriteCompletions, proxyWritePending: p.io.proxyWritePending,
      pendingIngressBytes: p.io.pendingIngressBytes, proxyReadPaused: p.fixture.proxyReadPaused,
      readyUtcMillis: p.timing.readyUtcMillis, expiresUtcMillis: p.timing.expiresUtcMillis, terminalUtcMillis: p.timing.terminalUtcMillis,
      terminalElapsedMillis: p.timing.terminalElapsedMillis, ownerResourcesReleased: p.control.resourcesReleased && (p.stream === null || p.stream.resourcesReleased),
      cleanupComplete: p.cleanup.complete, workers: p.cleanup.workers, timers: p.cleanup.timers, pendingCallbacks: p.cleanup.pendingCallbacks,
      terminalNotification: inspect.terminalNotification, callStartedNanos, callReceivedNanos });
  } catch { throw new EnrollmentRuntimeError('invalid_enrolled_host_observation'); }
}

export function createEnrolledStreamingInvocationParser(method, { onPhase } = {}) {
  return createEnrollmentSuiteInvocationParser(method, { onPhase, suite: 'a22b' });
}
export function parseEnrolledStreamingInvocation(output, { method, ...commandResult }) {
  const parser = createEnrolledStreamingInvocationParser(method);
  try { parser.push(typeof output === 'string' ? Buffer.from(output) : output); }
  catch (error) { if (!(error instanceof EnrollmentRuntimeError)) throw error; }
  return parser.finish(commandResult);
}
const fail = code => { throw new EnrollmentRuntimeError(code); };
function validateWorker(value) {
  V.exact(value, ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined', 'activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']);
  for (const key of ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined']) V.boolean(value[key]);
  for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']) V.integer(value[key], 0, 64);
}
function validateRuntime(value) {
  V.exact(value, ['format', 'revision', 'source', 'api', 'clock', 'scenarios', 'cleanup', 'problems']);
  if (value.format !== 'http-freekit-a22b-runtime' || value.revision !== 1) throw Error();
  if (value.source !== null) { V.exact(value.source, ['commit', 'trackedDirty']); V.commit(value.source.commit); V.boolean(value.source.trackedDirty); }
  if (value.api !== null) V.enumeration(value.api, [26, 37]);
  if (value.clock !== null) V.validateClock(value.clock);
  V.validateProblems(value.problems);
  if (!Array.isArray(value.scenarios) || value.scenarios.length !== enrolledStreamingCases.length) throw Error();
  for (const [index, item] of value.scenarios.entries()) {
    const descriptor = enrolledStreamingCases[index];
    V.exact(item, ['method', 'scenario', 'invocation', 'input', 'approval', 'profile', 'host', 'cleanup', 'problems']);
    if (item.method !== descriptor.method || item.scenario !== descriptor.scenario) throw Error();
    V.validateInvocation(item.invocation, descriptor.method, 'a22b'); V.validateProblems(item.problems);
    if (item.input !== null) {
      V.exact(item.input, ['byteCount', 'inputBytes', 'inputFinished', 'inputClosed', 'command', 'inputAbsentAfterPrepare']);
      V.integer(item.input.byteCount, 1, 16384); V.integer(item.input.inputBytes, 0, 16384); V.validateCommand(item.input.command);
      for (const key of ['inputFinished', 'inputClosed', 'inputAbsentAfterPrepare']) V.boolean(item.input[key]);
    }
    if (item.approval !== null) {
      V.exact(item.approval, ['liveAwaitingPhaseObserved', 'requested', 'completed', 'approvedResponsesDelivered', 'actualApprovedResponseDrops']);
      for (const key of ['liveAwaitingPhaseObserved', 'requested', 'completed']) V.boolean(item.approval[key]);
      for (const key of ['approvedResponsesDelivered', 'actualApprovedResponseDrops']) V.integer(item.approval[key], 0, 32);
    }
    if (item.profile !== null) {
      V.exact(item.profile, ['credentialLifetimeSeconds', 'sessionLifetimeMillis', 'credentialExpiresUtcMillis', 'gatewayExpiresUtcMillis', 'anchorExpiresUtcMillis']);
      V.integer(item.profile.credentialLifetimeSeconds, 1, 120); V.enumeration(item.profile.sessionLifetimeMillis, [15000, 120000]);
      for (const key of ['credentialExpiresUtcMillis', 'gatewayExpiresUtcMillis', 'anchorExpiresUtcMillis']) utc(item.profile[key]);
    }
    if (item.host !== null) {
      V.exact(item.host, ['awaitingPhaseObserved', 'blockedFirst', 'blockedLast', 'terminal', 'revokeAcknowledged', 'credentialStatus', 'credentialStatusObservedUtcMillis', 'credentialStatusAfterMethod']);
      for (const key of ['awaitingPhaseObserved', 'revokeAcknowledged', 'credentialStatusAfterMethod']) V.boolean(item.host[key]);
      for (const key of ['blockedFirst', 'blockedLast', 'terminal']) if (item.host[key] !== null) validateSnapshot(item.host[key]);
      V.enumeration(item.host.credentialStatus, [null, 'revoked', 'credential_expired', 'active']);
      if (item.host.credentialStatusObservedUtcMillis !== null) utc(item.host.credentialStatusObservedUtcMillis);
      if ((item.host.credentialStatus === null) !== (item.host.credentialStatusObservedUtcMillis === null)) throw Error();
    }
    if (item.cleanup !== null) {
      V.exact(item.cleanup, ['workerClosed', 'workerCommand', 'reverseRemovalExitCodes', 'ownedReversesAbsent', 'privateDirectoryRemoved', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
      if (item.cleanup.workerClosed !== null) validateWorker(item.cleanup.workerClosed);
      if (item.cleanup.workerCommand !== null) V.validateCommand(item.cleanup.workerCommand);
      if (!Array.isArray(item.cleanup.reverseRemovalExitCodes) || item.cleanup.reverseRemovalExitCodes.length > 3) throw Error();
      for (const code of item.cleanup.reverseRemovalExitCodes) V.integer(code, 0, 255);
      for (const key of ['ownedReversesAbsent', 'privateDirectoryRemoved', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']) V.boolean(item.cleanup[key]);
    }
  }
  if (value.cleanup !== null) {
    V.exact(value.cleanup, ['forceStopCommand', 'uninstallCommand', 'uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
    for (const key of ['forceStopCommand', 'uninstallCommand']) if (value.cleanup[key] !== null) V.validateCommand(value.cleanup[key]);
    for (const key of ['uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']) V.boolean(value.cleanup[key]);
  }
}
export function createEnrolledStreamingReport(value) {
  try { validateRuntime(value); return V.copyFreeze(value); }
  catch { fail('invalid_runtime_report'); }
}
export function decodeEnrolledStreamingReport(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > enrollmentRuntimeLimits.runtime) fail('runtime_report_limit');
  let value; try { value = parseEnrollmentJson(bytes); } catch { fail('invalid_runtime_report'); }
  return createEnrolledStreamingReport(value);
}
const blocked = value => value !== null && value.available && value.grantValid && value.invalidationCause === null &&
  value.controlPhase === 'active' && value.controlCause === null && ['open', 'half_closed'].includes(value.streamPhase) && value.streamCause === null &&
  value.controlsAdmitted === 1 && value.sessionLease && value.streamLeases === 1 && value.chargedBytes > 0 && value.chargedFrames > 0 &&
  value.proxyReadPaused && value.pendingIngressBytes === 4096 && value.proxyWritePending && value.proxyWriteEntries > value.proxyWriteCompletions &&
  value.writesAfterInvalidation === 0 && value.terminalUtcMillis === null && !value.ownerResourcesReleased;
const released = value => value !== null && value.available && ['closed', 'failed'].includes(value.controlPhase) && ['cancelled', 'failed'].includes(value.streamPhase) &&
  !value.sessionLease && value.ownerResourcesReleased && value.cleanupComplete && value.writesAfterInvalidation === 0 &&
  !value.proxyWritePending &&
  (!value.terminalNotification.attempted || value.terminalNotification.completed || value.terminalNotification.aborted) &&
  ['streamLeases', 'chargedBytes', 'chargedFrames', 'workers', 'timers', 'pendingCallbacks', 'pendingIngressBytes'].every(key => value[key] === 0);
function verifyScenario(item, descriptor) {
  const { input, approval, profile, host, cleanup } = item, observation = item.invocation.observation;
  if (item.problems.length || item.invocation.state !== 'passed') fail('runtime_invocation_failed');
  if (!input || input.inputBytes !== input.byteCount || !input.inputFinished || !input.inputClosed || !input.inputAbsentAfterPrepare || !V.commandPassed(input.command)) fail('runtime_input_failed');
  if (!approval || !approval.liveAwaitingPhaseObserved || !approval.requested || !approval.completed || approval.approvedResponsesDelivered < 1 || approval.actualApprovedResponseDrops !== 0) fail('runtime_approval_failed');
  if (!profile || profile.credentialLifetimeSeconds !== descriptor.credentialLifetimeSeconds || profile.sessionLifetimeMillis !== descriptor.sessionLifetimeMillis ||
      ['credentialExpiresUtcMillis', 'gatewayExpiresUtcMillis', 'anchorExpiresUtcMillis'].some(key => profile[key] !== observation[key])) fail('runtime_stream_profile_failed');
  if (!host || !host.awaitingPhaseObserved || !blocked(host.blockedFirst) || !blocked(host.blockedLast) || !released(host.terminal)) fail('runtime_stream_host_failed');
  const first = host.blockedFirst, last = host.blockedLast, terminal = host.terminal;
  if (last.callStartedNanos - first.callReceivedNanos < 250000000 || terminal.callStartedNanos < last.callReceivedNanos ||
      first.proxyWriteEntries !== last.proxyWriteEntries || first.proxyWriteCompletions !== last.proxyWriteCompletions ||
      terminal.applicationWriteAdmissions < last.applicationWriteAdmissions || terminal.proxyWriteEntries < last.proxyWriteEntries || terminal.proxyWriteCompletions < last.proxyWriteCompletions) fail('runtime_stream_interval_failed');
  for (const value of [first, last, terminal]) {
    if (value.credentialExpiresUtcMillis !== profile.credentialExpiresUtcMillis || value.gatewayExpiresUtcMillis !== profile.gatewayExpiresUtcMillis || value.sessionPolicyMillis !== profile.sessionLifetimeMillis ||
        value.readyUtcMillis !== first.readyUtcMillis || value.expiresUtcMillis !== first.expiresUtcMillis || value.expiresUtcMillis !== observation.sessionExpiresUtcMillis) fail('runtime_stream_profile_failed');
  }
  const expiry = terminal.expiresUtcMillis, ready = terminal.readyUtcMillis;
  if (profile.credentialExpiresUtcMillis - ready > profile.credentialLifetimeSeconds * 1000) fail('runtime_stream_profile_failed');
  const bound = Math.floor(Math.min(ready + profile.sessionLifetimeMillis, profile.credentialExpiresUtcMillis, profile.gatewayExpiresUtcMillis, profile.anchorExpiresUtcMillis) / 1000) * 1000;
  if (expiry % 1000 || expiry <= ready || expiry > bound) fail('runtime_stream_profile_failed');
  if (host.credentialStatus !== ({ revocation: 'revoked', credential_expiry: 'credential_expired', session_expiry: 'active' })[item.scenario]) fail('runtime_stream_policy_failed');
  if (item.scenario === 'revocation') {
    if (!host.revokeAcknowledged || terminal.invalidationCause !== 'device_revoked' || terminal.controlCause !== 'device_revoked' || !['device_revoked', 'network_unreachable'].includes(terminal.streamCause) || terminal.grantValid ||
        terminal.controlsAdmitted !== 1 || !['device_revoked', 'network_unreachable'].includes(observation.localCause) || host.credentialStatusAfterMethod) fail('runtime_stream_policy_failed');
  } else {
    if (expiry !== bound) fail('runtime_stream_profile_failed');
    if (host.revokeAcknowledged || !['session_expired', 'network_unreachable'].includes(terminal.controlCause) || !['session_expired', 'network_unreachable'].includes(terminal.streamCause) || !['session_expired', 'network_unreachable'].includes(observation.localCause)) fail('runtime_stream_policy_failed');
    const hostExpired = terminal.controlCause === 'session_expired', localExpired = observation.localCause === 'session_expired';
    if ((!hostExpired && !localExpired) || (hostExpired && (terminal.terminalUtcMillis === null ||
        (terminal.terminalUtcMillis < expiry && terminal.terminalElapsedMillis < expiry - ready))) ||
        (localExpired && observation.terminalObservedUtcMillis < expiry && observation.terminalObservedElapsedMillis < expiry - observation.readinessObservedUtcMillis)) fail('runtime_stream_deadline_failed');
    if (item.scenario === 'credential_expiry') {
      if (Math.floor(profile.credentialExpiresUtcMillis / 1000) * 1000 !== bound || terminal.controlsAdmitted !== 1 ||
          !host.credentialStatusAfterMethod || host.credentialStatusObservedUtcMillis < profile.credentialExpiresUtcMillis) fail('runtime_stream_policy_failed');
    } else if (bound !== Math.floor((ready + 15000) / 1000) * 1000 || profile.credentialExpiresUtcMillis <= expiry || terminal.controlsAdmitted !== 2 ||
        !terminal.grantValid || terminal.invalidationCause !== null || host.credentialStatusAfterMethod || host.credentialStatusObservedUtcMillis >= profile.credentialExpiresUtcMillis) fail('runtime_stream_policy_failed');
  }
  if (!cleanup || !V.workerPassed(cleanup.workerClosed) || !V.commandPassed(cleanup.workerCommand) || cleanup.reverseRemovalExitCodes.length !== 3 ||
      cleanup.reverseRemovalExitCodes.some(code => code !== 0) || !['ownedReversesAbsent', 'privateDirectoryRemoved', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => cleanup[key])) fail('runtime_cleanup_failed');
}
export function verifyEnrolledStreamingReport(report, { source, api }) {
  createEnrolledStreamingReport(report); V.commit(source); V.enumeration(api, [26, 37]);
  if (report.source?.commit !== source || report.source.trackedDirty || report.api !== api) fail('runtime_source_mismatch');
  if (!V.clockPassed(report.clock)) fail('runtime_clock_failed');
  if (report.problems.length) fail('runtime_invocation_failed');
  report.scenarios.forEach((item, index) => verifyScenario(item, enrolledStreamingCases[index]));
  const cleanup = report.cleanup;
  if (!cleanup || !['forceStopCommand', 'uninstallCommand'].every(key => V.commandPassed(cleanup[key])) ||
      !['uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => cleanup[key])) fail('runtime_cleanup_failed');
  return Object.freeze({ methods: 3, actualStarted: 3, actualCompleted: 3, api, source });
}
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);
function rendered(text) { if (Buffer.byteLength(text) > enrollmentRuntimeLimits.rendered) fail('rendered_report_limit'); return text; }
export function enrolledStreamingRuntimeXml(value) {
  const report = createEnrolledStreamingReport(value), invocations = report.scenarios.map(item => item.invocation);
  const rows = invocations.map(item => {
    const detail = item.problems.join(', ') + (item.failureType ? '\n' + item.failureType : '') + item.frames.map(frame => `\nat ${frame.className}.${frame.method}(${frame.file}:${frame.line})`).join('');
    const result = item.state === 'passed' ? '' : item.state === 'failed' ? `<failure message="Enrolled stream assertion failed">${escape(detail)}</failure>` : `<error message="Enrolled stream method did not complete">${escape(detail)}</error>`;
    return `<testcase classname="${enrolledStreamingClass}" name="${item.method}" time="0">${result}</testcase>`;
  });
  return rendered(`<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="${enrolledStreamingClass}" tests="3" failures="${invocations.filter(item => item.state === 'failed').length}" errors="${invocations.filter(item => !['passed', 'failed'].includes(item.state)).length}" skipped="0">\n${rows.join('\n')}\n<system-out>${escape(report.problems.join(', ') || 'Method observations only; final runtime and emulator cleanup JSON are required.')}</system-out>\n</testsuite>\n`);
}
export function enrolledStreamingRuntimeHtml(value) {
  const report = createEnrolledStreamingReport(value);
  return rendered('<!doctype html><html lang="en"><meta charset="utf-8"><title>Enrolled stream research results</title><body><h1>A22b method and host observations</h1><pre>' + escape(JSON.stringify(report, null, 2)) + '</pre></body></html>\n');
}
