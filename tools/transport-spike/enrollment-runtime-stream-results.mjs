import { EnrollmentRuntimeError, enrollmentRuntimeValidation as V } from './enrollment-runtime-results.mjs';
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
