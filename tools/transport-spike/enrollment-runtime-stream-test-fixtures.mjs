// Synthetic evidence only; no invitation, identity or credential material.
import { enrolledStreamingCases, enrolledStreamingClass, enrolledObservationSuffixes } from './enrollment-runtime-stream-descriptor.mjs';
import { parseEnrolledStreamingInvocation } from './enrollment-runtime-stream-results.mjs';
import { command, commandResult, runtime as enrollmentRuntime, worker, source } from './enrollment-runtime-test-fixtures.mjs';
export { source, command, commandResult };
export const now = 1792852701000;
export function observation(index = 0) {
  const scenario = enrolledStreamingCases[index].scenario, session = index === 2, end = now + (session ? 15000 : 60000), terminal = index === 0 ? now + 5000 : end;
  return { version: 1, scenario, credentialExpiresUtcMillis: now + 60000, gatewayExpiresUtcMillis: now + 3600000, anchorExpiresUtcMillis: now + 3600000,
    policyMillis: session ? 15000 : 120000, readinessObservedUtcMillis: now, sessionExpiresUtcMillis: end,
    terminalObservedUtcMillis: terminal, terminalObservedElapsedMillis: terminal - now, localCause: index === 0 ? 'device_revoked' : 'session_expired',
    applicationWriteEntered: 7, applicationWriteCompleted: 6, applicationWriteInFlight: 7, applicationPendingBytes: 4096, applicationChargedBytes: 8192,
    applicationChargedFrames: 2, applicationBlockedMillis: 250, prefixBytes: 4096, localTicks: 2, controlInactive: true, streamInactive: true,
    sameCredential: true, freshAdmission: session ? 'new_control' : 'denied', oldSessionRejected: session, newControlAdmitted: session,
    newControlObservedUtcMillis: session ? end + 1000 : null, socketsClosed: true, workersJoined: true,
    ownedThreadsAlive: 0, sessionLeases: 0, streamLeases: 0, chargedBytes: 0, pendingCallbacks: 0, timers: 0 };
}
export function status(index, code, extra = '') {
  return `INSTRUMENTATION_STATUS: class=${enrolledStreamingClass}\nINSTRUMENTATION_STATUS: test=${enrolledStreamingCases[index].method}\nINSTRUMENTATION_STATUS: numtests=1\nINSTRUMENTATION_STATUS: current=1\n${extra}INSTRUMENTATION_STATUS_CODE: ${code}\n`;
}
export const phase = value => `INSTRUMENTATION_STATUS: draftEnrolledVersion=1\nINSTRUMENTATION_STATUS: draftEnrolledPhase=${value}\nINSTRUMENTATION_STATUS_CODE: 2\n`;
export const bundle = value => enrolledObservationSuffixes.map(suffix => `INSTRUMENTATION_STATUS: draftEnrolled${suffix}=${value[suffix[0].toLowerCase() + suffix.slice(1)]}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 3\n';
export const transcript = index => status(index, 1) + enrolledStreamingCases[index].phases.slice(0, 10).map(phase).join('') + bundle(observation(index)) +
  enrolledStreamingCases[index].phases.slice(10).map(phase).join('') + status(index, 0) + 'INSTRUMENTATION_CODE: -1\n';
export function hostSnapshot(index, terminal = false) {
  const value = observation(index), cause = index === 0 ? 'device_revoked' : 'session_expired';
  return { available: true, grantValid: !terminal || index === 2, credentialExpiresUtcMillis: value.credentialExpiresUtcMillis,
    gatewayExpiresUtcMillis: value.gatewayExpiresUtcMillis, sessionPolicyMillis: value.policyMillis,
    invalidationCause: terminal && index !== 2 ? cause : null, revalidations: 5, controlsAdmitted: terminal && index === 2 ? 2 : 1,
    applicationWriteAdmissions: 8, writesAfterInvalidation: 0, controlPhase: terminal ? 'failed' : 'active', controlCause: terminal ? cause : null,
    sessionLease: !terminal, streamLeases: terminal ? 0 : 1, chargedBytes: terminal ? 0 : 8192,
    streamPhase: terminal ? 'failed' : 'open', streamCause: terminal ? cause : null, chargedFrames: terminal ? 0 : 2,
    proxyWriteEntries: 7, proxyWriteCompletions: terminal ? 7 : 6, proxyWritePending: !terminal, pendingIngressBytes: terminal ? 0 : 4096,
    proxyReadPaused: true, readyUtcMillis: now, expiresUtcMillis: value.sessionExpiresUtcMillis,
    terminalUtcMillis: terminal ? value.terminalObservedUtcMillis : null, terminalElapsedMillis: terminal ? value.terminalObservedElapsedMillis : null,
    ownerResourcesReleased: terminal, cleanupComplete: terminal, workers: terminal ? 0 : 4, timers: terminal ? 0 : 1, pendingCallbacks: terminal ? 0 : 1,
    terminalNotification: { attempted: terminal, completed: terminal, aborted: false }, callStartedNanos: terminal ? 5000000000 : 0, callReceivedNanos: terminal ? 5001000000 : 1000000 };
}
export function runtime() {
  const value = { format: 'http-freekit-a22b-runtime', revision: 1, source: { commit: source, trackedDirty: false }, api: 26, clock: enrollmentRuntime().clock,
    scenarios: enrolledStreamingCases.map((item, index) => ({ method: item.method, scenario: item.scenario,
      invocation: parseEnrolledStreamingInvocation(transcript(index), { method: item.method, ...commandResult() }),
      input: enrollmentRuntime().input,
      approval: { liveAwaitingPhaseObserved: true, requested: true, completed: true, approvedResponsesDelivered: 1, actualApprovedResponseDrops: 0 },
      profile: { credentialLifetimeSeconds: 60, sessionLifetimeMillis: item.sessionLifetimeMillis, credentialExpiresUtcMillis: now + 60000,
        gatewayExpiresUtcMillis: now + 3600000, anchorExpiresUtcMillis: now + 3600000 },
      host: { awaitingPhaseObserved: true, blockedFirst: hostSnapshot(index), blockedLast: { ...hostSnapshot(index), callStartedNanos: 251000000, callReceivedNanos: 252000000 },
        terminal: hostSnapshot(index, true), revokeAcknowledged: index === 0,
        credentialStatus: ['revoked', 'credential_expired', 'active'][index], credentialStatusObservedUtcMillis: index === 1 ? now + 60001 : now + 20000,
        credentialStatusAfterMethod: index === 1 },
      cleanup: { workerClosed: worker(), workerCommand: command(), reverseRemovalExitCodes: [0, 0, 0], ownedReversesAbsent: true,
        privateDirectoryRemoved: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true }, problems: [] })),
    cleanup: { forceStopCommand: command(), uninstallCommand: command(), uninstallConfirmed: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true }, problems: [] };
  return JSON.parse(JSON.stringify(value));
}
