// Synthetic adapter input only: no invitation, key or registry material.
import { expectedEnrollmentMethods, enrollmentRuntimeClass, enrollmentPhases, parseEnrollmentInvocation } from './enrollment-runtime-results.mjs';
export const source = 'a'.repeat(40);
export const command = () => ({ exitCode: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
export const commandResult = () => ({ code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
export function status(method, code, extra = '') {
  return `INSTRUMENTATION_STATUS: class=${enrollmentRuntimeClass}\nINSTRUMENTATION_STATUS: test=${method}\nINSTRUMENTATION_STATUS: numtests=1\nINSTRUMENTATION_STATUS: current=1\n${extra}INSTRUMENTATION_STATUS_CODE: ${code}\n`;
}
export const phase = value => `INSTRUMENTATION_STATUS: draftEnrollmentVersion=1\nINSTRUMENTATION_STATUS: draftEnrollmentPhase=${value}\nINSTRUMENTATION_STATUS_CODE: 2\n`;
export const transcript = method => status(method, 1) + enrollmentPhases[method].map(phase).join('') + status(method, 0) + 'INSTRUMENTATION_RESULT: stream=\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n';
export const worker = () => ({ admissionClosed: true, listenersClosed: true, storeClosed: true, issuerChildrenJoined: true,
  activeSockets: 0, pendingCallbacks: 0, pendingTimers: 0, issuerJobs: 0, signerGroups: 0, workers: 0 });
export function runtime() {
  return {
    format: 'http-freekit-a22a-runtime', revision: 1, source: { commit: source, trackedDirty: false }, api: 26,
    clock: { deviceEpochSeconds: 1792852701, hostBeforeMillis: 1792852701000, hostAfterMillis: 1792852701010, lowerBoundMillis: -10, upperBoundMillis: 999, roundTripMillis: 10 },
    invocations: expectedEnrollmentMethods.map(method => parseEnrollmentInvocation(transcript(method), { method, ...commandResult() })),
    input: { byteCount: 100, inputBytes: 100, inputFinished: true, inputClosed: true, command: command(), inputAbsentAfterPrepare: true },
    approval: { liveAwaitingPhaseObserved: true, dropArmAcknowledged: true, requestedAfterArm: true, completed: true, actualApprovedResponseDrops: 1, approvedResponsesAfterDrop: 1, reopenedApprovedResponses: 1 },
    stop: { forceStopCommand: command(), deviceBefore: 'device', deviceAfter: 'device', presenceBefore: 'present', presenceAfter: 'absent', absenceQueryExitCode: 0, absenceMarkerVerified: true },
    restart: { initialWorkerClosed: worker(), initialWorkerCommand: command(), opened: true, continuity: {
      setupPortBefore: 32101, setupPortAfter: 32101, credentialPortBefore: 32102, credentialPortAfter: 32102,
      gatewayCertificateSha256Before: '1'.repeat(64), gatewayCertificateSha256After: '1'.repeat(64),
      enrollmentAuthoritySha256Before: '2'.repeat(64), enrollmentAuthoritySha256After: '2'.repeat(64),
      approvedResultSha256Before: '3'.repeat(64), approvedResultSha256After: '3'.repeat(64) } },
    cleanup: { forceStopCommand: command(), uninstallCommand: command(), uninstallConfirmed: true, reverseRemovalExitCodes: [0, 0], ownedReversesAbsent: true,
      finalWorkerClosed: worker(), finalWorkerCommand: command(), ownedCommandsClosed: true, ownedCommandGroupsClosed: true, privateDirectoryRemoved: true },
    problems: [],
  };
}
export const host = () => ({ format: 'http-freekit-a22a-host-cleanup', revision: 1, sourceCommit: source, api: 26, driverExitCode: 0,
  emulatorStarted: true, stopAttempted: true, stopExitCode: 0, terminationObserved: true, joinObserved: true, emulatorExitCode: 0 });
export const clone = value => JSON.parse(JSON.stringify(value));
