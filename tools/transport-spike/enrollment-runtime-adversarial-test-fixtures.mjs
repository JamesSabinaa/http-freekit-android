// Synthetic report observations only. No invitation, nonce, key or certificate material.
import { enrollmentAdversarialCases, enrollmentAdversarialClass } from './enrollment-runtime-adversarial-descriptor.mjs';
import { parseEnrollmentAdversarialInvocation } from './enrollment-runtime-adversarial-results.mjs';
import { command, commandResult, source, worker, runtime as baseRuntime } from './enrollment-runtime-test-fixtures.mjs';
export { commandResult, source };
const now = 1792852701000;
export function observation(index = 0) {
  const common = { version: 1, scenario: ['proof_misuse', 'wrong_tls', 'pending_cancel', 'published_cancel'][index],
    originalKeyUnchanged: true, credentialSaved: index === 3, ownedStateAbsent: true, clientResourcesClosed: true };
  return { ...common, ...[
    { purposeHttp: 403, purposeCode: 'authentication_failed', wireContextHttp: 403, wireContextCode: 'authentication_failed',
      signedContextHttp: 403, signedContextCode: 'authentication_failed', sameChallengeHttp: 200, sameChallengeType: 'pair_pending',
      replayHttp: 403, replayCode: 'authentication_failed', freshStatusHttp: 200, freshStatusType: 'pair_pending', bindingUnchanged: true },
    { tlsFailureType: 'SSLException', freshStatusHttp: 200, freshStatusType: 'pair_pending', bindingUnchanged: true, expectedTrustUnchanged: true },
    { cancelHttp: 200, cancelCode: 'pairing_cancelled', replayHttp: 403, replayCode: 'authentication_failed', freshStatusHttp: 200,
      freshStatusCode: 'pairing_cancelled', bindingUnchanged: true },
    { approvalHttp: 200, approvalType: 'pair_approved', savedCredentialUnchanged: true, beforeMtlsHttp: 200, cancelHttp: 200,
      cancelCode: 'pairing_cancelled', afterMtlsHttp: 403, freshStatusHttp: 200, freshStatusCode: 'pairing_cancelled',
      credentialExpiresUtcMillis: now + 60000, refusalObservedUtcMillis: now + 5000, keyManagerUsableAtRefusal: true, bindingUnchanged: true },
  ][index] };
}
export const phase = value => `INSTRUMENTATION_STATUS: draftAdversarialVersion=1\nINSTRUMENTATION_STATUS: draftAdversarialPhase=${value}\nINSTRUMENTATION_STATUS_CODE: 2\n`;
export const status = (index, code, extra = '') => `INSTRUMENTATION_STATUS: class=${enrollmentAdversarialClass}\nINSTRUMENTATION_STATUS: test=${enrollmentAdversarialCases[index].method}\nINSTRUMENTATION_STATUS: numtests=1\nINSTRUMENTATION_STATUS: current=1\n${extra}INSTRUMENTATION_STATUS_CODE: ${code}\n`;
export const bundle = (index, value = observation(index)) => enrollmentAdversarialCases[index].observationSuffixes.map(suffix =>
  `INSTRUMENTATION_STATUS: draftAdversarial${suffix}=${value[suffix[0].toLowerCase() + suffix.slice(1)]}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 3\n';
export const transcript = index => status(index, 1) + enrollmentAdversarialCases[index].phases.slice(0, -1).map(phase).join('') +
  bundle(index) + phase('owned-state-forgotten') + status(index, 0) + 'INSTRUMENTATION_CODE: -1\n';
export function runtime() {
  const value = { format: 'http-freekit-a22c-runtime', revision: 1, source: { commit: source, trackedDirty: false }, api: 26,
    clock: baseRuntime().clock, scenarios: enrollmentAdversarialCases.map((descriptor, index) => ({ method: descriptor.method, scenario: descriptor.scenario,
      invocation: parseEnrollmentAdversarialInvocation(transcript(index), { method: descriptor.method, ...commandResult() }), input: baseRuntime().input,
      approval: index === 3 ? { liveAwaitingPhaseObserved: true, requested: true, completed: true, approvedResponsesDelivered: 1,
        actualApprovedResponseDrops: 0, issuerCommandsAfterApproval: 5, credentialExpiresUtcMillis: now + 60000 } : null,
      host: { registered: true, result: index < 2 ? 'pending' : 'cancelled', resultAfterMethod: true,
        dispatchesBefore: 0, dispatchesAfter: 12, issuerCommandsBefore: 2, issuerCommandsAfter: index === 3 ? 5 : 2, issuerJobsAfter: 0,
        lateApproval: index === 2 ? { livePhaseObserved: true, requested: true, completed: true, error: 'invitation_used', resultAfterAttempt: 'cancelled' } : null,
        alternateTls: index === 1 ? { accepted: 1, rejected: 1, httpDispatches: 0, secureConnections: 0, activeSockets: 0, pendingCallbacks: 0,
          pendingTimers: 0, workers: 0, childrenStarted: 2, childrenClosed: 2, childGroupsClosed: 2, admissionClosed: false, listenerClosed: false } : null },
      cleanup: { workerClosed: worker(), workerCommand: command(), reverseRemovalExitCodes: index === 1 ? [0, 0, 0] : [0, 0],
        ownedReversesAbsent: true, privateDirectoryRemoved: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true }, problems: [] })),
    cleanup: { forceStopCommand: command(), uninstallCommand: command(), uninstallConfirmed: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true }, problems: [] };
  return JSON.parse(JSON.stringify(value));
}
