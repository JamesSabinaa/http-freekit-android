// Synthetic finite report inputs only; no credentials, traffic records or runtime claim.
import { createCaptureFactoryInvocationParser, parseCaptureFactoryInvocation, verifyCaptureFactoryReport,
  captureFactoryClass, captureFactoryMethod, captureFactoryPhases, captureFactoryObservationSuffixes, captureFactoryPayload } from './capture-factory-results.mjs';
import { runtime as legacyRuntime, worker as workerClosed, command as commandObservation } from './enrollment-runtime-test-fixtures.mjs';
export const command = () => ({ code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
export const status = (code, stack) => `INSTRUMENTATION_STATUS: class=${captureFactoryClass}\nINSTRUMENTATION_STATUS: test=${captureFactoryMethod}\nINSTRUMENTATION_STATUS: numtests=1\n` +
  (stack ? `INSTRUMENTATION_STATUS: stack=${stack}\n` : '') + `INSTRUMENTATION_STATUS_CODE: ${code}\n`;
export const phase = value => `INSTRUMENTATION_STATUS: draftFactoryVersion=1\nINSTRUMENTATION_STATUS: draftFactoryPhase=${value}\nINSTRUMENTATION_STATUS_CODE: 2\n`;
export function facts() {
  const booleans = new Set(('CredentialSavedReloaded KeyNonexportable OriginalCredentialUnchanged VpnConsentGranted NoTunEstablished ' +
    'ApplicationOutputHalfClosed StrictResponseEof FactoryClosed RelayJoined ServiceObserverJoined ServiceDestroyed OwnedStateAbsent').split(' '));
  return Object.fromEntries(captureFactoryObservationSuffixes.map(suffix => ['draftFactory' + suffix, booleans.has(suffix) ? 'true' :
    suffix === 'SessionLease' ? 'false' : ['ProtectAttempts', 'ProtectSuccesses', 'BindAttempts', 'BindSuccesses'].includes(suffix) ? '2' :
    suffix === 'Version' ? '1' : suffix === 'RequestBodyBytes' ? '16421' : suffix === 'ResponseBodyBytes' ? '32787' :
    suffix === 'ResponseBodySha256' ? captureFactoryPayload.responseBodySha256 : '0']));
}
export const observation = value => Object.entries(value).map(([key, field]) => `INSTRUMENTATION_STATUS: ${key}=${field}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 3\n';
export const prefix = count => status(1) + captureFactoryPhases.slice(0, count).map(phase).join('');
export const transcript = value => prefix(9) + observation(value ?? facts()) + phase(captureFactoryPhases[9]) + status(0) + 'INSTRUMENTATION_CODE: -1\n';
export const parse = value => parseCaptureFactoryInvocation(value, command());
export const source = 'a'.repeat(40), desktopCommit = 'b'.repeat(40);
export function report() {
  return { format: 'http-freekit-capture-factory-runtime', revision: 1, source: { commit: source, trackedDirty: false }, api: 26,
    clock: legacyRuntime().clock, invocation: parse(transcript()),
    input: { byteCount: 100, inputBytes: 100, inputFinished: true, inputClosed: true, command: commandObservation(), inputAbsentAfterMethod: true },
    approval: { livePhaseObserved: true, requested: true, completed: true, approvedResponsesDelivered: 1, actualApprovedResponseDrops: 0, issuerCommandsBefore: 1, issuerCommandsAfter: 2, issuerJobsAfter: 0 },
    host: { desktopCommit, registered: true, liveReleasePhaseObserved: true, releaseRequested: true, releaseCompleted: true, gatewayStreamComplete: true,
      origin: { connections: 1, requests: 1, requestBodyBytes: 16421, requestBodySha256: captureFactoryPayload.requestBodySha256, requestVerified: true,
        responseBodyBytesWritten: 32787, responseBodySha256: captureFactoryPayload.responseBodySha256, responsePrefixWritten: true, responseEof: true,
        tailReleased: true, clientEndWriteApplied: true, originalDestinationMatched: true, captureMatched: true, tailReleaseRequested: true },
      backend: { closing: false, activeOwners: 0, admitted: 1, settled: 1, captures: 1, clientEndWrites: 1, proxyMode: 'http-origin-connect', negotiatedCapabilities: ['tcp-http-origin-connect'] } },
    resources: { workerClosed: workerClosed(), workerCommand: commandObservation(), reverseRemovalExitCodes: [0, 0, 0], ownedReversesAbsent: true,
      privateDirectoryRemoved: true, gatewayStreamComplete: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true },
    cleanup: { forceStopCommand: commandObservation(), uninstallCommand: commandObservation(), uninstallConfirmed: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true }, problems: [] };
}
export const clone = value => JSON.parse(JSON.stringify(value));
export const verify = value => verifyCaptureFactoryReport(value, { source, api: 26, desktopCommit });

