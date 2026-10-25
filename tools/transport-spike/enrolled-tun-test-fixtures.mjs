// Authored synthetic acceptance inputs; no Android execution or traffic claim.
import { enrolledTunClass, enrolledTunMethod, enrolledTunPhases } from './enrolled-tun-descriptor.mjs';
import { parseEnrolledTunInvocation, enrolledTunPayload, enrolledTunDesktopCommit, enrolledTunAcknowledgment, verifyEnrolledTunReport } from './enrolled-tun-results.mjs';
import { runtime as legacyRuntime, worker, command as commandObservation } from './enrollment-runtime-test-fixtures.mjs';
export const command = () => ({ code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true });
export const status = (code, stack) => `INSTRUMENTATION_STATUS: class=${enrolledTunClass}\nINSTRUMENTATION_STATUS: test=${enrolledTunMethod}\nINSTRUMENTATION_STATUS: numtests=1\n` +
  (stack ? `INSTRUMENTATION_STATUS: stack=${stack}\n` : '') + `INSTRUMENTATION_STATUS_CODE: ${code}\n`;
export const phase = value => `INSTRUMENTATION_STATUS: draftTunVersion=1\nINSTRUMENTATION_STATUS: draftTunPhase=${value}\nINSTRUMENTATION_STATUS_CODE: 2\n`;
export const facts = () => ({
  draftTunVersion: '1', draftTunCredentialSavedReloaded: 'true', draftTunKeyNonexportable: 'true', draftTunOriginalCredentialUnchanged: 'true',
  draftTunVpnConsentGranted: 'true', draftTunSeparateTrafficUid: 'true', draftTunSelectedUidVpnObserved: 'true', draftTunTunAndNativeObserved: 'true',
  draftTunForegroundNotificationObserved: 'true', draftTunHttpAttempts: '1', draftTunHttpOutputHalfClosed: 'true', draftTunStrictResponseEof: 'true',
  draftTunLocalStreamsDrained: 'true', draftTunHostCompleteAcknowledged: 'true', draftTunProtectAttempts: '2', draftTunProtectSuccesses: '2',
  draftTunBindAttempts: '2', draftTunBindSuccesses: '2', draftTunSelectedPackageCount: '1', draftTunInterceptedTcpFlows: '1', draftTunDirectTcpFlows: '0',
  draftTunUdpTargets: '0', draftTunUdp443Drops: '0', draftTunProtectFailures: '0', draftTunBindFailures: '0', draftTunResponseBodyBytes: '32787',
  draftTunResponseBodySha256: '62a22a63bb850ba7b263fccff99e868133570394d36d6ee16fd32e9d7c1a4601',
  draftTunCaptureStopped: 'true', draftTunTunClosed: 'true', draftTunNativeStopJoined: 'true', draftTunConfigurationAbsent: 'true', draftTunLifecycleJoined: 'true',
  draftTunActiveFlows: '0', draftTunOwnedSockets: '0', draftTunPendingOpens: '0', draftTunLiveWorkers: '0', draftTunFactoryClosed: 'true',
  draftTunFactoryPendingOpens: '0', draftTunFactoryPendingCalls: '0', draftTunRetainedTransports: '0', draftTunFactoryLiveWorkers: '0',
  draftTunSessionLease: 'false', draftTunStreamLeases: '0', draftTunChargedBytes: '0', draftTunPendingIngressBytes: '0',
  draftTunBackendOutputBytes: '0', draftTunBackendIncomingBytes: '0', draftTunNonVpnRouteObserved: 'true', draftTunTrafficWorkerJoined: 'true', draftTunOwnedStateAbsent: 'true',
});
export const observation = value => Object.entries(value).map(([key, field]) => `INSTRUMENTATION_STATUS: ${key}=${field}\n`).join('') + 'INSTRUMENTATION_STATUS_CODE: 3\n';
export const prefix = count => status(1) + enrolledTunPhases.slice(0, count).map(phase).join('');
export const transcript = value => prefix(14) + observation(value ?? facts()) + phase(enrolledTunPhases[14]) + status(0) + 'INSTRUMENTATION_CODE: -1\n';
export const source = 'a'.repeat(40), desktopCommit = enrolledTunDesktopCommit;
export function hostSnapshot() {
  return { profile: 'tun-http-h1', family: 'ipv4', gatewayStreamComplete: true,
    origin: { connections: 1, requests: 1, requestBodyBytes: 16421, requestBodySha256: enrolledTunPayload.requestBodySha256, requestVerified: true,
      responseBodyBytesWritten: 32787, responseBodySha256: enrolledTunPayload.responseBodySha256, responsePrefixWritten: true, responseEof: true,
      tailReleased: true, clientEndWriteApplied: true, originalDestinationMatched: true, captureMatched: true, tailReleaseRequested: true,
      tlsConnections: 0, tlsSniMatched: false, tlsAlpnH1: false, upgradeRequests: 0, upgradeAccepted: false, clientTextMessages: 0,
      clientBinaryMessages: 0, clientBinaryBytes: 0, clientBinarySha256: null, clientPings: 0, clientPongs: 0,
      clientCloseObserved: false, serverCloseWritten: false, failed: false },
    backend: { closing: false, activeOwners: 0, admitted: 1, settled: 1, captures: 1, clientEndWrites: 1,
      proxyMode: 'http-origin-connect', negotiatedCapabilities: [...enrolledTunPayload.gatewayCapabilities] } };
}
export function report(api = 26) {
  const bytes = Buffer.byteLength(enrolledTunAcknowledgment.bytes);
  return { format: 'http-freekit-enrolled-tun-runtime', revision: 1, source: { commit: source, trackedDirty: false }, api,
    clock: legacyRuntime().clock, invocation: parseEnrolledTunInvocation(transcript(), command()),
    input: { byteCount: 100, inputBytes: 100, inputFinished: true, inputClosed: true, command: commandObservation(), inputAbsentAfterMethod: true },
    approval: { livePhaseObserved: true, requested: true, completed: true, approvedResponsesDelivered: 1, actualApprovedResponseDrops: 0,
      issuerCommandsBefore: 1, issuerCommandsAfter: 2, issuerJobsAfter: 0 },
    host: { desktopCommit, registered: true, liveReleasePhaseObserved: true, releaseRequested: true, releaseCompleted: true,
      liveCompletionPhaseObserved: true, completeObservedBeforeAck: true, androidAckPhaseObserved: true, ...hostSnapshot() },
    alias: { platform: 'linux', initiallyAbsent: true, created: true, verified: true, removalRequested: true, removed: true, absenceConfirmed: true, refusal: null,
      commands: Object.fromEntries(['before', 'create', 'verify', 'remove', 'after'].map(key => [key, commandObservation()])) },
    ack: { byteCount: bytes, inputBytes: bytes, inputFinished: true, inputClosed: true, command: commandObservation(), published: true, absentAfterMethod: true },
    apkSetup: { sameSigner: true, controlTrafficGranted: true, packages: ['com.httpfreekit.capturetest', 'com.httpfreekit.capturetraffic'].map(packageName => ({
      package: packageName, initiallyAbsent: true, installAttempted: true, installed: true, installCommand: commandObservation(), forceStopCommand: commandObservation(),
      uninstallCommand: commandObservation(), uninstallConfirmed: true, absentAfterCleanup: true })),
      permissions: { mode: api === 26 ? 'not_required' : 'owned_ci_grant', interopLocalNetwork: api === 26 ? null : commandObservation(),
        trafficLocalNetwork: api === 26 ? null : commandObservation(), interopNotification: api === 26 ? null : commandObservation() } },
    resources: { workerClosed: worker(), workerCommand: commandObservation(), reverseRemovalExitCodes: [0, 0, 0], ownedReversesAbsent: true,
      privateDirectoryRemoved: true, gatewayStreamComplete: true, ownedCommandsClosed: true, ownedCommandGroupsClosed: true },
    cleanup: { forceStopCommand: commandObservation(), uninstallCommand: commandObservation(), uninstallConfirmed: true, packageAbsentAfterCleanup: true,
      ownedCommandsClosed: true, ownedCommandGroupsClosed: true }, problems: [] };
}
export const clone = value => JSON.parse(JSON.stringify(value));
export const verify = value => verifyEnrolledTunReport(value, { source, api: value.api, desktopCommit });
