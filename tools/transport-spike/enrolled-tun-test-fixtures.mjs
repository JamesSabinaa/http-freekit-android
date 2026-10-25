// Authored synthetic acceptance inputs; no Android execution or traffic claim.
import { enrolledTunClass, enrolledTunMethod, enrolledTunPhases } from './enrolled-tun-descriptor.mjs';
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
