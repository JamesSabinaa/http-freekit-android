import { enrolledObservationSuffixes, enrolledStreamingScenarios } from './enrollment-runtime-stream-descriptor.mjs';
export const enrolledObservationKeys = Object.freeze(enrolledObservationSuffixes.map(value => value[0].toLowerCase() + value.slice(1)));
const bools = new Set('ControlInactive StreamInactive SameCredential OldSessionRejected NewControlAdmitted SocketsClosed WorkersJoined'.split(' '));
const enums = { Scenario: ['revocation', 'credential_expiry', 'session_expiry'], LocalCause: ['device_revoked', 'session_expired', 'network_unreachable'],
  FreshAdmission: ['denied', 'new_control'] };
const utc = ['credentialExpiresUtcMillis', 'gatewayExpiresUtcMillis', 'anchorExpiresUtcMillis', 'readinessObservedUtcMillis', 'sessionExpiresUtcMillis', 'terminalObservedUtcMillis'];
const uint = (value, low = 0, high = 33570816) => { if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < low || value > high) throw Error(); };
export function validateEnrolledObservation(value, method) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== enrolledObservationKeys.length ||
      enrolledObservationKeys.some(key => !Object.hasOwn(value, key)) || value.version !== 1 || value.scenario !== enrolledStreamingScenarios[method]) throw Error();
  for (const suffix of enrolledObservationSuffixes) {
    const key = suffix[0].toLowerCase() + suffix.slice(1), item = value[key];
    if (bools.has(suffix)) { if (typeof item !== 'boolean') throw Error(); }
    else if (Object.hasOwn(enums, suffix)) { if (!enums[suffix].includes(item)) throw Error(); }
    else if (suffix !== 'NewControlObservedUtcMillis') uint(item, 0, Number.MAX_SAFE_INTEGER);
  }
  for (const key of utc) uint(value[key], 946684800000, 4102444800000);
  if (value.newControlObservedUtcMillis !== null) uint(value.newControlObservedUtcMillis, 946684800000, 4102444800000);
  uint(value.terminalObservedElapsedMillis, 0, 180000); uint(value.localTicks, 1, 180000);
  uint(value.applicationWriteEntered, 1); uint(value.applicationWriteCompleted); uint(value.applicationWriteInFlight, 1);
  uint(value.applicationPendingBytes, 1, 4096); uint(value.applicationChargedBytes, 1, 8192); uint(value.applicationChargedFrames, 1, 4);
  uint(value.applicationBlockedMillis, 250, 20000);
  if (value.applicationWriteCompleted >= value.applicationWriteEntered || value.applicationWriteInFlight !== value.applicationWriteEntered || value.prefixBytes !== 4096 ||
      !value.controlInactive || !value.streamInactive || !value.sameCredential || !value.socketsClosed || !value.workersJoined ||
      ['ownedThreadsAlive', 'sessionLeases', 'streamLeases', 'chargedBytes', 'pendingCallbacks', 'timers'].some(key => value[key] !== 0)) throw Error();
  const session = value.scenario === 'session_expiry';
  if (value.policyMillis !== (session ? 15000 : 120000) || value.freshAdmission !== (session ? 'new_control' : 'denied') ||
      value.oldSessionRejected !== session || value.newControlAdmitted !== session || (value.newControlObservedUtcMillis !== null) !== session ||
      (session && value.newControlObservedUtcMillis >= value.credentialExpiresUtcMillis)) throw Error();
  if (value.sessionExpiresUtcMillis % 1000 || value.sessionExpiresUtcMillis <= value.readinessObservedUtcMillis - 2000 ||
      value.sessionExpiresUtcMillis > Math.min(value.credentialExpiresUtcMillis, value.gatewayExpiresUtcMillis, value.anchorExpiresUtcMillis,
        value.readinessObservedUtcMillis + value.policyMillis + 2000) ||
      value.terminalObservedUtcMillis < value.readinessObservedUtcMillis) throw Error();
}
export function decodeEnrolledObservation(bundle, method) {
  if (!bundle || Object.keys(bundle).length !== enrolledObservationSuffixes.length) throw Error();
  const result = {};
  for (const suffix of enrolledObservationSuffixes) {
    const key = 'draftEnrolled' + suffix, raw = bundle[key];
    if (typeof raw !== 'string') throw Error();
    const out = suffix[0].toLowerCase() + suffix.slice(1);
    if (bools.has(suffix)) { if (!['true', 'false'].includes(raw)) throw Error(); result[out] = raw === 'true'; }
    else if (Object.hasOwn(enums, suffix)) result[out] = raw;
    else if (suffix === 'NewControlObservedUtcMillis' && raw === 'null') result[out] = null;
    else { if (!/^(?:0|[1-9][0-9]{0,15})$/.test(raw) || raw.includes('\n') || String(Number(raw)) !== raw) throw Error(); result[out] = Number(raw); }
  }
  validateEnrolledObservation(result, method); return result;
}
