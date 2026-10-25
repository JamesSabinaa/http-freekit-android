import { enrolledTunMethod, enrolledTunObservationSuffixes, enrolledTunPayload } from './enrolled-tun-descriptor.mjs';

const booleans = new Set(('CredentialSavedReloaded KeyNonexportable OriginalCredentialUnchanged VpnConsentGranted SeparateTrafficUid ' +
  'SelectedUidVpnObserved TunAndNativeObserved ForegroundNotificationObserved HttpOutputHalfClosed StrictResponseEof LocalStreamsDrained ' +
  'HostCompleteAcknowledged CaptureStopped TunClosed NativeStopJoined ConfigurationAbsent LifecycleJoined FactoryClosed SessionLease ' +
  'NonVpnRouteObserved TrafficWorkerJoined OwnedStateAbsent').split(' '));
const guards = new Set(['ProtectAttempts', 'ProtectSuccesses', 'BindAttempts', 'BindSuccesses']);
const one = new Set(['Version', 'HttpAttempts', 'SelectedPackageCount', 'InterceptedTcpFlows']);
const name = suffix => suffix[0].toLowerCase() + suffix.slice(1);
export const enrolledTunObservationKeys = Object.freeze(enrolledTunObservationSuffixes.map(name));

export function validateEnrolledTunObservation(value, method) {
  if (method !== enrolledTunMethod || !value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== enrolledTunObservationKeys.length || enrolledTunObservationKeys.some(key => !Object.hasOwn(value, key))) throw Error();
  for (const suffix of enrolledTunObservationSuffixes) {
    const item = value[name(suffix)];
    if (booleans.has(suffix)) { if (typeof item !== 'boolean' || item !== (suffix !== 'SessionLease')) throw Error(); }
    else if (suffix === 'ResponseBodySha256') { if (item !== enrolledTunPayload.responseBodySha256) throw Error(); }
    else {
      if (!Number.isSafeInteger(item) || Object.is(item, -0) || item < 0 || item > 131072) throw Error();
      const expected = one.has(suffix) ? 1 : guards.has(suffix) ? 2 : suffix === 'ResponseBodyBytes' ? enrolledTunPayload.responseBodyBytes : 0;
      if (item !== expected) throw Error();
    }
  }
}

export function decodeEnrolledTunObservation(bundle, method) {
  if (!bundle || Object.keys(bundle).length !== enrolledTunObservationSuffixes.length) throw Error();
  const result = {};
  for (const suffix of enrolledTunObservationSuffixes) {
    const raw = bundle['draftTun' + suffix];
    if (typeof raw !== 'string') throw Error();
    if (booleans.has(suffix)) { if (!['true', 'false'].includes(raw)) throw Error(); result[name(suffix)] = raw === 'true'; }
    else if (suffix === 'ResponseBodySha256') result[name(suffix)] = raw;
    else { if (!/^(?:0|[1-9][0-9]{0,5})$/.test(raw) || String(Number(raw)) !== raw) throw Error(); result[name(suffix)] = Number(raw); }
  }
  validateEnrolledTunObservation(result, method); return result;
}

export function enrolledTunFailureCategory(value) {
  return typeof value === 'string' && /^(?:none|traffic_close_io|traffic_command_failed|traffic_tcp_(?:connect|write|shutdown|reply|eof|close)_(?:timeout|io|protocol|other|reset|aborted|bad_fd|not_connected|closed))$/.exec(value)?.[0] === value;
}
