import { captureFactoryObservationSuffixes, captureFactoryMethod, captureFactoryPayload } from './capture-factory-descriptor.mjs';

const booleanSuffixes = new Set(('CredentialSavedReloaded KeyNonexportable OriginalCredentialUnchanged VpnConsentGranted NoTunEstablished ' +
  'ApplicationOutputHalfClosed StrictResponseEof FactoryClosed SessionLease RelayJoined ServiceObserverJoined ServiceDestroyed OwnedStateAbsent').split(' '));
const guardSuffixes = new Set(['ProtectAttempts', 'ProtectSuccesses', 'BindAttempts', 'BindSuccesses']);
export const captureFactoryObservationKeys = Object.freeze(captureFactoryObservationSuffixes.map(value => value[0].toLowerCase() + value.slice(1)));
const name = suffix => suffix[0].toLowerCase() + suffix.slice(1);
const uint = value => Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0 && value <= 131072;

export function validateCaptureFactoryObservation(value, method) {
  if (method !== captureFactoryMethod || !value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== captureFactoryObservationKeys.length || captureFactoryObservationKeys.some(key => !Object.hasOwn(value, key))) throw Error();
  for (const suffix of captureFactoryObservationSuffixes) {
    const item = value[name(suffix)];
    if (booleanSuffixes.has(suffix)) { if (typeof item !== 'boolean' || item !== (suffix !== 'SessionLease')) throw Error(); }
    else if (suffix === 'ResponseBodySha256') { if (item !== captureFactoryPayload.responseBodySha256) throw Error(); }
    else {
      if (!uint(item)) throw Error();
      const expected = suffix === 'Version' ? 1 : guardSuffixes.has(suffix) ? 2 : suffix === 'RequestBodyBytes' ? captureFactoryPayload.requestBodyBytes :
        suffix === 'ResponseBodyBytes' ? captureFactoryPayload.responseBodyBytes : 0;
      if (item !== expected) throw Error();
    }
  }
}

export function decodeCaptureFactoryObservation(bundle, method) {
  if (!bundle || Object.keys(bundle).length !== captureFactoryObservationSuffixes.length) throw Error();
  const result = {};
  for (const suffix of captureFactoryObservationSuffixes) {
    const raw = bundle['draftFactory' + suffix];
    if (typeof raw !== 'string') throw Error();
    if (booleanSuffixes.has(suffix)) { if (!['true', 'false'].includes(raw)) throw Error(); result[name(suffix)] = raw === 'true'; }
    else if (suffix === 'ResponseBodySha256') result[name(suffix)] = raw;
    else { if (!/^(?:0|[1-9][0-9]{0,5})$/.test(raw) || String(Number(raw)) !== raw) throw Error(); result[name(suffix)] = Number(raw); }
  }
  validateCaptureFactoryObservation(result, method); return result;
}
