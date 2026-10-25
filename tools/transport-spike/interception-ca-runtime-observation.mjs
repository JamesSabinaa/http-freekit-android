import { interceptionCaRuntimeMethod, interceptionCaRuntimeObservationSuffixes } from './interception-ca-runtime-descriptor.mjs';

const trueSuffixes = new Set(['SavedApprovalValidated', 'OriginalKeyUnchanged', 'PrivateKeyNonexportable', 'RecoveryUnchanged',
  'ApprovedCaHashMatched', 'CredentialLeafUnchanged', 'FreshLookupAfterFetch', 'Closed']);
const falseSuffixes = new Set(['ActiveCall', 'RawSocketOwned', 'TlsSocketOwned', 'DeadlineAlive', 'TlsCloserAlive', 'CleanupFailed']);
const name = suffix => suffix[0].toLowerCase() + suffix.slice(1);
export const interceptionCaObservationKeys = Object.freeze(interceptionCaRuntimeObservationSuffixes.map(name));
const fail = () => { throw Error('invalid_interception_ca_observation'); };
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![null, Object.prototype].includes(Object.getPrototypeOf(value))) fail();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key))) fail();
  for (const key of keys) if (!Object.hasOwn(Object.getOwnPropertyDescriptor(value, key) ?? {}, 'value')) fail();
}

export function validateInterceptionCaObservation(value, method) {
  if (method !== interceptionCaRuntimeMethod) fail();
  exact(value, interceptionCaObservationKeys);
  for (const suffix of interceptionCaRuntimeObservationSuffixes) {
    const item = value[name(suffix)];
    if (trueSuffixes.has(suffix)) { if (item !== true) fail(); }
    else if (falseSuffixes.has(suffix)) { if (item !== false) fail(); }
    else {
      if (!Number.isSafeInteger(item) || Object.is(item, -0)) fail();
      if (suffix === 'Version' || suffix === 'FetchAttempts') { if (item !== 1) fail(); }
      else if (suffix !== 'CaBytes' || item < 1 || item > 4096) fail();
    }
  }
}

export function decodeInterceptionCaObservation(bundle, method) {
  exact(bundle, interceptionCaRuntimeObservationSuffixes.map(suffix => 'draftCa' + suffix));
  const result = {};
  for (const suffix of interceptionCaRuntimeObservationSuffixes) {
    const raw = bundle['draftCa' + suffix];
    if (typeof raw !== 'string') fail();
    if (trueSuffixes.has(suffix) || falseSuffixes.has(suffix)) {
      if (raw !== 'true' && raw !== 'false') fail(); result[name(suffix)] = raw === 'true';
    } else {
      if (!/^(?:0|[1-9][0-9]{0,3})$/.test(raw) || String(Number(raw)) !== raw) fail();
      result[name(suffix)] = Number(raw);
    }
  }
  validateInterceptionCaObservation(result, method); return Object.freeze(result);
}
