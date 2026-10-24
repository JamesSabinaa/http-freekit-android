import { enrollmentAdversarialCases } from './enrollment-runtime-adversarial-descriptor.mjs';
const fields = {
  proof_misuse: { purposeHttp: 403, purposeCode: 'authentication_failed', wireContextHttp: 403, wireContextCode: 'authentication_failed',
    signedContextHttp: 403, signedContextCode: 'authentication_failed', sameChallengeHttp: 200, sameChallengeType: 'pair_pending',
    replayHttp: 403, replayCode: 'authentication_failed', freshStatusHttp: 200, freshStatusType: 'pair_pending', bindingUnchanged: true },
  wrong_tls: { tlsFailureType: 'SSLException', freshStatusHttp: 200, freshStatusType: 'pair_pending', bindingUnchanged: true, expectedTrustUnchanged: true },
  pending_cancel: { cancelHttp: 200, cancelCode: 'pairing_cancelled', replayHttp: 403, replayCode: 'authentication_failed',
    freshStatusHttp: 200, freshStatusCode: 'pairing_cancelled', bindingUnchanged: true },
  published_cancel: { approvalHttp: 200, approvalType: 'pair_approved', savedCredentialUnchanged: true, beforeMtlsHttp: 200,
    cancelHttp: 200, cancelCode: 'pairing_cancelled', afterMtlsHttp: 403, freshStatusHttp: 200, freshStatusCode: 'pairing_cancelled',
    keyManagerUsableAtRefusal: true, bindingUnchanged: true },
};
const normalized = suffix => suffix[0].toLowerCase() + suffix.slice(1);
function expected(method) {
  const descriptor = enrollmentAdversarialCases.find(value => value.method === method);
  if (!descriptor) throw Error();
  return { descriptor, values: { version: 1, scenario: descriptor.scenario, originalKeyUnchanged: true,
    credentialSaved: descriptor.scenario === 'published_cancel', ownedStateAbsent: true, clientResourcesClosed: true, ...fields[descriptor.scenario] } };
}
export function validateEnrollmentAdversarialObservation(value, method) {
  const { descriptor, values } = expected(method), keys = descriptor.observationSuffixes.map(normalized);
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) throw Error();
  for (const [key, required] of Object.entries(values)) if (value[key] !== required) throw Error();
  if (descriptor.scenario === 'published_cancel') {
    for (const key of ['credentialExpiresUtcMillis', 'refusalObservedUtcMillis']) {
      if (!Number.isSafeInteger(value[key]) || value[key] < 946684800000 || value[key] > 4102444800000) throw Error();
    }
    if (value.refusalObservedUtcMillis >= value.credentialExpiresUtcMillis) throw Error();
  }
}
export function decodeEnrollmentAdversarialObservation(bundle, method) {
  const { descriptor, values } = expected(method);
  if (!bundle || Object.keys(bundle).length !== descriptor.observationSuffixes.length) throw Error();
  const result = {};
  for (const suffix of descriptor.observationSuffixes) {
    const key = normalized(suffix), raw = bundle['draftAdversarial' + suffix];
    if (typeof raw !== 'string') throw Error();
    if (typeof values[key] === 'boolean') { if (!['true', 'false'].includes(raw)) throw Error(); result[key] = raw === 'true'; }
    else if (typeof values[key] === 'number' || key.endsWith('UtcMillis')) {
      if (!/^(?:0|[1-9][0-9]{0,15})$/.test(raw) || raw.includes('\n') || String(Number(raw)) !== raw) throw Error(); result[key] = Number(raw);
    } else result[key] = raw;
  }
  validateEnrollmentAdversarialObservation(result, method); return result;
}
