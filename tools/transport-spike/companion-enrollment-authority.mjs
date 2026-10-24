// Headless A21 coordinator: synchronous store primitives, no HTTP or signing owner.
import { randomBytes as secureRandom } from 'node:crypto';
import { inspect } from 'node:util';
import { decodeEnrollment, enrollmentMessage, enrollmentProofPayload } from './companion-enrollment-codec.mjs';

const responses = Object.freeze({ pair_request: 'pair_response', challenge_request: 'challenge_response',
  status_request: 'status_response', cancel_request: 'cancel_response' });
const codes = new Set(['invalid_message', 'message_too_large', 'unsupported_version',
  'unsupported_capability', 'authentication_failed', 'invitation_expired',
  'invitation_used', 'pairing_limit', 'pairing_unavailable']);
const bindingKeys = ['desktopId', 'gatewaySpkiSha256', 'invitationId', 'enrollmentId',
  'deviceSpkiDer', 'deviceSpkiSha256', 'reservationExpiresAt', 'resultExpiresAt'];
const contextKeys = ['desktopId', 'gatewaySpkiSha256', 'invitationId', 'enrollmentId', 'deviceSpkiSha256'];
class CoordinatorFailure extends Error {
  constructor(code) { super('Enrollment request failed'); this.code = code; }
}
const fail = code => { throw new CoordinatorFailure(code); };
const ended = binding => ({ protocolVersion: 1, type: 'pair_ended', desktopId: binding.desktopId,
  enrollmentId: binding.enrollmentId, code: 'result_expired' });

export class EnrollmentAuthority {
  #store;
  #random;
  #challenges = new Map();
  #issuance = new Map();
  #lastIssued = null;
  #closed = false;
  #unavailable = false;
  #busy = false;
  constructor({ store, randomBytes = secureRandom }) {
    if (!store || ['now', 'reserve', 'getBinding', 'verifyProof', 'readResult', 'cancel']
      .some(method => typeof store[method] !== 'function') || typeof randomBytes !== 'function') {
      fail('pairing_unavailable');
    }
    this.#store = store;
    this.#random = randomBytes;
    store.now();
    Object.freeze(this);
  }
  #now() {
    if (this.#closed || this.#unavailable) fail('pairing_unavailable');
    return this.#store.now();
  }
  #bytes() {
    try {
      const bytes = this.#random(32);
      if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) throw Error();
      return Buffer.from(bytes);
    } catch {
      this.#unavailable = true;
      fail('pairing_unavailable');
    }
  }
  #prune(now) {
    for (const [id, record] of this.#challenges) {
      if (now.monotonicMillis >= record.deadline) this.#challenges.delete(id);
    }
    for (const [id, last] of this.#issuance) {
      if (now.monotonicMillis - last >= 1000) this.#issuance.delete(id);
    }
  }
  #binding(request, requireLiveResult = false) {
    return this.#store.getBinding(request.desktopId, request.invitationId,
      request.enrollmentId, { requireLiveResult });
  }
  #issuanceAllowed(request, now) {
    this.#prune(now);
    const live = [...this.#challenges.values()].filter(record => !record.consumed);
    if (this.#challenges.size >= 128 || live.length >= 32 ||
        live.filter(record => record.binding.enrollmentId === request.enrollmentId).length >= 2 ||
        this.#issuance.has(request.enrollmentId) ||
        (this.#lastIssued !== null && now.monotonicMillis - this.#lastIssued < 100)) fail('pairing_limit');
  }
  #issue(request) {
    const binding = this.#binding(request, true).material();
    this.#issuanceAllowed(request, this.#now());
    let challengeId;
    for (let attempt = 0; attempt < 8; attempt++) {
      const candidate = 'ech_' + this.#bytes().toString('base64url');
      if (!this.#challenges.has(candidate)) { challengeId = candidate; break; }
    }
    if (!challengeId) fail('pairing_limit');
    const nonce = this.#bytes().toString('base64url');
    // This observation is the same one that checked both trusted result-window anchors.
    const finalSnapshot = this.#binding(request, true);
    const latestBinding = finalSnapshot.material();
    const now = finalSnapshot.observedAt();
    if (bindingKeys.some(key => latestBinding[key] !== binding[key])) fail('authentication_failed');
    this.#issuanceAllowed(request, now);
    const expiresAt = new Date(Math.floor((now.utcMillis + 10000) / 1000) * 1000)
      .toISOString().replace('.000Z', 'Z');
    const material = { protocolVersion: 1, type: 'pair_challenge', desktopId: binding.desktopId,
      gatewaySpkiSha256: binding.gatewaySpkiSha256, invitationId: binding.invitationId,
      enrollmentId: binding.enrollmentId, challengeId, deviceSpkiSha256: binding.deviceSpkiSha256,
      purpose: request.purpose, nonce, expiresAt };
    const message = enrollmentMessage('challenge_response', material);
    this.#challenges.set(challengeId, { binding: Object.freeze({ ...binding }), message,
      purpose: request.purpose, deadline: now.monotonicMillis + 10000, attempts: 0, consumed: false });
    this.#issuance.set(request.enrollmentId, now.monotonicMillis);
    this.#lastIssued = now.monotonicMillis;
    return message;
  }
  #proof(request, purpose) {
    const initial = this.#now();
    this.#prune(initial);
    const record = this.#challenges.get(request.challengeId);
    if (!record || record.consumed || record.attempts >= 3 || record.purpose !== purpose ||
        initial.monotonicMillis >= record.deadline ||
        ['desktopId', 'invitationId', 'enrollmentId'].some(key => record.binding[key] !== request[key])) {
      fail('authentication_failed');
    }
    const binding = this.#binding(request).material();
    if (bindingKeys.some(key => binding[key] !== record.binding[key])) fail('authentication_failed');
    const context = Object.fromEntries(contextKeys.map(key => [key, binding[key]]));
    context.purpose = purpose;
    const payload = enrollmentProofPayload(context, record.message);
    const valid = this.#store.verifyProof(request.enrollmentId, payload, Buffer.from(request.signature, 'base64url'));
    if (valid === false) {
      record.attempts++;
      fail('authentication_failed');
    }
    if (valid !== true) fail('pairing_unavailable');
    const latestBinding = this.#binding(request).material();
    const finalNow = this.#now();
    if (this.#challenges.get(request.challengeId) !== record || record.consumed ||
        finalNow.monotonicMillis >= record.deadline ||
        bindingKeys.some(key => latestBinding[key] !== record.binding[key])) fail('authentication_failed');
    // No callback/await/reentrancy point exists between this check and synchronous consume.
    record.consumed = true;
    // The Store rechecks both deadline anchors in its own read/cancel transaction.
    // This UTC check additionally avoids a mutation call after an already-observed result expiry.
    if (finalNow.utcMillis >= Date.parse(binding.resultExpiresAt)) {
      return enrollmentMessage(purpose === 'status' ? 'status_response' : 'cancel_response', ended(binding));
    }
    const result = (purpose === 'status' ? this.#store.readResult(request.enrollmentId)
      : this.#store.cancel(request.enrollmentId)).material();
    return enrollmentMessage(purpose === 'status' ? 'status_response' : 'cancel_response', result);
  }
  request(channel, bytes) {
    const response = responses[channel];
    if (!response) fail('invalid_message');
    const decoded = decodeEnrollment(channel, bytes);
    const failure = code => enrollmentMessage(response, { protocolVersion: 1, type: 'pair_error', code });
    if (!decoded.ok) return failure(decoded.code);
    if (this.#busy) return failure('pairing_unavailable');
    this.#busy = true;
    try {
      this.#now();
      const request = decoded.message.material();
      if (channel === 'pair_request') return enrollmentMessage(response, this.#store.reserve(request).material());
      if (channel === 'challenge_request') return this.#issue(request);
      return this.#proof(request, channel === 'status_request' ? 'status' : 'cancel');
    } catch (error) {
      const code = codes.has(error?.code) ? error.code : 'pairing_unavailable';
      if (code === 'pairing_unavailable') this.#unavailable = true;
      return failure(code);
    } finally { this.#busy = false; }
  }
  close() {
    this.#closed = true;
    this.#challenges.clear();
    this.#issuance.clear();
    // The creator retains Store ownership and joins signing/transport work before closing it.
  }
  toString() { return 'EnrollmentAuthority([REDACTED])'; }
  toJSON() { return { kind: 'EnrollmentAuthority', redacted: true }; }
  [inspect.custom]() { return this.toString(); }
}
Object.freeze(EnrollmentAuthority.prototype);
export const createEnrollmentAuthority = options => new EnrollmentAuthority(options);
