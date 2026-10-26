// Fixed local research profile only; no negotiated capability or production policy.
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';

export const referenceInterceptionProfile = Object.freeze({
  address: '198.18.0.2', hostname: 'reference-target.invalid', path: '/reference/proof',
  httpPort: 80, httpsPort: 443, maxBodyBytes: 4096, maxHeaderBytes: 4096,
  maxOwners: 2, timeoutMillis: 5000,
});

const codes = new Set(['configuration', 'assets_unavailable', 'backend_closed', 'admission_closed',
  'invalid_preface', 'invalid_request', 'upstream_failed', 'deadline', 'cleanup_unjoined', 'backend_failed']);
export class ReferenceInterceptionError extends Error {
  constructor(code = 'backend_failed', joined = true) {
    super('Reference interception research unavailable');
    this.name = 'ReferenceInterceptionError';
    this.code = codes.has(code) ? code : 'backend_failed';
    this.joined = joined === true;
  }
  toJSON() { return { code: this.code, joined: this.joined }; }
  [inspect.custom]() { return `ReferenceInterceptionError: ${this.code} (joined=${this.joined})`; }
}

export function referenceInterceptionResponse(body) {
  if (!(body instanceof Uint8Array) || body.byteLength > referenceInterceptionProfile.maxBodyBytes) {
    throw new ReferenceInterceptionError('invalid_request');
  }
  return Buffer.from('reference-origin:' + createHash('sha256').update(body).digest('hex'), 'ascii');
}
