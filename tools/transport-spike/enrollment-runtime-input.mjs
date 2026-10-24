// Explicit private binary input for the self-targeted A22 Android research APK.
import { createHash, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { inspect } from 'node:util';

const MAGIC = Buffer.from('HFKENR1\0', 'ascii');
const META = ['desktopId', 'logicalName', 'gatewayCertificateDer', 'gatewaySpkiSha256',
  'enrollmentAuthorityDer', 'interceptionCaCertificateSha256', 'setupPort', 'credentialPort'];
const INVITE = ['invitationId', 'invitationSecret', 'expiresAt'];
export class EnrollmentRuntimeInputError extends Error {
  constructor() { super('invalid_enrollment_runtime_input'); this.code = 'invalid_enrollment_runtime_input'; }
  toJSON() { return { code: this.code }; }
  [inspect.custom]() { return 'EnrollmentRuntimeInputError(invalid_enrollment_runtime_input)'; }
}
const bad = () => { throw new EnrollmentRuntimeInputError(); };
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) bad();
  const names = Reflect.ownKeys(value);
  if (names.length !== keys.length || names.some(name => typeof name !== 'string' || !keys.includes(name) ||
      !Object.hasOwn(Object.getOwnPropertyDescriptor(value, name), 'value'))) bad();
}
function matching(value, pattern) {
  if (typeof value !== 'string' || pattern.exec(value)?.[0] !== value) bad();
  return value;
}
function binary(value, min, max = min) {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3)) bad();
  matching(value, /^[A-Za-z0-9_-]+$/);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < min || bytes.length > max || bytes.toString('base64url') !== value) bad();
  return bytes;
}
function port(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65535) bad();
  return value;
}
function dns(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 253 || isIP(value)) bad();
  for (const label of value.split('.')) matching(label, /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/);
  return value;
}
function expiry(value) {
  matching(value, /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value.slice(0, -1) + '.000Z') bad();
  return value;
}

/** Returns explicit sensitive bytes; no logging, file I/O or default snapshot representation. */
export function encodeEnrollmentRuntimeInput(metadata, invitation) {
  try {
    exact(metadata, META);
    exact(invitation, INVITE);
    const gateway = binary(metadata.gatewayCertificateDer, 1, 4096);
    const pin = binary(metadata.gatewaySpkiSha256, 32);
    binary(metadata.enrollmentAuthorityDer, 1, 4096);
    binary(metadata.interceptionCaCertificateSha256, 32);
    const certificate = new X509Certificate(gateway);
    if (!certificate.raw.equals(gateway)) bad();
    const actualPin = createHash('sha256').update(certificate.publicKey.export({ format: 'der', type: 'spki' })).digest();
    if (!actualPin.equals(pin)) bad();
    const logicalName = dns(metadata.logicalName);
    const matched = certificate.checkHost(logicalName, { subject: 'never', wildcards: false,
      partialWildcards: false, multiLabelWildcards: false, singleLabelSubdomains: false });
    if (matched?.toLowerCase() !== logicalName.toLowerCase()) bad();
    const fields = [gateway, pin, Buffer.from(logicalName, 'ascii'),
      Buffer.from(matching(metadata.desktopId, /^[A-Za-z0-9_-]{1,128}$/), 'ascii'),
      Buffer.from(matching(invitation.invitationId, /^[A-Za-z0-9_-]{1,128}$/), 'ascii'),
      binary(invitation.invitationSecret, 32), Buffer.from(expiry(invitation.expiresAt), 'ascii')];
    const ports = Buffer.alloc(4);
    const setupPort = port(metadata.setupPort), credentialPort = port(metadata.credentialPort);
    if (setupPort === credentialPort) bad();
    ports.writeUInt16BE(setupPort, 0);
    ports.writeUInt16BE(credentialPort, 2);
    const parts = [MAGIC, ports];
    for (const value of fields) {
      const length = Buffer.alloc(2);
      length.writeUInt16BE(value.length);
      parts.push(length, value);
    }
    const bytes = Buffer.concat(parts);
    if (bytes.length > 16384) bad();
    return bytes;
  } catch { bad(); }
}
