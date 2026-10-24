import { encodeEnrollmentRuntimeInput } from './enrollment-runtime-input.mjs';

const fields = ['desktopId', 'logicalName', 'gatewayCertificateDer', 'gatewaySpkiSha256',
  'enrollmentAuthorityDer', 'interceptionCaCertificateSha256', 'setupPort', 'credentialPort'];
const magic = Buffer.from([72, 70, 75, 83, 84, 82, 49, 0]);
const bad = () => { throw Object.assign(Error('invalid_enrolled_stream_input'), { code: 'invalid_enrolled_stream_input' }); };

/** Explicit private bytes only. The caller owns delivery and clearing; never put these in diagnostics. */
export function encodeEnrolledStreamInput(metadata, invitation, scenario) {
  let seed, result;
  try {
    if (!metadata || ![Object.prototype, null].includes(Object.getPrototypeOf(metadata)) ||
        !Number.isInteger(scenario) || scenario < 1 || scenario > 3) bad();
    const names = Reflect.ownKeys(metadata), expected = [...fields, 'webSocketPort'];
    if (names.length !== expected.length || names.some(name => !expected.includes(name))) bad();
    const copied = Object.fromEntries(expected.map(name => {
      const property = Object.getOwnPropertyDescriptor(metadata, name);
      if (!property || !Object.hasOwn(property, 'value')) bad();
      return [name, property.value];
    }));
    const port = copied.webSocketPort;
    if (!Number.isInteger(port) || port < 1 || port > 65535 ||
        port === copied.setupPort || port === copied.credentialPort) bad();
    delete copied.webSocketPort;
    seed = encodeEnrollmentRuntimeInput(copied, invitation);
    if (seed.length + 13 > 16384) bad();
    result = Buffer.alloc(seed.length + 13);
    magic.copy(result); result.writeUInt16BE(port, 8); result[10] = scenario;
    result.writeUInt16BE(seed.length, 11); seed.copy(result, 13);
    return result;
  } catch {
    result?.fill(0);
    bad();
  } finally { seed?.fill(0); }
}
