// TEMP/in-memory software-key fixtures only. Never used by the reference authority.
import { generateKeyPairSync, sign } from 'node:crypto';

export function tlv(tag, value) {
  const body = Buffer.concat((Array.isArray(value) ? value : [value]).map(x => Buffer.from(x)));
  const length = body.length < 128 ? [body.length] : body.length < 256 ? [129, body.length] : [130, body.length >> 8, body.length & 255];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}
export const seq = (...parts) => tlv(48, parts);
const oid = hex => tlv(6, Buffer.from(hex, 'hex'));
const integer = value => {
  let hex = BigInt(value).toString(16); if (hex.length % 2) hex = '0' + hex;
  const body = Buffer.from(hex, 'hex'); return tlv(2, body[0] & 128 ? Buffer.concat([Buffer.of(0), body]) : body);
};
export const fixedSubject = seq(tlv(49, seq(oid('550403'), tlv(12, Buffer.from('HTTP FreeKit device')))));
const authoritySubject = seq(tlv(49, seq(oid('550403'), tlv(12, Buffer.from('A21 software fixture')))));
const alg = Buffer.from('300a06082a8648ce3d040302', 'hex');
const defaultTime = Date.parse('2030-01-02T00:00:00Z');
const time = millis => {
  const text = new Date(millis).toISOString().replace(/[-:]/g, '').replace('T', '').replace('.000Z', 'Z');
  return tlv(Number(text.slice(0, 4)) < 2050 ? 23 : 24, Buffer.from(Number(text.slice(0, 4)) < 2050 ? text.slice(2) : text));
};
const extension = (oidHex, content, critical = false) => seq(oid(oidHex), ...(critical ? [Buffer.from('0101ff', 'hex')] : []), tlv(4, content));
export function createCryptoFixture({ utcMillis = defaultTime } = {}) {
  const authority = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const device = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicDer = pair => pair.publicKey.export({ format: 'der', type: 'spki' });
  function csr({ subject = fixedSubject, attributes = Buffer.from('a000', 'hex'), key = device, publicKey = publicDer(key), version = 0, algorithm = alg } = {}) {
    const info = seq(integer(version), subject, publicKey, attributes);
    return seq(info, algorithm, tlv(3, Buffer.concat([Buffer.of(0), sign('sha256', info, key.privateKey)])));
  }
  function certificate({ ca = false, key = ca ? authority : device, signer = authority, serial = ca ? 1 : 2,
    subject = ca ? authoritySubject : fixedSubject, issuer = authoritySubject,
    notBefore = utcMillis - (ca ? 86400000 : 300000), notAfter = utcMillis + (ca ? 86400000 : 3600000),
    basic = Buffer.from(ca ? '30060101ff020100' : '3000', 'hex'), usage = Buffer.from(ca ? '03020106' : '03020780', 'hex'),
    basicCritical = true, usageCritical = true, eku = Buffer.from('300a06082b06010505070302', 'hex'), ekuCritical = false,
    extraExtensions = [], algorithm = alg } = {}) {
    const extensions = [extension('551d13', basic, basicCritical), extension('551d0f', usage, usageCritical),
      ...(eku === null ? [] : [extension('551d25', eku, ekuCritical)]), ...extraExtensions];
    const info = seq(Buffer.from('a003020102', 'hex'), integer(serial), algorithm, issuer,
      seq(time(notBefore), time(notAfter)), subject, publicDer(key), tlv(163, seq(...extensions)));
    return seq(info, algorithm, tlv(3, Buffer.concat([Buffer.of(0), sign('sha256', info, signer.privateKey)])));
  }
  return { authority, device, other, publicDer, csr, certificate, extension, utcMillis,
    caDer: certificate({ ca: true }), deviceSpkiDer: publicDer(device) };
}
