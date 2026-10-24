import { createHash, createPublicKey, verify, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';

// Isolated A21 public-profile validation. No keys, issuer process or listener is owned here.
const ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const ALG = Buffer.from('300a06082a8648ce3d040302', 'hex');
const SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex');
const SUBJECT = Buffer.from('301e311c301a06035504030c134854545020467265654b697420646576696365', 'hex');
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export class EnrollmentCryptoError extends Error {
  constructor() { super('Enrollment public profile rejected'); this.name = 'EnrollmentCryptoError'; this.code = 'authentication_failed'; }
  [inspect.custom]() { return 'EnrollmentCryptoError: authentication_failed'; }
  toJSON() { return { code: this.code }; }
}
function fail() { throw new EnrollmentCryptoError(); }
function guarded(work) { try { return work(); } catch { fail(); } }
export function enrollmentPublicSnapshot(material) {
  const bytes = JSON.stringify(material);
  return Object.freeze({ material: () => JSON.parse(bytes), toJSON: () => '[Enrollment public snapshot]',
    toString: () => '[Enrollment public snapshot]', [inspect.custom]: () => '[Enrollment public snapshot]' });
}
function bytes(value, max = 4096) {
  let result;
  if (typeof value === 'string') {
    if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(max * 4 / 3)) fail();
    result = Buffer.from(value, 'base64url');
    if (result.toString('base64url') !== value) fail();
  } else if (value instanceof Uint8Array) result = Buffer.from(value);
  else fail();
  if (result.length < 1 || result.length > max) fail();
  return result;
}
const equal = (a, b) => a.equals(b);
const hash = value => createHash('sha256').update(value).digest('base64url');

// Bounded canonical DER (not BER): a maximum of 4096 input bytes and 512 nodes.
function der(input) {
  const data = bytes(input); let nodes = 0;
  function read(start, limit, depth) {
    if (++nodes > 512 || depth > 16 || start + 2 > limit) fail();
    let offset = start; const tag = data[offset++];
    if ((tag & 31) === 31 || tag === 0) fail();
    let length = data[offset++];
    if (length & 128) {
      const count = length & 127;
      if (count < 1 || count > 2 || offset + count > limit || data[offset] === 0) fail();
      length = 0; for (let i = 0; i < count; i++) length = length * 256 + data[offset++];
      if (length < 128) fail();
    }
    const end = offset + length; if (end > limit) fail();
    const content = data.subarray(offset, end), raw = data.subarray(start, end), children = [];
    if (tag & 32) {
      let cursor = offset;
      while (cursor < end) { const child = read(cursor, end, depth + 1); children.push(child); cursor = child.end; }
      if (tag === 0x31) for (let i = 1; i < children.length; i++) if (Buffer.compare(children[i - 1].raw, children[i].raw) > 0) fail();
    } else if ((tag & 192) === 0) {
      if (tag === 1 && (length !== 1 || ![0, 255].includes(content[0]))) fail();
      if (tag === 2 && (!length || (length > 1 && ((content[0] === 0 && !(content[1] & 128)) || (content[0] === 255 && (content[1] & 128)))))) fail();
      if (tag === 3 && (!length || content[0] > 7 || (length === 1 && content[0] !== 0) || (content.at(-1) & ((1 << content[0]) - 1)))) fail();
      if (tag === 5 && length !== 0) fail();
      if (tag === 6) {
        if (!length) fail(); let first = true;
        for (const octet of content) { if (first && octet === 128) fail(); first = !(octet & 128); }
        if (!first) fail();
      }
      if (tag === 12) utf8.decode(content);
      if (tag === 19 && !/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(content.toString('latin1'))) fail();
      if (tag === 22 && content.some(v => v > 127)) fail();
      if ([16, 17].includes(tag)) fail();
    }
    return { tag, raw, content, children, end };
  }
  const root = read(0, data.length, 0); if (root.end !== data.length) fail(); return root;
}
function sequence(node, count) { if (node.tag !== 48 || (count !== undefined && node.children.length !== count)) fail(); return node.children; }
function uint(node, maxBytes = 20) {
  if (node.tag !== 2 || !node.content.length || node.content.length > maxBytes + 1 || (node.content[0] & 128)) fail();
  const value = BigInt('0x' + node.content.toString('hex')); if (value <= 0n || (node.content.length > maxBytes && node.content[0] !== 0)) fail(); return value;
}
function signature(value) {
  const raw = bytes(value, 72); if (raw.length < 8) fail();
  const [r, s] = sequence(der(raw), 2); if (uint(r, 32) >= ORDER || uint(s, 32) >= ORDER) fail(); return raw;
}
function spki(value) {
  const raw = bytes(value); if (raw.length !== 91 || !equal(raw.subarray(0, SPKI_PREFIX.length), SPKI_PREFIX)) fail();
  const key = createPublicKey({ key: raw, type: 'spki', format: 'der' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' || !equal(key.export({ type: 'spki', format: 'der' }), raw)) fail();
  // Point decoding/curve validation is delegated to the established provider.
  key.export({ format: 'jwk' }); return { raw, key };
}
export function verifyEnrollmentSignature(deviceSpkiDer, payload, candidate) {
  try { const key = spki(deviceSpkiDer).key; const sig = signature(candidate);
    if (!(payload instanceof Uint8Array) || payload.length > 1024) return false;
    return verify('sha256', payload, key, sig);
  } catch { return false; }
}
export function validateEnrollmentCsr(value) {
  return guarded(() => {
    const request = der(value), [info, algorithm, sig] = sequence(request, 3);
    const [version, subject, publicKey, attributes] = sequence(info, 4);
    if (!equal(version.raw, Buffer.from('020100', 'hex')) || !equal(subject.raw, SUBJECT) ||
      !equal(attributes.raw, Buffer.from('a000', 'hex')) || !equal(algorithm.raw, ALG) || sig.tag !== 3 || sig.content[0] !== 0) fail();
    const { raw, key } = spki(publicKey.raw), signed = signature(sig.content.subarray(1));
    if (!verify('sha256', info.raw, key, signed)) fail();
    return enrollmentPublicSnapshot({ csrDer: request.raw.toString('base64url'), deviceSpkiDer: raw.toString('base64url'), deviceSpkiSha256: hash(raw) });
  });
}
function time(node) {
  const text = node.content.toString('ascii'); let iso;
  if (node.tag === 23 && /^[0-9]{12}Z$/.test(text)) {
    const year = Number(text.slice(0, 2)); if (year >= 50) fail();
    iso = `20${text.slice(0, 2)}-${text.slice(2, 4)}-${text.slice(4, 6)}T${text.slice(6, 8)}:${text.slice(8, 10)}:${text.slice(10, 12)}Z`;
  } else if (node.tag === 24 && /^20[5-9][0-9]{11}Z$/.test(text)) {
    iso = `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12, 14)}Z`;
  } else fail();
  const millis = Date.parse(iso); if (!Number.isSafeInteger(millis) || new Date(millis).toISOString().replace('.000Z', 'Z') !== iso) fail(); return { iso, millis };
}
function name(node) {
  for (const set of sequence(node)) {
    if (set.tag !== 49 || !set.children.length) fail();
    for (const member of set.children) { const [oid, value] = sequence(member, 2); if (oid.tag !== 6 || ![12, 19, 20, 22, 28, 30].includes(value.tag)) fail(); }
  }
  if (!node.children.length) fail();
}
function extensions(node, authority) {
  if (node.tag !== 163 || node.children.length !== 1) fail();
  const found = new Map();
  for (const extension of sequence(node.children[0])) {
    const fields = sequence(extension); if (fields.length < 2 || fields.length > 3 || fields[0].tag !== 6) fail();
    const oid = fields[0].content.toString('hex'); if (found.has(oid)) fail();
    const critical = fields.length === 3; if (critical && !equal(fields[1].raw, Buffer.from('0101ff', 'hex'))) fail();
    const value = fields.at(-1); if (value.tag !== 4) fail(); const inner = der(value.content);
    if (critical && !['551d13', '551d0f', '551d25', '551d0e', '551d23'].includes(oid)) fail();
    found.set(oid, { critical, inner });
  }
  const bc = found.get('551d13'), ku = found.get('551d0f'), eku = found.get('551d25');
  if (!bc?.critical || !ku?.critical) fail();
  if (!equal(bc.inner.raw, Buffer.from(authority ? '30060101ff020100' : '3000', 'hex')) ||
    !equal(ku.inner.raw, Buffer.from(authority ? '03020106' : '03020780', 'hex'))) fail();
  if ((!authority && !eku) || (eku && !equal(eku.inner.raw, Buffer.from('300a06082b06010505070302', 'hex')))) fail();
  const ski = found.get('551d0e'); if (ski && (ski.inner.tag !== 4 || !ski.inner.content.length)) fail();
  const aki = found.get('551d23'); if (aki && aki.inner.tag !== 48) fail();
}
function certificate(value, authority) {
  const root = der(value), [tbs, algorithm, sig] = sequence(root, 3), fields = sequence(tbs, 8);
  const [version, serial, tbsAlgorithm, issuer, validity, subject, publicKey, extension] = fields;
  if (!equal(version.raw, Buffer.from('a003020102', 'hex')) || !equal(algorithm.raw, ALG) || !equal(tbsAlgorithm.raw, ALG) || sig.tag !== 3 || sig.content[0] !== 0) fail();
  const serialValue = uint(serial); name(issuer); name(subject); const [before, after] = sequence(validity, 2);
  const notBefore = time(before), notAfter = time(after); if (notBefore.millis >= notAfter.millis) fail();
  const key = spki(publicKey.raw); extensions(extension, authority); const signed = signature(sig.content.subarray(1));
  const x509 = new X509Certificate(root.raw); if (!equal(x509.raw, root.raw) || !equal(x509.publicKey.export({ format: 'der', type: 'spki' }), key.raw)) fail();
  if (authority && (!equal(issuer.raw, subject.raw) || !verify('sha256', tbs.raw, key.key, signed) || !x509.verify(key.key))) fail();
  if (!authority && !equal(subject.raw, SUBJECT)) fail();
  return { raw: root.raw, tbs, issuer, subject, key, signed, x509, serial: serialValue.toString(), notBefore, notAfter };
}
function at(cert, utcMillis) {
  if (utcMillis !== undefined && (!Number.isSafeInteger(utcMillis) || utcMillis < cert.notBefore.millis || utcMillis >= cert.notAfter.millis)) fail();
}
function certMaterial(cert) {
  return { certificateDer: cert.raw.toString('base64url'), deviceSpkiDer: cert.key.raw.toString('base64url'), deviceSpkiSha256: hash(cert.key.raw),
    serial: cert.serial, notBefore: cert.notBefore.iso, notAfter: cert.notAfter.iso };
}
export function validateEnrollmentAuthority(value, { utcMillis } = {}) {
  return guarded(() => { const cert = certificate(value, true); at(cert, utcMillis); return enrollmentPublicSnapshot(certMaterial(cert)); });
}
export function validateEnrollmentCertificate(value, { authority, deviceSpkiDer, serial, notBefore, notAfter, utcMillis } = {}) {
  return guarded(() => {
    const issuer = certificate(authority, true), leaf = certificate(value, false);
    if (!equal(leaf.issuer.raw, issuer.subject.raw) || !verify('sha256', leaf.tbs.raw, issuer.key.key, leaf.signed) || !leaf.x509.verify(issuer.key.key) ||
      leaf.notBefore.millis < issuer.notBefore.millis || leaf.notAfter.millis > issuer.notAfter.millis) fail();
    if (deviceSpkiDer !== undefined && !equal(leaf.key.raw, spki(deviceSpkiDer).raw)) fail();
    if (serial !== undefined && (typeof serial !== 'string' || !/^[1-9][0-9]{0,15}$/.test(serial) || BigInt(serial) > BigInt(Number.MAX_SAFE_INTEGER) || serial !== leaf.serial)) fail();
    if ((notBefore !== undefined && notBefore !== leaf.notBefore.iso) || (notAfter !== undefined && notAfter !== leaf.notAfter.iso)) fail();
    at(issuer, utcMillis); at(leaf, utcMillis); return enrollmentPublicSnapshot(certMaterial(leaf));
  });
}
