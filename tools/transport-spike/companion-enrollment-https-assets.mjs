// Private TEMP software identities for the isolated A22 fixture; no production provisioning.
import { createHash, createPrivateKey, createPublicKey, randomBytes, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { inspect } from 'node:util';
import { runDraftCommand } from './draft-stream-command.mjs';
import { enrollmentPublicSnapshot, validateEnrollmentAuthority } from './companion-enrollment-crypto.mjs';

export const enrollmentLogicalName = 'enrollment-research.invalid';
const hash = value => createHash('sha256').update(value).digest('base64url');
const manifestName = 'enrollment-fixture.json';
const fields = 'revision desktopId logicalName gatewayCertificateDer gatewaySpkiSha256 enrollmentAuthorityDer interceptionCaCertificateSha256 setupPort credentialPort'.split(' ');
export class EnrollmentFixtureError extends Error {
  constructor(code = 'pairing_unavailable', joined = true) { super('Enrollment research fixture unavailable'); this.name = 'EnrollmentFixtureError'; this.code = code; this.joined = joined; }
  [inspect.custom]() { return `EnrollmentFixtureError: ${this.code} (joined=${this.joined})`; }
  toJSON() { return { code: this.code, joined: this.joined }; }
}
function fail(joined = true) { throw new EnrollmentFixtureError('pairing_unavailable', joined); }
export function enrollmentPrivateDirectory(directory) {
  try {
    if (typeof directory !== 'string' || !path.isAbsolute(directory)) fail();
    const absolute = path.resolve(directory), real = fs.realpathSync(absolute);
    if (process.platform === 'win32' ? absolute.toLowerCase() !== real.toLowerCase() : absolute !== real) fail();
    let current = absolute;
    while (true) { const stat = fs.lstatSync(current); if (stat.isSymbolicLink() || !stat.isDirectory()) fail(); const parent = path.dirname(current); if (parent === current) break; current = parent; }
    if (process.platform !== 'win32' && (fs.statSync(absolute).mode & 0o077)) fail();
    return real;
  } catch { fail(); }
}
function read(directory, name, max = 16384) {
  const filename = path.join(directory, name), stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > max || (process.platform !== 'win32' && (stat.mode & 0o077))) fail();
  return fs.readFileSync(filename);
}
const date = millis => new Date(millis).toISOString().replace(/[-:]/g, '').replace('T', '').replace('.000Z', 'Z');
async function command(openssl, args, cwd) {
  let result;
  try { result = await runDraftCommand(openssl, args, { cwd, timeoutMillis: 5000, maxOutputBytes: 16384 }); }
  catch { fail(false); }
  if (!result.closeObserved || !result.processGroupClosed) fail(false);
  if (result.reason || result.code !== 0) fail();
  return result.output;
}
function privateFile(directory, name, text) { fs.writeFileSync(path.join(directory, name), text, { mode: 0o600, flag: 'wx' }); }
function matchIdentity(directory, name, now) {
  const cert = new X509Certificate(read(directory, `${name}.pem`)), key = createPrivateKey(read(directory, `${name}-key.pem`, 4096));
  if (cert.raw.length > 4096 || key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
    !createPublicKey(key).export({ format: 'der', type: 'spki' }).equals(cert.publicKey.export({ format: 'der', type: 'spki' })) ||
    !cert.verify(cert.publicKey) || cert.subject !== cert.issuer || now < Date.parse(cert.validFrom) || now >= Date.parse(cert.validTo)) fail();
  return cert;
}
function interceptionCertificate(value, now) {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > 4096) fail();
  const bytes = Buffer.from(value), cert = new X509Certificate(bytes), key = cert.publicKey;
  const notBefore = Date.parse(cert.validFrom), notAfter = Date.parse(cert.validTo);
  const supportedKey = key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1' ||
    key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails?.modulusLength >= 2048 && key.asymmetricKeyDetails.modulusLength <= 4096;
  if (!cert.raw.equals(bytes) || !cert.ca || cert.subject !== cert.issuer || !cert.checkIssued(cert) || !cert.verify(key) || !supportedKey ||
      !Number.isSafeInteger(notBefore) || !Number.isSafeInteger(notAfter) || notBefore >= notAfter || now < notBefore || now >= notAfter ||
      cert.keyUsage !== undefined && (cert.keyUsage.length !== 1 || cert.keyUsage[0] !== '1.3.6.1.5.5.7.3.1')) fail();
  return cert;
}
class EnrollmentAssets {
  #directory; #material;
  constructor(directory, material) { this.#directory = directory; this.#material = structuredClone(material); }
  metadata() { const { revision: _, ...material } = this.#material; return enrollmentPublicSnapshot(material); }
  authorityDer() { return this.#material.enrollmentAuthorityDer; }
  tlsOptions() { return { key: read(this.#directory, 'gateway-key.pem', 4096), cert: read(this.#directory, 'gateway.pem'), minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', handshakeTimeout: 5000, ALPNProtocols: ['http/1.1'] }; }
  commitPorts(setupPort, credentialPort) {
    if (![setupPort, credentialPort].every(port => Number.isInteger(port) && port > 0 && port <= 65535) || setupPort === credentialPort) fail();
    if (this.#material.setupPort && (this.#material.setupPort !== setupPort || this.#material.credentialPort !== credentialPort)) fail();
    const next = { ...this.#material, setupPort, credentialPort };
    const temporary = path.join(this.#directory, 'enrollment-fixture.next');
    fs.writeFileSync(temporary, JSON.stringify(next), { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporary, path.join(this.#directory, manifestName)); this.#material = next;
  }
  toString() { return '[Enrollment research identities]'; }
  toJSON() { return '[Enrollment research identities]'; }
  [inspect.custom]() { return this.toString(); }
}
export async function enrollmentFixtureAssets({ directory, mode, openssl, setupPort, credentialPort, interceptionCaCertificateDer }) {
  try {
    directory = enrollmentPrivateDirectory(directory);
    if (!['create', 'open'].includes(mode) || typeof openssl !== 'string' || !openssl || openssl.length > 4096 || /[\u0000\r\n]/.test(openssl) ||
      ![setupPort, credentialPort].every(port => Number.isInteger(port) && port >= (mode === 'create' ? 0 : 1) && port <= 65535) || (setupPort !== 0 && setupPort === credentialPort)) fail();
    const now = Date.now(), floored = Math.floor(now / 1000) * 1000, before = floored - 300000, after = floored + 7200000;
    if (before < Date.parse('2000-01-01T00:00:00Z') || after > Date.parse('2099-12-31T23:59:59Z')) fail();
    // This optional trusted composition input is public material only. Snapshot
    // it before the first child await, without changing the default identities.
    const suppliedInterception = interceptionCaCertificateDer === undefined ? null : interceptionCertificate(interceptionCaCertificateDer, now);
    if (mode === 'create') {
      if (fs.readdirSync(directory).length) fail();
      privateFile(directory, 'initializing', 'A22 research initialization\n');
      if (!/^OpenSSL 3\./.test(await command(openssl, ['version'], directory))) fail();
      privateFile(directory, 'request.cnf', '[req]\ndistinguished_name=subject\nprompt=no\nstring_mask=utf8only\n[subject]\nCN=HTTP FreeKit research\n');
      for (const [name, subject, gateway] of [['enrollment-authority', 'Enrollment research authority', false], ['interception', 'Enrollment research interception identity', false], ['gateway', enrollmentLogicalName, true]]) {
        if (name === 'interception' && suppliedInterception) {
          privateFile(directory, 'interception.pem', suppliedInterception.toString());
          continue;
        }
        await command(openssl, ['req', '-config', 'request.cnf', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256', '-utf8', '-subj', `/CN=${subject}`, '-keyout', `${name}-key.pem`, '-out', `${name}.csr.pem`], directory);
        fs.chmodSync(path.join(directory, `${name}-key.pem`), 0o600); fs.chmodSync(path.join(directory, `${name}.csr.pem`), 0o600);
        const work = path.join(directory, `${name}-bootstrap`); fs.mkdirSync(work, { mode: 0o700 }); fs.mkdirSync(path.join(work, 'issued'), { mode: 0o700 });
        privateFile(work, 'index.txt', ''); privateFile(work, 'serial', randomBytes(16).toString('hex') + '\n');
        privateFile(work, 'issuer.cnf', '[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=index.txt\nnew_certs_dir=issued\nserial=serial\ndefault_md=sha256\npolicy=subject\ncopy_extensions=none\nstring_mask=utf8only\n[subject]\ncommonName=supplied\n[identity]\n' +
          (gateway ? `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${enrollmentLogicalName}\n` : 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n'));
        await command(openssl, ['ca', '-config', 'issuer.cnf', '-batch', '-notext', '-md', 'sha256', '-selfsign', '-keyfile', path.join(directory, `${name}-key.pem`),
          '-startdate', date(before), '-enddate', date(after), '-extensions', 'identity', '-in', path.join(directory, `${name}.csr.pem`), '-out', path.join(directory, `${name}.pem`)], work);
        fs.chmodSync(path.join(directory, `${name}.pem`), 0o600); fs.rmSync(work, { recursive: true, force: true }); fs.unlinkSync(path.join(directory, `${name}.csr.pem`));
      }
      const gateway = matchIdentity(directory, 'gateway', now), authority = matchIdentity(directory, 'enrollment-authority', now),
        interception = suppliedInterception ?? matchIdentity(directory, 'interception', now);
      validateEnrollmentAuthority(authority.raw, { utcMillis: now });
      if (!suppliedInterception) validateEnrollmentAuthority(interception.raw, { utcMillis: now });
      const material = { revision: 1, desktopId: 'a22_' + randomBytes(32).toString('base64url'), logicalName: enrollmentLogicalName,
        gatewayCertificateDer: gateway.raw.toString('base64url'), gatewaySpkiSha256: hash(gateway.publicKey.export({ format: 'der', type: 'spki' })),
        enrollmentAuthorityDer: authority.raw.toString('base64url'), interceptionCaCertificateSha256: hash(interception.raw), setupPort, credentialPort };
      privateFile(directory, manifestName, JSON.stringify(material)); fs.unlinkSync(path.join(directory, 'initializing')); return new EnrollmentAssets(directory, material);
    }
    if (fs.existsSync(path.join(directory, 'initializing'))) fail();
    const encoded = read(directory, manifestName, 16384).toString('utf8'), material = JSON.parse(encoded);
    if (!material || Object.keys(material).length !== fields.length || fields.some(key => !Object.hasOwn(material, key)) || material.revision !== 1 ||
      /^[A-Za-z0-9_-]{1,128}$/.exec(material.desktopId)?.[0] !== material.desktopId || encoded !== JSON.stringify(material) ||
      material.logicalName !== enrollmentLogicalName || material.setupPort !== setupPort || material.credentialPort !== credentialPort) fail();
    const gateway = matchIdentity(directory, 'gateway', now), authority = matchIdentity(directory, 'enrollment-authority', now),
      interception = suppliedInterception ? interceptionCertificate(new X509Certificate(read(directory, 'interception.pem')).raw, now) : matchIdentity(directory, 'interception', now);
    if (suppliedInterception && (!interception.raw.equals(suppliedInterception.raw) || fs.existsSync(path.join(directory, 'interception-key.pem')))) fail();
    validateEnrollmentAuthority(authority.raw, { utcMillis: now });
    if (!suppliedInterception) validateEnrollmentAuthority(interception.raw, { utcMillis: now });
    if (gateway.ca || gateway.checkHost(enrollmentLogicalName, { subject: 'never', wildcards: false }) !== enrollmentLogicalName ||
      material.gatewayCertificateDer !== gateway.raw.toString('base64url') || material.gatewaySpkiSha256 !== hash(gateway.publicKey.export({ format: 'der', type: 'spki' })) ||
      material.enrollmentAuthorityDer !== authority.raw.toString('base64url') || material.interceptionCaCertificateSha256 !== hash(interception.raw)) fail();
    return new EnrollmentAssets(directory, material);
  } catch (failure) { if (failure instanceof EnrollmentFixtureError) throw failure; fail(); }
}
