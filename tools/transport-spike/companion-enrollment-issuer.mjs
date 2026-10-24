// A22 software issuer adapter only. Never import into a production gateway.
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { inspect } from 'node:util';
import { runDraftCommand } from './draft-stream-command.mjs';
import { enrollmentPublicSnapshot, validateEnrollmentAuthority, validateEnrollmentCsr,
  validateEnrollmentCertificate } from './companion-enrollment-crypto.mjs';

const MAX_FILE = 16384;
const full = (text, expression) => typeof text === 'string' && expression.exec(text)?.[0] === text;
const canonical = (value, minimum, maximum = minimum) => {
  if (!full(value, /^[A-Za-z0-9_-]+$/) || value.length > Math.ceil(maximum * 4 / 3)) throw Error();
  const raw = Buffer.from(value, 'base64url');
  if (raw.length < minimum || raw.length > maximum || raw.toString('base64url') !== value) throw Error(); return raw;
};
const date = value => {
  if (!full(value, /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/) ||
      new Date(value).toISOString().replace('.000Z', 'Z') !== value) throw Error();
  return value.replace(/[-:T]/g, '');
};
const pem = (type, raw) => `-----BEGIN ${type}-----\n${raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${type}-----\n`;
function regular(filename, limit = MAX_FILE) {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > limit ||
    (process.platform !== 'win32' && (stat.mode & 0o077))) throw Error();
  return fs.readFileSync(filename);
}
export class EnrollmentIssuerError extends Error {
  constructor(joined = true) { super('Enrollment issuer unavailable'); this.name = 'EnrollmentIssuerError'; this.code = 'pairing_unavailable'; this.joined = joined; }
  toJSON() { return { code: this.code, joined: this.joined }; }
  [inspect.custom]() { return `EnrollmentIssuerError: pairing_unavailable (joined=${this.joined})`; }
}

class EnrollmentIssuer {
  #directory; #work; #openssl; #authority; #keyPath; #certPath;
  #active = new Set(); #directories = new Set(); #unjoined = new Set();
  #closing = false; #closed = false; #unavailable = false; #closeTask;
  #started = 0; #joined = 0; #groups = 0;
  constructor({ directory, openssl, enrollmentAuthorityDer }) {
    try {
      if (typeof directory !== 'string' || !path.isAbsolute(directory) || typeof openssl !== 'string' || !openssl || openssl.length > 4096 || /[\u0000\r\n]/.test(openssl)) throw Error();
      const real = fs.realpathSync(directory), resolved = path.resolve(directory), stat = fs.lstatSync(directory);
      if (process.platform === 'win32' ? real.toLowerCase() !== resolved.toLowerCase() : real !== resolved) throw Error();
      if (!stat.isDirectory() || stat.isSymbolicLink() || (process.platform !== 'win32' && (stat.mode & 0o077))) throw Error();
      this.#directory = real; this.#openssl = openssl;
      this.#authority = validateEnrollmentAuthority(enrollmentAuthorityDer).material();
      this.#keyPath = path.join(real, 'enrollment-authority-key.pem'); this.#certPath = path.join(real, 'enrollment-authority.pem');
      const cert = new X509Certificate(regular(this.#certPath)), key = createPrivateKey(regular(this.#keyPath, 4096));
      if (cert.raw.toString('base64url') !== this.#authority.certificateDer || key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
          createPublicKey(key).export({ format: 'der', type: 'spki' }).toString('base64url') !== this.#authority.deviceSpkiDer) throw Error();
      this.#work = path.join(real, 'issuer-jobs');
      if (!fs.existsSync(this.#work)) fs.mkdirSync(this.#work, { mode: 0o700 });
      const work = fs.lstatSync(this.#work);
      if (!work.isDirectory() || work.isSymbolicLink() || fs.readdirSync(this.#work).length || (process.platform !== 'win32' && (work.mode & 0o077))) throw Error();
    } catch { throw new EnrollmentIssuerError(); }
  }
  async initialize() {
    const result = await this.#command(['version'], this.#directory, new AbortController().signal);
    if (result.code !== 0 || result.reason || !full(result.output.trim(), /^OpenSSL 3\.[^\r\n]*$/)) throw new EnrollmentIssuerError();
    return this;
  }
  async #command(args, cwd, signal) {
    this.#started++;
    let result;
    try { result = await runDraftCommand(this.#openssl, args, { cwd, timeoutMillis: 5000, maxOutputBytes: 16384, abortSignal: signal }); }
    catch { this.#unjoined.add(Object.freeze({})); this.#unavailable = true; throw new EnrollmentIssuerError(false); }
    if (result.closeObserved) this.#joined++;
    if (result.processGroupClosed) this.#groups++;
    if (!result.closeObserved || !result.processGroupClosed) { this.#unjoined.add(result); this.#unavailable = true; throw new EnrollmentIssuerError(false); }
    return result;
  }
  #validateJob(snapshot) {
    const job = snapshot?.material?.();
    const keys = 'desktopId invitationId enrollmentId deviceId generation token serial deviceSpkiDer deviceSpkiSha256 csrDer capabilities notBefore notAfter subject profile'.split(' ');
    if (!job || Object.keys(job).length !== keys.length || keys.some(key => !Object.hasOwn(job, key)) ||
      !full(job.desktopId, /^[A-Za-z0-9_-]{1,128}$/) || !full(job.invitationId, /^[A-Za-z0-9_-]{1,128}$/) ||
      !full(job.enrollmentId, /^enr_[A-Za-z0-9_-]{43}$/) || !full(job.deviceId, /^dev_[A-Za-z0-9_-]{43}$/) ||
      !Number.isInteger(job.generation) || job.generation < 1 || job.generation > 2147483647 ||
      !full(job.serial, /^[1-9][0-9]{0,15}$/) || BigInt(job.serial) > BigInt(Number.MAX_SAFE_INTEGER) ||
      job.subject !== 'CN=HTTP FreeKit device' || job.profile !== 'p256-client-auth-v1' ||
      !Array.isArray(job.capabilities) || !job.capabilities.length || job.capabilities.length > 16 ||
      job.capabilities.some(cap => !full(cap, /^[a-z][a-z0-9-]{0,31}$/)) || new Set(job.capabilities).size !== job.capabilities.length ||
      job.capabilities.join('\0') !== [...job.capabilities].sort().join('\0')) throw Error();
    canonical(job.token, 32); canonical(job.enrollmentId.slice(4), 32); canonical(job.deviceId.slice(4), 32);
    const csr = validateEnrollmentCsr(job.csrDer).material(); canonical(job.deviceSpkiDer, 91); canonical(job.deviceSpkiSha256, 32);
    date(job.notBefore); date(job.notAfter);
    if (job.deviceSpkiDer !== csr.deviceSpkiDer || job.deviceSpkiSha256 !== csr.deviceSpkiSha256 || job.notBefore >= job.notAfter ||
      job.notBefore < this.#authority.notBefore || job.notAfter > this.#authority.notAfter) throw Error();
    return job;
  }
  issue(jobSnapshot, { signal } = {}) {
    if (this.#closing || this.#closed || this.#unavailable || signal?.aborted || this.#active.size >= 4) return Promise.reject(new EnrollmentIssuerError());
    const entry = { controller: new AbortController(), task: null };
    this.#active.add(entry); entry.task = this.#issue(entry, jobSnapshot, signal); return entry.task;
  }
  async #issue(entry, snapshot, signal) {
    let directory, joined = true;
    const abort = () => entry.controller.abort(); signal?.addEventListener('abort', abort, { once: true });
    try {
      const job = this.#validateJob(snapshot);
      directory = fs.mkdtempSync(path.join(this.#work, 'job-')); fs.chmodSync(directory, 0o700); this.#directories.add(directory);
      fs.mkdirSync(path.join(directory, 'issued'), { mode: 0o700 });
      fs.writeFileSync(path.join(directory, 'index.txt'), '', { mode: 0o600 });
      let serial = BigInt(job.serial).toString(16); if (serial.length % 2) serial = '0' + serial;
      fs.writeFileSync(path.join(directory, 'serial'), serial + '\n', { mode: 0o600 });
      fs.writeFileSync(path.join(directory, 'request.pem'), pem('CERTIFICATE REQUEST', canonical(job.csrDer, 1, 4096)), { mode: 0o600 });
      fs.writeFileSync(path.join(directory, 'job.cnf'), '[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=index.txt\nnew_certs_dir=issued\nserial=serial\n' +
        'default_md=sha256\npolicy=subject\nunique_subject=no\ncopy_extensions=none\nstring_mask=utf8only\n' +
        '[subject]\ncommonName=supplied\n[client]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n', { mode: 0o600 });
      if (this.#closing || entry.controller.signal.aborted) throw new EnrollmentIssuerError();
      joined = false;
      const result = await this.#command(['ca', '-config', 'job.cnf', '-name', 'issuer', '-batch', '-notext', '-md', 'sha256', '-utf8',
        '-subj', '/CN=HTTP FreeKit device', '-startdate', date(job.notBefore), '-enddate', date(job.notAfter), '-extensions', 'client',
        '-keyfile', this.#keyPath, '-cert', this.#certPath, '-in', 'request.pem', '-out', 'leaf.pem'], directory, entry.controller.signal);
      joined = true;
      if (this.#closing || entry.controller.signal.aborted || result.code !== 0 || result.reason) throw new EnrollmentIssuerError();
      fs.chmodSync(path.join(directory, 'leaf.pem'), 0o600);
      const candidate = new X509Certificate(regular(path.join(directory, 'leaf.pem'))).raw;
      const checked = validateEnrollmentCertificate(candidate, { authority: this.#authority.certificateDer, deviceSpkiDer: job.deviceSpkiDer,
        serial: job.serial, notBefore: job.notBefore, notAfter: job.notAfter }).material();
      return enrollmentPublicSnapshot({ clientCertificateDer: checked.certificateDer });
    } catch (failure) { throw new EnrollmentIssuerError(failure instanceof EnrollmentIssuerError ? failure.joined : joined); }
    finally {
      signal?.removeEventListener('abort', abort);
      this.#active.delete(entry);
      if (joined && directory) {
        try { fs.rmSync(directory, { recursive: true, force: true }); this.#directories.delete(directory); }
        catch { this.#unavailable = true; throw new EnrollmentIssuerError(); }
      }
    }
  }
  snapshot() { return Object.freeze({ activeJobs: this.#active.size, unjoinedChildren: this.#unjoined.size,
    jobDirectories: this.#directories.size, commandsStarted: this.#started, commandsClosed: this.#joined,
    processGroupsClosed: this.#groups, closing: this.#closing, closed: this.#closed }); }
  close() {
    if (this.#closed) return Promise.resolve(this.snapshot());
    if (this.#closeTask) return this.#closeTask;
    this.#closing = true;
    this.#closeTask = (async () => {
      const entries = [...this.#active]; entries.forEach(entry => entry.controller.abort());
      await Promise.allSettled(entries.map(entry => entry.task));
      if (this.#active.size || this.#unjoined.size || this.#joined !== this.#started || this.#groups !== this.#started) throw new EnrollmentIssuerError(false);
      for (const directory of this.#directories) { try { fs.rmSync(directory, { recursive: true, force: true }); this.#directories.delete(directory); } catch {} }
      if (this.#directories.size) throw new EnrollmentIssuerError();
      this.#closed = true; return this.snapshot();
    })();
    return this.#closeTask;
  }
  toString() { return '[Enrollment research issuer]'; }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return this.toString(); }
}
export async function startEnrollmentIssuer(options) {
  let issuer;
  try { issuer = new EnrollmentIssuer({ openssl: process.env.OPENSSL_BIN ?? 'openssl', ...options }); return await issuer.initialize(); }
  catch (failure) { try { await issuer?.close(); } catch {} throw new EnrollmentIssuerError(failure instanceof EnrollmentIssuerError ? failure.joined : true); }
}
