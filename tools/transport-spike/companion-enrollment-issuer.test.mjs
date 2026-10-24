import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { startEnrollmentIssuer } from './companion-enrollment-issuer.mjs';
import { createEnrollmentStore } from './companion-enrollment-store.mjs';
import { validateEnrollmentCertificate } from './companion-enrollment-crypto.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';

function fixture(t) {
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-enrollment-issuer-')), crypto = createCryptoFixture();
  fs.chmodSync(directory, 0o700);
  const keyFile = path.join(directory, 'enrollment-authority-key.pem');
  fs.writeFileSync(keyFile, crypto.authority.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  fs.writeFileSync(path.join(directory, 'enrollment-authority.pem'), new X509Certificate(crypto.caDer).toString(), { mode: 0o600 });
  const metadata = { desktopId: 'issuer_fixture', gatewaySpkiSha256: randomBytes(32).toString('base64url'), enrollmentAuthorityDer: crypto.caDer.toString('base64url'), interceptionCaCertificateSha256: randomBytes(32).toString('base64url'), supportedCapabilities: ['tcp-http'], credentialLifetimeSeconds: 3600 };
  const store = createEnrollmentStore({ directory, metadata, clock: () => ({ utcMillis: crypto.utcMillis, monotonicMillis: 0 }) });
  let issuer; const jobs = [];
  t.after(async () => {
    await issuer?.close();
    for (const job of jobs) store.abandon(job);
    store.close(); assert(directory.startsWith(root + path.sep)); fs.rmSync(directory, { recursive: true, force: true });
  });
  return { directory, keyFile, crypto, store,
    get issuer() { return issuer; },
    start: async (options = {}) => issuer = await startEnrollmentIssuer({ directory, enrollmentAuthorityDer: metadata.enrollmentAuthorityDer, ...options }),
    job: (key = crypto.device) => {
      const invitation = store.createInvitation().material();
      const registration = store.reserve({ ...invitation, desktopId: metadata.desktopId, csrDer: crypto.csr({ key }).toString('base64url'), deviceName: 'Issuer software fixture', capabilities: ['tcp-http'] }).material();
      const job = store.beginApproval(registration.enrollmentId).job; jobs.push(job); return job;
    },
  };
}
const rejects = promise => assert.rejects(promise, failure => {
  assert.equal(failure.code, 'pairing_unavailable'); assert.equal(failure.joined, true); assert.equal(failure.cause, undefined);
  assert(!inspect(failure).includes('file:')); return true;
});
const keyHash = filename => createHash('sha256').update(fs.readFileSync(filename)).digest('hex');

test('real OpenSSL issuer exactly matches Store job profile and authorizes only after publication', async t => {
  const f = fixture(t), job = f.job(), before = keyHash(f.keyFile); await f.start();
  const result = await f.issuer.issue(job), material = result.material(), expected = job.material();
  const leaf = Buffer.from(material.clientCertificateDer, 'base64url');
  assert.equal(f.store.authorizeCertificate(leaf), null);
  const checked = validateEnrollmentCertificate(leaf, { authority: f.crypto.caDer, ...expected, utcMillis: f.crypto.utcMillis }).material();
  assert.equal(checked.serial, expected.serial); assert.equal(checked.notBefore, expected.notBefore); assert.equal(checked.notAfter, expected.notAfter);
  assert.equal(f.store.publish(job, leaf).material().clientCertificateDer, material.clientCertificateDer);
  assert(f.store.authorizeCertificate(leaf)); assert.equal(keyHash(f.keyFile), before);
  assert.deepEqual(f.issuer.snapshot(), { activeJobs: 0, unjoinedChildren: 0, jobDirectories: 0, commandsStarted: 2, commandsClosed: 2, processGroupsClosed: 2, closing: false, closed: false });
  material.clientCertificateDer = 'changed'; assert.notEqual(result.material().clientCertificateDer, material.clientCertificateDer);
});
test('concurrent real issuance uses independent CA indexes/serials and retains exact distinct bindings', async t => {
  const f = fixture(t), a = f.job(), b = f.job(f.crypto.other); await f.start();
  const [first, second] = await Promise.all([f.issuer.issue(a), f.issuer.issue(b)]);
  for (const [job, candidate] of [[a, first], [b, second]]) f.store.publish(job, Buffer.from(candidate.material().clientCertificateDer, 'base64url'));
  assert.notEqual(a.material().serial, b.material().serial); assert.equal(f.issuer.snapshot().commandsClosed, 3);
  assert.deepEqual(fs.readdirSync(path.join(f.directory, 'issuer-jobs')), []);
});
test('a real signed leaf after rejection remains unpublished and cannot authorize', async t => {
  const f = fixture(t), job = f.job(); await f.start();
  const signing = f.issuer.issue(job); f.store.reject(job.material().enrollmentId);
  const raw = Buffer.from((await signing).material().clientCertificateDer, 'base64url');
  assert.throws(() => f.store.publish(job, raw), failure => failure.code === 'authentication_failed');
  assert.equal(f.store.authorizeCertificate(raw), null); assert.equal(f.issuer.snapshot().commandsClosed, 2);
});
test('close interrupts an actually admitted issuer child and joins it before any Store handle release', async t => {
  const f = fixture(t), job = f.job(); await f.start();
  const signing = f.issuer.issue(job); assert.equal(f.issuer.snapshot().commandsStarted, 2); assert.equal(f.issuer.snapshot().activeJobs, 1);
  const rejected = rejects(signing), closing = f.issuer.close();
  assert.throws(() => f.store.close(), failure => failure.code === 'pairing_unavailable');
  await rejected; const closed = await closing;
  assert.equal(closed.closed, true); assert.equal(closed.activeJobs, 0); assert.equal(closed.unjoinedChildren, 0); assert.equal(closed.jobDirectories, 0);
  assert.equal(closed.commandsClosed, closed.commandsStarted); assert.equal(closed.processGroupsClosed, closed.commandsStarted);
  await rejects(f.issuer.issue(job)); f.store.abandon(job);
});
test('caller abort rejects only after real child closure and leaves no work directory', async t => {
  const f = fixture(t), job = f.job(); await f.start(); const controller = new AbortController();
  const signing = f.issuer.issue(job, { signal: controller.signal }); assert.equal(f.issuer.snapshot().activeJobs, 1); controller.abort();
  await rejects(signing); assert.equal(f.issuer.snapshot().commandsStarted, 2); assert.equal(f.issuer.snapshot().commandsClosed, 2);
  assert.equal(f.issuer.snapshot().jobDirectories, 0); assert.equal(f.issuer.snapshot().unjoinedChildren, 0);
});
test('pre-aborted and malformed jobs are refused before a signing child or work directory is admitted', async t => {
  const f = fixture(t), job = f.job(); await f.start(); const controller = new AbortController(); controller.abort();
  await rejects(f.issuer.issue(job, { signal: controller.signal }));
  for (const changed of [{ serial: '01' }, { subject: 'CN=other' }, { deviceSpkiDer: f.crypto.publicDer(f.crypto.other).toString('base64url') },
    { notAfter: '2030-01-03T01:00:00Z' }, { capabilities: ['other', 'tcp-http', 'other'] }, { profile: 'unreviewed' }]) {
    await rejects(f.issuer.issue({ material: () => ({ ...job.material(), ...changed }) }));
  }
  assert.equal(f.issuer.snapshot().commandsStarted, 1); assert.equal(f.issuer.snapshot().jobDirectories, 0);
});
test('missing or mismatched fixed authority assets fail closed without overwriting them', async t => {
  const f = fixture(t), original = fs.readFileSync(f.keyFile);
  fs.writeFileSync(f.keyFile, f.crypto.other.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await rejects(f.start()); assert.notDeepEqual(fs.readFileSync(f.keyFile), original);
  fs.writeFileSync(f.keyFile, original); fs.unlinkSync(path.join(f.directory, 'enrollment-authority.pem')); await rejects(f.start());
});
test('real OpenSSL signing failure is static, joined and never publishes a candidate', async t => {
  const f = fixture(t), job = f.job(); await f.start(); const original = fs.readFileSync(f.keyFile);
  fs.writeFileSync(f.keyFile, 'controlled unusable software-key fixture');
  try { await rejects(f.issuer.issue(job)); } finally { fs.writeFileSync(f.keyFile, original); }
  assert.equal(f.issuer.snapshot().commandsClosed, 2); assert.equal(f.issuer.snapshot().jobDirectories, 0);
  assert.equal(f.store.readResult(job.material().enrollmentId).material().type, 'pair_pending');
});
test('default issuer and result diagnostics never contain paths, job tokens, CSR or certificate material', async t => {
  const f = fixture(t), job = f.job(); await f.start(); const result = await f.issuer.issue(job);
  for (const text of [String(f.issuer), inspect(f.issuer), JSON.stringify(f.issuer), inspect(result), JSON.stringify(result)]) {
    for (const value of [f.directory, job.material().token, job.material().csrDer, result.material().clientCertificateDer]) assert(!text.includes(value));
  }
});
