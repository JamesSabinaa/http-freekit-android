import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createEnrollmentStore, openEnrollmentStore } from './companion-enrollment-store.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';

const outcomes = [];
const childJoins = new WeakMap();
const helper = fileURLToPath(new URL('./companion-enrollment-store-crash-child.mjs', import.meta.url));
function barrier(child, marker) {
  return new Promise((resolve, reject) => {
    let text = ''; const timer = setTimeout(() => finish(Error('Child barrier unavailable')), 10000);
    const data = bytes => { text += bytes.toString('ascii'); if (text.length > 128 || text.includes('FAILED')) finish(Error('Child barrier failed')); else if (text === marker + '\n') finish(); };
    const exit = () => finish(Error('Child exited before barrier'));
    function finish(error) { clearTimeout(timer); child.stdout.off('data', data); child.off('exit', exit); error ? reject(error) : resolve(); }
    child.stdout.on('data', data); child.once('exit', exit);
  });
}
async function exitAfterKill(child) {
  let timer;
  try {
    if (child.exitCode === null && child.signalCode === null) assert(child.kill('SIGKILL'));
    return await Promise.race([childJoins.get(child), new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Owned child did not close')), 5000); })]);
  } finally { clearTimeout(timer); }
}
for (const operation of ['reserve', 'claim', 'publish', 'revoke']) for (const position of ['before', 'after']) {
  test(`real owned child kill ${position} ${operation} commit preserves exact recoverable tuple and owner exclusion`, { timeout: 20000 }, async t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-enrollment-crash-')), crypto = createCryptoFixture();
    const metadata = { desktopId: 'crash_fixture', gatewaySpkiSha256: randomBytes(32).toString('base64url'), enrollmentAuthorityDer: crypto.caDer.toString('base64url'), interceptionCaCertificateSha256: randomBytes(32).toString('base64url'), supportedCapabilities: ['tcp'] };
    const options = { directory, metadata, clock: () => ({ utcMillis: crypto.utcMillis, monotonicMillis: 0 }) };
    let store = createEnrollmentStore(options), child, joined = false;
    t.after(async () => { try { if (child && !joined) await exitAfterKill(child); } finally { try { store?.close(); } finally { fs.rmSync(directory, { force: true, recursive: true }); } } });
    const invitation = store.createInvitation().material(), pair = { desktopId: metadata.desktopId, ...invitation, csrDer: crypto.csr().toString('base64url'), deviceName: 'Crash fixture', capabilities: ['tcp'] };
    let registration, candidate;
    if (operation !== 'reserve') registration = store.reserve(pair).material();
    if (operation === 'publish') candidate = crypto.certificate({ serial: 1 });
    if (operation === 'revoke') { const job = store.beginApproval(registration.enrollmentId).job; candidate = crypto.certificate({ serial: job.material().serial }); store.publish(job, candidate); }
    store.close();
    const inputPath = path.join(directory, 'test-input.json');
    fs.writeFileSync(inputPath, JSON.stringify({ directory, metadata, utcMillis: crypto.utcMillis, operation, position, pair, enrollmentId: registration?.enrollmentId, candidate: candidate?.toString('base64url') }), { mode: 0o600 });
    child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', helper, inputPath], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    childJoins.set(child, new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal }))));
    await barrier(child, position === 'before' ? 'BEFORE_COMMIT' : 'AFTER_COMMIT');
    assert.throws(() => openEnrollmentStore(options), e => e.code === 'pairing_unavailable');
    const reader = new DatabaseSync(path.join(directory, 'enrollment.sqlite'), { readOnly: true, timeout: 50 });
    try { assert.throws(() => reader.prepare('SELECT version FROM meta').get(), e => e.errcode === 5); } finally { reader.close(); }
    const journal = path.join(directory, 'enrollment.sqlite-journal');
    const journalExistsBeforeKill = fs.existsSync(journal);
    let journalBytesBeforeKill = 0, journalHeaderNonzero = false;
    if (journalExistsBeforeKill) {
      journalBytesBeforeKill = fs.statSync(journal).size;
      const header = Buffer.alloc(8), fd = fs.openSync(journal, 'r');
      try { fs.readSync(fd, header, 0, 8, 0); } finally { fs.closeSync(fd); }
      journalHeaderNonzero = header.some(value => value !== 0);
    }
    if (position === 'before') { assert(journalBytesBeforeKill > 28); assert(journalHeaderNonzero, 'dirty-page spill has a real recovery journal header'); }
    const killed = await exitAfterKill(child); joined = true; assert.equal(killed.signal, 'SIGKILL');
    // Only after actual child exit/join may recovery acquire the owner lease.
    store = openEnrollmentStore(options); store.close();
    const recoveredDb = new DatabaseSync(path.join(directory, 'enrollment.sqlite'), { readOnly: true });
    let durableRow;
    try {
      const enrollmentCount = recoveredDb.prepare('SELECT count(*) AS n FROM enrollments').get().n;
      const expectedPublished = operation === 'revoke' || (operation === 'publish' && position === 'after');
      assert.equal(enrollmentCount, operation === 'reserve' && position === 'before' ? 0 : 1);
      assert.equal(recoveredDb.prepare('SELECT count(*) AS n FROM credentials').get().n, Number(expectedPublished));
      assert.equal(recoveredDb.prepare('SELECT consumed FROM invitations').get().consumed, Number(expectedPublished));
      durableRow = recoveredDb.prepare('SELECT id,state FROM enrollments').get();
      if (operation === 'claim') assert.equal(durableRow.state, position === 'before' ? 'pending' : 'issuing');
      if (operation === 'publish') assert.equal(durableRow.state, position === 'before' ? 'issuing' : 'approved');
      if (operation === 'revoke') { assert.equal(durableRow.state, position === 'before' ? 'approved' : 'revoked'); assert.equal(recoveredDb.prepare('SELECT active FROM credentials').get().active, Number(position === 'before')); }
    } finally { recoveredDb.close(); }
    store = openEnrollmentStore(options); let tuple;
    if (operation === 'reserve') {
      const recovered = store.reserve(pair).material();
      if (position === 'after') assert.equal(recovered.enrollmentId, durableRow.id);
      tuple = position === 'before' ? 'reservation_rolled_back' : 'reservation_retained';
      const job = store.beginApproval(recovered.enrollmentId).job; assert.equal(job.material().serial, '1'); store.abandon(job);
    } else if (operation === 'claim') {
      assert.equal(store.readResult(registration.enrollmentId).material().type, 'pair_pending');
      const job = store.beginApproval(registration.enrollmentId).job;
      assert.equal(job.material().serial, position === 'before' ? '1' : '2'); store.abandon(job);
      tuple = position === 'before' ? 'claim_rolled_back' : 'intent_reclaimed';
    } else if (operation === 'publish') {
      const result = store.readResult(registration.enrollmentId).material();
      assert.equal(result.type, position === 'before' ? 'pair_pending' : 'pair_approved');
      assert.equal(Boolean(store.authorizeCertificate(candidate)), position === 'after');
      if (position === 'before') { const job = store.beginApproval(registration.enrollmentId).job; assert.equal(job.material().serial, '2'); store.abandon(job); }
      else assert.equal(result.clientCertificateDer, candidate.toString('base64url'));
      tuple = position === 'before' ? 'publication_rolled_back' : 'exact_publication_retained';
    } else {
      assert.equal(store.readResult(registration.enrollmentId).material().type, position === 'before' ? 'pair_approved' : 'pair_ended');
      assert.equal(Boolean(store.authorizeCertificate(candidate)), position === 'before');
      tuple = position === 'before' ? 'revocation_rolled_back' : 'revocation_retained';
    }
    store.close();
    const verifier = new DatabaseSync(path.join(directory, 'enrollment.sqlite'), { readOnly: true });
    try { assert.equal(verifier.prepare('PRAGMA integrity_check').get().integrity_check, 'ok'); assert.equal(verifier.prepare('PRAGMA foreign_key_check').all().length, 0); } finally { verifier.close(); }
    outcomes.push({ id: `${operation}-${position}`, operation, position, barrierObserved: true, ownerExcluded: true, readerExcluded: true, killRequested: true, childExitJoined: true, journalExistsBeforeKill, journalBytesBeforeKill, journalHeaderNonzero, recovered: true, integrity: true, tuple });
  });
}
test.after(() => {
  if (!process.env.FREEKIT_ENROLLMENT_CRASH_REPORT) return;
  const filename = path.resolve(process.env.FREEKIT_ENROLLMENT_CRASH_REPORT);
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  const cwd = fileURLToPath(new URL('../../', import.meta.url));
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'ascii', timeout: 2000, maxBuffer: 128 }).trim();
  const trackedDirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd, timeout: 2000, maxBuffer: 65536 }).length !== 0;
  assert.match(commit, /^[0-9a-f]{40}$/);
  fs.writeFileSync(filename, JSON.stringify({ format: 'http-freekit-enrollment-store-crash', revision: '1', node: process.version, platform: process.platform, powerLossTested: false, source: { commit, trackedDirty }, cases: outcomes }, null, 2) + '\n');
});
