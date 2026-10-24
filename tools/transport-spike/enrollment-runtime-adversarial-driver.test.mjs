import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { enrollmentRuntimeOptions, registerEnrollmentReverses } from './run-enrollment-runtime.mjs';
import { EnrollmentRuntimeWorker } from './enrollment-runtime-worker.mjs';
import { decodeEnrollmentAdversarialReport as decodeAdversarialEnrollmentReport, enrollmentAdversarialReportPaths as adversarialEnrollmentReportPaths,
  verifyEnrollmentAdversarialReport as verifyAdversarialEnrollmentReport } from './enrollment-runtime-adversarial-results.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const successful = output => ({ code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true, output });

test('wrong-peer reverse validates all role ports before mutation and retains successful late ownership', async () => {
  const metadata = { setupPort: 32101, credentialPort: 32102, adversarialPeerPort: 32103 };
  for (const mutation of [{ adversarialPeerPort: 0 }, { adversarialPeerPort: '32103' }, { adversarialPeerPort: 32101 },
    { adversarialPeerPort: 65536 }, { webSocketPort: 32104 }]) {
    let called = false;
    await assert.rejects(registerEnrollmentReverses(async () => { called = true; }, { ...metadata, ...mutation }, []));
    assert.equal(called, false);
  }
  let calls = 0; const owned = [];
  await assert.rejects(registerEnrollmentReverses(async args => {
    const port = 32101 + calls++;
    assert.deepEqual(args, ['reverse', '--no-rebind', 'tcp:' + port, 'tcp:' + port]);
    return successful(calls === 3 ? 'unexpected' : '');
  }, metadata, owned), /^Error: enrollment_fixture_failed$/);
  assert.deepEqual(owned, [32101, 32102, 32103].map(port => ({ devicePort: port, hostPort: port })));
});

test('malformed adversarial start cannot create assets or consume the single valid legacy start', async () => {
  const temporary = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(temporary, 'freekit-adversarial-ipc-'));
  fs.chmodSync(directory, 0o700);
  const worker = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)), cwd: ROOT });
  const args = { directory, mode: 'create', openssl: process.env.OPENSSL_BIN ?? 'openssl', setupPort: 0, credentialPort: 0 };
  try {
    for (const mutation of [{ mode: 'open' }, { setupPort: 32101, credentialPort: 32101 },
      { setupPort: -1 }, { adversarialPeerPort: 32103 }, { extra: 'PRIVATE' }]) {
      await assert.rejects(worker.request('startAdversarial', { ...args, ...mutation }), error => error.code === 'invalid_message');
      assert.deepEqual(fs.readdirSync(directory), []);
    }
    const metadata = (await worker.request('start', args, { timeoutMillis: 60000 })).material();
    assert.equal(Object.keys(metadata).length, 8);
    await assert.rejects(worker.request('startAdversarial', args), error => error.code === 'pairing_unavailable');
  } finally {
    await worker.close();
    assert.equal(worker.closedSnapshot().material().storeClosed, true);
    assert.equal(worker.commandObservation().processGroupClosed, true);
    assert.equal(path.dirname(directory), temporary); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('actual unavailable-device preflight retains four unstarted cases and only bounded sanitized reports', () => {
  assert.equal(enrollmentRuntimeOptions(['--serial', 'device', '--suite', 'a22c']).suite, 'a22c');
  assert.equal(enrollmentRuntimeOptions(['--serial', 'device']).suite, 'a22a');
  const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: ROOT, encoding: 'utf8' }).trim() !== '';
  const result = spawnSync(process.execPath, ['tools/transport-spike/run-enrollment-runtime.mjs', '--serial',
    'adversarial-PRIVATE-unavailable-device', '--suite', 'a22c', '--adb', process.execPath],
  { cwd: ROOT, encoding: 'utf8', timeout: 20000, windowsHide: true });
  assert.equal(result.error, undefined); assert.equal(result.status, 1);
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE|invitation|BEGIN.*PRIVATE KEY/);
  assert.match(result.stdout, /0 started, 0 completed; failed/);
  const report = decodeAdversarialEnrollmentReport(fs.readFileSync(path.join(ROOT, adversarialEnrollmentReportPaths.runtime)));
  assert.deepEqual(report.problems, [dirty ? 'source_not_clean' : 'selected_device_unavailable']);
  assert.equal(report.scenarios.length, 4);
  for (const item of report.scenarios) {
    assert.equal(item.invocation.state, 'not_started'); assert.equal(item.invocation.actualStarted, 0); assert.equal(item.invocation.actualCompleted, 0);
    for (const key of ['input', 'approval', 'host', 'cleanup']) assert.equal(item[key], null);
  }
  assert.equal(report.cleanup.ownedCommandsClosed, true); assert.equal(report.cleanup.ownedCommandGroupsClosed, true);
  assert.throws(() => verifyAdversarialEnrollmentReport(report, { source: report.source.commit, api: 26 }));
  assert.match(fs.readFileSync(path.join(ROOT, adversarialEnrollmentReportPaths.xml), 'utf8'), /tests="4" failures="0" errors="4" skipped="0"/);
});

test('actual adversarial private start returns one extra public port and joins its service before Store release', async () => {
  const temporary = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(temporary, 'freekit-adversarial-ipc-'));
  fs.chmodSync(directory, 0o700);
  const worker = new EnrollmentRuntimeWorker({ entry: fileURLToPath(new URL('./companion-enrollment-worker.mjs', import.meta.url)), cwd: ROOT });
  try {
    const metadata = (await worker.request('startAdversarial', { directory, mode: 'create', openssl: process.env.OPENSSL_BIN ?? 'openssl',
      setupPort: 0, credentialPort: 0 }, { timeoutMillis: 60000 })).material();
    assert.equal(Object.keys(metadata).length, 9);
    const ports = [metadata.setupPort, metadata.credentialPort, metadata.adversarialPeerPort];
    assert(ports.every(port => Number.isSafeInteger(port) && port >= 1 && port <= 65535)); assert.equal(new Set(ports).size, 3);
    const snapshot = (await worker.request('snapshot')).material();
    assert.equal(snapshot.alternateTls.listenerClosed, false);
    assert.equal(snapshot.alternateTls.childrenStarted, snapshot.alternateTls.childrenClosed);
    assert.equal(snapshot.alternateTls.childrenStarted, snapshot.alternateTls.childGroupsClosed);
  } finally {
    await worker.close();
    const closed = worker.closedSnapshot().material();
    for (const key of ['admissionClosed', 'listenersClosed', 'storeClosed', 'issuerChildrenJoined']) assert.equal(closed[key], true);
    for (const key of ['activeSockets', 'pendingCallbacks', 'pendingTimers', 'issuerJobs', 'signerGroups', 'workers']) assert.equal(closed[key], 0);
    assert.equal(closed.alternateTls.admissionClosed, true); assert.equal(closed.alternateTls.listenerClosed, true);
    assert.equal(worker.commandObservation().closeObserved, true); assert.equal(worker.commandObservation().processGroupClosed, true);
    assert.equal(path.dirname(directory), temporary); fs.rmSync(directory, { recursive: true, force: true });
  }
});
