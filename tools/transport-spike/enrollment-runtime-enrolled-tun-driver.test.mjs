import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, X509Certificate } from 'node:crypto';
import { enrollmentRuntimeOptions } from './run-enrollment-runtime.mjs';
import { runEnrolledTunRuntime } from './run-enrolled-tun-runtime.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';
import { createCryptoFixture, fixedSubject, seq, tlv } from './companion-enrollment-crypto-fixtures.mjs';
import { report, hostSnapshot, command, phase, status, facts, observation, source, desktopCommit } from './enrolled-tun-test-fixtures.mjs';
import { enrolledTunPhases, enrolledTunReportPaths, decodeEnrolledTunReport } from './enrolled-tun-results.mjs';
import { worker as workerClosed } from './enrollment-runtime-test-fixtures.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url)), entry = path.join(ROOT, 'tools/transport-spike/run-enrollment-runtime.mjs');
const options = { serial: 'owned-test', adb: 'unused', desktopRoot: ROOT, desktopCommit, openssl: 'unused', suite: 'c5' };
const material = value => ({ material: () => value });
const fixture = createCryptoFixture(), logicalName = 'enrollment.freekit.invalid';
const gateway = fixture.certificate({ key: fixture.other, signer: fixture.other, subject: fixedSubject, issuer: fixedSubject,
  eku: Buffer.from('300a06082b06010505070301', 'hex'), extraExtensions: [fixture.extension('551d11', seq(tlv(0x82, Buffer.from(logicalName))))] });
const metadata = { desktopId: 'desk', logicalName, gatewayCertificateDer: gateway.toString('base64url'),
  gatewaySpkiSha256: createHash('sha256').update(new X509Certificate(gateway).publicKey.export({ format: 'der', type: 'spki' })).digest('base64url'),
  enrollmentAuthorityDer: fixture.caDer.toString('base64url'), interceptionCaCertificateSha256: Buffer.alloc(32, 8).toString('base64url'),
  setupPort: 12345, credentialPort: 23456, webSocketPort: 34567 };
const invitation = { invitationId: 'invite', invitationSecret: Buffer.alloc(32, 9).toString('base64url'), expiresAt: '2030-01-02T00:05:00Z' };
const enrollmentId = 'enr_' + Buffer.alloc(32, 1).toString('base64url'), date = '2030-01-02T00:05:00Z';
const registration = { protocolVersion: 1, type: 'pair_registered', desktopId: 'desk', invitationId: 'invite', enrollmentId,
  deviceSpkiSha256: Buffer.alloc(32, 2).toString('base64url'), reservationExpiresAt: date, resultExpiresAt: date };
const approved = { protocolVersion: 1, type: 'pair_approved', desktopId: 'desk', enrollmentId, deviceId: 'dev_' + Buffer.alloc(32, 3).toString('base64url'),
  clientCertificateDer: 'AQ', enrollmentAuthorityDer: metadata.enrollmentAuthorityDer, interceptionCaCertificateSha256: metadata.interceptionCaCertificateSha256,
  capabilities: ['tcp-http-origin-connect', 'tcp-https-connect'], credentialExpiresAt: date, resultExpiresAt: date };
const tick = () => new Promise(done => setImmediate(done));

async function simulated(mode = 'complete') {
  const calls = [], positive = report(), controller = new AbortController(); let callback, releaseRegistration, snapshotCount = 0, closed = false;
  const record = extra => { const value = { ...command(), stderrBytes: 0, output: '', ...extra }; host.commands.push(value); return value; };
  const emit = text => callback(Buffer.from(text));
  const host = { controller, abort: () => controller.abort(), commands: [], command: () => { throw Error('Unexpected host command'); }, installAttempted: false, dispose() {},
    async prepare(value) { value.source = { commit: source, trackedDirty: false }; value.api = 26; value.clock = positive.clock; host.installAttempted = true; },
    async cleanupPackage() { calls.push('interop-cleanup'); return { forceStopCommand: positive.cleanup.forceStopCommand, uninstallCommand: positive.cleanup.uninstallCommand, uninstallConfirmed: true, failed: false }; },
    async adb(args, timeout, extras = {}) {
      if (args.includes('instrument')) {
        assert.equal(timeout, 300000); callback = extras.onStdoutChunk;
        emit(status(1) + enrolledTunPhases.slice(0, 2).map(phase).join(''));
        if (mode === 'unterminated') { emit(phase('awaiting-host-approval').trimEnd()); return record({}); }
        emit(phase('awaiting-host-approval'));
        if (mode === 'closed-before-registration') return record({});
        for (let n = 0; n < 10 && !calls.includes('approve'); n++) await tick(); assert(calls.includes('approve'));
        emit(enrolledTunPhases.slice(3, 8).map(phase).join(''));
        for (let n = 0; n < 10 && !calls.includes('releaseOriginTail'); n++) await tick(); assert(calls.includes('releaseOriginTail'));
        emit(enrolledTunPhases.slice(8, 10).map(phase).join(''));
        for (let n = 0; n < 10 && !calls.includes('publish'); n++) await tick(); assert(calls.includes('publish'));
        // The publisher emits Android's acknowledgment before returning its ADB receipt.
        for (let n = 0; n < 10 && !calls.includes('published-receipt'); n++) await tick(); assert(calls.includes('published-receipt'));
        return record({});
      }
      if (extras.stdinBytes) return record({ inputBytes: extras.stdinBytes.length, inputFinished: true, inputClosed: true });
      if (args.includes('run-as')) return record({ output: 'TUN_INPUT_AND_GATE_ABSENT\n' });
      if (args.includes('sh')) return record({ output: 'TUN_INTEROP_ABSENT\n' });
      return record({});
    } };
  const worker = { async request(op, args, requestOptions) {
    calls.push(op);
    if (op === 'startTunOrigin') { assert.deepEqual(args, { desktopRoot: ROOT, desktopCommit, openssl: 'unused' }); return material(metadata); }
    if (op === 'createInvitation') return material(invitation);
    if (op === 'waitForRegistered') {
      if (mode === 'closed-before-registration') return await new Promise(done => { releaseRegistration = () => done(material(registration)); });
      return material(registration);
    }
    if (op === 'approve') return material(approved);
    if (op === 'releaseOriginTail') { assert.equal(requestOptions.timeoutMillis, 20000); return material(hostSnapshot()); }
    if (op === 'snapshot') return material({ ...(snapshotCount++ ? hostSnapshot() : {}), enrollment: { issuer: { commandsStarted: snapshotCount === 1 ? 1 : 2 },
      issuerJobs: 0, approvedResponsesDelivered: 1, droppedApprovedResponses: 0 } });
    throw Error('Unexpected worker operation');
  }, async close() { calls.push('worker-close'); releaseRegistration?.(); closed = true; },
  closedSnapshot: () => closed ? material({ ...workerClosed(), privateDirectoryRemoved: true, gatewayStreamComplete: true }) : null,
  commandObservation: command };
  const result = await runEnrolledTunRuntime(options, { platform: 'linux', writeReports: false, createHost: () => host,
    createAlias: () => ({ snapshot: () => positive.alias, prepare: async () => { calls.push('alias-prepare'); },
      remove: async ({ fixtureJoined }) => { assert.equal(fixtureJoined, true); assert(calls.includes('worker-close')); calls.push('alias-remove'); } }),
    createWorker: () => worker, createPackages: () => ({ snapshot: () => positive.apkSetup, prepare: async () => { calls.push('packages-prepare'); },
      cleanup: async () => { calls.push('packages-cleanup'); if (mode === 'package-cleanup-fails') throw Error('CANARY_PRIVATE'); return { failed: false, snapshot: positive.apkSetup }; } }),
    async publishAcknowledgment() {
      calls.push('publish'); assert(calls.includes('releaseOriginTail')); assert(snapshotCount >= 2);
      emit(enrolledTunPhases.slice(10, 14).map(phase).join('') + observation(facts()) + phase(enrolledTunPhases[14]) + status(0) + 'INSTRUMENTATION_CODE: -1\n');
      await tick(); calls.push('published-receipt'); return positive.ack;
    } });
  return { ...result, calls };
}

test('C5 driver uses actual finite phase authority and accepts Android ACK before the publication receipt settles', async () => {
  const result = await simulated(); assert.equal(result.ok, true); assert.equal(result.report.host.completeObservedBeforeAck, true);
  assert.equal(result.report.host.androidAckPhaseObserved, true); assert(result.calls.indexOf('publish') > result.calls.indexOf('releaseOriginTail'));
  assert(result.calls.indexOf('alias-remove') > result.calls.indexOf('worker-close'));
});
test('C5 unterminated approval and delayed registration after command close cannot authorize operator approval or ACK', async () => {
  for (const mode of ['unterminated', 'closed-before-registration']) {
    const result = await simulated(mode); assert.equal(result.ok, false); assert(!result.calls.includes('approve')); assert(!result.calls.includes('publish'));
    assert.equal(result.report.approval.requested, false); assert.equal(result.report.host.completeObservedBeforeAck, false);
  }
});
test('C5 failed extra-package cleanup cannot bypass independent interop and joined-fixture alias cleanup', async () => {
  const result = await simulated('package-cleanup-fails'); assert.equal(result.ok, false);
  assert(result.report.problems.includes('enrollment_cleanup_failed')); assert(result.calls.includes('interop-cleanup')); assert(result.calls.includes('alias-remove'));
  assert(!JSON.stringify(result.report).includes('CANARY'));
});
test('C5 CLI requires the exact clean C3 desktop pin and explicit path without changing legacy defaults', () => {
  const args = ['--serial', 'device', '--suite', 'c5', '--desktop-root', ROOT, '--desktop-commit', desktopCommit];
  assert.equal(enrollmentRuntimeOptions(args).suite, 'c5'); assert.equal(enrollmentRuntimeOptions(['--serial', 'device']).suite, 'a22a');
  for (const changed of [args.slice(0, 4), args.map(value => value === ROOT ? '.' : value), args.map(value => value === desktopCommit ? 'b'.repeat(40) : value),
    args.map(value => value === 'c5' ? 'a22a' : value), [...args, '--desktop-commit', desktopCommit]]) assert.throws(() => enrollmentRuntimeOptions(changed));
});
test('actual unsupported/pre-device C5 CLI refusal retains finite unstarted evidence and starts no fixture or alias', async () => {
  const result = await runDraftCommand(process.execPath, [entry, '--serial', 'CANARY_unavailable', '--suite', 'c5', '--desktop-root', ROOT,
    '--desktop-commit', desktopCommit, '--adb', process.execPath], { cwd: ROOT, timeoutMillis: 15000, maxOutputBytes: 32768 });
  assert.equal(result.code, 1); assert(result.closeObserved && result.processGroupClosed); assert(!String(result.output + result.stderr).includes('CANARY'));
  const value = decodeEnrolledTunReport(fs.readFileSync(path.join(ROOT, enrolledTunReportPaths.runtime)));
  assert.equal(value.invocation.state, 'not_started'); assert.equal(value.invocation.actualStarted + value.invocation.actualCompleted, 0);
  for (const key of ['host', 'input', 'approval', 'resources', 'ack', 'apkSetup']) assert.equal(value[key], null);
  assert.equal(value.alias.created, false); assert.equal(value.alias.commands.before, null);
  if (process.platform === 'win32') { assert.equal(value.alias.refusal, 'unsupported_platform'); assert.equal(value.source, null); }
  for (const key of ['runtime', 'xml', 'html']) assert(!/CANARY|invitationSecret|clientCertificateDer|PRIVATE KEY/.test(fs.readFileSync(path.join(ROOT, enrolledTunReportPaths[key]), 'utf8')));
});
