import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runReferenceTunRuntime, parseReferenceTunArguments, referenceTunGateScript, publishReferenceTunAcknowledgment } from './run-reference-tun-runtime.mjs';
import { runDraftCommand } from './draft-stream-command.mjs';
import { createCryptoFixture, fixedSubject, seq, tlv } from './companion-enrollment-crypto-fixtures.mjs';
import { report as legacyFixture } from './enrolled-tun-test-fixtures.mjs';
import { worker as gatewayClosed } from './enrollment-runtime-test-fixtures.mjs';
import * as D from './reference-tun-descriptor.mjs';
import { projectReferenceTunHost, referenceTunHostComplete, decodeReferenceTunReport, verifyReferenceTunReport, referenceTunRuntimeXml, referenceTunRuntimeHtml } from './reference-tun-results.mjs';
const fixture = createCryptoFixture(), logicalName = 'enrollment.freekit.invalid';
const certificate = fixture.certificate({ key: fixture.other, signer: fixture.other, subject: fixedSubject, issuer: fixedSubject,
  eku: Buffer.from('300a06082b06010505070301', 'hex'), extraExtensions: [fixture.extension('551d11', seq(tlv(0x82, Buffer.from(logicalName))))] });
const metadata = { desktopId: 'desk', logicalName, gatewayCertificateDer: certificate.toString('base64url'),
  gatewaySpkiSha256: createHash('sha256').update(new X509Certificate(certificate).publicKey.export({ format: 'der', type: 'spki' })).digest('base64url'),
  enrollmentAuthorityDer: fixture.caDer.toString('base64url'), interceptionCaCertificateSha256: Buffer.alloc(32, 8).toString('base64url'),
  setupPort: 12345, credentialPort: 23456, webSocketPort: 34567 };
const invitation = { invitationId: 'invite', invitationSecret: Buffer.alloc(32, 9).toString('base64url'), expiresAt: '2030-01-02T00:05:00Z' };
const enrollmentId = 'enr_' + Buffer.alloc(32, 1).toString('base64url'), date = '2030-01-02T00:05:00Z';
const registration = { protocolVersion: 1, type: 'pair_registered', desktopId: 'desk', invitationId: 'invite', enrollmentId,
  deviceSpkiSha256: Buffer.alloc(32, 2).toString('base64url'), reservationExpiresAt: date, resultExpiresAt: date };
const approved = { protocolVersion: 1, type: 'pair_approved', desktopId: 'desk', enrollmentId, deviceId: 'dev_' + Buffer.alloc(32, 3).toString('base64url'),
  clientCertificateDer: 'AQ', enrollmentAuthorityDer: metadata.enrollmentAuthorityDer, interceptionCaCertificateSha256: metadata.interceptionCaCertificateSha256,
  capabilities: [...D.referenceTunPayload.gatewayCapabilities], credentialExpiresAt: date, resultExpiresAt: date };
const joinedGateway = () => ({ ...gatewayClosed(), closed: true, authorityClosed: true, acceptedSockets: 0, tlsSockets: 0, bodyReaders: 0, requestTasks: 0,
  pendingWriteCallbacks: 0, registrationWaiters: 0, listeners: 0,
  issuer: { commandsStarted: 2, commandsClosed: 2, processGroupsClosed: 2 },
  stream: { sessionLeases: 0, streamLeases: 0, chargedBytes: 0, ownerRecords: 0, authenticatedSockets: 0, proxySockets: 0, listeners: 0, workers: 0, timers: 0, pendingCallbacks: 0 } });
const command = () => ({ code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true, stderrBytes: 0, output: '' });
const processState = () => ({ closeObserved: true, exitCode: 0, signal: null, processGroupJoined: true, stdoutJoined: true, stderrJoined: true, stdinJoined: true,
  pendingWrites: 0, pendingRequests: 0, forced: false, failure: null });
const tick = () => new Promise(done => setImmediate(done));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function hostSnapshot(method) {
  const https = method === D.referenceTunMethods[1], requestSha256 = digest(Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 31 + 7) & 255)));
  return { stream: { phase: 'complete', resourcesReleased: true, streamLease: false, clientEofEmitted: true, gatewayEofEmitted: true, chargedBytes: 0,
    fixtureUploadBytesRead: 0, fixtureResponseBytesWritten: 0, cleanupComplete: true },
    backend: { ownersCreated: 1, ownersClosed: 1, activeOwners: 0, activeSockets: 0, activeRequests: 0, listeners: 0, upstreamDials: 1,
      interceptedHttpRequests: https ? 0 : 1, interceptedHttpsRequests: https ? 1 : 0, upstreamHttpRequests: https ? 0 : 1, upstreamHttpsRequests: https ? 1 : 0,
      interceptionTlsHandshakes: https ? 1 : 0, upstreamTlsHandshakes: https ? 1 : 0, rejectedPrefaces: 0, closed: false },
    evidence: [{ mode: https ? 'https' : 'http', requestBytes: 4096, requestSha256, responseBytes: 81, responseSha256: digest(Buffer.from('reference-origin:' + requestSha256)) }] };
}
const inspection = () => ({ probe: { stream: { phase: 'complete', webSocketClosed: true, chargedFrames: 0 }, control: { sessionLease: true, streamLeases: 0, chargedBytes: 0 }, io: { pendingIngressBytes: 0 } } });
const bundle = (fields, code) => Object.entries(fields).map(([key, value]) => `INSTRUMENTATION_STATUS: ${key}=${value}\n`).join('') + `INSTRUMENTATION_STATUS_CODE: ${code}\n`;
const phase = name => bundle({ draftReferenceTunVersion: 1, draftReferenceTunPhase: name }, 2);
function observation(method) {
  return bundle(Object.fromEntries(Object.entries(D.referenceTunObservationTypes).map(([key, type]) => [D.referenceTunPrefix + key,
    String(type === 'true' ? true : type === 'false' ? false : type === 'https' ? method === D.referenceTunMethods[1] : ({ version: 1, one: 1, zero: 0, guard: 2, responseBytes: 81 })[type])])), 3);
}
async function simulated(mode = 'complete') {
  const calls = [], legacy = legacyFixture(), controller = new AbortController(); let callback, method, releaseRegistration, ownerCount = 0;
  const record = extra => { const result = { ...command(), ...extra }; host.commands.push(result); return result; };
  const emit = text => callback(Buffer.from(text));
  const identity = () => ({ class: D.referenceTunClass, test: method, numtests: 1, current: 1 });
  const host = { controller, abort: () => controller.abort(), commands: [], installAttempted: false,
    dispose() { calls.push('disposed'); }, async prepare(report) { report.source = legacy.source; report.api = 26; report.clock = legacy.clock; host.installAttempted = true; },
    async cleanupPackage() { calls.push('interop-cleanup'); return { ...legacy.cleanup, packageAbsentAfterCleanup: undefined, ownedCommandsClosed: undefined, ownedCommandGroupsClosed: undefined, failed: false }; },
    async adb(args, timeout, extras = {}) {
      if (args.includes('instrument')) {
        method = args[args.indexOf('class') + 1].split('#')[1]; calls.push(method); callback = extras.onStdoutChunk;
        emit(bundle(identity(), 1) + D.referenceTunPhases.slice(0, 2).map(phase).join(''));
        if (mode === 'unterminated') { emit(phase('awaiting-host-approval').trimEnd()); return record({}); }
        emit(phase('awaiting-host-approval'));
        if (mode === 'closed-before-registration') return record({});
        for (let i = 0; i < 12 && !calls.includes('approve-' + ownerCount); i++) await tick();
        assert(calls.includes('approve-' + ownerCount));
        emit(D.referenceTunPhases.slice(3, 11).map(phase).join(''));
        if (mode === 'bad-origin') { for (let i = 0; i < 4; i++) await tick(); return record({}); }
        for (let i = 0; i < 12 && !calls.includes('receipt-' + ownerCount); i++) await tick();
        assert(calls.includes('receipt-' + ownerCount)); return record({});
      }
      if (extras.stdinBytes) return record({ inputBytes: extras.stdinBytes.length, inputFinished: true, inputClosed: true });
      if (args.includes('run-as')) return record({ output: 'REFERENCE_TUN_INPUT_AND_GATE_ABSENT\n' });
      if (args.includes('sh')) return record({ output: 'REFERENCE_TUN_INTEROP_ABSENT\n' });
      calls.push(args.includes('--remove') ? 'reverse-remove' : 'reverse'); return record({});
    } };
  // Exact host cleanup keys only, as returned by the actual shared owner.
  host.cleanupPackage = async () => { calls.push('interop-cleanup'); return { forceStopCommand: legacy.cleanup.forceStopCommand,
    uninstallCommand: legacy.cleanup.uninstallCommand, uninstallConfirmed: true, failed: false }; };
  const result = await runReferenceTunRuntime({ serial: 'owned-test', adb: 'unused', openssl: 'unused' }, {
    writeReports: false, quiet: true, createHost: () => host,
    createPackages: () => ({ prepare: async () => {}, snapshot: () => legacy.apkSetup, cleanup: async () => { calls.push('packages-cleanup'); if (mode === 'package-cleanup-fails') throw Error('CANARY_PRIVATE'); return { failed: false }; } }),
    async createWorker() {
      const ordinal = ++ownerCount; calls.push('worker-' + ordinal);
      return { metadata: async () => metadata, createInvitation: async () => invitation,
        async waitForRegistered(id, options) { assert.equal(id, invitation.invitationId); assert.equal(options.timeoutMillis, 10000);
          if (mode === 'closed-before-registration') return await new Promise(done => { releaseRegistration = () => done(registration); }); return registration; },
        async approve(id) { assert.equal(id, enrollmentId); calls.push('approve-' + ordinal); return approved; },
        async snapshot() { const value = hostSnapshot(method); if (mode === 'bad-origin') value.evidence[0].responseSha256 = '0'.repeat(64); return value; },
        inspectEnrollment: async () => inspection(),
        async close() { calls.push('worker-close-' + ordinal); releaseRegistration?.(); const value = hostSnapshot(method); value.backend.closed = true;
          return { ...value, gateway: joinedGateway(), assets: { closed: true, commandsStarted: 2, commandsClosed: 2, processGroupsClosed: 2 }, privateDirectoryRemoved: true }; },
        processSnapshot() { const value = processState(); if (mode === 'forced') value.forced = true; return value; } };
    },
    async publishAcknowledgment() {
      calls.push('publish-' + ownerCount); assert(calls.includes('approve-' + ownerCount));
      emit(D.referenceTunPhases.slice(11).map(phase).join('') + observation(method) + bundle(identity(), 0) + 'INSTRUMENTATION_CODE: -1\n');
      await tick(); calls.push('receipt-' + ownerCount);
      return { byteCount: Buffer.byteLength(D.referenceTunAcknowledgment.bytes), inputBytes: Buffer.byteLength(D.referenceTunAcknowledgment.bytes), inputFinished: true,
        inputClosed: true, command: legacy.ack.command, published: true };
    },
  });
  return { ...result, calls };
}
test('two ordered standalone cases require fresh parent owners and independent COMPLETE before ACK/Stop', async () => {
  const result = await simulated(); assert.equal(result.ok, true);
  assert.equal(result.calls.filter(call => call.startsWith('worker-') && !call.startsWith('worker-close')).length, 2);
  assert(result.calls.indexOf('worker-close-1') < result.calls.indexOf(D.referenceTunMethods[1]));
  assert(result.calls.indexOf('publish-1') > result.calls.indexOf('approve-1'));
  for (const item of result.report.methods) assert(item.host.completeObservedBeforeAck && item.host.androidAckPhaseObserved);
  assert.equal(result.calls.filter(call => call === 'reverse-remove').length, 6);
  assert.equal(decodeReferenceTunReport(Buffer.from(JSON.stringify(result.report))).format, D.referenceTunReportFormat);
  assert.match(referenceTunRuntimeXml(result.report), /tests="2"/); assert.doesNotMatch(referenceTunRuntimeHtml(result.report), /requestSha256|invitationSecret|clientCertificateDer/);
});
test('unterminated phase and late registration cannot authorize approval or acknowledgment after process close', async () => {
  for (const mode of ['unterminated', 'closed-before-registration']) {
    const result = await simulated(mode); assert.equal(result.ok, false);
    assert(!result.calls.includes('approve-1')); assert(!result.calls.includes('publish-1'));
    assert(result.calls.includes('worker-close-1')); assert(result.calls.includes('interop-cleanup')); assert(result.calls.includes('disposed'));
    assert.equal(result.report.methods[1].invocation.actualStarted, 0);
  }
});
test('origin mismatch, forced parent termination and independent package cleanup failures stay failures', async () => {
  for (const mode of ['bad-origin', 'forced', 'package-cleanup-fails']) {
    const result = await simulated(mode); assert.equal(result.ok, false); assert(result.calls.includes('interop-cleanup')); assert(result.calls.includes('worker-close-1'));
    assert.equal(JSON.stringify(result.report).includes('CANARY'), false);
    if (mode === 'bad-origin') assert(!result.calls.includes('publish-1'));
  }
});
test('all finite host facts and process/source/clock/transfer/package cleanup gates are required', async () => {
  const result = await simulated(), valid = result.report;
  for (const key of Object.keys(valid.methods[0].host.completion)) {
    const value = structuredClone(valid); value.methods[0].host.completion[key] = null;
    assert.throws(() => verifyReferenceTunReport(value, { source: valid.source.commit, api: 26 }), key);
  }
  const mutations = [r => { r.source.trackedDirty = true; }, r => { r.clock.roundTripMillis = 2001; }, r => { r.methods.reverse(); },
    r => { r.methods[0].input.inputClosed = false; }, r => { r.methods[0].approval.completed = false; }, r => { r.methods[0].ack.published = false; },
    r => { r.methods[0].host.completeObservedBeforeAck = false; }, r => { r.methods[0].resources.process.stdoutJoined = false; },
    r => { r.methods[0].resources.ownedReversesAbsent = false; }, r => { r.methods[0].resources.reverseCommands.pop(); },
    r => { r.methods[0].resources.privateDirectoryRemoved = false; }, r => { r.methods[0].resources.backendJoined = false; },
    r => { r.apkSetup.sameSigner = false; }, r => { r.cleanup.packageAbsentAfterCleanup = false; }, r => { r.cleanup.ownedCommandGroupsClosed = false; },
    r => { r.methods[0].invocation.actualCompleted = 0; }, r => { r.methods[0].resources.gateway.listenersClosed = false; }];
  for (const mutate of mutations) { const value = structuredClone(valid); mutate(value); assert.throws(() => verifyReferenceTunReport(value, { source: valid.source.commit, api: 26 })); }
});
test('absent actual host facts remain null, never successful zero/default observations', () => {
  const value = projectReferenceTunHost(null, null, D.referenceTunMethods[0]);
  assert(Object.values(value).every(item => item === null)); assert.equal(referenceTunHostComplete(value, D.referenceTunMethods[0]), false);
  const raw = hostSnapshot(D.referenceTunMethods[0]); delete raw.evidence[0].requestSha256;
  assert.equal(projectReferenceTunHost(raw, inspection(), D.referenceTunMethods[0]).requestMatched, null);
});
test('standalone CLI rejects legacy desktop/alias/suite arguments and invalid/duplicate values', () => {
  assert.equal(parseReferenceTunArguments(['--serial', 'owned-device']).serial, 'owned-device');
  for (const args of [['--serial', 'x', '--suite', 'c5'], ['--serial', 'x', '--desktop-root', '/tmp'], ['--serial', 'x', '--serial', 'y'], ['--serial', 'bad\n'], ['--serial']]) assert.throws(() => parseReferenceTunArguments(args));
});
test('actual atomic reference gate publication is one-shot and refuses preexisting symlinks', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-reference-gate-test-'));
  try {
    const local = path.join(directory, 'gate'); fs.mkdirSync(local, { mode: 0o700 });
    const script = referenceTunGateScript.replace('directory=no_backup/draft-enrollment-research', 'directory="' + local + '"');
    const run = () => runDraftCommand('sh', ['-c', script], { cwd: directory, timeoutMillis: 5000, stdinBytes: Buffer.from(D.referenceTunAcknowledgment.bytes) });
    const first = await run(); assert.equal(first.code, 0); assert(first.closeObserved && first.processGroupClosed);
    const filename = path.join(local, 'reference-tun-complete-v1.bin'); assert.equal(fs.readFileSync(filename, 'ascii'), D.referenceTunAcknowledgment.bytes);
    assert.equal((fs.statSync(filename).mode & 0o777), 0o600); assert.notEqual((await run()).code, 0);
    fs.unlinkSync(filename); fs.symlinkSync(path.join(local, 'missing'), filename); assert.notEqual((await run()).code, 0);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test('actual pre-device CLI refusal writes independent finite unstarted reports without leaking serial', async () => {
  const root = new URL('../../', import.meta.url), entry = new URL('./run-reference-tun-runtime.mjs', import.meta.url);
  const result = await runDraftCommand(process.execPath, [entry.pathname, '--serial', 'CANARY_unavailable', '--adb', process.execPath],
    { cwd: root.pathname, timeoutMillis: 15000, maxOutputBytes: 32768 });
  assert.equal(result.code, 1); assert(result.closeObserved && result.processGroupClosed);
  assert.doesNotMatch(String(result.output + result.stderr), /CANARY/);
  const report = decodeReferenceTunReport(fs.readFileSync(new URL(D.referenceTunReportPaths.runtime, root)));
  assert.equal(report.methods.length, 2);
  for (const item of report.methods) { assert.equal(item.invocation.actualStarted, 0); assert.equal(item.invocation.actualCompleted, 0); assert.equal(item.host, null); }
  for (const key of ['runtime', 'xml', 'html']) assert.doesNotMatch(fs.readFileSync(new URL(D.referenceTunReportPaths[key], root), 'utf8'), /CANARY|invitationSecret|clientCertificateDer|PRIVATE KEY/);
});
test('publisher uses bounded input receipts and redacts private input bytes after command settles', async () => {
  let retained;
  const result = await publishReferenceTunAcknowledgment({ async adb(args, timeout, extras) {
    assert.equal(timeout, 10000); assert(args.includes('run-as')); retained = extras.stdinBytes;
    assert.equal(retained.toString('ascii'), D.referenceTunAcknowledgment.bytes);
    return { ...command(), inputBytes: retained.length, inputFinished: true, inputClosed: true, output: 'REFERENCE_TUN_GATE_PUBLISHED\n' };
  } });
  assert.equal(result.published, true); assert(retained.every(byte => byte === 0));
});
