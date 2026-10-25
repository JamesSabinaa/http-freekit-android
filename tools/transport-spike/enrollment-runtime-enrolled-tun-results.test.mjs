import test from 'node:test';
import assert from 'node:assert/strict';
import { createEnrolledTunReport, decodeEnrolledTunReport, enrolledTunHostComplete, projectEnrolledTunHostSnapshot,
  enrolledTunRuntimeXml, enrolledTunRuntimeHtml, parseEnrolledTunInvocation, createEnrolledTunInvocationParser } from './enrolled-tun-results.mjs';
import { report, verify, clone, hostSnapshot, command, prefix, status } from './enrolled-tun-test-fixtures.mjs';

test('C5 complete report independently binds both APIs, host COMPLETE, alias, gate and all three package owners', () => {
  for (const api of [26, 37]) {
    const value = report(api), bytes = Buffer.from(JSON.stringify(value));
    assert.deepEqual(decodeEnrolledTunReport(bytes), createEnrolledTunReport(value)); assert.equal(verify(value).methods, 1);
    assert(enrolledTunHostComplete(value.host)); assert(Object.isFrozen(projectEnrolledTunHostSnapshot(value.host).origin));
    assert.match(enrolledTunRuntimeXml(value), /tests="1" failures="0" errors="0" skipped="0"/);
    assert(enrolledTunRuntimeHtml(value).includes('C5 method and host observations')); assert(bytes.length < 32768);
  }
});

test('C5 rejects every contradictory host HTTP/COMPLETE fact and unrelated TLS/upgrade activity', () => {
  for (const group of ['origin', 'backend']) for (const [key, value] of Object.entries(hostSnapshot()[group])) {
    const changed = report(); changed.host[group][key] = typeof value === 'boolean' ? !value : typeof value === 'number' ? value + 1 :
      value === null ? '0'.repeat(64) : Array.isArray(value) ? ['tcp-http-origin-connect'] : key.endsWith('Sha256') ? '0'.repeat(64) : null;
    assert.throws(() => verify(changed), undefined, `${group}.${key}`); assert(!enrolledTunHostComplete(changed.host));
  }
  for (const key of ['registered', 'liveReleasePhaseObserved', 'releaseRequested', 'releaseCompleted', 'liveCompletionPhaseObserved',
    'gatewayStreamComplete', 'completeObservedBeforeAck', 'androidAckPhaseObserved']) {
    const changed = report(); changed.host[key] = false; assert.throws(() => verify(changed), undefined, key);
  }
  for (const [key, value] of [['profile', 'http-h1'], ['family', 'ipv6'], ['desktopCommit', 'b'.repeat(40)]]) {
    const changed = report(); changed.host[key] = value; assert.throws(() => verify(changed));
  }
});

test('C5 source projection copies actual finite fields and rejects foreign payload or credential material', () => {
  const source = { ...hostSnapshot(), enrollment: { secret: 'CANARY_PRIVATE' } };
  const projected = projectEnrolledTunHostSnapshot(source); assert(!JSON.stringify(projected).includes('CANARY'));
  source.origin.requests = 2; assert.equal(projected.origin.requests, 1);
  for (const group of ['origin', 'backend']) {
    const value = hostSnapshot(); value[group].secret = 'CANARY'; assert.throws(() => projectEnrolledTunHostSnapshot(value));
  }
});

test('C5 requires every alias ownership and acknowledged gate barrier with actual command closure', () => {
  for (const key of ['initiallyAbsent', 'created', 'verified', 'removalRequested', 'removed', 'absenceConfirmed']) {
    const value = report(); value.alias[key] = false; assert.throws(() => verify(value), undefined, key);
  }
  for (const key of ['before', 'create', 'verify', 'remove', 'after']) {
    const value = report(); value.alias.commands[key].processGroupClosed = false; assert.throws(() => verify(value), undefined, key);
  }
  for (const key of ['inputFinished', 'inputClosed', 'published', 'absentAfterMethod']) {
    const value = report(); value.ack[key] = false; assert.throws(() => verify(value), undefined, key);
  }
  for (const change of [{ platform: 'unsupported' }, { refusal: 'alias_verify_failed' }]) {
    const value = report(); Object.assign(value.alias, change); assert.throws(() => verify(value));
  }
  for (const change of [{ byteCount: 1 }, { inputBytes: 0 }, { command: null }]) {
    const value = report(); Object.assign(value.ack, change); assert.throws(() => verify(value));
  }
});

test('C5 never substitutes interop ownership for extras, signer/signature grants or API37 permissions', () => {
  for (const key of ['sameSigner', 'controlTrafficGranted']) { const value = report(); value.apkSetup[key] = false; assert.throws(() => verify(value)); }
  for (let index = 0; index < 2; index++) for (const key of ['initiallyAbsent', 'installAttempted', 'installed', 'uninstallConfirmed', 'absentAfterCleanup',
    'installCommand', 'forceStopCommand', 'uninstallCommand']) {
    const value = report(); value.apkSetup.packages[index][key] = key.endsWith('Command') ? null : false; assert.throws(() => verify(value), undefined, key);
  }
  for (const key of ['interopLocalNetwork', 'trafficLocalNetwork', 'interopNotification']) {
    const value = report(37); value.apkSetup.permissions[key] = null; assert.throws(() => verify(value));
    const legacy = report(); legacy.apkSetup.permissions[key] = value.ack.command; assert.throws(() => verify(legacy));
  }
  const wrongOwner = report(); wrongOwner.apkSetup.packages[0].package = 'com.httpfreekit.interop.test'; assert.throws(() => verify(wrongOwner));
  const noInterop = report(); noInterop.cleanup.packageAbsentAfterCleanup = false; assert.throws(() => verify(noInterop));
});

test('C5 source/clock, approval, private input and all independent resource joins remain mandatory', () => {
  const changes = [value => value.source.trackedDirty = true, value => value.source.commit = 'b'.repeat(40), value => value.clock.lowerBoundMillis--,
    value => value.input.inputAbsentAfterMethod = false, value => value.input.inputBytes = 0, value => value.input.command.closeObserved = false,
    value => value.approval.livePhaseObserved = false, value => value.approval.completed = false, value => value.approval.issuerCommandsAfter = 1,
    value => value.approval.actualApprovedResponseDrops = 1, value => value.resources.workerClosed.workers = 1,
    value => value.resources.workerCommand.closeObserved = false, value => value.resources.reverseRemovalExitCodes.pop(),
    value => value.resources.privateDirectoryRemoved = false, value => value.resources.gatewayStreamComplete = false,
    value => value.cleanup.uninstallConfirmed = false, value => value.cleanup.ownedCommandsClosed = false,
    value => value.cleanup.ownedCommandGroupsClosed = false, value => value.problems.push('enrollment_cleanup_failed')];
  for (const change of changes) { const value = report(); change(value); assert.throws(() => verify(value)); }
});

test('C5 incomplete/failed evidence remains renderable but cannot be accepted or repaired by full host facts', () => {
  for (const invocation of [createEnrolledTunInvocationParser().finish(), parseEnrolledTunInvocation(prefix(8) + status(-2,
    'java.lang.AssertionError: Enrolled TUN research failed at http-command-started (IOException); category=traffic_tcp_eof_reset; cleanup=false.') + 'INSTRUMENTATION_CODE: -1\n', command())]) {
    const value = report(); value.invocation = invocation; assert.throws(() => verify(value));
    const xml = enrolledTunRuntimeXml(value); assert.match(xml, /<(?:error|failure) message=/); assert(!xml.includes('CANARY'));
  }
  const partial = report(); partial.source = partial.api = partial.clock = partial.input = partial.approval = partial.host = partial.ack = partial.apkSetup = partial.resources = partial.cleanup = null;
  partial.invocation = createEnrolledTunInvocationParser().finish(); assert.doesNotThrow(() => createEnrolledTunReport(partial)); assert.throws(() => verify(partial));
});

test('C5 strict JSON and typed finite schemas reject additions, duplicates, bounds and non-booleans', () => {
  const unknown = report(); unknown.secret = 'CANARY'; assert.throws(() => createEnrolledTunReport(unknown));
  assert.throws(() => decodeEnrolledTunReport(Buffer.from(JSON.stringify(report()).replace('"revision":1', '"revision":1,"revision":1'))));
  assert.throws(() => decodeEnrolledTunReport(Buffer.alloc(65537, 32)));
  for (const change of [value => value.alias.created = 1, value => value.apkSetup.sameSigner = 'true', value => value.host.origin.connections = true,
    value => value.host.origin.requests = 33570817, value => value.ack.published = 1]) {
    const value = clone(report()); change(value); assert.throws(() => createEnrolledTunReport(value));
  }
});
