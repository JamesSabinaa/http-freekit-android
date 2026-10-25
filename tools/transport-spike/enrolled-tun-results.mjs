import { createEnrollmentSuiteInvocationParser, EnrollmentRuntimeError, enrollmentRuntimeValidation as V, enrollmentRuntimeLimits } from './enrollment-runtime-results.mjs';
import { enrolledTunMethod, enrolledTunClass, enrolledTunPayload, enrolledTunAcknowledgment } from './enrolled-tun-descriptor.mjs';
import { enrolledTunAliasRefusals } from './enrolled-tun-host.mjs';
import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';
export * from './enrolled-tun-descriptor.mjs';

export function createEnrolledTunInvocationParser({ onPhase } = {}) {
  return createEnrollmentSuiteInvocationParser(enrolledTunMethod, { onPhase, suite: 'c5' });
}
export function parseEnrolledTunInvocation(output, commandResult) {
  const parser = createEnrolledTunInvocationParser();
  try { parser.push(typeof output === 'string' ? Buffer.from(output) : output); }
  catch (error) { if (!(error instanceof EnrollmentRuntimeError)) throw error; }
  return parser.finish(commandResult);
}

export const enrolledTunDesktopCommit = '2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6';
const fail = code => { throw new EnrollmentRuntimeError(code); };
const bools = (value, keys) => keys.forEach(key => V.boolean(value[key]));
const counts = (value, keys) => keys.forEach(key => V.integer(value[key], 0, 33570816));
const nullableCommands = value => { for (const command of Object.values(value)) if (command !== null) V.validateCommand(command); };
const originTrue = ['requestVerified', 'responsePrefixWritten', 'responseEof', 'tailReleased', 'clientEndWriteApplied', 'originalDestinationMatched', 'captureMatched', 'tailReleaseRequested'];
const originFalse = ['tlsSniMatched', 'tlsAlpnH1', 'upgradeAccepted', 'clientCloseObserved', 'serverCloseWritten', 'failed'];
const originZero = ['tlsConnections', 'upgradeRequests', 'clientTextMessages', 'clientBinaryMessages', 'clientBinaryBytes', 'clientPings', 'clientPongs'];
const originCounts = ['connections', 'requests', 'requestBodyBytes', 'responseBodyBytesWritten', ...originZero];
const originHashes = ['requestBodySha256', 'responseBodySha256', 'clientBinarySha256'];
const originKeys = [...originTrue, ...originFalse, ...originCounts, ...originHashes];
const backendKeys = ['closing', 'activeOwners', 'admitted', 'settled', 'captures', 'clientEndWrites', 'proxyMode', 'negotiatedCapabilities'];
const hostFlags = ['registered', 'liveReleasePhaseObserved', 'releaseRequested', 'releaseCompleted', 'liveCompletionPhaseObserved', 'gatewayStreamComplete', 'completeObservedBeforeAck', 'androidAckPhaseObserved'];
const packageFlags = ['initiallyAbsent', 'installAttempted', 'installed', 'uninstallConfirmed', 'absentAfterCleanup'];
const permissionKeys = ['interopLocalNetwork', 'trafficLocalNetwork', 'interopNotification'];
const aliasFlags = ['initiallyAbsent', 'created', 'verified', 'removalRequested', 'removed', 'absenceConfirmed'];
function validateOrigin(value) {
  V.exact(value, originKeys); bools(value, [...originTrue, ...originFalse]); counts(value, originCounts);
  for (const key of originHashes) if (value[key] !== null) V.hash(value[key]);
}
function validateBackend(value) {
  V.exact(value, backendKeys); V.boolean(value.closing); counts(value, ['activeOwners', 'admitted', 'settled', 'captures', 'clientEndWrites']);
  V.enumeration(value.proxyMode, [null, 'http-origin-connect']);
  if (!Array.isArray(value.negotiatedCapabilities) || value.negotiatedCapabilities.length > 3 || new Set(value.negotiatedCapabilities).size !== value.negotiatedCapabilities.length ||
      value.negotiatedCapabilities.some(capability => !['tcp-http', 'tcp-https-connect', 'tcp-http-origin-connect'].includes(capability))) throw Error();
}
export function projectEnrolledTunHostSnapshot(snapshot) {
  try {
    V.enumeration(snapshot.profile, ['tun-http-h1']); V.enumeration(snapshot.family, ['ipv4']);
    validateOrigin(snapshot.origin); validateBackend(snapshot.backend); V.boolean(snapshot.gatewayStreamComplete);
    return V.copyFreeze({ profile: snapshot.profile, family: snapshot.family, gatewayStreamComplete: snapshot.gatewayStreamComplete,
      origin: snapshot.origin, backend: snapshot.backend });
  } catch { fail('invalid_runtime_report'); }
}
export function enrolledTunHostComplete(snapshot) {
  let value; try { value = projectEnrolledTunHostSnapshot(snapshot); } catch { return false; }
  const { origin, backend } = value;
  return value.gatewayStreamComplete && originTrue.every(key => origin[key]) && originFalse.every(key => !origin[key]) && originZero.every(key => origin[key] === 0) &&
    origin.clientBinarySha256 === null && origin.connections === 1 && origin.requests === 1 &&
    origin.requestBodyBytes === enrolledTunPayload.requestBodyBytes && origin.requestBodySha256 === enrolledTunPayload.requestBodySha256 &&
    origin.responseBodyBytesWritten === enrolledTunPayload.responseBodyBytes && origin.responseBodySha256 === enrolledTunPayload.responseBodySha256 &&
    !backend.closing && backend.activeOwners === 0 && ['admitted', 'settled', 'captures', 'clientEndWrites'].every(key => backend[key] === 1) &&
    backend.proxyMode === 'http-origin-connect' && JSON.stringify(backend.negotiatedCapabilities) === JSON.stringify(enrolledTunPayload.gatewayCapabilities);
}
function validateReport(value) {
  V.exact(value, ['format', 'revision', 'source', 'api', 'clock', 'invocation', 'input', 'approval', 'host', 'alias', 'ack', 'apkSetup', 'resources', 'cleanup', 'problems']);
  if (value.format !== 'http-freekit-enrolled-tun-runtime' || value.revision !== 1) throw Error();
  if (value.source !== null) { V.exact(value.source, ['commit', 'trackedDirty']); V.commit(value.source.commit); V.boolean(value.source.trackedDirty); }
  if (value.api !== null) V.enumeration(value.api, [26, 37]); if (value.clock !== null) V.validateClock(value.clock);
  V.validateInvocation(value.invocation, enrolledTunMethod, 'c5'); V.validateProblems(value.problems);
  if (value.input !== null) {
    V.exact(value.input, ['byteCount', 'inputBytes', 'inputFinished', 'inputClosed', 'command', 'inputAbsentAfterMethod']);
    V.integer(value.input.byteCount, 1, 16384); V.integer(value.input.inputBytes, 0, 16384); V.validateCommand(value.input.command);
    bools(value.input, ['inputFinished', 'inputClosed', 'inputAbsentAfterMethod']);
  }
  if (value.approval !== null) {
    V.exact(value.approval, ['livePhaseObserved', 'requested', 'completed', 'approvedResponsesDelivered', 'actualApprovedResponseDrops', 'issuerCommandsBefore', 'issuerCommandsAfter', 'issuerJobsAfter']);
    bools(value.approval, ['livePhaseObserved', 'requested', 'completed']); counts(value.approval, ['approvedResponsesDelivered', 'actualApprovedResponseDrops', 'issuerCommandsBefore']);
    for (const key of ['issuerCommandsAfter', 'issuerJobsAfter']) if (value.approval[key] !== null) V.integer(value.approval[key], 0, 33570816);
  }
  if (value.host !== null) {
    V.exact(value.host, ['desktopCommit', ...hostFlags, 'profile', 'family', 'origin', 'backend']); V.commit(value.host.desktopCommit); bools(value.host, hostFlags);
    V.enumeration(value.host.profile, [null, 'tun-http-h1']); V.enumeration(value.host.family, [null, 'ipv4']);
    if (value.host.origin !== null) validateOrigin(value.host.origin); if (value.host.backend !== null) validateBackend(value.host.backend);
  }
  V.exact(value.alias, ['platform', ...aliasFlags, 'refusal', 'commands']); V.enumeration(value.alias.platform, ['linux', 'unsupported']); bools(value.alias, aliasFlags);
  V.enumeration(value.alias.refusal, [null, ...enrolledTunAliasRefusals]); V.exact(value.alias.commands, ['before', 'create', 'verify', 'remove', 'after']); nullableCommands(value.alias.commands);
  if (value.ack !== null) {
    V.exact(value.ack, ['byteCount', 'inputBytes', 'inputFinished', 'inputClosed', 'command', 'published', 'absentAfterMethod']);
    V.integer(value.ack.byteCount, 1, 128); V.integer(value.ack.inputBytes, 0, 128); V.validateCommand(value.ack.command);
    bools(value.ack, ['inputFinished', 'inputClosed', 'published', 'absentAfterMethod']);
  }
  if (value.apkSetup !== null) {
    V.exact(value.apkSetup, ['sameSigner', 'controlTrafficGranted', 'packages', 'permissions']); bools(value.apkSetup, ['sameSigner', 'controlTrafficGranted']);
    if (!Array.isArray(value.apkSetup.packages) || value.apkSetup.packages.length !== 2) throw Error();
    value.apkSetup.packages.forEach((item, index) => {
      V.exact(item, ['package', ...packageFlags, 'installCommand', 'forceStopCommand', 'uninstallCommand']);
      if (item.package !== ['com.httpfreekit.capturetest', 'com.httpfreekit.capturetraffic'][index]) throw Error(); bools(item, packageFlags);
      nullableCommands(Object.fromEntries(['installCommand', 'forceStopCommand', 'uninstallCommand'].map(key => [key, item[key]])));
    });
    V.exact(value.apkSetup.permissions, ['mode', ...permissionKeys]); V.enumeration(value.apkSetup.permissions.mode, [null, 'not_required', 'owned_ci_grant']);
    nullableCommands(Object.fromEntries(permissionKeys.map(key => [key, value.apkSetup.permissions[key]])));
  }
  if (value.resources !== null) {
    V.exact(value.resources, ['workerClosed', 'workerCommand', 'reverseRemovalExitCodes', 'ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayStreamComplete', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
    if (value.resources.workerClosed !== null) V.validateWorker(value.resources.workerClosed);
    if (value.resources.workerCommand !== null) V.validateCommand(value.resources.workerCommand);
    if (!Array.isArray(value.resources.reverseRemovalExitCodes) || value.resources.reverseRemovalExitCodes.length > 3) throw Error(); value.resources.reverseRemovalExitCodes.forEach(code => V.integer(code, 0, 255));
    bools(value.resources, ['ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayStreamComplete', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
  }
  if (value.cleanup !== null) {
    V.exact(value.cleanup, ['forceStopCommand', 'uninstallCommand', 'uninstallConfirmed', 'packageAbsentAfterCleanup', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
    nullableCommands({ forceStopCommand: value.cleanup.forceStopCommand, uninstallCommand: value.cleanup.uninstallCommand });
    bools(value.cleanup, ['uninstallConfirmed', 'packageAbsentAfterCleanup', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
  }
}
export function createEnrolledTunReport(value) {
  try { validateReport(value); return V.copyFreeze(value); } catch { fail('invalid_runtime_report'); }
}
export function decodeEnrolledTunReport(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > enrollmentRuntimeLimits.runtime) fail('runtime_report_limit');
  let value; try { value = parseEnrollmentJson(bytes); } catch { fail('invalid_runtime_report'); } return createEnrolledTunReport(value);
}
export function verifyEnrolledTunReport(value, { source, api, desktopCommit }) {
  const report = createEnrolledTunReport(value); V.commit(source); V.commit(desktopCommit); V.enumeration(api, [26, 37]);
  if (desktopCommit !== enrolledTunDesktopCommit || report.source?.commit !== source || report.source.trackedDirty || report.api !== api || report.host?.desktopCommit !== desktopCommit) fail('runtime_source_mismatch');
  if (!V.clockPassed(report.clock)) fail('runtime_clock_failed');
  if (report.problems.length || report.invocation.state !== 'passed') fail('runtime_invocation_failed');
  const { input, approval, host, resources, cleanup, alias, ack, apkSetup } = report;
  if (!input || input.inputBytes !== input.byteCount || !input.inputFinished || !input.inputClosed || !input.inputAbsentAfterMethod || !V.commandPassed(input.command)) fail('runtime_input_failed');
  if (!approval || !approval.livePhaseObserved || !approval.requested || !approval.completed || approval.approvedResponsesDelivered < 1 || approval.actualApprovedResponseDrops !== 0 ||
      approval.issuerCommandsAfter === null || approval.issuerCommandsAfter <= approval.issuerCommandsBefore || approval.issuerJobsAfter !== 0) fail('runtime_approval_failed');
  if (!host || !hostFlags.every(key => host[key]) || !enrolledTunHostComplete(host)) fail('runtime_enrolled_tun_host_failed');
  if (alias.platform !== 'linux' || alias.refusal !== null || !aliasFlags.every(key => alias[key]) || !Object.values(alias.commands).every(V.commandPassed)) fail('runtime_enrolled_tun_alias_failed');
  if (!ack || ack.byteCount !== Buffer.byteLength(enrolledTunAcknowledgment.bytes) || ack.inputBytes !== ack.byteCount || !V.commandPassed(ack.command) ||
      !['inputFinished', 'inputClosed', 'published', 'absentAfterMethod'].every(key => ack[key])) fail('runtime_enrolled_tun_ack_failed');
  if (!apkSetup || !apkSetup.sameSigner || !apkSetup.controlTrafficGranted || apkSetup.packages.some(item => !packageFlags.every(key => item[key]) ||
      !['installCommand', 'forceStopCommand', 'uninstallCommand'].every(key => V.commandPassed(item[key]))) ||
      (api === 26 ? apkSetup.permissions.mode !== 'not_required' || permissionKeys.some(key => apkSetup.permissions[key] !== null) :
        apkSetup.permissions.mode !== 'owned_ci_grant' || permissionKeys.some(key => !V.commandPassed(apkSetup.permissions[key])))) fail('runtime_enrolled_tun_packages_failed');
  if (!resources || !V.workerPassed(resources.workerClosed) || !V.commandPassed(resources.workerCommand) || resources.reverseRemovalExitCodes.length !== 3 ||
      resources.reverseRemovalExitCodes.some(code => code !== 0) || !['ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayStreamComplete', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => resources[key])) fail('runtime_cleanup_failed');
  if (!cleanup || !V.commandPassed(cleanup.forceStopCommand) || !V.commandPassed(cleanup.uninstallCommand) ||
      !['uninstallConfirmed', 'packageAbsentAfterCleanup', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => cleanup[key])) fail('runtime_cleanup_failed');
  return Object.freeze({ methods: 1, actualStarted: 1, actualCompleted: 1, source, api, desktopCommit });
}
const escape = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[character]);
const render = text => { if (Buffer.byteLength(text) > enrollmentRuntimeLimits.rendered) fail('rendered_report_limit'); return text; };
export function enrolledTunRuntimeXml(value) {
  const report = createEnrolledTunReport(value), item = report.invocation;
  const detail = item.problems.join(', ') + (item.failure ? `\n${item.failure.phase}/${item.failure.type}/${item.failure.category}/cleanup=${item.failure.cleanup}` : '') +
    item.frames.map(frame => `\nat ${frame.className}.${frame.method}(${frame.file}:${frame.line})`).join('');
  const result = item.state === 'passed' ? '' : item.state === 'failed' ? `<failure message="Enrolled TUN assertion failed">${escape(detail)}</failure>` : `<error message="Enrolled TUN method did not complete">${escape(detail)}</error>`;
  return render(`<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="${enrolledTunClass}" tests="1" failures="${item.state === 'failed' ? 1 : 0}" errors="${['passed', 'failed'].includes(item.state) ? 0 : 1}" skipped="0">\n` +
    `<testcase classname="${enrolledTunClass}" name="${enrolledTunMethod}" time="0">${result}</testcase>\n<system-out>${escape(report.problems.join(', ') || 'Method observations only; exact host/runtime/emulator cleanup JSON are required.')}</system-out>\n</testsuite>\n`);
}
export function enrolledTunRuntimeHtml(value) {
  return render('<!doctype html><html lang="en"><meta charset="utf-8"><title>Enrolled TUN research results</title><body><h1>C5 method and host observations</h1><pre>' +
    escape(JSON.stringify(createEnrolledTunReport(value), null, 2)) + '</pre></body></html>\n');
}
