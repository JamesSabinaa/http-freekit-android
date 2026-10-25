import { createEnrollmentSuiteInvocationParser, EnrollmentRuntimeError, enrollmentRuntimeValidation as V, enrollmentRuntimeLimits } from './enrollment-runtime-results.mjs';
import { captureFactoryMethod, captureFactoryClass, captureFactoryPayload } from './capture-factory-descriptor.mjs';
import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';
export * from './capture-factory-descriptor.mjs';

export function createCaptureFactoryInvocationParser({ onPhase } = {}) {
  return createEnrollmentSuiteInvocationParser(captureFactoryMethod, { onPhase, suite: 'c2' });
}
export function parseCaptureFactoryInvocation(output, commandResult) {
  const parser = createCaptureFactoryInvocationParser();
  try { parser.push(typeof output === 'string' ? Buffer.from(output) : output); }
  catch (error) { if (!(error instanceof EnrollmentRuntimeError)) throw error; }
  return parser.finish(commandResult);
}

const fail = code => { throw new EnrollmentRuntimeError(code); };
const bools = (value, keys) => keys.forEach(key => V.boolean(value[key]));
const counts = (value, keys) => keys.forEach(key => V.integer(value[key], 0, 33570816));
const originBooleans = ['requestVerified', 'responsePrefixWritten', 'responseEof', 'tailReleased', 'clientEndWriteApplied',
  'originalDestinationMatched', 'captureMatched', 'tailReleaseRequested'];
const originCounts = ['connections', 'requests', 'requestBodyBytes', 'responseBodyBytesWritten'];
function validateReport(value) {
  V.exact(value, ['format', 'revision', 'source', 'api', 'clock', 'invocation', 'input', 'approval', 'host', 'resources', 'cleanup', 'problems']);
  if (value.format !== 'http-freekit-capture-factory-runtime' || value.revision !== 1) throw Error();
  if (value.source !== null) { V.exact(value.source, ['commit', 'trackedDirty']); V.commit(value.source.commit); V.boolean(value.source.trackedDirty); }
  if (value.api !== null) V.enumeration(value.api, [26, 37]); if (value.clock !== null) V.validateClock(value.clock);
  V.validateInvocation(value.invocation, captureFactoryMethod, 'c2'); V.validateProblems(value.problems);
  if (value.input !== null) {
    V.exact(value.input, ['byteCount', 'inputBytes', 'inputFinished', 'inputClosed', 'command', 'inputAbsentAfterMethod']);
    V.integer(value.input.byteCount, 1, 16384); V.integer(value.input.inputBytes, 0, 16384); V.validateCommand(value.input.command);
    bools(value.input, ['inputFinished', 'inputClosed', 'inputAbsentAfterMethod']);
  }
  if (value.approval !== null) {
    V.exact(value.approval, ['livePhaseObserved', 'requested', 'completed', 'approvedResponsesDelivered', 'actualApprovedResponseDrops', 'issuerCommandsBefore', 'issuerCommandsAfter', 'issuerJobsAfter']);
    bools(value.approval, ['livePhaseObserved', 'requested', 'completed']);
    counts(value.approval, ['approvedResponsesDelivered', 'actualApprovedResponseDrops', 'issuerCommandsBefore']);
    for (const key of ['issuerCommandsAfter', 'issuerJobsAfter']) if (value.approval[key] !== null) V.integer(value.approval[key], 0, 33570816);
  }
  if (value.host !== null) {
    V.exact(value.host, ['desktopCommit', 'registered', 'liveReleasePhaseObserved', 'releaseRequested', 'releaseCompleted', 'gatewayStreamComplete', 'origin', 'backend']);
    V.commit(value.host.desktopCommit); bools(value.host, ['registered', 'liveReleasePhaseObserved', 'releaseRequested', 'releaseCompleted', 'gatewayStreamComplete']);
    if (value.host.origin !== null) {
      V.exact(value.host.origin, [...originBooleans, ...originCounts, 'requestBodySha256', 'responseBodySha256']);
      bools(value.host.origin, originBooleans); counts(value.host.origin, originCounts);
      for (const key of ['requestBodySha256', 'responseBodySha256']) if (value.host.origin[key] !== null) V.hash(value.host.origin[key]);
    }
    if (value.host.backend !== null) {
      const backend = value.host.backend;
      V.exact(backend, ['closing', 'activeOwners', 'admitted', 'settled', 'captures', 'clientEndWrites', 'proxyMode', 'negotiatedCapabilities']);
      V.boolean(backend.closing); counts(backend, ['activeOwners', 'admitted', 'settled', 'captures', 'clientEndWrites']);
      V.enumeration(backend.proxyMode, [null, 'http-origin-connect']);
      if (!Array.isArray(backend.negotiatedCapabilities) || backend.negotiatedCapabilities.length > 3 ||
          new Set(backend.negotiatedCapabilities).size !== backend.negotiatedCapabilities.length ||
          backend.negotiatedCapabilities.some(capability => !['tcp-http', 'tcp-https-connect', 'tcp-http-origin-connect'].includes(capability))) throw Error();
    }
  }
  if (value.resources !== null) {
    V.exact(value.resources, ['workerClosed', 'workerCommand', 'reverseRemovalExitCodes', 'ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayStreamComplete', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
    if (value.resources.workerClosed !== null) V.validateWorker(value.resources.workerClosed);
    if (value.resources.workerCommand !== null) V.validateCommand(value.resources.workerCommand);
    if (!Array.isArray(value.resources.reverseRemovalExitCodes) || value.resources.reverseRemovalExitCodes.length > 3) throw Error();
    value.resources.reverseRemovalExitCodes.forEach(code => V.integer(code, 0, 255));
    bools(value.resources, ['ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayStreamComplete', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
  }
  if (value.cleanup !== null) {
    V.exact(value.cleanup, ['forceStopCommand', 'uninstallCommand', 'uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
    for (const key of ['forceStopCommand', 'uninstallCommand']) if (value.cleanup[key] !== null) V.validateCommand(value.cleanup[key]);
    bools(value.cleanup, ['uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
  }
}
export function createCaptureFactoryReport(value) {
  try { validateReport(value); return V.copyFreeze(value); } catch { fail('invalid_runtime_report'); }
}
export function decodeCaptureFactoryReport(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > enrollmentRuntimeLimits.runtime) fail('runtime_report_limit');
  let value; try { value = parseEnrollmentJson(bytes); } catch { fail('invalid_runtime_report'); }
  return createCaptureFactoryReport(value);
}
export function verifyCaptureFactoryReport(value, { source, api, desktopCommit }) {
  const report = createCaptureFactoryReport(value); V.commit(source); V.commit(desktopCommit); V.enumeration(api, [26, 37]);
  if (report.source?.commit !== source || report.source.trackedDirty || report.api !== api || (report.host !== null && report.host.desktopCommit !== desktopCommit)) fail('runtime_source_mismatch');
  if (!V.clockPassed(report.clock)) fail('runtime_clock_failed');
  if (report.problems.length || report.invocation.state !== 'passed') fail('runtime_invocation_failed');
  const { input, approval, host, resources, cleanup } = report;
  if (!input || input.inputBytes !== input.byteCount || !input.inputFinished || !input.inputClosed || !input.inputAbsentAfterMethod || !V.commandPassed(input.command)) fail('runtime_input_failed');
  if (!approval || !approval.livePhaseObserved || !approval.requested || !approval.completed || approval.approvedResponsesDelivered < 1 || approval.actualApprovedResponseDrops !== 0 ||
      approval.issuerCommandsAfter === null || approval.issuerCommandsAfter <= approval.issuerCommandsBefore || approval.issuerJobsAfter !== 0) fail('runtime_approval_failed');
  if (!host) fail('runtime_capture_factory_host_failed');
  const origin = host.origin, backend = host.backend;
  if (!host.registered || !host.liveReleasePhaseObserved || !host.releaseRequested || !host.releaseCompleted || !host.gatewayStreamComplete ||
      !origin || !backend || !originBooleans.every(key => origin[key]) || origin.connections !== 1 || origin.requests !== 1 ||
      origin.requestBodyBytes !== captureFactoryPayload.requestBodyBytes || origin.requestBodySha256 !== captureFactoryPayload.requestBodySha256 ||
      origin.responseBodyBytesWritten !== captureFactoryPayload.responseBodyBytes || origin.responseBodySha256 !== captureFactoryPayload.responseBodySha256 ||
      backend.activeOwners !== 0 || backend.admitted !== 1 || backend.settled !== 1 || backend.captures !== 1 || backend.clientEndWrites !== 1 ||
      backend.proxyMode !== 'http-origin-connect' || backend.negotiatedCapabilities.length !== 1 || backend.negotiatedCapabilities[0] !== 'tcp-http-origin-connect') fail('runtime_capture_factory_host_failed');
  if (!resources || !V.workerPassed(resources.workerClosed) || !V.commandPassed(resources.workerCommand) || resources.reverseRemovalExitCodes.length !== 3 ||
      resources.reverseRemovalExitCodes.some(code => code !== 0) || !['ownedReversesAbsent', 'privateDirectoryRemoved', 'gatewayStreamComplete', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => resources[key])) fail('runtime_cleanup_failed');
  if (!cleanup || !V.commandPassed(cleanup.forceStopCommand) || !V.commandPassed(cleanup.uninstallCommand) ||
      !['uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => cleanup[key])) fail('runtime_cleanup_failed');
  return Object.freeze({ methods: 1, actualStarted: 1, actualCompleted: 1, source, api, desktopCommit });
}
const escape = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[character]);
const render = text => { if (Buffer.byteLength(text) > enrollmentRuntimeLimits.rendered) fail('rendered_report_limit'); return text; };
export function captureFactoryRuntimeXml(value) {
  const report = createCaptureFactoryReport(value), item = report.invocation;
  const detail = item.problems.join(', ') + (item.failure ? `\n${item.failure.phase}/${item.failure.type}/cleanup=${item.failure.cleanup}` : '') +
    item.frames.map(frame => `\nat ${frame.className}.${frame.method}(${frame.file}:${frame.line})`).join('');
  const result = item.state === 'passed' ? '' : item.state === 'failed' ? `<failure message="Capture factory assertion failed">${escape(detail)}</failure>` : `<error message="Capture factory method did not complete">${escape(detail)}</error>`;
  return render(`<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="${captureFactoryClass}" tests="1" failures="${item.state === 'failed' ? 1 : 0}" errors="${['passed', 'failed'].includes(item.state) ? 0 : 1}" skipped="0">\n` +
    `<testcase classname="${captureFactoryClass}" name="${captureFactoryMethod}" time="0">${result}</testcase>\n<system-out>${escape(report.problems.join(', ') || 'Method observations only; exact host/runtime/emulator cleanup JSON are required.')}</system-out>\n</testsuite>\n`);
}
export function captureFactoryRuntimeHtml(value) {
  return render('<!doctype html><html lang="en"><meta charset="utf-8"><title>Capture factory research results</title><body><h1>C2 method and host observations</h1><pre>' +
    escape(JSON.stringify(createCaptureFactoryReport(value), null, 2)) + '</pre></body></html>\n');
}
