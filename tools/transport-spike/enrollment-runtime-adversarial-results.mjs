import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';
import { EnrollmentRuntimeError, enrollmentRuntimeValidation as V, enrollmentRuntimeLimits, createEnrollmentSuiteInvocationParser } from './enrollment-runtime-results.mjs';
import { enrollmentAdversarialClass, enrollmentAdversarialCases } from './enrollment-runtime-adversarial-descriptor.mjs';
export * from './enrollment-runtime-adversarial-descriptor.mjs';
const COUNT = 33570816;
const fail = code => { throw new EnrollmentRuntimeError(code); };
const utc = value => V.integer(value, 946684800000, 4102444800000);
const optionalCount = value => { if (value !== null) V.integer(value, 0, COUNT); };
export function createEnrollmentAdversarialInvocationParser(method, { onPhase } = {}) {
  return createEnrollmentSuiteInvocationParser(method, { onPhase, suite: 'a22c' });
}
export function parseEnrollmentAdversarialInvocation(output, { method, ...commandResult }) {
  const parser = createEnrollmentAdversarialInvocationParser(method);
  try { parser.push(typeof output === 'string' ? Buffer.from(output) : output); }
  catch (error) { if (!(error instanceof EnrollmentRuntimeError)) throw error; }
  return parser.finish(commandResult);
}
const alternateFields = ['accepted', 'rejected', 'httpDispatches', 'secureConnections', 'activeSockets', 'pendingCallbacks', 'pendingTimers', 'workers',
  'childrenStarted', 'childrenClosed', 'childGroupsClosed', 'admissionClosed', 'listenerClosed'];
function validateRuntime(value) {
  V.exact(value, ['format', 'revision', 'source', 'api', 'clock', 'scenarios', 'cleanup', 'problems']);
  if (value.format !== 'http-freekit-a22c-runtime' || value.revision !== 1) throw Error();
  if (value.source !== null) { V.exact(value.source, ['commit', 'trackedDirty']); V.commit(value.source.commit); V.boolean(value.source.trackedDirty); }
  if (value.api !== null) V.enumeration(value.api, [26, 37]);
  if (value.clock !== null) V.validateClock(value.clock);
  V.validateProblems(value.problems);
  if (!Array.isArray(value.scenarios) || value.scenarios.length !== enrollmentAdversarialCases.length) throw Error();
  value.scenarios.forEach((item, index) => {
    const descriptor = enrollmentAdversarialCases[index];
    V.exact(item, ['method', 'scenario', 'invocation', 'input', 'approval', 'host', 'cleanup', 'problems']);
    if (item.method !== descriptor.method || item.scenario !== descriptor.scenario) throw Error();
    V.validateInvocation(item.invocation, item.method, 'a22c'); V.validateProblems(item.problems);
    if (item.input !== null) {
      V.exact(item.input, ['byteCount', 'inputBytes', 'inputFinished', 'inputClosed', 'command', 'inputAbsentAfterPrepare']);
      V.integer(item.input.byteCount, 1, 16384); V.integer(item.input.inputBytes, 0, 16384); V.validateCommand(item.input.command);
      for (const key of ['inputFinished', 'inputClosed', 'inputAbsentAfterPrepare']) V.boolean(item.input[key]);
    }
    if (item.approval !== null) {
      V.exact(item.approval, ['liveAwaitingPhaseObserved', 'requested', 'completed', 'approvedResponsesDelivered', 'actualApprovedResponseDrops', 'issuerCommandsAfterApproval', 'credentialExpiresUtcMillis']);
      for (const key of ['liveAwaitingPhaseObserved', 'requested', 'completed']) V.boolean(item.approval[key]);
      for (const key of ['approvedResponsesDelivered', 'actualApprovedResponseDrops']) V.integer(item.approval[key], 0, COUNT);
      optionalCount(item.approval.issuerCommandsAfterApproval); if (item.approval.credentialExpiresUtcMillis !== null) utc(item.approval.credentialExpiresUtcMillis);
    }
    if (item.host !== null) {
      V.exact(item.host, ['registered', 'result', 'resultAfterMethod', 'dispatchesBefore', 'dispatchesAfter', 'issuerCommandsBefore', 'issuerCommandsAfter', 'issuerJobsAfter', 'lateApproval', 'alternateTls']);
      V.boolean(item.host.registered); V.boolean(item.host.resultAfterMethod); V.enumeration(item.host.result, [null, 'pending', 'cancelled']);
      for (const key of ['dispatchesBefore', 'issuerCommandsBefore']) V.integer(item.host[key], 0, COUNT);
      for (const key of ['dispatchesAfter', 'issuerCommandsAfter', 'issuerJobsAfter']) optionalCount(item.host[key]);
      if (item.host.lateApproval !== null) {
        V.exact(item.host.lateApproval, ['livePhaseObserved', 'requested', 'completed', 'error', 'resultAfterAttempt']);
        for (const key of ['livePhaseObserved', 'requested', 'completed']) V.boolean(item.host.lateApproval[key]);
        V.enumeration(item.host.lateApproval.error, [null, 'invitation_used']); V.enumeration(item.host.lateApproval.resultAfterAttempt, [null, 'cancelled']);
      }
      if (item.host.alternateTls !== null) {
        V.exact(item.host.alternateTls, alternateFields);
        for (const key of alternateFields) ['admissionClosed', 'listenerClosed'].includes(key) ? V.boolean(item.host.alternateTls[key]) : V.integer(item.host.alternateTls[key], 0, COUNT);
      }
    }
    if (item.cleanup !== null) {
      V.exact(item.cleanup, ['workerClosed', 'workerCommand', 'reverseRemovalExitCodes', 'ownedReversesAbsent', 'privateDirectoryRemoved', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
      if (item.cleanup.workerClosed !== null) V.validateWorker(item.cleanup.workerClosed);
      if (item.cleanup.workerCommand !== null) V.validateCommand(item.cleanup.workerCommand);
      if (!Array.isArray(item.cleanup.reverseRemovalExitCodes) || item.cleanup.reverseRemovalExitCodes.length > 3) throw Error();
      for (const code of item.cleanup.reverseRemovalExitCodes) V.integer(code, 0, 255);
      for (const key of ['ownedReversesAbsent', 'privateDirectoryRemoved', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']) V.boolean(item.cleanup[key]);
    }
  });
  if (value.cleanup !== null) {
    V.exact(value.cleanup, ['forceStopCommand', 'uninstallCommand', 'uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']);
    for (const key of ['forceStopCommand', 'uninstallCommand']) if (value.cleanup[key] !== null) V.validateCommand(value.cleanup[key]);
    for (const key of ['uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']) V.boolean(value.cleanup[key]);
  }
}
export function createEnrollmentAdversarialReport(value) {
  try { validateRuntime(value); return V.copyFreeze(value); } catch { fail('invalid_runtime_report'); }
}
export function decodeEnrollmentAdversarialReport(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > enrollmentRuntimeLimits.runtime) fail('runtime_report_limit');
  let value; try { value = parseEnrollmentJson(bytes); } catch { fail('invalid_runtime_report'); }
  return createEnrollmentAdversarialReport(value);
}
export function verifyEnrollmentAdversarialReport(report, { source, api }) {
  createEnrollmentAdversarialReport(report); V.commit(source); V.enumeration(api, [26, 37]);
  if (report.source?.commit !== source || report.source.trackedDirty || report.api !== api) fail('runtime_source_mismatch');
  if (!V.clockPassed(report.clock)) fail('runtime_clock_failed');
  if (report.problems.length) fail('runtime_invocation_failed');
  for (const item of report.scenarios) {
    if (item.problems.length || item.invocation.state !== 'passed') fail('runtime_invocation_failed');
    const { input, host, approval, cleanup } = item;
    if (!input || input.inputBytes !== input.byteCount || !input.inputFinished || !input.inputClosed || !input.inputAbsentAfterPrepare || !V.commandPassed(input.command)) fail('runtime_input_failed');
    if (!host || !host.registered || !host.resultAfterMethod || host.result !== (['proof_misuse', 'wrong_tls'].includes(item.scenario) ? 'pending' : 'cancelled') ||
        host.dispatchesAfter === null || host.dispatchesAfter <= host.dispatchesBefore || host.issuerCommandsAfter === null || host.issuerJobsAfter !== 0) fail('runtime_adversarial_host_failed');
    if (item.scenario === 'published_cancel') {
      if (!approval || !approval.liveAwaitingPhaseObserved || !approval.requested || !approval.completed || approval.approvedResponsesDelivered < 1 || approval.actualApprovedResponseDrops !== 0 ||
          approval.issuerCommandsAfterApproval === null || approval.issuerCommandsAfterApproval <= host.issuerCommandsBefore || host.issuerCommandsAfter !== approval.issuerCommandsAfterApproval ||
          approval.credentialExpiresUtcMillis !== item.invocation.observation.credentialExpiresUtcMillis) fail('runtime_approval_failed');
    } else if (approval !== null || host.issuerCommandsAfter !== host.issuerCommandsBefore) fail('runtime_adversarial_host_failed');
    if (item.scenario === 'pending_cancel') {
      const late = host.lateApproval;
      if (!late || !late.livePhaseObserved || !late.requested || !late.completed || late.error !== 'invitation_used' || late.resultAfterAttempt !== 'cancelled') fail('runtime_adversarial_host_failed');
    } else if (host.lateApproval !== null) fail('runtime_adversarial_host_failed');
    if (item.scenario === 'wrong_tls') {
      const alternate = host.alternateTls;
      if (!alternate || alternate.accepted < 1 || alternate.rejected < 1 || alternate.secureConnections !== 0 || alternate.httpDispatches !== 0 ||
          alternate.childrenStarted !== alternate.childrenClosed || alternate.childrenStarted !== alternate.childGroupsClosed) fail('runtime_adversarial_tls_failed');
    } else if (host.alternateTls !== null) fail('runtime_adversarial_tls_failed');
    if (!cleanup || !V.workerPassed(cleanup.workerClosed) || !V.commandPassed(cleanup.workerCommand) || cleanup.reverseRemovalExitCodes.length !== (item.scenario === 'wrong_tls' ? 3 : 2) ||
        cleanup.reverseRemovalExitCodes.some(code => code !== 0) || !['ownedReversesAbsent', 'privateDirectoryRemoved', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => cleanup[key])) fail('runtime_cleanup_failed');
  }
  if (!report.cleanup || !['forceStopCommand', 'uninstallCommand'].every(key => V.commandPassed(report.cleanup[key])) ||
      !['uninstallConfirmed', 'ownedCommandsClosed', 'ownedCommandGroupsClosed'].every(key => report.cleanup[key])) fail('runtime_cleanup_failed');
  return Object.freeze({ methods: 4, actualStarted: 4, actualCompleted: 4, api, source });
}
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);
const rendered = text => { if (Buffer.byteLength(text) > enrollmentRuntimeLimits.rendered) fail('rendered_report_limit'); return text; };
export function enrollmentAdversarialRuntimeXml(value) {
  const report = createEnrollmentAdversarialReport(value), invocations = report.scenarios.map(item => item.invocation);
  const rows = invocations.map(item => {
    const detail = item.problems.join(', ') + (item.failureType ? '\n' + item.failureType : '') + item.frames.map(frame => `\nat ${frame.className}.${frame.method}(${frame.file}:${frame.line})`).join('');
    const result = item.state === 'passed' ? '' : item.state === 'failed' ? `<failure message="Adversarial enrollment assertion failed">${escape(detail)}</failure>` : `<error message="Adversarial enrollment method did not complete">${escape(detail)}</error>`;
    return `<testcase classname="${enrollmentAdversarialClass}" name="${item.method}" time="0">${result}</testcase>`;
  });
  return rendered(`<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="${enrollmentAdversarialClass}" tests="4" failures="${invocations.filter(item => item.state === 'failed').length}" errors="${invocations.filter(item => !['passed', 'failed'].includes(item.state)).length}" skipped="0">\n${rows.join('\n')}\n<system-out>${escape(report.problems.join(', ') || 'Method observations only; final runtime and emulator cleanup JSON are required.')}</system-out>\n</testsuite>\n`);
}
export function enrollmentAdversarialRuntimeHtml(value) {
  return rendered('<!doctype html><html lang="en"><meta charset="utf-8"><title>Adversarial enrollment research results</title><body><h1>A22c method and host observations</h1><pre>' +
    escape(JSON.stringify(createEnrollmentAdversarialReport(value), null, 2)) + '</pre></body></html>\n');
}
