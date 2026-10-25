// A23 combines the two unmodified A22a observations with one independent CA method.
import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';
import { createEnrollmentRuntimeReport, verifyEnrollmentRuntime, enrollmentRuntimeValidation as V,
  enrollmentRuntimeLimits, enrollmentRuntimeClass, expectedEnrollmentMethods,
  createEnrollmentSuiteInvocationParser, EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { interceptionCaRuntimeClass, interceptionCaRuntimeMethod, interceptionCaRuntimeReportPaths } from './interception-ca-runtime-descriptor.mjs';

export { interceptionCaRuntimeReportPaths };
const fail = code => { throw new EnrollmentRuntimeError(code); };
export const interceptionCaMethods = Object.freeze([expectedEnrollmentMethods[0], interceptionCaRuntimeMethod, expectedEnrollmentMethods[1]]);
export const createInterceptionCaInvocationParser = (onPhase) => createEnrollmentSuiteInvocationParser(interceptionCaRuntimeMethod, { suite: 'a23', onPhase });

function projectA22(report) {
  const { ca, permission, ...base } = report;
  return { ...base, format: 'http-freekit-a22a-runtime', invocations: [report.invocations[0], report.invocations[2]] };
}
function validate(report) {
  try {
    V.exact(report, ['format', 'revision', 'source', 'api', 'clock', 'invocations', 'input', 'approval', 'stop', 'restart', 'cleanup', 'problems', 'ca', 'permission']);
    if (report.format !== 'http-freekit-a23-runtime' || report.revision !== 1 || !Array.isArray(report.invocations) || report.invocations.length !== 3) throw Error();
    createEnrollmentRuntimeReport(projectA22(report));
    V.validateInvocation(report.invocations[1], interceptionCaRuntimeMethod, 'a23');
    if (report.permission !== null) {
      V.exact(report.permission, ['mode', 'declared', 'grantCommand', 'readbackCommand', 'readbackGranted']);
      V.enumeration(report.permission.mode, ['owned_ci_grant', 'not_required']); V.boolean(report.permission.declared); V.boolean(report.permission.readbackGranted);
      if (report.permission.grantCommand !== null) V.validateCommand(report.permission.grantCommand);
      if (report.permission.readbackCommand !== null) V.validateCommand(report.permission.readbackCommand);
    }
    if (report.ca !== null) {
      V.exact(report.ca, ['beforeBytes', 'afterBytes', 'beforeMatchesApproval', 'afterMatchesApproval', 'beforeMatchesMetadata', 'afterMatchesMetadata', 'digestUnchanged', 'bytesUnchanged']);
      for (const field of ['beforeBytes', 'afterBytes']) V.integer(report.ca[field], 1, 4096);
      for (const field of ['beforeMatchesApproval', 'afterMatchesApproval', 'beforeMatchesMetadata', 'afterMatchesMetadata', 'digestUnchanged', 'bytesUnchanged']) V.boolean(report.ca[field]);
    }
    return V.copyFreeze(report);
  } catch { fail('invalid_runtime_report'); }
}
export const createInterceptionCaRuntimeReport = validate;
export function decodeInterceptionCaRuntimeReport(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > enrollmentRuntimeLimits.runtime) fail('runtime_report_limit');
  let report; try { report = parseEnrollmentJson(bytes); } catch { fail('invalid_runtime_report'); }
  return validate(report);
}
export function verifyInterceptionCaRuntimeReport(value, { source, api }) {
  const report = validate(value);
  verifyEnrollmentRuntime(projectA22(report), { source, api });
  if (report.invocations[1].state !== 'passed') fail('runtime_invocation_failed');
  const permission = report.permission;
  if (!permission || (api === 26 ? permission.mode !== 'not_required' || permission.declared || permission.grantCommand !== null || permission.readbackCommand !== null || permission.readbackGranted
    : permission.mode !== 'owned_ci_grant' || !permission.declared || !permission.readbackGranted || !V.commandPassed(permission.grantCommand) || !V.commandPassed(permission.readbackCommand))) fail('runtime_ca_permission_failed');
  const ca = report.ca;
  if (!ca || !ca.beforeMatchesApproval || !ca.afterMatchesApproval || !ca.beforeMatchesMetadata || !ca.afterMatchesMetadata ||
      !ca.digestUnchanged || !ca.bytesUnchanged || ca.beforeBytes !== ca.afterBytes || ca.beforeBytes !== report.invocations[1].observation.caBytes) fail('runtime_ca_evidence_failed');
  return Object.freeze({ methods: 3, actualStarted: 3, actualCompleted: 3, api, source });
}
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);
const rendered = text => { if (Buffer.byteLength(text) > enrollmentRuntimeLimits.rendered) fail('rendered_report_limit'); return text; };
export function interceptionCaRuntimeXml(value) {
  const report = validate(value), rows = report.invocations.map((item, index) => {
    const detail = item.problems.join(', ') + (item.failureType ? '\n' + item.failureType : '') + item.frames.map(frame => `\nat ${frame.className}.${frame.method}(${frame.file}:${frame.line})`).join('');
    const outcome = item.state === 'passed' ? '' : item.state === 'failed' ? `<failure message="Enrollment assertion failed">${escape(detail)}</failure>` : `<error message="Enrollment method did not complete">${escape(detail)}</error>`;
    return `<testcase classname="${index === 1 ? interceptionCaRuntimeClass : enrollmentRuntimeClass}" name="${item.method}" time="0">${outcome}</testcase>`;
  });
  return rendered(`<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="http-freekit-a23-runtime" tests="3" failures="${report.invocations.filter(item => item.state === 'failed').length}" errors="${report.invocations.filter(item => !['passed', 'failed'].includes(item.state)).length}" skipped="0">\n${rows.join('\n')}\n<system-out>${escape(report.problems.join(', ') || 'Method observations only; final runtime and emulator cleanup JSON are required.')}</system-out>\n</testsuite>\n`);
}
export function interceptionCaRuntimeHtml(value) {
  return rendered('<!doctype html><html lang="en"><meta charset="utf-8"><title>Interception CA research results</title><body><h1>A23 method and host observations</h1><pre>' + escape(JSON.stringify(validate(value), null, 2)) + '</pre></body></html>\n');
}
