// Independent seven-method gate. Never infer execution from a summary, count or generated XML.
import { MAX_INSTRUMENTATION_BYTES, safeStack } from './instrumentation-results.mjs';
import { measureFixtureClock } from './android-peer.mjs';

export const MAX_DRAFT_CLOCK_SKEW_MILLIS = 2000;
export const MAX_DRAFT_CLOCK_PROBE_MILLIS = 2000;
export function measureDraftStreamingClock(deviceEpochText, hostBeforeMillis, hostAfterMillis) {
  let measurement;
  try { measurement = measureFixtureClock(deviceEpochText, hostBeforeMillis, hostAfterMillis); }
  catch { throw Error('draft_clock_probe_invalid'); }
  return { ...measurement, draftClockStatus: measurement.fixtureClockRoundTripMillis > MAX_DRAFT_CLOCK_PROBE_MILLIS
    ? 'probe_budget_exceeded' : Math.abs(measurement.fixtureClockSkewMillis) > MAX_DRAFT_CLOCK_SKEW_MILLIS
      ? 'skew_exceeds_bound' : 'within_bound' };
}

export const draftStreamingClass = 'com.httpfreekit.interop.DraftStreamingInteropTest';
export const expectedDraftStreamingTests = Object.freeze([
  'authenticatedControlAndGatedStreamPreserveHalfClose',
  'boundedBackpressureResumesWithoutDroppingBytes',
  'cancelClosesAnObservedBlockedWriterAndJoinsResources',
  'expiryClosesAnObservedBlockedWriterAndJoinsResources',
  'wrongSessionAndDeviceBindingAreRejected',
  'malformedAndOversizedIngressFailBeforeForwarding',
  'prematureCloseCannotCompleteStream',
]);
const setupCodes = new Set([
  'selected_device_unavailable', 'research_apk_build_failed', 'research_apk_install_failed',
  'unexpected_research_apk_metadata', 'research_runner_not_registered', 'device_clock_probe_failed',
  'draft_clock_outside_bound', 'draft_clock_probe_invalid', 'invalid_public_fixture_input',
  'owned_child_timeout', 'owned_child_cleanup_failed', 'owned_child_spawn_failed', 'instrumentation_output_limit',
  'host_setup_failed', 'research_run_cancelled',
]);
export function draftSetupCode(value) { return setupCodes.has(value) ? value : 'host_setup_failed'; }

export function parseDraftStreamingInstrumentation(output, { exitCode = 0, signal = null, transportError = null } = {}) {
  const cases = expectedDraftStreamingTests.map(name => ({ name, state: 'not_started', detail: 'Case was not executed.' }));
  const problems = [];
  const problem = code => { if (problems.length < 24 && !problems.includes(code)) problems.push(code); };
  if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > MAX_INSTRUMENTATION_BYTES) {
    output = ''; problem('instrumentation_output_limit');
  }
  if (exitCode !== 0 || signal !== null) problem('adb_instrumentation_process_failed');
  if (transportError !== null) problem(draftSetupCode(transportError));
  let pending = Object.create(null), lastKey, active, terminalCount = 0, terminal;
  let started = 0, completed = 0;
  for (const line of output.split(/\r?\n/)) {
    let match;
    if ((match = /^INSTRUMENTATION_STATUS: ([A-Za-z0-9_]+)=(.*)$/.exec(line))) {
      if (terminalCount) problem('status_after_terminal_result');
      const [, key, value] = match;
      if (Object.hasOwn(pending, key)) problem('duplicate_status_field');
      if (Object.keys(pending).length >= 32 && !Object.hasOwn(pending, key)) {
        problem('status_field_limit'); lastKey = undefined; continue;
      }
      pending[key] = value.slice(0, 8192); lastKey = key;
    } else if ((match = /^INSTRUMENTATION_STATUS_CODE: (-?[0-9]+)$/.exec(line))) {
      if (terminalCount) problem('status_after_terminal_result');
      const status = Number(match[1]);
      const index = cases.findIndex(value => value.name === pending.test);
      if (pending.Error !== undefined || pending.error !== undefined) problem('instrumentation_status_error');
      if (pending.class !== draftStreamingClass || index < 0) problem('unexpected_test_identity');
      else {
        const current = cases[index];
        if (pending.numtests !== String(cases.length)) problem('unexpected_declared_test_count');
        if (status === 1) {
          if (pending.stack) problem('failure_stack_with_start_status');
          if (active !== undefined || current.state !== 'not_started') problem('duplicate_or_overlapping_test_start');
          else {
            current.state = 'running'; current.detail = 'Case started but did not complete.';
            active = { index, ordinal: ++started };
            if (pending.current !== undefined && pending.current !== String(active.ordinal)) problem('unexpected_case_ordinal');
          }
        } else if (active?.index !== index || current.state !== 'running') problem('test_end_without_matching_start');
        else {
          if (pending.current !== undefined && pending.current !== String(active.ordinal)) problem('unexpected_case_ordinal');
          current.state = status === 0 ? 'passed' : 'failed';
          current.detail = status === 0 ? '' : `Instrumentation status ${status}.\n${safeStack(pending.stack ?? '')}`;
          if (![0, -1, -2, -3, -4].includes(status)) problem('unknown_test_result_code');
          if (status === -3 || status === -4) problem('test_skip_or_assumption_failure');
          if (status === 0 && pending.stack) problem('failure_stack_with_success_status');
          completed++; active = undefined;
        }
      }
      pending = Object.create(null); lastKey = undefined;
    } else if (/^INSTRUMENTATION_RESULT: (?:shortMsg|longMsg)=/.test(line)) {
      problem('instrumentation_failure_message'); lastKey = undefined;
    } else if (/^INSTRUMENTATION_RESULT: stream=.*(?:FAILURES!!!|Process crashed)/i.test(line)) {
      problem('instrumentation_failure_message'); lastKey = undefined;
    } else if ((match = /^INSTRUMENTATION_CODE: (-?[0-9]+)$/.exec(line))) {
      terminal = Number(match[1]); terminalCount++; lastKey = undefined;
    } else if (/^INSTRUMENTATION_(?:FAILED|ABORTED):/.test(line)) {
      problem('instrumentation_failed_or_aborted'); lastKey = undefined;
    } else if (/^INSTRUMENTATION_RESULT:/.test(line)) lastKey = undefined;
    else if (lastKey === 'stack' && pending.stack.length < 8192) pending.stack += `\n${line}`;
  }
  if (Object.keys(pending).length) problem('unterminated_status_bundle');
  if (terminalCount !== 1 || terminal !== -1) problem('missing_or_failed_terminal_result');
  if (started !== cases.length || completed !== cases.length) problem('incomplete_test_execution');
  return { cases, problems, started, completed,
    ok: problems.length === 0 && cases.every(value => value.state === 'passed') };
}

const escape = value => String(value).replace(/[&<>"']/g, character =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[character]);

export function draftStreamingXml(result) {
  // Reports cannot silently narrow the fixed gate or invent extra cases.
  if (result.cases.length !== expectedDraftStreamingTests.length ||
      result.cases.some((value, index) => value.name !== expectedDraftStreamingTests[index])) throw Error('invalid_result_contract');
  const runFailure = result.problems.join(', ');
  let attach = result.problems.length > 0 && result.cases.every(value => value.state === 'passed');
  let failures = 0, errors = 0;
  const rows = result.cases.map(value => {
    let diagnostic = '';
    if (value.state === 'failed') { failures++; diagnostic = `<failure message="Research assertion failed">${escape(value.detail)}</failure>`; }
    else if (value.state !== 'passed') { errors++; diagnostic = `<error message="Case did not complete">${escape(runFailure)}</error>`; }
    else if (attach) { errors++; attach = false; diagnostic = `<error message="Run failed after test completion">${escape(runFailure)}</error>`; }
    return `  <testcase name="${value.name}" classname="${draftStreamingClass}" time="0">${diagnostic}</testcase>`;
  });
  const properties = Object.entries(result.diagnostics ?? {}).map(([key, value]) =>
    `    <property name="${escape(key)}" value="${escape(value)}"/>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="${draftStreamingClass}" tests="7" failures="${failures}" errors="${errors}" skipped="0">\n` +
    `  <properties><property name="actualStarted" value="${result.started}"/><property name="actualCompleted" value="${result.completed}"/>\n${properties}\n  </properties>\n` +
    rows.join('\n') + `\n  <system-out>${escape(runFailure || 'Seven actual start/end pairs and terminal success verified.')}</system-out>\n</testsuite>\n`;
}

export function draftStreamingHtml(result) {
  return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Draft streaming research</title><body>' +
    `<h1>Authenticated draft streaming: ${result.ok ? 'passed' : 'failed'}</h1>` +
    `<p>Actual starts: ${result.started}; completions: ${result.completed}.</p><p>${escape(result.problems.join(', '))}</p>` +
    `<pre>${escape(JSON.stringify(result.diagnostics ?? {}, null, 2))}</pre><ul>` +
    result.cases.map(value => `<li>${value.name}: ${value.state}<pre>${escape(value.detail)}</pre></li>`).join('') + '</ul></body></html>';
}
