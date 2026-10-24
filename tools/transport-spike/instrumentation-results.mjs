import { expectedTests } from './android-peer.mjs';

export const researchClass = 'com.httpfreekit.interop.AndroidNodeInteropTest';
export const MAX_INSTRUMENTATION_BYTES = 256 * 1024;

// Only exception types and platform/research call sites are retained. Messages can contain key data.
export function safeStack(value) {
  const selected = [];
  for (const line of String(value).split(/\r?\n/).slice(0, 256)) {
    const exception = /^(?:\s*(?:Caused by:|Suppressed:)\s*)?((?:java|javax|android|androidx|com\.android|com\.httpfreekit|org\.junit)\.[A-Za-z0-9_.$]+(?:Exception|Error|Failure))(?::|$)/.exec(line);
    const frame = /^\s*at ((?:com\.httpfreekit|com\.android|android|androidx\.test|java|javax|org\.junit)\.[A-Za-z0-9_.$<>]+\((?:[A-Za-z0-9_.$]+(?::[0-9]+)?|Native Method|Unknown Source)\))/.exec(line);
    if (exception) selected.push(exception[1]);
    else if (frame) selected.push(`at ${frame[1]}`);
    if (selected.length === 32) break;
  }
  return selected.join('\n') || 'No permitted exception type or call site was reported.';
}

export function parseInstrumentation(output, { exitCode = 0, transportError = null } = {}) {
  const cases = expectedTests.map(name => ({ name, state: 'not_started', detail: 'Case was not executed.' }));
  const problems = [];
  const problem = value => { if (problems.length < 16 && !problems.includes(value)) problems.push(value); };
  if (Buffer.byteLength(output, 'utf8') > MAX_INSTRUMENTATION_BYTES) { output = ''; problem('instrumentation_output_limit'); }
  if (exitCode !== 0) problem('adb_instrumentation_process_failed');
  if (transportError) problem(transportError);
  let pending = {};
  let lastKey;
  let active;
  let terminal;
  let terminalCount = 0;
  for (const line of output.split(/\r?\n/)) {
    let match;
    if ((match = /^INSTRUMENTATION_STATUS: ([A-Za-z0-9_]+)=(.*)$/.exec(line))) {
      if (terminalCount) problem('status_after_terminal_result');
      const [, key, value] = match;
      if (Object.hasOwn(pending, key)) problem('duplicate_status_field');
      pending[key] = value.slice(0, 8192);
      lastKey = key;
    } else if ((match = /^INSTRUMENTATION_STATUS_CODE: (-?[0-9]+)$/.exec(line))) {
      const code = Number(match[1]);
      if (pending.Error !== undefined || pending.error !== undefined) problem('instrumentation_status_error');
      const index = cases.findIndex(value => value.name === pending.test);
      if (pending.class !== researchClass || index === -1) problem('unexpected_test_identity');
      else {
        const current = cases[index];
        if (pending.numtests !== undefined && pending.numtests !== '4') problem('unexpected_declared_test_count');
        if (code === 1) {
          if (active !== undefined || current.state !== 'not_started') problem('duplicate_or_overlapping_test_start');
          else { current.state = 'running'; current.detail = 'Case started but did not complete.'; active = index; }
        } else {
          if (active !== index || current.state !== 'running') problem('test_end_without_matching_start');
          else {
            current.state = code === 0 ? 'passed' : 'failed';
            current.detail = code === 0 ? '' : `Instrumentation test status ${code}.\n${safeStack(pending.stack ?? '')}`;
            if (![0, -1, -2, -3, -4].includes(code)) problem('unknown_test_result_code');
            if (code === -3 || code === -4) problem('test_skip_or_assumption_failure');
            if (code === 0 && pending.stack) problem('failure_stack_with_success_status');
            active = undefined;
          }
        }
      }
      pending = {}; lastKey = undefined;
    } else if (/^INSTRUMENTATION_RESULT: (?:shortMsg|longMsg)=/.test(line)) {
      problem(/Process crashed/i.test(line) ? 'instrumentation_process_crashed' : 'instrumentation_failure_message');
      lastKey = undefined;
    } else if ((match = /^INSTRUMENTATION_CODE: (-?[0-9]+)$/.exec(line))) {
      terminal = Number(match[1]); terminalCount++;
      lastKey = undefined;
    } else if (/^INSTRUMENTATION_(?:FAILED|ABORTED):/.test(line)) {
      problem('instrumentation_failed_or_aborted'); lastKey = undefined;
    } else if (/^INSTRUMENTATION_RESULT:/.test(line)) lastKey = undefined;
    else if (lastKey === 'stack' && pending.stack.length < 8192) pending.stack += `\n${line}`;
  }
  if (Object.keys(pending).length) problem('unterminated_status_bundle');
  if (terminalCount !== 1 || terminal !== -1) problem('missing_or_failed_terminal_result');
  if (cases.some(value => value.state === 'not_started' || value.state === 'running')) problem('incomplete_test_execution');
  return { cases, problems, ok: problems.length === 0 && cases.every(value => value.state === 'passed'),
    started: cases.filter(value => value.state !== 'not_started').length,
    completed: cases.filter(value => ['passed', 'failed'].includes(value.state)).length };
}

const escape = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[character]);
export function resultXml(result) {
  const runFailure = result.problems.join(', ');
  let attachRunError = result.problems.length > 0 && result.cases.every(value => value.state === 'passed');
  const rows = result.cases.map(value => {
    let diagnostic = '';
    if (value.state === 'failed') diagnostic = `<failure message="Instrumentation assertion failed">${escape(value.detail)}</failure>`;
    else if (value.state !== 'passed') diagnostic = `<error message="Case did not complete">${escape(value.detail + '\n' + runFailure)}</error>`;
    else if (attachRunError) { diagnostic = `<error message="Instrumentation run failed after test completion">${escape(runFailure)}</error>`; attachRunError = false; }
    return `    <testcase name="${value.name}" classname="${researchClass}" time="0">${diagnostic}</testcase>`;
  });
  const failures = rows.filter(value => value.includes('<failure ')).length;
  const errors = rows.filter(value => value.includes('<error ')).length;
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="${researchClass}" tests="4" failures="${failures}" errors="${errors}" skipped="0">\n` +
    `  <properties><property name="actualStarted" value="${result.started}"/><property name="actualCompleted" value="${result.completed}"/></properties>\n` +
    rows.join('\n') + `\n  <system-out>${escape(runFailure || 'All four exact start/end pairs and the terminal success result were verified.')}</system-out>\n</testsuite>\n`;
}
export function resultHtml(result) {
  return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Research instrumentation results</title><body>' +
    `<h1>Android to Node research: ${result.ok ? 'passed' : 'failed'}</h1><p>Actual starts: ${result.started}; actual completions: ${result.completed}.</p>` +
    `<p>${escape(result.problems.join(', '))}</p><ul>` + result.cases.map(value => `<li>${value.name}: ${value.state}<pre>${escape(value.detail)}</pre></li>`).join('') + '</ul></body></html>';
}
