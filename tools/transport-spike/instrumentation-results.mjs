import { expectedTests } from './android-peer.mjs';
import fs from 'node:fs';
import path from 'node:path';

export const researchClass = 'com.httpfreekit.interop.AndroidNodeInteropTest';
export const MAX_INSTRUMENTATION_BYTES = 256 * 1024;
export const MAX_ADB_DIAGNOSTIC_BYTES = 16 * 1024;
export const MAX_ADB_SERVER_LOG_BYTES = 64 * 1024;
const logBaselines = new WeakMap();
const sourceNames = new Set(['adb.cpp', 'main.cpp', 'adb_client.cpp', 'adb_listeners.cpp', 'adb_utils.cpp', 'sockets.cpp',
  'services.cpp', 'transport.cpp', 'transport_local.cpp', 'socket_spec.cpp', 'sysdeps_unix.cpp', 'fdevent.cpp', 'fdevent_epoll.cpp']);
const baselineStatuses = new Set(['not_configured', 'invalid_explicit_path', 'not_regular_file', 'not_private_file', 'not_owned_file',
  'file_size_unsupported', 'identity_changed', 'unavailable']);
const signalNames = new Set(['SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGILL', 'SIGTRAP', 'SIGABRT', 'SIGBUS', 'SIGFPE', 'SIGKILL', 'SIGSEGV', 'SIGPIPE', 'SIGALRM', 'SIGTERM']);

function logFileStatus(stat) {
  if (!stat.isFile()) return 'not_regular_file';
  if (process.platform !== 'win32' && (stat.mode & 0o077n) !== 0n) return 'not_private_file';
  if (typeof process.getuid === 'function' && stat.uid !== BigInt(process.getuid())) return 'not_owned_file';
  if (stat.size > BigInt(Number.MAX_SAFE_INTEGER)) return 'file_size_unsupported';
  return 'ready';
}
const sameFile = (first, second) => first.dev === second.dev && first.ino === second.ino;
const openLog = file => fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));

/** Opaque baseline: paths, file identities and old content are never included in reports. */
export function snapshotAdbServerLog(explicitPath) {
  let descriptor;
  try {
    if (!explicitPath) return Object.freeze({ status: 'not_configured' });
    if (typeof explicitPath !== 'string' || !path.isAbsolute(explicitPath) || explicitPath.length > 4096) return Object.freeze({ status: 'invalid_explicit_path' });
    const before = fs.lstatSync(explicitPath, { bigint: true });
    let status = logFileStatus(before);
    if (status !== 'ready') return Object.freeze({ status });
    descriptor = openLog(explicitPath);
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFile(before, stat)) return Object.freeze({ status: 'identity_changed' });
    status = logFileStatus(stat);
    if (status !== 'ready') return Object.freeze({ status });
    const offset = Number(stat.size);
    const last = Buffer.alloc(1);
    const boundary = offset === 0 || (fs.readSync(descriptor, last, 0, 1, offset - 1) === 1 && last[0] === 10);
    const baseline = Object.freeze({ status: 'ready' });
    logBaselines.set(baseline, { file: explicitPath, stat, offset, boundary });
    return baseline;
  } catch { return Object.freeze({ status: 'unavailable' }); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

export function readAdbServerLog(baseline) {
  const empty = status => ({ status, markers: 'none_observed', sourceLocations: 'none_observed', bytesRead: 0, byteLimit: 'within', partialLine: 'none' });
  const saved = logBaselines.get(baseline);
  if (!saved) return empty(baseline?.status === 'ready' ? 'invalid_or_consumed_baseline' : baselineStatuses.has(baseline?.status) ? baseline.status : 'invalid_baseline');
  // A baseline is single-use, including on failure, so later recovery commands cannot contaminate it.
  logBaselines.delete(baseline);
  let descriptor;
  try {
    const before = fs.lstatSync(saved.file, { bigint: true });
    if (!sameFile(saved.stat, before)) return empty('rotated_or_replaced');
    let status = logFileStatus(before);
    if (status !== 'ready') return empty(status);
    descriptor = openLog(saved.file);
    const current = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFile(saved.stat, current)) return empty('rotated_or_replaced');
    status = logFileStatus(current);
    if (status !== 'ready') return empty(status);
    if (current.size < BigInt(saved.offset)) return empty('truncated');
    const appended = Number(current.size) - saved.offset;
    if (appended === 0) return empty('no_new_bytes');
    const bytes = Buffer.alloc(Math.min(appended, MAX_ADB_SERVER_LOG_BYTES));
    const count = fs.readSync(descriptor, bytes, 0, bytes.length, saved.offset);
    if (count !== bytes.length) return empty('changed_during_read');
    if (!sameFile(saved.stat, fs.lstatSync(saved.file, { bigint: true })) || fs.fstatSync(descriptor, { bigint: true }).size < current.size) return empty('changed_during_read');
    let text = bytes.toString('utf8');
    let partial = false;
    if (!saved.boundary) { text = text.includes('\n') ? text.slice(text.indexOf('\n') + 1) : ''; partial = true; }
    if (!text.endsWith('\n')) { text = text.slice(0, text.lastIndexOf('\n') + 1); partial = true; }
    const markers = new Set();
    const sources = new Set();
    for (const line of text.split('\n')) {
      if (line.includes('failed to get kill-server process callchain')) markers.add('adb_callchain_capture_failed_marker');
      else if (line.includes('kill-server process callchain')) markers.add('adb_callchain_positive_marker');
      if (line.includes('adb server killed by remote request')) markers.add('adb_remote_kill_request_marker');
      if (line.includes('disallowed connect to')) markers.add('adb_reverse_connect_rejection_marker');
      for (const match of line.matchAll(/(?:^|[\s/\\])([A-Za-z0-9_]+\.cpp):([1-9][0-9]{0,6})(?=$|[\s:])/g)) {
        if (sourceNames.has(match[1]) && sources.size < 16) sources.add(`${match[1]}:${match[2]}`);
      }
    }
    return { status: 'read', markers: [...markers].join(', ') || 'none_observed', sourceLocations: [...sources].join(', ') || 'none_observed',
      bytesRead: count, byteLimit: appended > MAX_ADB_SERVER_LOG_BYTES ? 'reached' : 'within', partialLine: partial ? 'omitted' : 'none' };
  } catch { return empty('unavailable'); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

export function adbStderrCategories(value) {
  const text = Buffer.isBuffer(value) ? null : String(value ?? '');
  const length = text === null ? value.length : Buffer.byteLength(text);
  const bytes = text === null ? value : Buffer.from(text.slice(0, MAX_ADB_DIAGNOSTIC_BYTES));
  const bounded = bytes.subarray(0, MAX_ADB_DIAGNOSTIC_BYTES).toString('utf8');
  const categories = [];
  const patterns = [
    ['adb_channel_closed', /(?:^|\n)(?:adb: )?error: closed(?:\r?\n|$)/i],
    ['adb_device_not_found', /device ['"][^\r\n]{1,128}['"] not found|no devices\/emulators found/i],
    ['adb_device_offline', /device (?:is )?offline/i],
    ['adb_device_unauthorized', /device (?:is )?unauthorized/i],
    ['adb_protocol_fault', /protocol fault/i],
    ['adb_connection_reset', /connection reset by peer/i],
    ['adb_connection_refused', /connection refused/i],
    ['adb_broken_pipe', /broken pipe/i],
    ['adb_transport_closing', /transport (?:is )?closing/i],
    ['adb_daemon_unreachable', /cannot connect to daemon|failed to start daemon|cannot connect to (?:adb )?server/i],
    ['adb_daemon_starting', /daemon not running|daemon started successfully/i],
    ['adb_version_mismatch', /server version[^\r\n]{0,100}doesn.t match/i],
    ['adb_reverse_listener_missing', /listener ['"]tcp:[0-9]+['"] not found/i],
    ['adb_bind_failed', /cannot bind (?:listener|to)|address already in use/i],
    ['adb_response_read_failed', /failed to read (?:response|status)|couldn.t read status/i],
  ];
  for (const [category, pattern] of patterns) if (pattern.test(bounded)) categories.push(category);
  if (length > MAX_ADB_DIAGNOSTIC_BYTES) categories.push('adb_stderr_diagnostic_limit');
  if (!categories.length) categories.push(length ? 'adb_stderr_unclassified' : 'adb_stderr_empty');
  return categories;
}
export function commandDiagnostic({ code = null, signal = null, stderr = '', spawnError = null } = {}) {
  return {
    exitCode: Number.isInteger(code) && code >= 0 && code <= 0xffffffff ? code : 'none',
    signal: signal === null ? 'none' : signalNames.has(signal) ? signal : 'unrecognized_signal',
    stderr: adbStderrCategories(stderr).join(', '),
    spawnError: spawnError === null ? 'none' : ['ENOENT', 'EACCES', 'ETIMEDOUT', 'ENOBUFS'].includes(spawnError) ? spawnError : 'unclassified_spawn_error',
  };
}
export function adbPublicVersion(value) {
  const text = String(value).slice(0, 4096);
  return {
    adbProtocolVersion: /Android Debug Bridge version ([0-9.]{1,32})/.exec(text)?.[1] ?? 'unavailable',
    adbBuildVersion: /(?:^|\n)Version ([0-9.]{1,32}-[0-9]{1,32})/.exec(text)?.[1] ?? 'unavailable',
    adbDaemonVersion: /(?:^|\n)\s*version:\s*"([0-9.]{1,32})"/.exec(text)?.[1] ?? 'unavailable',
  };
}

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

export function parseInstrumentation(output, { exitCode = 0, signal = null, transportError = null } = {}) {
  const cases = expectedTests.map(name => ({ name, state: 'not_started', detail: 'Case was not executed.' }));
  const problems = [];
  const problem = value => { if (problems.length < 16 && !problems.includes(value)) problems.push(value); };
  if (Buffer.byteLength(output, 'utf8') > MAX_INSTRUMENTATION_BYTES) { output = ''; problem('instrumentation_output_limit'); }
  if (exitCode !== 0 || signal !== null) problem('adb_instrumentation_process_failed');
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
  const diagnostics = Object.entries(result.diagnostics ?? {}).map(([name, value]) => `<property name="${escape(name)}" value="${escape(value)}"/>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="${researchClass}" tests="4" failures="${failures}" errors="${errors}" skipped="0">\n` +
    `  <properties><property name="actualStarted" value="${result.started}"/><property name="actualCompleted" value="${result.completed}"/>${diagnostics}</properties>\n` +
    rows.join('\n') + `\n  <system-out>${escape(runFailure || 'All four exact start/end pairs and the terminal success result were verified.')}</system-out>\n</testsuite>\n`;
}
export function resultHtml(result) {
  return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Research instrumentation results</title><body>' +
    `<h1>Android to Node research: ${result.ok ? 'passed' : 'failed'}</h1><p>Actual starts: ${result.started}; actual completions: ${result.completed}.</p>` +
    `<p>${escape(result.problems.join(', '))}</p><pre>${escape(JSON.stringify(result.diagnostics ?? {}, null, 2))}</pre><ul>` + result.cases.map(value => `<li>${value.name}: ${value.state}<pre>${escape(value.detail)}</pre></li>`).join('') + '</ul></body></html>';
}
