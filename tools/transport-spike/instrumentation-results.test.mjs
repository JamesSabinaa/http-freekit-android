import assert from 'node:assert/strict';
import test from 'node:test';
import { expectedTests } from './android-peer.mjs';
import { MAX_ADB_DIAGNOSTIC_BYTES, MAX_INSTRUMENTATION_BYTES, adbPublicVersion, adbStderrCategories, commandDiagnostic, parseInstrumentation, researchClass, resultHtml, resultXml, safeStack } from './instrumentation-results.mjs';

const bundle = (name, code, extra = '') => `INSTRUMENTATION_STATUS: class=${researchClass}\nINSTRUMENTATION_STATUS: test=${name}\nINSTRUMENTATION_STATUS: numtests=4\n${extra}INSTRUMENTATION_STATUS_CODE: ${code}\n`;
const pair = name => bundle(name, 1) + bundle(name, 0);
const terminal = 'INSTRUMENTATION_RESULT: stream=\nOK (4 tests)\nINSTRUMENTATION_CODE: -1\n';
const success = expectedTests.map(pair).join('') + terminal;

test('requires four exact paired results and the final instrumentation success', () => {
  const result = parseInstrumentation(success);
  assert.equal(result.ok, true);
  assert.equal(result.started, 4);
  assert.equal(result.completed, 4);
  assert.match(resultXml(result), /tests="4" failures="0" errors="0" skipped="0"/);
});
test('preserves safe multiline failure types and research call sites while omitting messages', () => {
  const output = bundle(expectedTests[0], 1) + bundle(expectedTests[0], -2,
    'INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: TOPSECRET_RAW_BODY\n' +
    '\tat com.httpfreekit.interop.AndroidNodeInteropTest.nonexportableIdentityEnrollsAndEchoes64KiB(AndroidNodeInteropTest.kt:85)\n' +
    'Caused by: javax.net.ssl.SSLHandshakeException: TOPSECRET_RAW_BODY\n') + expectedTests.slice(1).map(pair).join('') + terminal;
  const result = parseInstrumentation(output);
  assert.equal(result.ok, false);
  assert.equal(result.completed, 4);
  const xml = resultXml(result);
  assert.match(xml, /javax.net.ssl.SSLHandshakeException/);
  assert.match(xml, /AndroidNodeInteropTest.kt:85/);
  assert.doesNotMatch(xml + resultHtml(result), /TOPSECRET_RAW_BODY/);
  assert.match(xml, /failures="1" errors="0"/);
});
test('a crash after one start reports one incomplete start and three unexecuted cases', () => {
  const result = parseInstrumentation(bundle(expectedTests[0], 1) + 'INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: 0\n');
  assert.equal(result.ok, false);
  assert.equal(result.started, 1);
  assert.equal(result.completed, 0);
  assert.ok(result.problems.includes('instrumentation_process_crashed'));
  assert.match(resultXml(result), /failures="0" errors="4"/);
  assert.equal((resultXml(result).match(/<testcase /g) ?? []).length, 4);
  assert.equal(result.cases.filter(value => value.state === 'not_started').length, 3);
});
test('empty failed status remains a failure without inventing a cause', () => {
  const result = parseInstrumentation(bundle(expectedTests[0], 1) + bundle(expectedTests[0], -2) + terminal);
  assert.equal(result.ok, false);
  assert.equal(result.started, 1);
  assert.equal(result.completed, 1);
  assert.match(resultXml(result), /failures="1" errors="3"/);
  assert.match(resultXml(result), /No permitted exception type or call site/);
});
test('missing terminal result and a crash after four passes fail the overall run', () => {
  for (const suffix of ['', 'INSTRUMENTATION_CODE: 0\n', 'INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: -1\n']) {
    const result = parseInstrumentation(expectedTests.map(pair).join('') + suffix);
    assert.equal(result.ok, false);
    assert.match(resultXml(result), /failures="0" errors="1"/);
    assert.equal(result.completed, 4);
  }
});
test('duplicates, unexpected identities and end without start cannot pass', () => {
  for (const output of [pair(expectedTests[0]) + success, success.replace(researchClass, 'com.other.Test'), bundle(expectedTests[0], 0) + success,
    success.replace(expectedTests[0], 'unrecognizedTest')]) assert.equal(parseInstrumentation(output).ok, false);
});
test('ignored tests and assumption failures are rejected', () => {
  for (const code of [-3, -4]) {
    const result = parseInstrumentation(bundle(expectedTests[0], 1) + bundle(expectedTests[0], code) + expectedTests.slice(1).map(pair).join('') + terminal);
    assert.equal(result.ok, false);
    assert.ok(result.problems.includes('test_skip_or_assumption_failure'));
    assert.match(resultXml(result), /failures="1"/);
  }
});
test('nonzero adb exit, capture limits and task timeouts reject apparently successful text', () => {
  assert.equal(parseInstrumentation(success, { exitCode: 1 }).ok, false);
  assert.equal(parseInstrumentation(success, { transportError: 'owned_child_timeout' }).ok, false);
  const tooLarge = parseInstrumentation('x'.repeat(MAX_INSTRUMENTATION_BYTES + 1));
  assert.ok(tooLarge.problems.includes('instrumentation_output_limit'));
  assert.equal(tooLarge.started, 0);
});
test('terminal duplication, wrong count, late status and incomplete bundle are rejected', () => {
  for (const output of [success + 'INSTRUMENTATION_CODE: -1\n', success.replace('numtests=4', 'numtests=3'),
    success + bundle(expectedTests[0], 1), success + 'INSTRUMENTATION_STATUS: stack=java.lang.Error\n',
    success.replace('numtests=4', 'Error=synthetic_failure\nINSTRUMENTATION_STATUS: numtests=4')]) assert.equal(parseInstrumentation(output).ok, false);
});
test('diagnostic sanitization ignores arbitrary messages, paths and payload lines', () => {
  const safe = safeStack('TOPSECRET_RAW_BODY\n/private/key.pem\njava.lang.RuntimeException: TOPSECRET_RAW_BODY\n\tat com.httpfreekit.interop.AndroidNodeInteropTest.wrongPinIsRejected(AndroidNodeInteropTest.kt:12)\n');
  assert.doesNotMatch(safe, /TOPSECRET|private\/key/);
  assert.match(safe, /java.lang.RuntimeException/);
});
test('known ADB errors map to fixed categories without retaining serials or messages', () => {
  const samples = [
    ['adb: error: closed\n', 'adb_channel_closed'],
    ["error: device 'emulator-5554' not found\n", 'adb_device_not_found'],
    ['error: device offline\n', 'adb_device_offline'],
    ['error: device unauthorized\n', 'adb_device_unauthorized'],
    ["protocol fault (couldn't read status): Connection reset by peer\n", 'adb_protocol_fault'],
    ['cannot connect to daemon: Connection refused\n', 'adb_daemon_unreachable'],
    ["adb server version (41) doesn't match this client (40); killing...\n", 'adb_version_mismatch'],
    ["adb: error: listener 'tcp:49123' not found\n", 'adb_reverse_listener_missing'],
  ];
  for (const [message, category] of samples) {
    const output = adbStderrCategories(message + 'DO_NOT_RETAIN\n');
    assert.ok(output.includes(category));
    assert.doesNotMatch(JSON.stringify(output), /emulator-5554|49123|DO_NOT_RETAIN/);
  }
});
test('ADB stderr classification bounds inspected bytes and handles unknown or empty text', () => {
  assert.deepEqual(adbStderrCategories(''), ['adb_stderr_empty']);
  assert.deepEqual(adbStderrCategories('DO_NOT_RETAIN'), ['adb_stderr_unclassified']);
  const excess = Buffer.concat([Buffer.alloc(MAX_ADB_DIAGNOSTIC_BYTES, 120), Buffer.from('\nerror: closed\nDO_NOT_RETAIN')]);
  assert.deepEqual(adbStderrCategories(excess), ['adb_stderr_diagnostic_limit']);
  assert.ok(adbStderrCategories('error: closed\n' + 'x'.repeat(MAX_ADB_DIAGNOSTIC_BYTES)).includes('adb_channel_closed'));
});
test('exact child exit codes and known signals are preserved while invalid values are rejected', () => {
  assert.equal(commandDiagnostic({ code: 139 }).exitCode, 139);
  assert.equal(commandDiagnostic({ code: 0xc0000005 }).exitCode, 0xc0000005);
  assert.equal(commandDiagnostic({ code: null, signal: 'SIGSEGV' }).signal, 'SIGSEGV');
  assert.equal(commandDiagnostic({ code: null, signal: 'SIGKILL' }).exitCode, 'none');
  assert.equal(commandDiagnostic({ signal: 'DO_NOT_RETAIN' }).signal, 'unrecognized_signal');
  assert.equal(commandDiagnostic({ code: 'DO_NOT_RETAIN' }).exitCode, 'none');
  assert.equal(commandDiagnostic({ spawnError: 'ENOENT' }).spawnError, 'ENOENT');
  assert.equal(parseInstrumentation(success, { exitCode: 0, signal: 'SIGTERM' }).ok, false);
});
test('public ADB version parsing excludes installed paths and arbitrary surrounding text', () => {
  const version = adbPublicVersion('Android Debug Bridge version 1.0.41\nVersion 37.0.1-15733141\nInstalled as /private/DO_NOT_RETAIN/adb\n');
  assert.deepEqual(version, { adbProtocolVersion: '1.0.41', adbBuildVersion: '37.0.1-15733141', adbDaemonVersion: 'unavailable' });
  const daemon = adbPublicVersion('version: "37.0.1"\nserver_path: "/private/DO_NOT_RETAIN/adb"\n');
  assert.equal(daemon.adbDaemonVersion, '37.0.1');
  assert.doesNotMatch(JSON.stringify(daemon), /private|DO_NOT_RETAIN/);
  assert.doesNotMatch(JSON.stringify(version), /private|DO_NOT_RETAIN/);
  assert.equal(adbPublicVersion('DO_NOT_RETAIN').adbBuildVersion, 'unavailable');
});
test('safe command diagnostics survive XML and HTML rendering without raw stderr', () => {
  const result = parseInstrumentation(success, { exitCode: null, signal: 'SIGABRT' });
  const diagnostic = commandDiagnostic({ code: null, signal: 'SIGABRT', stderr: 'error: closed\nDO_NOT_RETAIN' });
  result.diagnostics = { instrumentationExitCode: diagnostic.exitCode, instrumentationSignal: diagnostic.signal, instrumentationStderr: diagnostic.stderr };
  const xml = resultXml(result);
  assert.match(xml, /name="instrumentationSignal" value="SIGABRT"/);
  assert.match(xml, /adb_channel_closed/);
  assert.doesNotMatch(xml + resultHtml(result), /DO_NOT_RETAIN|error: closed/);
  assert.equal(result.ok, false);
});
