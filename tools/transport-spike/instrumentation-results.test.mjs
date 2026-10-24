import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { expectedTests } from './android-peer.mjs';
import { releaseOwnedReversePorts, reserveFixtureReversePorts } from './reverse-mappings.mjs';
import { MAX_ADB_DIAGNOSTIC_BYTES, MAX_ADB_SERVER_LOG_BYTES, MAX_INSTRUMENTATION_BYTES, adbPublicVersion, adbStderrCategories, commandDiagnostic, parseInstrumentation, readAdbServerLog, researchClass, resultHtml, resultXml, safeStack, snapshotAdbServerLog } from './instrumentation-results.mjs';

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

function withPrivateLog(initial, action) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-server-log-test-'));
  const file = path.join(directory, 'server.log');
  fs.writeFileSync(file, initial, { mode: 0o600 });
  try { return action(file, directory); }
  finally {
    assert.equal(path.dirname(fs.realpathSync(directory)), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('freekit-server-log-test-'));
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
test('server-log baseline excludes stale markers and returns no paths or content', () => {
  withPrivateLog('adb.cpp:123 adb server killed by remote request DO_NOT_RETAIN\n', file => {
    const baseline = snapshotAdbServerLog(file);
    assert.deepEqual(baseline, { status: 'ready' });
    fs.appendFileSync(file, 'main.cpp:45 ordinary current entry DO_NOT_RETAIN\n');
    const result = readAdbServerLog(baseline);
    assert.equal(result.status, 'read');
    assert.equal(result.markers, 'none_observed');
    assert.equal(result.sourceLocations, 'main.cpp:45');
    assert.doesNotMatch(JSON.stringify({ baseline, result }), /DO_NOT_RETAIN|server\.log|freekit-server-log-test/);
    const report = parseInstrumentation(success);
    report.diagnostics = result;
    assert.doesNotMatch(resultXml(report) + resultHtml(report), /DO_NOT_RETAIN|server\.log|freekit-server-log-test/);
  });
});
test('verified callchain failure is distinct from positive callchain and remote-request markers', () => {
  withPrivateLog('', file => {
    const failed = snapshotAdbServerLog(file);
    fs.appendFileSync(file, 'adb.cpp:500 failed to get kill-server process callchain DO_NOT_RETAIN\n');
    assert.equal(readAdbServerLog(failed).markers, 'adb_callchain_capture_failed_marker');
    const positive = snapshotAdbServerLog(file);
    fs.appendFileSync(file, 'adb.cpp:501 kill-server process callchain DO_NOT_RETAIN --private-argument\n' +
      'adb.cpp:502 adb server killed by remote request DO_NOT_RETAIN\n' +
      'adb.cpp:525 handle_packet disallowed connect to tcp:43123 from emulator-5554 DO_NOT_RETAIN\n');
    const result = readAdbServerLog(positive);
    assert.equal(result.markers, 'adb_callchain_positive_marker, adb_remote_kill_request_marker, adb_reverse_connect_rejection_marker');
    assert.doesNotMatch(JSON.stringify(result), /DO_NOT_RETAIN|private-argument|43123|emulator-5554/);
  });
});
test('server-log rotation and truncation fail closed without classifying replacement bytes', () => {
  withPrivateLog('baseline original content long enough\n', file => {
    const truncated = snapshotAdbServerLog(file);
    fs.truncateSync(file, 0);
    assert.equal(readAdbServerLog(truncated).status, 'truncated');
    fs.appendFileSync(file, 'original\n');
    const rotated = snapshotAdbServerLog(file);
    fs.renameSync(file, file + '.old');
    fs.writeFileSync(file, 'kill-server process callchain\n', { mode: 0o600 });
    const result = readAdbServerLog(rotated);
    assert.equal(result.status, 'rotated_or_replaced');
    assert.equal(result.markers, 'none_observed');
    assert.equal(result.bytesRead, 0);
  });
});
test('server-log reads cap newly appended bytes and exclude markers beyond the cap', () => {
  withPrivateLog('', file => {
    const baseline = snapshotAdbServerLog(file);
    fs.appendFileSync(file, 'x'.repeat(MAX_ADB_SERVER_LOG_BYTES) + '\nkill-server process callchain DO_NOT_RETAIN\n');
    const result = readAdbServerLog(baseline);
    assert.equal(result.bytesRead, MAX_ADB_SERVER_LOG_BYTES);
    assert.equal(result.byteLimit, 'reached');
    assert.equal(result.partialLine, 'omitted');
    assert.equal(result.markers, 'none_observed');
  });
});
test('partial baseline and final lines cannot create a positive marker from a split failure', () => {
  withPrivateLog('failed to get ', file => {
    const baseline = snapshotAdbServerLog(file);
    fs.appendFileSync(file, 'kill-server process callchain DO_NOT_RETAIN\nmain.cpp:42 ordinary entry\nkill-server process callchain');
    const result = readAdbServerLog(baseline);
    assert.equal(result.markers, 'none_observed');
    assert.equal(result.partialLine, 'omitted');
    assert.equal(result.sourceLocations, 'main.cpp:42');
  });
});
test('only allowlisted public source locations survive server-log classification', () => {
  withPrivateLog('', file => {
    const baseline = snapshotAdbServerLog(file);
    fs.appendFileSync(file, '/private/DO_NOT_RETAIN/unknown.cpp:123 private.cpp:8 caller /private/DO_NOT_RETAIN/sockets.cpp:77\n');
    const result = readAdbServerLog(baseline);
    assert.equal(result.sourceLocations, 'sockets.cpp:77');
    assert.doesNotMatch(JSON.stringify(result), /DO_NOT_RETAIN|unknown\.cpp|private\.cpp|caller/);
  });
});
test('server-log diagnostics have no shared-default fallback and baselines are single-use', () => {
  assert.equal(snapshotAdbServerLog().status, 'not_configured');
  assert.equal(snapshotAdbServerLog('relative/server.log').status, 'invalid_explicit_path');
  assert.equal(readAdbServerLog({ status: 'DO_NOT_RETAIN' }).status, 'invalid_baseline');
  withPrivateLog('', (file, directory) => {
    assert.equal(snapshotAdbServerLog(directory).status, 'not_regular_file');
    assert.equal(snapshotAdbServerLog(path.join(directory, 'absent.log')).status, 'unavailable');
    const baseline = snapshotAdbServerLog(file);
    assert.equal(readAdbServerLog(baseline).status, 'no_new_bytes');
    fs.appendFileSync(file, 'kill-server process callchain\n');
    assert.equal(readAdbServerLog(baseline).status, 'invalid_or_consumed_baseline');
    if (process.platform !== 'win32') {
      fs.chmodSync(file, 0o644);
      assert.equal(snapshotAdbServerLog(file).status, 'not_private_file');
      fs.chmodSync(file, 0o600);
      fs.symlinkSync(file, file + '.link');
      assert.equal(snapshotAdbServerLog(file + '.link').status, 'not_regular_file');
    }
  });
});

function mappingBackend({ response = () => '', initial = [], failReserve, failRemove } = {}) {
  const state = new Map(initial);
  const commands = [];
  const adb = args => {
    commands.push([...args]);
    assert.equal(args[0], 'reverse');
    if (args[1] === '--no-rebind') {
      assert.equal(args.length, 4);
      const device = args[2];
      const host = args[3];
      assert.match(device, /^tcp:[1-9][0-9]*$/);
      assert.match(host, /^tcp:[1-9][0-9]*$/);
      if (state.has(device)) throw Error('existing_mapping_collision');
      if (device === failReserve) throw Error('registration_command_failed');
      state.set(device, host);
      return response(device.slice(4), commands.length);
    }
    assert.equal(args[1], '--remove');
    assert.equal(args.length, 3);
    if (args[2] === failRemove) throw Error('removal_command_failed');
    assert.ok(state.delete(args[2]), 'Cleanup attempted an unowned or missing mapping');
    return '';
  };
  return { adb, state, commands };
}
const fixturePorts = { enrollmentPort: 50111, webSocketPort: 50112 };
test('explicit distinct ports register and release with both documented successful responses', () => {
  for (const response of [() => '', port => `\r\n${port}\n`]) {
    const backend = mappingBackend({ response });
    const owned = [];
    const selected = reserveFixtureReversePorts(backend.adb, fixturePorts, owned);
    assert.deepEqual(selected, { enrollmentPort: '50111', webSocketPort: '50112' });
    assert.deepEqual([...backend.state], [['tcp:50111', 'tcp:50111'], ['tcp:50112', 'tcp:50112']]);
    assert.equal(owned.length, 2);
    assert.deepEqual(releaseOwnedReversePorts(backend.adb, owned), []);
    assert.equal(backend.state.size, 0);
    assert.equal(owned.length, 0);
  }
});
test('an initial collision preserves the existing mapping and records no ownership', () => {
  const backend = mappingBackend({ initial: [['tcp:50111', 'tcp:60200']] });
  const owned = [];
  assert.throws(() => reserveFixtureReversePorts(backend.adb, fixturePorts, owned), /existing_mapping_collision/);
  assert.equal(owned.length, 0);
  assert.deepEqual(releaseOwnedReversePorts(backend.adb, owned), []);
  assert.deepEqual([...backend.state], [['tcp:50111', 'tcp:60200']]);
  assert.equal(backend.commands.length, 1);
});
test('a second-port collision releases only the first successful reservation', () => {
  const backend = mappingBackend({ initial: [['tcp:50112', 'tcp:60200']] });
  const owned = [];
  assert.throws(() => reserveFixtureReversePorts(backend.adb, fixturePorts, owned), /existing_mapping_collision/);
  assert.deepEqual(owned, [{ devicePort: '50111', hostPort: '50111' }]);
  assert.equal(backend.state.get('tcp:50112'), 'tcp:60200');
  assert.deepEqual(releaseOwnedReversePorts(backend.adb, owned), []);
  assert.deepEqual([...backend.state], [['tcp:50112', 'tcp:60200']]);
});
test('command failure never records the failed port and preserves unrelated mappings', () => {
  const backend = mappingBackend({ initial: [['tcp:50113', 'tcp:60200']], failReserve: 'tcp:50112' });
  const owned = [];
  assert.throws(() => reserveFixtureReversePorts(backend.adb, fixturePorts, owned), /registration_command_failed/);
  assert.equal(owned.length, 1);
  assert.equal(backend.state.has('tcp:50112'), false);
  assert.deepEqual(releaseOwnedReversePorts(backend.adb, owned), []);
  assert.deepEqual([...backend.state], [['tcp:50113', 'tcp:60200']]);
});
test('unexpected output after command success still leaves every successful port cleanable', () => {
  for (const failureAt of [1, 2]) for (const unexpected of ['unexpected_response', '65535']) {
    const backend = mappingBackend({ initial: [['tcp:65535', 'tcp:60200']], response: (_port, command) => command === failureAt ? unexpected : '' });
    const owned = [];
    assert.throws(() => reserveFixtureReversePorts(backend.adb, fixturePorts, owned), /unexpected_reverse_registration_response/);
    assert.equal(owned.length, failureAt);
    assert.equal(backend.state.size, failureAt + 1);
    assert.deepEqual(releaseOwnedReversePorts(backend.adb, owned), []);
    assert.deepEqual([...backend.state], [['tcp:65535', 'tcp:60200']]);
  }
});
test('invalid or repeated fixture ports fail before any reverse command runs', () => {
  for (const ports of [{ enrollmentPort: 0, webSocketPort: 50112 }, { enrollmentPort: 50111, webSocketPort: 50111 },
    { enrollmentPort: '50111', webSocketPort: 50112 }, { enrollmentPort: 50111, webSocketPort: 65536 }]) {
    const backend = mappingBackend();
    const owned = [];
    assert.throws(() => reserveFixtureReversePorts(backend.adb, ports, owned), /invalid_distinct_fixture_ports/);
    assert.equal(backend.commands.length, 0);
    assert.equal(backend.state.size, 0);
    assert.equal(owned.length, 0);
  }
});
test('cleanup attempts all owned ports, reports failures, and never removes unrelated registrations', () => {
  const backend = mappingBackend({ initial: [['tcp:50113', 'tcp:60200']], failRemove: 'tcp:50112' });
  const owned = [];
  reserveFixtureReversePorts(backend.adb, fixturePorts, owned);
  assert.deepEqual(releaseOwnedReversePorts(backend.adb, owned), ['owned_reverse_mapping_cleanup_failed']);
  assert.deepEqual([...backend.state], [['tcp:50113', 'tcp:60200'], ['tcp:50112', 'tcp:50112']]);
  const count = backend.commands.length;
  assert.deepEqual(releaseOwnedReversePorts(backend.adb, owned), []);
  assert.equal(backend.commands.length, count);
});
