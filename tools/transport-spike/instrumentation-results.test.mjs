import assert from 'node:assert/strict';
import test from 'node:test';
import { expectedTests } from './android-peer.mjs';
import { MAX_INSTRUMENTATION_BYTES, parseInstrumentation, researchClass, resultHtml, resultXml, safeStack } from './instrumentation-results.mjs';

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
