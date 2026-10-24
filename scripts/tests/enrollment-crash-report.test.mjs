import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { EnrollmentCorpusError } from '../enrollment-corpus.mjs';
import { ENROLLMENT_CRASH_CASES, validateEnrollmentCrashReport, verifyEnrollmentCrashReport } from '../enrollment-crash-report.mjs';
import { temporary, write } from './enrollment-test-support.mjs';

const SHA = 'a'.repeat(40), options = { sourceCommit: SHA, platform: 'linux' };
const script = fileURLToPath(new URL('../verify-enrollment-crash-report.mjs', import.meta.url));
/** Synthetic gate test data, never evidence that an OS process was killed. */
function fixture() {
  return { format: 'http-freekit-enrollment-store-crash', revision: '1', node: 'v24.22.1', platform: 'linux', powerLossTested: false,
    source: { commit: SHA, trackedDirty: false }, cases: ENROLLMENT_CRASH_CASES.map(([operation, position, tuple]) => ({
      id: `${operation}-${position}`, operation, position, barrierObserved: true, ownerExcluded: true, readerExcluded: true,
      killRequested: true, childExitJoined: true, recovered: true, integrity: true,
      journalExistsBeforeKill: position === 'before', journalBytesBeforeKill: position === 'before' ? 4096 : 0,
      journalHeaderNonzero: position === 'before', tuple })) };
}
const rejected = (run, code) => assert.throws(run, e => e instanceof EnrollmentCorpusError && (!code || e.code === code));

test('exact eight ordered synthetic outcomes pass only their expected source/platform', () => {
  assert.equal(validateEnrollmentCrashReport(fixture(), options).cases, 8);
});
test('missing, extra, duplicate or reordered crash cases fail', () => {
  for (const mutate of [r => r.cases.pop(), r => r.cases.push(r.cases[0]), r => { r.cases[1] = r.cases[0]; }, r => r.cases.reverse()]) {
    const r = fixture(); mutate(r); rejected(() => validateEnrollmentCrashReport(r, options));
  }
});
test('each operation must retain its exact before/after durable tuple', () => {
  for (let i = 0; i < 8; i++) { const r = fixture(); r.cases[i].tuple = 'PRIVATE_CANARY'; rejected(() => validateEnrollmentCrashReport(r, options), 'invalid_crash_case'); }
});
test('no barrier, owner exclusion, actual kill/join or recovery flag can be missing', () => {
  for (const flag of ['barrierObserved', 'ownerExcluded', 'readerExcluded', 'killRequested', 'childExitJoined', 'recovered', 'integrity']) {
    const r = fixture(); r.cases[0][flag] = false; rejected(() => validateEnrollmentCrashReport(r, options), 'incomplete_crash_evidence');
  }
});
test('before-commit recovery requires actual nonempty nonzero-header journal facts', () => {
  for (const changes of [{ journalExistsBeforeKill: false, journalBytesBeforeKill: 0, journalHeaderNonzero: false },
    { journalBytesBeforeKill: 28 }, { journalHeaderNonzero: false }]) {
    const r = fixture(); Object.assign(r.cases[0], changes); rejected(() => validateEnrollmentCrashReport(r, options), 'missing_crash_recovery_journal');
  }
});
test('journal absence and header/length metadata must be consistent', () => {
  for (const changes of [{ journalExistsBeforeKill: false, journalBytesBeforeKill: 10 },
    { journalExistsBeforeKill: true, journalBytesBeforeKill: 0, journalHeaderNonzero: true }]) {
    const r = fixture(); Object.assign(r.cases[1], changes); rejected(() => validateEnrollmentCrashReport(r, options), 'invalid_crash_journal');
  }
});
test('journal metadata uses bounded integer/boolean types', () => {
  for (const value of [-1, 0.5, 33554433, '4096', true]) { const r = fixture(); r.cases[0].journalBytesBeforeKill = value; rejected(() => validateEnrollmentCrashReport(r, options), 'invalid_crash_journal'); }
  const r = fixture(); r.cases[0].journalHeaderNonzero = 1; rejected(() => validateEnrollmentCrashReport(r, options), 'invalid_crash_journal');
});
test('wrong source, dirty tracked input, Node version or platform cannot pass', () => {
  for (const mutate of [r => { r.source.commit = 'b'.repeat(40); }, r => { r.source.trackedDirty = true; },
    r => { r.source.trackedDirty = 0; }, r => { r.node = 'v25.0.0'; }, r => { r.platform = 'win32'; }]) {
    const r = fixture(); mutate(r); rejected(() => validateEnrollmentCrashReport(r, options));
  }
});
test('process crash evidence never claims a power-loss test', () => {
  const r = fixture(); r.powerLossTested = true; rejected(() => validateEnrollmentCrashReport(r, options), 'invalid_crash_header');
});
test('raw paths/material and unknown envelope/case fields are excluded', () => {
  for (const nested of [false, true]) { const r = fixture(); (nested ? r.cases[0] : r).raw = 'PRIVATE_CANARY'; rejected(() => validateEnrollmentCrashReport(r, options), 'invalid_crash_shape'); }
});
test('report reads are bounded, strict and do not accept a previous run file', () => temporary(root => {
  const file = path.join(root, 'crash.json'); write(file, fixture());
  verifyEnrollmentCrashReport(file, { ...options, startedEpochSeconds: Math.floor(Date.now() / 1000) });
  fs.utimesSync(file, 1, 1); rejected(() => verifyEnrollmentCrashReport(file, { ...options, startedEpochSeconds: Math.floor(Date.now() / 1000) }), 'stale_crash_report');
  fs.writeFileSync(file, Buffer.alloc(32769)); rejected(() => verifyEnrollmentCrashReport(file, options), 'file_limit');
  fs.writeFileSync(file, '{"format":"x","format":"y"}'); rejected(() => verifyEnrollmentCrashReport(file, options), 'duplicate_json_key');
}));
test('invalid caller source/platform/freshness options fail closed', () => {
  rejected(() => validateEnrollmentCrashReport(fixture(), { sourceCommit: 'PRIVATE_CANARY', platform: 'linux' }), 'invalid_crash_arguments');
  rejected(() => validateEnrollmentCrashReport(fixture(), { sourceCommit: SHA, platform: 'PRIVATE_CANARY' }), 'invalid_crash_arguments');
  rejected(() => validateEnrollmentCrashReport(fixture(), null), 'invalid_crash_arguments');
  temporary(root => {
    const file = path.join(root, 'crash.json'); write(file, fixture());
    for (const startedEpochSeconds of [-1, NaN, '1']) rejected(() => verifyEnrollmentCrashReport(file, { ...options, startedEpochSeconds }), 'invalid_crash_arguments');
  });
});
test('CLI failures retain only fixed categories, never supplied private material', () => {
  for (const args of [['--report', 'PRIVATE_CANARY_PATH', '--source', SHA], ['--PRIVATE_CANARY_ARG'], ['--started', 'PRIVATE_CANARY'], ['--started', '1\n']]) {
    const r = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', timeout: 10000 });
    assert.equal(r.status, 1); assert.ok(!(r.stdout + r.stderr).includes('PRIVATE_CANARY'), 'No supplied data in diagnostics');
  }
});
