import fs from 'node:fs';
import { EnrollmentCorpusError, readEnrollmentJson } from './enrollment-corpus.mjs';

export const ENROLLMENT_CRASH_CASES = Object.freeze([
  ['reserve', 'before', 'reservation_rolled_back'], ['reserve', 'after', 'reservation_retained'],
  ['claim', 'before', 'claim_rolled_back'], ['claim', 'after', 'intent_reclaimed'],
  ['publish', 'before', 'publication_rolled_back'], ['publish', 'after', 'exact_publication_retained'],
  ['revoke', 'before', 'revocation_rolled_back'], ['revoke', 'after', 'revocation_retained'],
].map(Object.freeze));
const FLAGS = ['barrierObserved', 'ownerExcluded', 'readerExcluded', 'killRequested', 'childExitJoined', 'recovered', 'integrity'];
const CASE_KEYS = ['id', 'operation', 'position', ...FLAGS, 'journalExistsBeforeKill', 'journalBytesBeforeKill', 'journalHeaderNonzero', 'tuple'];
const fail = code => { throw new EnrollmentCorpusError(code); };
function keys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== expected.length ||
      !expected.every(key => Object.hasOwn(value, key))) fail('invalid_crash_shape');
}
function source(value) { return typeof value === 'string' && value.length === 40 && /^[a-f0-9]{40}$/.test(value); }

/** Validate reported actual-process outcomes; this does not execute or model a crash. */
export function validateEnrollmentCrashReport(report, options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) fail('invalid_crash_arguments');
  const { sourceCommit, platform = 'linux' } = options;
  if (!source(sourceCommit) || !['linux', 'win32'].includes(platform)) fail('invalid_crash_arguments');
  keys(report, ['format', 'revision', 'node', 'platform', 'powerLossTested', 'source', 'cases']);
  if (report.format !== 'http-freekit-enrollment-store-crash' || report.revision !== '1' || report.node !== 'v24.22.1' ||
      report.platform !== platform || report.powerLossTested !== false) fail('invalid_crash_header');
  keys(report.source, ['commit', 'trackedDirty']);
  if (report.source.commit !== sourceCommit || report.source.trackedDirty !== false) fail('invalid_crash_source');
  if (!Array.isArray(report.cases) || report.cases.length !== ENROLLMENT_CRASH_CASES.length) fail('incomplete_crash_cases');
  report.cases.forEach((item, index) => {
    keys(item, CASE_KEYS);
    const [operation, position, tuple] = ENROLLMENT_CRASH_CASES[index];
    if (item.id !== `${operation}-${position}` || item.operation !== operation || item.position !== position || item.tuple !== tuple) fail('invalid_crash_case');
    if (!FLAGS.every(name => item[name] === true)) fail('incomplete_crash_evidence');
    if (typeof item.journalExistsBeforeKill !== 'boolean' || typeof item.journalHeaderNonzero !== 'boolean' ||
        !Number.isSafeInteger(item.journalBytesBeforeKill) || item.journalBytesBeforeKill < 0 || item.journalBytesBeforeKill > 32 * 1024 * 1024) fail('invalid_crash_journal');
    if (!item.journalExistsBeforeKill && (item.journalBytesBeforeKill !== 0 || item.journalHeaderNonzero) ||
        item.journalHeaderNonzero && item.journalBytesBeforeKill < 8) fail('invalid_crash_journal');
    if (position === 'before' && (!item.journalExistsBeforeKill || item.journalBytesBeforeKill <= 28 || !item.journalHeaderNonzero)) fail('missing_crash_recovery_journal');
  });
  return { format: report.format, revision: report.revision, sourceCommit, platform, node: report.node, cases: 8, powerLossTested: false };
}

export function verifyEnrollmentCrashReport(file, options) {
  const report = readEnrollmentJson(file, 32768).value;
  if (options?.startedEpochSeconds !== undefined) {
    const started = options.startedEpochSeconds;
    if (!Number.isSafeInteger(started) || started < 0) fail('invalid_crash_arguments');
    let modified;
    try { modified = fs.statSync(file).mtimeMs; } catch { fail('input_unavailable'); }
    if (modified < started * 1000 - 2000 || modified > Date.now() + 2000) fail('stale_crash_report');
  }
  return validateEnrollmentCrashReport(report, options);
}
