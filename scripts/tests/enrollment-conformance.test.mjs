import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { EnrollmentCorpusError, loadEnrollmentCorpus, compareEnrollmentReports } from '../enrollment-corpus.mjs';
import { withCorpus, withReports, change, read, write } from './enrollment-test-support.mjs';

const corpus = loadEnrollmentCorpus();
const script = fileURLToPath(new URL('../compare-enrollment-conformance.mjs', import.meta.url));
const rejected = (run, code) => assert.throws(run, e => e instanceof EnrollmentCorpusError && (!code || e.code === code));
const compare = files => compareEnrollmentReports(corpus, files.kotlin, files.node);

test('two complete independent-shaped synthetic reports match every expectation', () => withReports(corpus, files => {
  const summary = compare(files); assert.equal(summary.codecCases, 272); assert.equal(summary.proofCases, 39); assert.equal(summary.comparisonCases, 31);
}));
test('agreement on the same incorrect codec result is rejected', () => withReports(corpus, files => {
  for (const file of [files.kotlin, files.node]) { const r = read(file); r.codec[0].actual.canonicalSha256 = '0'.repeat(64); write(file, r); }
  rejected(() => compare(files), 'outcome_mismatch');
}));
test('actual proof digests must match exact expected payload bytes', () => withReports(corpus, files => {
  for (const file of [files.kotlin, files.node]) { const r = read(file); r.proof[0].actual.payloadSha256 = '1'.repeat(64); write(file, r); }
  rejected(() => compare(files), 'outcome_mismatch');
}));
test('stale corpus digest and wrong implementation identity cannot pass', () => {
  for (const field of ['corpusSha256', 'implementation']) withReports(corpus, files => {
    const r = read(files.kotlin); r[field] = field === 'implementation' ? 'node' : '0'.repeat(64); write(files.kotlin, r);
    rejected(() => compare(files), 'stale_or_wrong_report');
  });
});
test('exact byte formatting changes invalidate prior reports', () => withCorpus(root => withReports(corpus, files => {
  change(root, 'manifest', () => {}); const modified = loadEnrollmentCorpus(root);
  assert.notEqual(modified.digest, corpus.digest);
  rejected(() => compareEnrollmentReports(modified, files.kotlin, files.node), 'stale_or_wrong_report');
})));
test('missing and extra result subsets fail rather than counting a nonempty sample', () => {
  for (const add of [false, true]) withReports(corpus, files => {
    const r = read(files.node); if (add) r.codec.push(r.codec[0]); else r.codec.pop(); write(files.node, r);
    rejected(() => compare(files), 'report_case_count');
  });
});
test('duplicate or reordered IDs fail even when outcomes have valid shapes', () => {
  for (const reorder of [false, true]) withReports(corpus, files => {
    const r = read(files.kotlin);
    if (reorder) [r.codec[0], r.codec[1]] = [r.codec[1], r.codec[0]]; else r.codec[1].id = r.codec[0].id;
    write(files.kotlin, r); rejected(() => compare(files), 'report_case_identity');
  });
});
test('unknown report and outcome fields cannot carry input or diagnostic material', () => {
  for (const nested of [false, true]) withReports(corpus, files => {
    const r = read(files.node); if (nested) r.proof[0].actual.context = 'PRIVATE_CANARY'; else r.material = 'PRIVATE_CANARY';
    write(files.node, r); rejected(() => compare(files), 'invalid_shape');
  });
});
test('duplicate JSON report members and interrupted output fail closed', () => {
  withReports(corpus, files => { fs.writeFileSync(files.kotlin, '{"format":"x","format":"y"}'); rejected(() => compare(files), 'duplicate_json_key'); });
  withReports(corpus, files => { fs.writeFileSync(files.kotlin, '{"format":'); rejected(() => compare(files), 'invalid_json'); });
});
test('booleans and proof/public-fingerprint types cannot be substituted', () => {
  for (const [kind, replacement] of [['codec', { ok: 1, canonicalSha256: '0'.repeat(64) }],
    ['proof', { ok: true, payloadSha256: 1 }], ['comparison', { ok: true, value: false }]]) withReports(corpus, files => {
    const r = read(files.node); r[kind][0].actual = replacement; write(files.node, r); rejected(() => compare(files), 'invalid_outcome');
  });
});
test('missing and oversized report files return only bounded static errors', () => {
  withReports(corpus, files => { fs.unlinkSync(files.node); rejected(() => compare(files), 'input_unavailable'); });
  withReports(corpus, files => { fs.writeFileSync(files.node, Buffer.alloc(16777217)); rejected(() => compare(files), 'file_limit'); });
});
test('comparator CLI rejects private material without echoing it', () => withReports(corpus, files => {
  const r = read(files.node); r.codec[0].actual = { ok: false, code: 'PRIVATE_CANARY' }; write(files.node, r);
  const result = spawnSync(process.execPath, [script, '--kotlin', files.kotlin, '--node', files.node], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 1); assert.ok(!(result.stdout + result.stderr).includes('PRIVATE_CANARY'), 'No supplied material in diagnostic output');
  assert.ok(!result.stderr.includes('at '), 'No provider traceback');
}));
test('synthetic report schema omits every raw fixture input', () => withReports(corpus, files => {
  const wire = fs.readFileSync(files.node, 'utf8');
  for (const field of ['wireHex', 'payloadHex', 'challengeWireHex', 'invitationSecret', 'context']) assert.ok(!wire.includes(`"${field}"`), 'No raw material fields');
  const result = spawnSync(process.execPath, [script, '--kotlin', files.kotlin, '--node', files.node], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0); assert.ok(result.stdout.includes(corpus.digest));
}));
