import assert from 'node:assert/strict';
import test from 'node:test';
import { loadEnrollmentCorpus, expectedEnrollmentOutcome } from '../../scripts/enrollment-corpus.mjs';
import { executeEnrollmentCorpus, writeEnrollmentConformance } from './companion-enrollment-conformance.mjs';

test('executes every independent enrollment case and writes actual outcomes before comparing', () => {
  const { corpus, report } = writeEnrollmentConformance();
  let first;
  for (const kind of ['codec', 'proof', 'comparison']) {
    for (let index = 0; index < corpus[kind].length; index++) {
      const item = corpus[kind][index], actual = report[kind][index];
      assert.equal(actual.id, item.id);
      const expected = expectedEnrollmentOutcome(kind, item.expect);
      if (JSON.stringify(actual.actual) !== JSON.stringify(expected) && !first) first = kind + '/' + item.id;
    }
  }
  console.log('draft_enrollment_conformance codec=' + report.codec.length + ' proof=' + report.proof.length +
    ' comparison=' + report.comparison.length + ' sha256=' + report.corpusSha256);
  assert.equal(first, undefined, 'enrollment_conformance_mismatch:' + (first ?? 'none'));
});

test('actual generation never reads an expectation, even for proof payloads', () => {
  const corpus = loadEnrollmentCorpus();
  const poisoned = { digest: corpus.digest };
  for (const kind of ['codec', 'proof', 'comparison']) {
    poisoned[kind] = corpus[kind].map(item => Object.defineProperty(Object.create(item), 'expect',
      { get() { throw Error('actual_execution_read_expectation'); } }));
  }
  const actual = executeEnrollmentCorpus(poisoned);
  assert.equal(actual.codec.length, corpus.codec.length);
  assert.equal(actual.proof.length, corpus.proof.length);
  assert.equal(actual.comparison.length, corpus.comparison.length);
});
