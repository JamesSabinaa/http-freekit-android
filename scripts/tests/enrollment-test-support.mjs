import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_ENROLLMENT_CORPUS, ENROLLMENT_FILES, expectedEnrollmentOutcome } from '../enrollment-corpus.mjs';

export function temporary(run) {
  const parent = fs.realpathSync(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(parent, 'freekit-enrollment-test-'));
  try { return run(directory); }
  finally {
    const resolved = path.resolve(directory);
    if (path.dirname(resolved) !== parent || !path.basename(resolved).startsWith('freekit-enrollment-test-')) throw new Error('Unsafe test cleanup target');
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}
export function withCorpus(run) {
  return temporary(directory => {
    for (const name of ENROLLMENT_FILES) fs.copyFileSync(path.join(DEFAULT_ENROLLMENT_CORPUS, name), path.join(directory, name));
    return run(directory);
  });
}
export const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
export const write = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
export function change(root, kind, mutate) {
  const file = path.join(root, `${kind}.json`), value = read(file); mutate(value); write(file, value);
}
/** Synthetic comparator unit-test records, never an implementation execution report. */
export function syntheticReport(corpus, implementation) {
  return { format: 'http-freekit-a21', revision: '0.4', kind: 'results', implementation, corpusSha256: corpus.digest,
    ...Object.fromEntries(['codec', 'proof', 'comparison'].map(kind => [kind,
      corpus[kind].map(c => ({ id: c.id, actual: expectedEnrollmentOutcome(kind, c.expect) }))])) };
}
export function withReports(corpus, run) {
  return temporary(root => {
    const kotlin = path.join(root, 'kotlin.json'), node = path.join(root, 'node.json');
    write(kotlin, syntheticReport(corpus, 'kotlin')); write(node, syntheticReport(corpus, 'node'));
    return run({ root, kotlin, node });
  });
}
