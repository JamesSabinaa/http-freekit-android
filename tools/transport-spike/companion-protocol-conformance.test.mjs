import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { executeCorpus, loadCorpus, renderInput, runConformance } from './companion-protocol-conformance.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const source = path.join(root, 'protocol/fixtures/a19-draft-0.3');
const script = path.join(root, 'tools/transport-spike/companion-protocol-conformance.mjs');
function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-a19-corpus-'));
  for (const name of ['codec.json', 'lifecycle.json', 'manifest.json']) fs.copyFileSync(path.join(source, name), path.join(directory, name));
  return { directory,
    read: name => JSON.parse(fs.readFileSync(path.join(directory, name), 'utf8')),
    write: (name, value) => fs.writeFileSync(path.join(directory, name), JSON.stringify(value)),
    close() {
      const resolved = fs.realpathSync(directory);
      assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
      assert.ok(path.basename(resolved).startsWith('freekit-a19-corpus-'));
      fs.rmSync(resolved, { recursive: true });
    } };
}
function mutation(action, execute = false) {
  const files = fixture();
  try { action(files); assert.throws(() => execute ? executeCorpus(loadCorpus(files.directory)) : loadCorpus(files.directory)); }
  finally { files.close(); }
}

test('actual committed corpus executes every manifest ID and lifecycle operation exactly once', () => {
  const corpus = loadCorpus(source), report = executeCorpus(corpus);
  assert.deepEqual(report.codec.map(c => c.id), corpus.manifest.codecIds);
  assert.deepEqual(report.lifecycle.map(c => c.id), corpus.manifest.lifecycleIds);
  for (let i = 0; i < report.lifecycle.length; i++) assert.equal(report.lifecycle[i].steps.length, corpus.lifecycle[i].steps.length);
  assert.equal(report.implementation, 'node');
  assert.match(report.corpusSha256, /^[a-f0-9]{64}$/);
});

test('altering expected outcomes changes the digest but cannot change computed actual outcomes', () => {
  const files = fixture();
  try {
    const original = loadCorpus(files.directory), before = executeCorpus(original);
    const codec = files.read('codec.json');
    const accepted = codec.cases.find(c => c.expect.code === 'ok');
    accepted.expect = { code: 'invalid_message' };
    files.write('codec.json', codec);
    const lifecycle = files.read('lifecycle.json');
    lifecycle.cases[0].steps[0].expect.code = 'invalid_message';
    files.write('lifecycle.json', lifecycle);
    const changed = loadCorpus(files.directory), after = executeCorpus(changed);
    assert.notEqual(changed.corpusSha256, original.corpusSha256);
    assert.deepEqual(after.codec, before.codec);
    assert.deepEqual(after.lifecycle, before.lifecycle);
  } finally { files.close(); }
});

test('missing, extra, duplicate, reordered and cross-kind manifest IDs cannot hide skipped cases', () => {
  const actions = [
    f => { const x = f.read('manifest.json'); x.codecIds.pop(); f.write('manifest.json', x); },
    f => { const x = f.read('manifest.json'); x.codecIds[1] = x.codecIds[0]; f.write('manifest.json', x); },
    f => { const x = f.read('manifest.json'); x.lifecycleIds[0] = x.codecIds[0]; x.lifecycleIds.sort(); f.write('manifest.json', x); },
    f => { const x = f.read('codec.json'); [x.cases[0], x.cases[1]] = [x.cases[1], x.cases[0]]; f.write('codec.json', x); },
    f => { const x = f.read('lifecycle.json'); x.cases.push(x.cases[0]); f.write('lifecycle.json', x); },
    f => { const x = f.read('manifest.json'); x.extra = true; f.write('manifest.json', x); },
  ];
  actions.forEach(action => mutation(action));
});

test('bounded duplicate-aware file decoding rejects malformed, nonUTF8, BOM and oversized corpus files', () => {
  for (const content of [Buffer.from('{'), Buffer.from([0xff]), Buffer.alloc(2 * 1024 * 1024 + 1)]) {
    mutation(f => fs.writeFileSync(path.join(f.directory, 'manifest.json'), content));
  }
  mutation(f => {
    const filename = path.join(f.directory, 'manifest.json'), valid = fs.readFileSync(filename);
    fs.writeFileSync(filename, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), valid]));
  });
  mutation(f => {
    const filename = path.join(f.directory, 'manifest.json'), valid = fs.readFileSync(filename, 'utf8');
    fs.writeFileSync(filename, '{"format":"http-freekit-a19",' + valid.slice(1));
  });
  mutation(f => fs.unlinkSync(path.join(f.directory, 'manifest.json')));
});

test('bounded byte descriptors reject invalid lengths before allocation and never evaluate expressions', () => {
  assert.equal(renderInput({ prefixHex: '01', repeatHex: 'ff', repeatCount: 2, suffixHex: '02' }).toString('hex'), '01ffff02');
  assert.equal(renderInput({ wireHex: '' }).length, 0);
  assert.equal(renderInput({ prefixHex: '', repeatHex: '00', repeatCount: 65537, suffixHex: '' }).length, 65537);
  for (const input of [{ wireHex: '0' }, { wireHex: 'FF' }, { wireHex: '00', file: 'secret' },
    { prefixHex: '01', repeatHex: '00', repeatCount: 65537, suffixHex: '' },
    { prefixHex: '', repeatHex: '0000', repeatCount: 0, suffixHex: '' },
    { prefixHex: '', repeatHex: '00', repeatCount: 65538, suffixHex: '' },
    { eval: 'process.exit(0)' }]) assert.throws(() => renderInput(input));
});

test('unknown operations/fields, absent references and clocks on snapshots are corpus errors', () => {
  for (const action of [
    f => { const x = f.read('lifecycle.json'); x.cases[0].steps[0].op = 'run_code'; f.write('lifecycle.json', x); },
    f => { const x = f.read('lifecycle.json'); x.cases[0].steps[0].unknown = 1; f.write('lifecycle.json', x); },
    f => { const x = f.read('lifecycle.json'); const first = x.cases[0].steps[0];
      x.cases[0].steps[0] = { op: 'snapshot', clock: x.cases[0].initialClock, expect: first.expect }; f.write('lifecycle.json', x); },
    f => { const x = f.read('lifecycle.json'); const first = x.cases[0].steps[0];
      x.cases[0].steps[0] = { op: 'peek', stream: 'absent', direction: 'client', count: 1, expect: first.expect }; f.write('lifecycle.json', x); },
  ]) mutation(action, true);
});

test('report export contains actual results, while console output exposes only coverage and digest', () => {
  const files = fixture();
  try {
    const output = path.join(files.directory, 'actual.json');
    const summary = runConformance(files.directory, output), report = JSON.parse(fs.readFileSync(output, 'utf8'));
    assert.equal(summary.corpusSha256, report.corpusSha256);
    assert.equal(summary.codecCount, report.codec.length);
    assert.equal(summary.stepCount, report.lifecycle.reduce((n, c) => n + c.steps.length, 0));
    const command = spawnSync(process.execPath, [script, '--fixtures', files.directory, '--output', output], { encoding: 'utf8', timeout: 10000 });
    assert.equal(command.status, 0, command.stderr);
    const printed = JSON.parse(command.stdout);
    assert.deepEqual(printed.codecIds, summary.codecIds);
    assert.deepEqual(printed.lifecycleIds, summary.lifecycleIds);
    // A permitted case ID may contain "snapshot"; inspect fields rather than matching that word.
    assert.deepEqual(Object.keys(printed).sort(), ['codecCount', 'codecIds', 'corpusSha256', 'lifecycleCount', 'lifecycleIds', 'stepCount']);
    fs.writeFileSync(path.join(files.directory, 'manifest.json'), 'DO_NOT_PRINT_INPUT_OR_PATH');
    const failed = spawnSync(process.execPath, [script, '--fixtures', files.directory, '--output', output], { encoding: 'utf8', timeout: 10000 });
    assert.notEqual(failed.status, 0);
    assert.equal(failed.stdout, '');
    assert.equal(failed.stderr.trim(), 'companion_conformance_failed');
    assert.ok(!failed.stderr.includes(files.directory));
  } finally { files.close(); }
});
