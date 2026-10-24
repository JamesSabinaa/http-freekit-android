import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { EnrollmentCorpusError, loadEnrollmentCorpus, parseEnrollmentJson } from '../enrollment-corpus.mjs';
import { withCorpus, change, read, write } from './enrollment-test-support.mjs';

const script = fileURLToPath(new URL('../check-enrollment-corpus.mjs', import.meta.url));
const rejected = (run, code) => assert.throws(run, e => e instanceof EnrollmentCorpusError && (!code || e.code === code));

test('committed corpus has complete bounded coverage and immutable exact-byte identity', () => {
  const c = loadEnrollmentCorpus();
  assert.equal(c.codec.length, 272); assert.equal(c.proof.length, 39); assert.equal(c.comparison.length, 31);
  assert.equal(c.digest, 'f9ca02fde11c58c286bddb3319e89258a780fdf4f446ee842e46c4e07b9d5fe4');
  assert.ok(Object.isFrozen(c) && Object.isFrozen(c.proof[0].context));
  assert.throws(() => { c.proof[0].context.purpose = 'cancel'; }, TypeError);
});
test('fixture JSON rejects decoded duplicate keys including escaped spellings', () => {
  for (const raw of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}']) rejected(() => parseEnrollmentJson(Buffer.from(raw)), 'duplicate_json_key');
  const safe = parseEnrollmentJson(Buffer.from('{"__proto__":{"safe":true}}'));
  assert.equal(Object.getPrototypeOf(safe), null); assert.ok(Object.hasOwn(safe, '__proto__'));
});
test('fixture JSON rejects malformed Unicode, BOM, nonfinite, fractional and huge numbers', () => {
  for (const raw of [Buffer.from([0xff]), Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
    Buffer.from('"\\ud800"'), Buffer.from('"\\udfff"'), Buffer.from('NaN'), Buffer.from('Infinity'),
    Buffer.from('1.0'), Buffer.from('1e0'), Buffer.from('9'.repeat(5000)), Buffer.from('-0')]) rejected(() => parseEnrollmentJson(raw));
});
test('generic parse depth, array and object limits fail before unbounded trees', () => {
  for (const raw of ['['.repeat(14) + '0' + ']'.repeat(14), JSON.stringify(Array(513).fill(0)),
    JSON.stringify(Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`k${i}`, 0])))]) rejected(() => parseEnrollmentJson(Buffer.from(raw)), 'json_bounds');
});
test('file discovery and reads reject missing files, unexpected JSON and oversized bytes', () => {
  withCorpus(root => { fs.unlinkSync(path.join(root, 'proof.json')); rejected(() => loadEnrollmentCorpus(root), 'invalid_file_set'); });
  withCorpus(root => { write(path.join(root, 'PRIVATE_CANARY.json'), {}); rejected(() => loadEnrollmentCorpus(root), 'invalid_file_set'); });
  withCorpus(root => { fs.writeFileSync(path.join(root, 'codec.json'), Buffer.alloc(2097153)); rejected(() => loadEnrollmentCorpus(root), 'file_limit'); });
});
test('manifest order, duplicate IDs and cross-category collisions cannot pass', () => {
  withCorpus(root => { change(root, 'manifest', m => m.codecIds.reverse()); rejected(() => loadEnrollmentCorpus(root), 'case_identity'); });
  withCorpus(root => { change(root, 'codec', m => { m.cases[1].id = m.cases[0].id; }); rejected(() => loadEnrollmentCorpus(root), 'case_identity'); });
  withCorpus(root => {
    const id = read(path.join(root, 'codec.json')).cases[0].id;
    change(root, 'proof', m => { m.cases[0].id = id; }); change(root, 'manifest', m => { m.proofIds[0] = id; });
    rejected(() => loadEnrollmentCorpus(root), 'case_identity');
  });
});
test('exact envelopes and case shapes reject extra fields without reading diagnostics', () => {
  withCorpus(root => { change(root, 'codec', m => { m.extra = 'PRIVATE_CANARY'; }); rejected(() => loadEnrollmentCorpus(root), 'invalid_shape'); });
  withCorpus(root => { change(root, 'proof', m => { m.cases[0].path = 'PRIVATE_CANARY'; }); rejected(() => loadEnrollmentCorpus(root), 'invalid_shape'); });
});
test('empty executable corpora and omitted channel coverage never count as evidence', () => {
  withCorpus(root => { change(root, 'proof', m => { m.cases = []; }); change(root, 'manifest', m => { m.proofIds = []; }); rejected(() => loadEnrollmentCorpus(root), 'case_count'); });
  withCorpus(root => { change(root, 'codec', m => { for (const c of m.cases) if (c.channel === 'cancel_request') c.channel = 'status_request'; }); rejected(() => loadEnrollmentCorpus(root), 'missing_coverage'); });
});
test('coverage requires every decoder code and both accepted proof purposes', () => {
  withCorpus(root => { change(root, 'codec', m => { for (const c of m.cases) if (c.expect.code === 'unsupported_version') c.expect.code = 'invalid_message'; }); rejected(() => loadEnrollmentCorpus(root), 'missing_coverage'); });
  withCorpus(root => { change(root, 'proof', m => { for (const c of m.cases) if (c.expect.ok) c.context.purpose = 'status'; }); rejected(() => loadEnrollmentCorpus(root), 'missing_coverage'); });
});
test('hex inputs require exact type, lowercase, whole bytes and finite rendered size', () => {
  for (const value of [{}, 'A0', '0']) withCorpus(root => {
    change(root, 'codec', m => { m.cases[0].wireHex = value; }); rejected(() => loadEnrollmentCorpus(root), 'invalid_hex');
  });
  withCorpus(root => { change(root, 'codec', m => { m.cases.find(c => c.expect.code === 'message_too_large').wireHex = '00'.repeat(65536); }); loadEnrollmentCorpus(root); });
  withCorpus(root => { change(root, 'codec', m => { m.cases[0].wireHex = '00'.repeat(65537); }); rejected(() => loadEnrollmentCorpus(root), 'json_bounds'); });
});
test('size-result precedence is checked independently of protocol parsing', () => {
  withCorpus(root => { change(root, 'codec', m => { m.cases.find(c => c.expect.code === 'message_too_large').expect.code = 'invalid_message'; }); rejected(() => loadEnrollmentCorpus(root), 'size_precedence'); });
  withCorpus(root => { change(root, 'proof', m => { m.cases[0].expect = { ok: false, code: 'message_too_large' }; }); rejected(() => loadEnrollmentCorpus(root), 'size_precedence'); });
});
test('outcomes reject bool/number substitutions, object codes, newline hashes and unknown fields', () => {
  for (const expect of [{ ok: 1, canonicalSha256: '0'.repeat(64) }, { ok: false, code: {} },
    { ok: true, canonicalSha256: '0'.repeat(64) + '\n' }, { ok: true, canonicalSha256: '0'.repeat(64), material: 'PRIVATE_CANARY' }]) withCorpus(root => {
    change(root, 'codec', m => { m.cases[0].expect = expect; }); rejected(() => loadEnrollmentCorpus(root));
  });
});
test('context arguments have separate depth, member and compact-byte limits', () => {
  for (const context of [{ a: { b: { c: { d: {} } } } }, Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, 0])), 'x'.repeat(4097)]) withCorpus(root => {
    change(root, 'proof', m => { m.cases.find(c => !c.expect.ok).context = context; }); rejected(() => loadEnrollmentCorpus(root), 'argument_limit');
  });
});
test('accepted proof expectations require bounded nonempty exact bytes and valid context shape', () => {
  for (const payloadHex of ['', '00'.repeat(1025), 'AA']) withCorpus(root => {
    change(root, 'proof', m => { m.cases[0].expect.payloadHex = payloadHex; }); rejected(() => loadEnrollmentCorpus(root), 'invalid_hex');
  });
  withCorpus(root => { change(root, 'proof', m => { delete m.cases[0].context.purpose; }); rejected(() => loadEnrollmentCorpus(root), 'invalid_shape'); });
});
test('comparison outcomes reject malformed public fingerprints and invalid rejection codes', () => {
  withCorpus(root => { change(root, 'comparison', m => { m.cases[0].expect.value += '\n'; }); rejected(() => loadEnrollmentCorpus(root), 'invalid_outcome'); });
  withCorpus(root => { change(root, 'comparison', m => { m.cases.find(c => !c.expect.ok).expect.code = 'unsupported_version'; }); rejected(() => loadEnrollmentCorpus(root), 'invalid_outcome'); });
});
test('validator CLI errors are static even for private path and argument canaries', () => {
  for (const args of [['--corpus', 'PRIVATE_CANARY_PATH'], ['--PRIVATE_CANARY_ARG']]) {
    const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 1); assert.ok(!(result.stdout + result.stderr).includes('PRIVATE_CANARY'), 'Input material must stay out of diagnostics');
    assert.ok(!result.stderr.includes('at '), 'No provider traceback');
  }
});
