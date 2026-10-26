import test from 'node:test';
import assert from 'node:assert/strict';
import * as D from './reference-tun-descriptor.mjs';
import { createReferenceTunInvocationParser, decodeReferenceTunObservation } from './reference-tun-results.mjs';
const command = { code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true };
export function observationBundle(method) {
  return Object.fromEntries(Object.entries(D.referenceTunObservationTypes).map(([key, type]) => [D.referenceTunPrefix + key,
    String(type === 'true' ? true : type === 'false' ? false : type === 'https' ? method === D.referenceTunMethods[1] : ({ version: 1, one: 1, zero: 0, guard: 2, responseBytes: 81 })[type])]));
}
const bundle = (fields, code) => Object.entries(fields).map(([key, value]) => `INSTRUMENTATION_STATUS: ${key}=${value}\n`).join('') + `INSTRUMENTATION_STATUS_CODE: ${code}\n`;
export function transcript(method) {
  const identity = { class: D.referenceTunClass, test: method, numtests: 1, current: 1 };
  return bundle(identity, 1) + D.referenceTunPhases.map(phase => bundle({ [D.referenceTunPrefix + 'Version']: 1, [D.referenceTunPrefix + 'Phase']: phase }, 2)).join('') +
    bundle(observationBundle(method), 3) + bundle(identity, 0) + 'INSTRUMENTATION_CODE: -1\n';
}
function parse(text, method = D.referenceTunMethods[0], result = command) {
  const parser = createReferenceTunInvocationParser(method);
  try { parser.push(Buffer.from(text)); } catch { /* retain finite failure */ }
  return parser.finish(result);
}
for (const method of D.referenceTunMethods) test('exact byte-fragmented real event grammar ' + method, () => {
  const parser = createReferenceTunInvocationParser(method);
  for (const byte of Buffer.from(transcript(method))) parser.push(Buffer.from([byte]));
  const result = parser.finish(command);
  assert.equal(result.state, 'passed'); assert.equal(result.actualStarted, 1); assert.equal(result.actualCompleted, 1);
  assert.equal(result.observation.tlsUsed, method === D.referenceTunMethods[1]);
  assert.equal(Object.hasOwn(result.observation, 'tlsAlpnH1'), false);
});
test('phase, identity, duplicate, missing facts, terminal, process closure fail closed', () => {
  const method = D.referenceTunMethods[0], good = transcript(method);
  for (const text of [good.replace('strict-csr-reserved', 'not-real'), good.replace(method, D.referenceTunMethods[1]),
    good.replace('draftReferenceTunVersion=1', 'draftReferenceTunVersion=2'), good.replace('draftReferenceTunVersion=1\n', 'draftReferenceTunVersion=1\nINSTRUMENTATION_STATUS: draftReferenceTunVersion=1\n'),
    good.replace('INSTRUMENTATION_STATUS: draftReferenceTunSocketClosed=true\n', ''), good.replace('INSTRUMENTATION_CODE: -1\n', ''), good + bundle({ class: D.referenceTunClass, test: method, numtests: 1 }, 0),
    good.replace('draftReferenceTunTlsUsed=false', 'draftReferenceTunTlsUsed=true')]) assert.notEqual(parse(text).state, 'passed');
  assert.notEqual(parse(good, method, { ...command, processGroupClosed: false }).state, 'passed');
});
test('no residual phase can initiate work after command close; parser bounds and UTF8 are strict', () => {
  let phases = 0;
  const parser = createReferenceTunInvocationParser(D.referenceTunMethods[0], { onPhase() { phases++; } });
  parser.push(Buffer.from(bundle({ class: D.referenceTunClass, test: D.referenceTunMethods[0], numtests: 1 }, 1) +
    'INSTRUMENTATION_STATUS: draftReferenceTunVersion=1\nINSTRUMENTATION_STATUS: draftReferenceTunPhase=input-consumed\nINSTRUMENTATION_STATUS_CODE: 2'));
  assert.notEqual(parser.finish(command).state, 'passed'); assert.equal(phases, 0);
  for (const bytes of [Buffer.from([255]), Buffer.alloc(262145, 65), Buffer.alloc(8193, 65)]) {
    const p = createReferenceTunInvocationParser(D.referenceTunMethods[0]); assert.throws(() => p.push(bytes)); assert.notEqual(p.finish(command).state, 'passed');
  }
});
test('observation copies actual guard counts and rejects absent, numeric variants and extras', () => {
  const method = D.referenceTunMethods[0], raw = observationBundle(method);
  for (const key of ['ProtectAttempts', 'ProtectSuccesses', 'BindAttempts', 'BindSuccesses']) raw[D.referenceTunPrefix + key] = '3';
  assert.equal(decodeReferenceTunObservation(raw, method).protectAttempts, 3);
  for (const changed of [{ ...raw, draftReferenceTunBindSuccesses: '2' }, { ...raw, draftReferenceTunVersion: '01' }, { ...raw, secret: 'x' }, { ...raw, draftReferenceTunSocketClosed: 'True' }]) assert.throws(() => decodeReferenceTunObservation(changed, method));
});
test('failure retains finite category only and never raw diagnostics', () => {
  const method = D.referenceTunMethods[0];
  const text = bundle({ class: D.referenceTunClass, test: method, numtests: 1 }, 1) + bundle({ class: D.referenceTunClass, test: method, numtests: 1,
    stack: 'java.lang.AssertionError: Reference TUN research failed at traffic-command-started type=IOException category=traffic_reference_eof cleanup=false\nsecret-provider-diagnostic' }, -2) + 'INSTRUMENTATION_CODE: -1\n';
  const result = parse(text); assert.equal(result.state, 'failed'); assert.equal(result.failure.category, 'traffic_reference_eof');
  assert.equal(JSON.stringify(result).includes('secret-provider'), false);
});
