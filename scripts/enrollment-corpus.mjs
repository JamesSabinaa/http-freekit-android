import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const ENROLLMENT_FORMAT = 'http-freekit-a21';
export const ENROLLMENT_REVISION = '0.4';
export const ENROLLMENT_FILES = Object.freeze(['codec.json', 'comparison.json', 'manifest.json', 'proof.json']);
export const ENROLLMENT_CHANNELS = Object.freeze(['pair_request', 'challenge_request', 'status_request', 'cancel_request',
  'pair_response', 'challenge_response', 'status_response', 'cancel_response']);
export const DEFAULT_ENROLLMENT_CORPUS = fileURLToPath(new URL('../protocol/fixtures/a21-draft-0.4/', import.meta.url));
const FILE_LIMIT = 2 * 1024 * 1024;
export const ENROLLMENT_REPORT_LIMIT = 16 * 1024 * 1024;
const CASE_LIMITS = Object.freeze({ codec: 512, proof: 256, comparison: 128 });
const KINDS = Object.freeze(['codec', 'proof', 'comparison']);
const CODES = new Set(['invalid_message', 'message_too_large', 'unsupported_version']);
const HASH = /^[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{0,79}$/;
const CONTEXT_FIELDS = ['desktopId', 'gatewaySpkiSha256', 'invitationId', 'enrollmentId', 'deviceSpkiSha256', 'purpose'];

export class EnrollmentCorpusError extends Error {
  constructor(code) { super(`Enrollment conformance rejected: ${code}`); this.name = 'EnrollmentCorpusError'; this.code = code; }
}
const fail = code => { throw new EnrollmentCorpusError(code); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function keys(value, expected) {
  if (!object(value) || Object.keys(value).length !== expected.length || !expected.every(key => Object.hasOwn(value, key))) fail('invalid_shape');
}
function textMatches(value, expression) { return typeof value === 'string' && expression.test(value) && value.match(expression)?.[0] === value; }
function wellFormed(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

/** Fixture/report JSON only. Raw protocol negatives are bytes in wireHex, not parsed here. */
export function parseEnrollmentJson(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) fail('invalid_json');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail('invalid_json'); }
  let index = 0, nodes = 0;
  const space = () => { while (index < text.length && ' \t\r\n'.includes(text[index])) index++; };
  function string() {
    const start = index++;
    while (index < text.length) {
      const c = text[index++];
      if (c === '"') {
        let result;
        try { result = JSON.parse(text.slice(start, index)); } catch { fail('invalid_json'); }
        if (result.length > 131072 || !wellFormed(result)) fail('json_bounds');
        return result;
      }
      if (c === '\\') { if (index >= text.length) fail('invalid_json'); index++; }
      else if (c.charCodeAt(0) < 32) fail('invalid_json');
    }
    fail('invalid_json');
  }
  function value(depth) {
    if (++nodes > 100000 || depth > 12) fail('json_bounds');
    space();
    if (text[index] === '"') return string();
    if (text[index] === '{') {
      index++; space(); const result = Object.create(null); let count = 0;
      if (text[index] === '}') { index++; return result; }
      while (true) {
        space(); if (text[index] !== '"') fail('invalid_json');
        const key = string();
        if (Object.hasOwn(result, key)) fail('duplicate_json_key');
        if (++count > 64) fail('json_bounds');
        space(); if (text[index++] !== ':') fail('invalid_json');
        result[key] = value(depth + 1); space();
        const c = text[index++]; if (c === '}') return result; if (c !== ',') fail('invalid_json');
      }
    }
    if (text[index] === '[') {
      index++; space(); const result = [];
      if (text[index] === ']') { index++; return result; }
      while (true) {
        if (result.length >= 512) fail('json_bounds');
        result.push(value(depth + 1)); space();
        const c = text[index++]; if (c === ']') return result; if (c !== ',') fail('invalid_json');
      }
    }
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(token, index)) { index += token.length; return result; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)/.exec(text.slice(index));
    if (!match || match[0].length > 17 || match[0] === '-0') fail('invalid_json');
    const number = Number(match[0]); if (!Number.isSafeInteger(number)) fail('invalid_json');
    index += match[0].length; return number;
  }
  const result = value(1); space(); if (index !== text.length) fail('invalid_json');
  return result;
}

export function readEnrollmentJson(file, limit = FILE_LIMIT) {
  let descriptor;
  try {
    if (!fs.lstatSync(file).isFile() || fs.lstatSync(file).isSymbolicLink()) fail('input_unavailable');
    descriptor = fs.openSync(file, 'r');
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) fail('input_unavailable');
    if (stat.size > limit) fail('file_limit');
    const chunks = []; let total = 0;
    while (true) {
      const chunk = Buffer.alloc(Math.min(65536, limit + 1 - total));
      const count = fs.readSync(descriptor, chunk, 0, chunk.length, null);
      if (count === 0) break;
      total += count; if (total > limit) fail('file_limit');
      chunks.push(chunk.subarray(0, count));
    }
    const bytes = Buffer.concat(chunks, total);
    return { bytes, value: parseEnrollmentJson(bytes) };
  } catch (error) {
    if (error instanceof EnrollmentCorpusError) throw error;
    fail('input_unavailable');
  } finally { if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch { fail('input_unavailable'); } } }
}

function hex(value, maximum, nonempty = false) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || value.length > maximum * 2 ||
      !textMatches(value, /^[a-f0-9]*$/) || nonempty && value.length === 0) fail('invalid_hex');
  return Buffer.from(value, 'hex');
}
function argument(value) {
  function visit(item, depth) {
    if (item !== null && typeof item === 'object') {
      if (depth > 4 || Object.keys(item).length > 32) fail('argument_limit');
      for (const child of Object.values(item)) visit(child, depth + 1);
    }
  }
  visit(value, 1);
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') > 4096) fail('argument_limit');
}
function outcome(kind, value, expected) {
  if (!object(value) || typeof value.ok !== 'boolean') fail('invalid_outcome');
  if (!value.ok) {
    keys(value, ['ok', 'code']);
    if (typeof value.code !== 'string' || !(kind === 'comparison' ? value.code === 'invalid_message' : CODES.has(value.code))) fail('invalid_outcome');
    return;
  }
  const field = kind === 'codec' ? 'canonicalSha256' : kind === 'comparison' ? 'value' : expected ? 'payloadHex' : 'payloadSha256';
  keys(value, ['ok', field]);
  if (field === 'payloadHex') hex(value[field], 1024, true);
  else if (field === 'value') { if (!textMatches(value[field], /^[a-f0-9]{8}(?:-[a-f0-9]{8}){7}$/)) fail('invalid_outcome'); }
  else if (!textMatches(value[field], HASH)) fail('invalid_outcome');
}
function header(value, kind) {
  if (value.format !== ENROLLMENT_FORMAT || value.revision !== ENROLLMENT_REVISION || value.kind !== kind) fail('invalid_header');
}
function freeze(value) {
  if (value !== null && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}

export function loadEnrollmentCorpus(root = DEFAULT_ENROLLMENT_CORPUS) {
  if (typeof root !== 'string') fail('input_unavailable');
  let names;
  try { names = fs.readdirSync(root).filter(name => name.endsWith('.json')).sort(); } catch { fail('input_unavailable'); }
  if (JSON.stringify(names) !== JSON.stringify(ENROLLMENT_FILES)) fail('invalid_file_set');
  const files = Object.fromEntries(ENROLLMENT_FILES.map(name => [name, readEnrollmentJson(path.join(root, name))]));
  const manifest = files['manifest.json'].value;
  keys(manifest, ['format', 'revision', 'kind', 'codecIds', 'proofIds', 'comparisonIds']); header(manifest, 'manifest');
  const sha = createHash('sha256');
  for (const name of ENROLLMENT_FILES) sha.update(name, 'utf8').update('\0').update(files[name].bytes).update('\0');
  const result = { digest: sha.digest('hex') }, seen = new Set();
  for (const kind of KINDS) {
    const envelope = files[`${kind}.json`].value;
    keys(envelope, ['format', 'revision', 'kind', 'cases']); header(envelope, kind);
    const ids = manifest[`${kind}Ids`], cases = envelope.cases;
    if (!Array.isArray(ids) || !Array.isArray(cases) || cases.length < 1 || cases.length > CASE_LIMITS[kind] || ids.length !== cases.length) fail('case_count');
    for (let index = 0; index < cases.length; index++) {
      const c = cases[index];
      keys(c, kind === 'codec' ? ['id', 'channel', 'wireHex', 'expect'] : kind === 'proof' ?
        ['id', 'context', 'challengeWireHex', 'expect'] : ['id', 'gatewayPin', 'deviceHash', 'expect']);
      if (!textMatches(c.id, ID) || c.id !== ids[index] || seen.has(c.id)) fail('case_identity');
      seen.add(c.id); outcome(kind, c.expect, true);
      if (kind === 'codec' || kind === 'proof') {
        const bytes = hex(c[kind === 'codec' ? 'wireHex' : 'challengeWireHex'], 65536);
        if (bytes.length > 16384 ? c.expect.ok || c.expect.code !== 'message_too_large' : !c.expect.ok && c.expect.code === 'message_too_large') fail('size_precedence');
      }
      if (kind === 'codec') { if (!ENROLLMENT_CHANNELS.includes(c.channel)) fail('invalid_channel'); }
      else if (kind === 'proof') {
        argument(c.context);
        if (c.expect.ok) { keys(c.context, CONTEXT_FIELDS); if (!Object.values(c.context).every(v => typeof v === 'string') || !['status', 'cancel'].includes(c.context.purpose)) fail('invalid_positive_context'); }
      } else { argument(c.gatewayPin); argument(c.deviceHash); }
    }
    result[kind] = cases;
  }
  for (const channel of ENROLLMENT_CHANNELS) {
    if (![true, false].every(ok => result.codec.some(c => c.channel === channel && c.expect.ok === ok))) fail('missing_coverage');
  }
  if (![...CODES].every(code => result.codec.some(c => !c.expect.ok && c.expect.code === code)) ||
      !['status', 'cancel'].every(purpose => result.proof.some(c => c.expect.ok && c.context.purpose === purpose)) ||
      !result.proof.some(c => !c.expect.ok) || ![true, false].every(ok => result.comparison.some(c => c.expect.ok === ok))) fail('missing_coverage');
  return freeze(result);
}

export function expectedEnrollmentOutcome(kind, expectation) {
  outcome(kind, expectation, true);
  if (kind === 'proof' && expectation.ok) return { ok: true, payloadSha256: createHash('sha256').update(Buffer.from(expectation.payloadHex, 'hex')).digest('hex') };
  return { ...expectation };
}
const stable = value => JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))));

export function compareEnrollmentReports(corpus, kotlinFile, nodeFile) {
  const normalized = [];
  for (const [implementation, file] of [['kotlin', kotlinFile], ['node', nodeFile]]) {
    const report = readEnrollmentJson(file, ENROLLMENT_REPORT_LIMIT).value;
    keys(report, ['format', 'revision', 'kind', 'implementation', 'corpusSha256', 'codec', 'proof', 'comparison']);
    header(report, 'results');
    if (report.implementation !== implementation || report.corpusSha256 !== corpus.digest) fail('stale_or_wrong_report');
    const actual = {};
    for (const kind of KINDS) {
      if (!Array.isArray(report[kind]) || report[kind].length !== corpus[kind].length) fail('report_case_count');
      actual[kind] = report[kind].map((record, index) => {
        keys(record, ['id', 'actual']); const c = corpus[kind][index];
        if (record.id !== c.id) fail('report_case_identity'); outcome(kind, record.actual, false);
        if (stable(record.actual) !== stable(expectedEnrollmentOutcome(kind, c.expect))) fail('outcome_mismatch');
        return stable(record.actual);
      });
    }
    normalized.push(actual);
  }
  if (JSON.stringify(normalized[0]) !== JSON.stringify(normalized[1])) fail('implementation_disagreement');
  return enrollmentCorpusSummary(corpus, { implementations: ['kotlin', 'node'] });
}

export function enrollmentCorpusSummary(corpus, extra = {}) {
  return { format: ENROLLMENT_FORMAT, revision: ENROLLMENT_REVISION, corpusSha256: corpus.digest,
    codecCases: corpus.codec.length, proofCases: corpus.proof.length, comparisonCases: corpus.comparison.length, ...extra };
}
