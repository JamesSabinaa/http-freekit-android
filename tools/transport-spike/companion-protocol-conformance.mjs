// Synthetic test adapter only; expected outcomes are never used to compute actual outcomes.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { decodeCorpusJson, decodeMessage } from './companion-protocol-codec.mjs';
import { CompanionBudgetPool, CompanionControl } from './companion-protocol-lifecycle.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const MAX_FILE = 2 * 1024 * 1024;
class CorpusError extends Error { constructor() { super('invalid_conformance_corpus'); this.code = 'invalid_conformance_corpus'; } }
const bad = () => { throw new CorpusError(); };
const full = (value, pattern) => typeof value === 'string' && pattern.exec(value)?.[0] === value;
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
function exact(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || Object.keys(value).some(k => !fields.includes(k))) bad();
}
function boundedFile(filename) {
  let fd;
  try {
    fd = fs.openSync(filename, 'r');
    const bytes = Buffer.alloc(MAX_FILE + 1);
    let size = 0;
    while (size <= MAX_FILE) {
      const count = fs.readSync(fd, bytes, size, bytes.length - size, null);
      if (count === 0) break;
      size += count;
    }
    if (size === 0 || size > MAX_FILE) bad();
    return bytes.subarray(0, size);
  } catch { bad(); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function envelope(value, kind, additional) {
  exact(value, ['format', 'revision', 'kind', ...additional]);
  if (value.format !== 'http-freekit-a19' || value.revision !== '0.3' || value.kind !== kind) bad();
}
function reference(value) { if (!full(value, /^[a-z][a-z0-9-]{0,39}$/)) bad(); }
function clock(value) {
  exact(value, ['utcMillis', 'monotonicMillis']);
  if (!integer(value.utcMillis, 0, Number.MAX_SAFE_INTEGER) || !integer(value.monotonicMillis, 0, Number.MAX_SAFE_INTEGER)) bad();
}
export function renderInput(value) {
  const hex = text => full(text, /^(?:[0-9a-f]{2})*$/) && text.length <= 131074;
  if (value && Object.hasOwn(value, 'wireHex')) {
    exact(value, ['wireHex']);
    if (!hex(value.wireHex)) bad();
    return Buffer.from(value.wireHex, 'hex');
  }
  exact(value, ['prefixHex', 'repeatHex', 'repeatCount', 'suffixHex']);
  if (!hex(value.prefixHex) || !hex(value.suffixHex) || !full(value.repeatHex, /^[0-9a-f]{2}$/) ||
      !integer(value.repeatCount, 0, 65537)) bad();
  const prefix = value.prefixHex.length / 2, suffix = value.suffixHex.length / 2;
  if (prefix + suffix > 65537 - value.repeatCount) bad();
  const bytes = Buffer.alloc(prefix + value.repeatCount + suffix);
  Buffer.from(value.prefixHex, 'hex').copy(bytes);
  bytes.fill(Number.parseInt(value.repeatHex, 16), prefix, prefix + value.repeatCount);
  Buffer.from(value.suffixHex, 'hex').copy(bytes, prefix + value.repeatCount);
  return bytes;
}
const operationFields = {
  create_control: ['control'], control_text: ['control', 'direction', 'input'], control_activity: ['control', 'direction'],
  allocate_stream: ['control', 'stream', 'deviceId', 'sessionHeader'], stream_text: ['stream', 'direction', 'input'],
  binary: ['stream', 'direction', 'input'], peek: ['stream', 'direction', 'count'], drain: ['stream', 'direction', 'count'],
  snapshot: [],
};
function validateOperation(step) {
  if (!step || typeof step.op !== 'string') bad();
  let fields;
  if (['local_cancel', 'tick', 'ws_closed', 'resources_closed'].includes(step.op)) {
    if (Object.hasOwn(step, 'control') === Object.hasOwn(step, 'stream')) bad();
    fields = [Object.hasOwn(step, 'control') ? 'control' : 'stream', ...(step.op === 'ws_closed' ? ['closeCode'] : [])];
  } else fields = operationFields[step.op];
  if (!fields) bad();
  if (step.op === 'snapshot' && Object.hasOwn(step, 'clock')) bad();
  exact(step, ['op', 'expect', ...fields, ...(Object.hasOwn(step, 'clock') ? ['clock'] : [])]);
  if (step.clock !== undefined) clock(step.clock);
  for (const name of ['control', 'stream']) if (Object.hasOwn(step, name)) reference(step[name]);
  if (Object.hasOwn(step, 'direction') && (typeof step.direction !== 'string' || step.direction.length > 128 ||
      [...step.direction].some(c => c.charCodeAt(0) > 127))) bad();
  if (Object.hasOwn(step, 'count') && !integer(step.count, -1, 16777217)) bad();
  if (Object.hasOwn(step, 'closeCode') && !integer(step.closeCode, 1000, 4999)) bad();
  if (Object.hasOwn(step, 'input')) renderInput(step.input);
  if (Object.hasOwn(step, 'sessionHeader') && (typeof step.sessionHeader !== 'string' || step.sessionHeader.length > 128)) bad();
  if (Object.hasOwn(step, 'deviceId') && (typeof step.deviceId !== 'string' || step.deviceId.length > 128)) bad();
  if (!step.expect || typeof step.expect !== 'object' || Array.isArray(step.expect)) bad();
  exact(step.expect, ['code', 'effects', 'snapshot', ...(Object.hasOwn(step.expect, 'peekHex') ? ['peekHex'] : [])]);
}

export function loadCorpus(directory) {
  const names = ['codec.json', 'lifecycle.json', 'manifest.json'], files = {}, parsed = {}, hash = createHash('sha256');
  for (const name of names) {
    files[name] = boundedFile(path.join(directory, name));
    hash.update(name, 'utf8').update(Buffer.from([0])).update(files[name]).update(Buffer.from([0]));
    try { parsed[name] = decodeCorpusJson(files[name]); } catch { bad(); }
  }
  const manifest = parsed['manifest.json'];
  envelope(manifest, 'manifest', ['codecIds', 'lifecycleIds']);
  const all = new Set();
  for (const kind of ['codec', 'lifecycle']) {
    const ids = manifest[`${kind}Ids`], data = parsed[`${kind}.json`];
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 256 || ids.some(id => !full(id, /^[a-z][a-z0-9-]{0,79}$/)) ||
        ids.some((id, index) => index > 0 && id <= ids[index - 1])) bad();
    for (const id of ids) { if (all.has(id)) bad(); all.add(id); }
    envelope(data, kind, ['cases']);
    if (!Array.isArray(data.cases) || data.cases.length !== ids.length) bad();
    data.cases.forEach((item, index) => { if (item.id !== ids[index]) bad(); });
  }
  for (const item of parsed['codec.json'].cases) {
    exact(item, ['id', 'channel', 'input', 'expect']);
    if (!['control', 'stream'].includes(item.channel)) bad();
    renderInput(item.input);
    exact(item.expect, item.expect?.code === 'ok' ? ['code', 'message'] : ['code']);
  }
  for (const item of parsed['lifecycle.json'].cases) {
    exact(item, ['id', 'pool', 'initialClock', 'controls', 'steps']);
    exact(item.pool, ['maxSessions', 'maxStreams', 'maxBytes']);
    if (!integer(item.pool.maxSessions, 1, 16) || !integer(item.pool.maxStreams, 1, 256) || !integer(item.pool.maxBytes, 1, 16777216)) bad();
    clock(item.initialClock);
    if (!item.controls || typeof item.controls !== 'object' || Array.isArray(item.controls) || Object.keys(item.controls).length > 2048) bad();
    for (const [name, definition] of Object.entries(item.controls)) {
      reference(name); exact(definition, ['deviceId', 'desktopId', 'supportedCapabilities']);
    }
    if (!Array.isArray(item.steps) || item.steps.length < 1 || item.steps.length > 2048) bad();
    item.steps.forEach(validateOperation);
  }
  return { manifest, codec: parsed['codec.json'].cases, lifecycle: parsed['lifecycle.json'].cases, corpusSha256: hash.digest('hex') };
}

function runTrace(item) {
  const pool = new CompanionBudgetPool(item.pool), controlObjects = new Map(), streamObjects = new Map(), refs = new Map();
  const get = (map, ref) => { if (!map.has(ref)) bad(); return map.get(ref); };
  const snapshot = () => ({ pool: pool.snapshot(),
    controls: Object.fromEntries([...controlObjects.keys()].sort().map(ref => [ref, controlObjects.get(ref).snapshot()])),
    streams: Object.fromEntries([...streamObjects.keys()].sort().map(ref => [ref,
      { control: refs.get(streamObjects.get(ref)).control, ...streamObjects.get(ref).snapshot() }])) });
  return item.steps.map(step => {
    const now = step.clock ?? item.initialClock;
    let outcome = { code: 'ok', effects: [] };
    const target = () => Object.hasOwn(step, 'control') ? get(controlObjects, step.control) : get(streamObjects, step.stream);
    switch (step.op) {
      case 'create_control': {
        if (controlObjects.has(step.control) || !Object.hasOwn(item.controls, step.control)) bad();
        controlObjects.set(step.control, new CompanionControl({ pool, ...item.controls[step.control], clock: now })); break;
      }
      case 'control_text': outcome = get(controlObjects, step.control).text(step.direction, renderInput(step.input), now); break;
      case 'control_activity': outcome = get(controlObjects, step.control).activity(step.direction, now); break;
      case 'allocate_stream': {
        if (streamObjects.has(step.stream)) bad();
        outcome = get(controlObjects, step.control).allocateStream(step.deviceId, step.sessionHeader, now);
        if (outcome.code === 'ok') {
          streamObjects.set(step.stream, outcome.stream); refs.set(outcome.stream, { stream: step.stream, control: step.control });
        }
        break;
      }
      case 'stream_text': outcome = get(streamObjects, step.stream).text(step.direction, renderInput(step.input), now); break;
      case 'binary': outcome = get(streamObjects, step.stream).binary(step.direction, renderInput(step.input), now); break;
      case 'peek': outcome = get(streamObjects, step.stream).peek(step.direction, step.count, now); break;
      case 'drain': outcome = get(streamObjects, step.stream).drain(step.direction, step.count, now); break;
      case 'local_cancel': outcome = target().localCancel(now); break;
      case 'tick': outcome = target().tick(now); break;
      case 'ws_closed': outcome = target().wsClosed(step.closeCode, now); break;
      case 'resources_closed': outcome = target().resourcesClosed(now); break;
      case 'snapshot': break;
      default: bad();
    }
    const effects = outcome.effects.map(effect => {
      const reference = refs.get(effect.stream); if (!reference || effect.type !== 'write_eof') bad();
      return { type: 'write_eof', stream: reference.stream, direction: effect.direction };
    }).sort((a, b) => a.stream < b.stream ? -1 : a.stream > b.stream ? 1 : a.direction < b.direction ? -1 : a.direction > b.direction ? 1 : 0);
    return { code: ['tick', 'ws_closed', 'resources_closed', 'snapshot'].includes(step.op) ? 'ok' : outcome.code,
      effects, snapshot: snapshot(), ...(step.op === 'peek' && outcome.code === 'ok' ? { peekHex: outcome.bytes.toString('hex') } : {}) };
  });
}
export function executeCorpus(corpus) {
  return { format: 'http-freekit-a19', revision: '0.3', kind: 'results', implementation: 'node', corpusSha256: corpus.corpusSha256,
    codec: corpus.codec.map(item => {
      let actual;
      try { actual = { code: 'ok', message: decodeMessage(item.channel, renderInput(item.input)).toWire() }; }
      catch (error) { actual = { code: ['message_too_large', 'invalid_message', 'unsupported_version'].includes(error.code) ? error.code : 'invalid_message' }; }
      return { id: item.id, actual };
    }), lifecycle: corpus.lifecycle.map(item => ({ id: item.id, steps: runTrace(item) })) };
}
export function runConformance(directory = path.join(ROOT, 'protocol/fixtures/a19-draft-0.3'), output = path.join(ROOT, 'build/reports/draft-protocol/node-conformance.json')) {
  const corpus = loadCorpus(directory), report = executeCorpus(corpus);
  const bytes = Buffer.from(JSON.stringify(report, null, 2) + '\n');
  if (bytes.length > 16 * 1024 * 1024) bad();
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, bytes);
  return { corpusSha256: report.corpusSha256, codecIds: report.codec.map(c => c.id), lifecycleIds: report.lifecycle.map(c => c.id),
    codecCount: report.codec.length, lifecycleCount: report.lifecycle.length, stepCount: report.lifecycle.reduce((n, c) => n + c.steps.length, 0) };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = {};
    for (let i = 2; i < process.argv.length; i += 2) {
      const key = process.argv[i];
      if (!['--fixtures', '--output'].includes(key) || options[key] || !process.argv[i + 1]) bad();
      options[key] = process.argv[i + 1];
    }
    console.log(JSON.stringify(runConformance(options['--fixtures'], options['--output'])));
  } catch { console.error('companion_conformance_failed'); process.exitCode = 1; }
}
