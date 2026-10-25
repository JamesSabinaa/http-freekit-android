// One bounded shared vector file, not a transport or an alternative HTTP parser.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { decodeCorpusJson } from './companion-protocol-codec.mjs';
const defaultFile = fileURLToPath(new URL('../../protocol/fixtures/c2-draft-0.5/wire.json', import.meta.url));
const fail = () => { throw Error('invalid_http_origin_vectors'); };
const full = (value, pattern) => typeof value === 'string' && pattern.exec(value)?.[0] === value;
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const exact = (value, names) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== names.length || Object.keys(value).some(key => !names.includes(key))) fail();
};
const hex = value => full(value, /^(?:[0-9a-f]{2})*$/) && value.length <= 131072;
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
export function loadHttpOriginVectors(filename = defaultFile) {
  let descriptor;
  try {
    const before = fs.lstatSync(filename); if (!before.isFile() || before.isSymbolicLink() || before.size < 1 || before.size > 131072) fail();
    descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = fs.fstatSync(descriptor); if (!stat.isFile() || stat.size !== before.size || stat.ino !== before.ino || stat.dev !== before.dev) fail();
    const buffer = Buffer.alloc(stat.size + 1); let size = 0;
    while (size < buffer.length) { const count = fs.readSync(descriptor, buffer, size, buffer.length - size, null); if (!count) break; size += count; }
    if (size !== stat.size) fail();
    const raw = buffer.subarray(0, size), value = decodeCorpusJson(raw);
    exact(value, ['format', 'revision', 'requests', 'opens', 'responses', 'prefaces']);
    if (value.format !== 'http-freekit-http-origin-vectors' || value.revision !== 1) fail();
    const identifiers = new Set();
    for (const group of ['requests', 'opens', 'responses', 'prefaces']) {
      const cases = value[group]; if (!Array.isArray(cases) || cases.length < 1 || cases.length > 64) fail();
      for (const entry of cases) {
        exact(entry, ['id', ...(group === 'requests' ? ['addressHex','port'] : group === 'opens' ? ['wireHex'] : ['chunksHex']), 'expect']);
        if (!full(entry.id, /^[a-z0-9-]{1,80}$/) || identifiers.has(entry.id)) fail(); identifiers.add(entry.id);
        if (group === 'requests' && (!hex(entry.addressHex) || !integer(entry.port, -1, 65536))) fail();
        if (group === 'opens' && !hex(entry.wireHex)) fail();
        if (['responses','prefaces'].includes(group)) {
          if (!Array.isArray(entry.chunksHex) || entry.chunksHex.length < 1 || entry.chunksHex.length > 128 ||
              !entry.chunksHex.every(hex) || entry.chunksHex.reduce((sum, chunk) => sum + chunk.length / 2, 0) > 65536) fail();
        }
        const expect = entry.expect;
        if (!expect || !['accepted','rejected'].includes(expect.outcome)) fail();
        if (expect.outcome === 'rejected') {
          exact(expect, group === 'opens' ? ['outcome','code'] : ['outcome']);
          if (group === 'opens' && !['invalid_message','unsupported_version','message_too_large'].includes(expect.code)) fail();
        } else {
          exact(expect, ['outcome', ...(group === 'requests' ? ['wireHex'] : group === 'opens' ? ['canonicalHex'] : group === 'responses' ? ['remainingHex'] : ['family','addressHex','headHex'])]);
          for (const [key, data] of Object.entries(expect)) if (key.endsWith('Hex') && !hex(data)) fail();
          if (group === 'prefaces' && (![4,6].includes(expect.family) || expect.addressHex.length !== (expect.family === 4 ? 8 : 32))) fail();
        }
      }
    }
    const after = fs.fstatSync(descriptor);
    if (after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ino !== stat.ino || after.dev !== stat.dev) fail();
    return freeze({ sha256: createHash('sha256').update(raw).digest('hex'), requests: value.requests, opens: value.opens, responses: value.responses, prefaces: value.prefaces });
  } catch { fail(); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}
