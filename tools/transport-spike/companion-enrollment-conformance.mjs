// Actual execution only. Independent fixture expectations are never actual-result inputs.
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadEnrollmentCorpus, ENROLLMENT_REPORT_LIMIT } from '../../scripts/enrollment-corpus.mjs';
import { decodeEnrollment, encodeEnrollment, enrollmentProofPayload,
  enrollmentComparisonCode } from './companion-enrollment-codec.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const rejected = () => ({ ok: false, code: 'invalid_message' });
function codecActual(item) {
  const decoded = decodeEnrollment(item.channel, Buffer.from(item.wireHex, 'hex'));
  return decoded.ok ? { ok: true, canonicalSha256: sha(encodeEnrollment(decoded.message)) } : decoded;
}
function proofActual(item) {
  const decoded = decodeEnrollment('challenge_response', Buffer.from(item.challengeWireHex, 'hex'));
  if (!decoded.ok) return decoded;
  try { return { ok: true, payloadSha256: sha(enrollmentProofPayload(item.context, decoded.message)) }; }
  catch { return rejected(); }
}
function comparisonActual(item) {
  try { return { ok: true, value: enrollmentComparisonCode(item.gatewayPin, item.deviceHash) }; }
  catch { return rejected(); }
}

export function executeEnrollmentCorpus(corpus) {
  return { format: 'http-freekit-a21', revision: '0.4', kind: 'results', implementation: 'node',
    corpusSha256: corpus.digest,
    codec: corpus.codec.map(item => ({ id: item.id, actual: codecActual(item) })),
    proof: corpus.proof.map(item => ({ id: item.id, actual: proofActual(item) })),
    comparison: corpus.comparison.map(item => ({ id: item.id, actual: comparisonActual(item) })) };
}
export function writeEnrollmentConformance({ corpusDirectory,
  output = path.join(ROOT, 'build/reports/draft-enrollment/node-conformance.json') } = {}) {
  const corpus = loadEnrollmentCorpus(corpusDirectory);
  const report = executeEnrollmentCorpus(corpus);
  const encoded = Buffer.from(JSON.stringify(report));
  if (encoded.length > ENROLLMENT_REPORT_LIMIT) throw Error('enrollment_report_limit');
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, encoded);
  return { corpus, report };
}
