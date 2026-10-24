import { EnrollmentCorpusError, loadEnrollmentCorpus, enrollmentCorpusSummary } from './enrollment-corpus.mjs';

try {
  const args = process.argv.slice(2);
  if (args.length !== 0 && !(args.length === 2 && args[0] === '--corpus')) throw new EnrollmentCorpusError('invalid_arguments');
  console.log(JSON.stringify(enrollmentCorpusSummary(loadEnrollmentCorpus(args[1]))));
} catch (error) {
  if (!(error instanceof EnrollmentCorpusError)) throw error;
  console.error(JSON.stringify({ ok: false, code: error.code })); process.exitCode = 1;
}
