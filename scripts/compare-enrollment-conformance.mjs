import { EnrollmentCorpusError, loadEnrollmentCorpus, compareEnrollmentReports } from './enrollment-corpus.mjs';

try {
  const args = process.argv.slice(2), options = {};
  if (args.length % 2 !== 0) throw new EnrollmentCorpusError('invalid_arguments');
  for (let i = 0; i < args.length; i += 2) {
    if (!['--corpus', '--kotlin', '--node'].includes(args[i]) || Object.hasOwn(options, args[i])) throw new EnrollmentCorpusError('invalid_arguments');
    options[args[i]] = args[i + 1];
  }
  const corpus = loadEnrollmentCorpus(options['--corpus']);
  console.log(JSON.stringify(compareEnrollmentReports(corpus,
    options['--kotlin'] ?? 'build/reports/draft-enrollment/kotlin-conformance.json',
    options['--node'] ?? 'build/reports/draft-enrollment/node-conformance.json')));
} catch (error) {
  if (!(error instanceof EnrollmentCorpusError)) throw error;
  console.error(JSON.stringify({ ok: false, code: error.code })); process.exitCode = 1;
}
