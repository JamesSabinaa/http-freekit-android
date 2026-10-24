import { EnrollmentCorpusError } from './enrollment-corpus.mjs';
import { verifyEnrollmentCrashReport } from './enrollment-crash-report.mjs';

try {
  const args = process.argv.slice(2), values = {};
  if (args.length % 2 !== 0) throw new EnrollmentCorpusError('invalid_crash_arguments');
  for (let i = 0; i < args.length; i += 2) {
    if (!['--report', '--source', '--platform', '--started'].includes(args[i]) || Object.hasOwn(values, args[i])) throw new EnrollmentCorpusError('invalid_crash_arguments');
    values[args[i]] = args[i + 1];
  }
  if (values['--started'] !== undefined && values['--started'].match(/^(?:0|[1-9][0-9]{0,9})$/)?.[0] !== values['--started']) throw new EnrollmentCorpusError('invalid_crash_arguments');
  const result = verifyEnrollmentCrashReport(values['--report'] ?? 'build/reports/enrollment-store/crash.json', {
    sourceCommit: values['--source'] ?? process.env.GITHUB_SHA, platform: values['--platform'] ?? process.platform,
    ...(values['--started'] === undefined ? {} : { startedEpochSeconds: Number(values['--started']) }),
  });
  console.log(JSON.stringify(result));
} catch (error) {
  if (!(error instanceof EnrollmentCorpusError)) throw error;
  console.error(JSON.stringify({ ok: false, code: error.code })); process.exitCode = 1;
}
