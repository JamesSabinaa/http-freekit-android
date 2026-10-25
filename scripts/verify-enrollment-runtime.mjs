import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { decodeEnrollmentRuntime, decodeEnrollmentHostCleanup, enrollmentReportPaths, enrollmentRuntimeLimits,
  verifyEnrollmentRuntime, verifyEnrollmentHostCleanup, enrollmentRuntimeXml, enrollmentRuntimeHtml, EnrollmentRuntimeError } from '../tools/transport-spike/enrollment-runtime-results.mjs';
import { decodeEnrolledStreamingReport, verifyEnrolledStreamingReport, enrolledStreamingRuntimeXml, enrolledStreamingRuntimeHtml,
  enrolledStreamingReportPaths } from '../tools/transport-spike/enrollment-runtime-stream-results.mjs';
import { decodeEnrollmentAdversarialReport, verifyEnrollmentAdversarialReport, enrollmentAdversarialRuntimeXml, enrollmentAdversarialRuntimeHtml,
  enrollmentAdversarialReportPaths } from '../tools/transport-spike/enrollment-runtime-adversarial-results.mjs';
import { decodeCaptureFactoryReport, verifyCaptureFactoryReport, captureFactoryRuntimeXml, captureFactoryRuntimeHtml,
  captureFactoryReportPaths } from '../tools/transport-spike/capture-factory-results.mjs';
import { decodeEnrolledTunReport, verifyEnrolledTunReport, enrolledTunRuntimeXml, enrolledTunRuntimeHtml,
  enrolledTunReportPaths, enrolledTunDesktopCommit } from '../tools/transport-spike/enrolled-tun-results.mjs';
const adapters = Object.freeze({
  a22a: [enrollmentReportPaths, decodeEnrollmentRuntime, verifyEnrollmentRuntime, enrollmentRuntimeXml, enrollmentRuntimeHtml],
  a22b: [enrolledStreamingReportPaths, decodeEnrolledStreamingReport, verifyEnrolledStreamingReport, enrolledStreamingRuntimeXml, enrolledStreamingRuntimeHtml],
  a22c: [enrollmentAdversarialReportPaths, decodeEnrollmentAdversarialReport, verifyEnrollmentAdversarialReport, enrollmentAdversarialRuntimeXml, enrollmentAdversarialRuntimeHtml],
  c2: [captureFactoryReportPaths, decodeCaptureFactoryReport, verifyCaptureFactoryReport, captureFactoryRuntimeXml, captureFactoryRuntimeHtml],
  c5: [enrolledTunReportPaths, decodeEnrolledTunReport, verifyEnrolledTunReport, enrolledTunRuntimeXml, enrolledTunRuntimeHtml],
});

export function readEnrollmentRuntimeFile(file, limit, started) {
  let descriptor;
  try {
    if (typeof file !== 'string' || !file || file.length > 4096) throw Error();
    const before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink()) throw Error();
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || before.dev !== stat.dev || before.ino !== stat.ino || stat.size > limit ||
        stat.mtimeMs < started * 1000 || stat.mtimeMs > Date.now() + 2000) throw Error();
    const bytes = Buffer.alloc(stat.size + 1);
    let total = 0;
    while (total < bytes.length) {
      const count = fs.readSync(descriptor, bytes, total, bytes.length - total, null);
      if (!count) break; total += count;
    }
    const after = fs.fstatSync(descriptor), current = fs.lstatSync(file);
    if (total !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs ||
        current.dev !== stat.dev || current.ino !== stat.ino || current.isSymbolicLink()) throw Error();
    return bytes.subarray(0, total);
  } catch { throw new EnrollmentRuntimeError('runtime_file_unavailable_or_stale'); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}
export function verifyEnrollmentRuntimeFiles({ runtime, host, xml, html, source, api, started, suite = 'a22a', desktopSource }) {
  if (typeof source !== 'string' || source.length !== 40 || !/^[0-9a-f]{40}$/.test(source) || ![26, 37].includes(api) ||
      !Number.isSafeInteger(started) || started < 946684800 || started > 4102444800 || !Object.hasOwn(adapters, suite)) throw new EnrollmentRuntimeError('invalid_runtime_arguments');
  const desktopSuite = suite === 'c2' || suite === 'c5';
  if (desktopSuite ? typeof desktopSource !== 'string' || desktopSource.length !== 40 || !/^[0-9a-f]{40}$/.test(desktopSource) : desktopSource !== undefined) throw new EnrollmentRuntimeError('invalid_runtime_arguments');
  if (suite === 'c5' && desktopSource !== enrolledTunDesktopCommit) throw new EnrollmentRuntimeError('invalid_runtime_arguments');
  const [paths, decode, verify, renderXml, renderHtml] = adapters[suite];
  const report = decode(readEnrollmentRuntimeFile(runtime ?? paths.runtime, enrollmentRuntimeLimits.runtime, started));
  const cleanup = decodeEnrollmentHostCleanup(readEnrollmentRuntimeFile(host ?? paths.host, enrollmentRuntimeLimits.host, started), { suite });
  const result = verify(report, { source, api, ...(desktopSuite ? { desktopCommit: desktopSource } : {}) });
  verifyEnrollmentHostCleanup(cleanup, { source, api, suite });
  for (const [file, expected] of [[xml ?? paths.xml, renderXml(report)], [html ?? paths.html, renderHtml(report)]]) {
    if (!readEnrollmentRuntimeFile(file, enrollmentRuntimeLimits.rendered, started).equals(Buffer.from(expected))) throw new EnrollmentRuntimeError('runtime_projection_mismatch');
  }
  return result;
}
function main(args) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/verify-enrollment-runtime.mjs --source COMMIT --api 26|37 --started EPOCH_SECONDS [--suite a22a|a22b|a22c|c2|c5] [--desktop-source COMMIT for c2/c5] [--runtime FILE] [--host FILE] [--xml FILE] [--html FILE]'); return;
  }
  const options = {}, names = new Set(['--runtime', '--host', '--xml', '--html', '--source', '--api', '--started', '--suite', '--desktop-source']);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index], value = args[index + 1];
    const key = name === '--desktop-source' ? 'desktopSource' : name.slice(2);
    if (!names.has(name) || !value || Object.hasOwn(options, key)) throw new EnrollmentRuntimeError('invalid_runtime_arguments');
    options[key] = value;
  }
  if (!['26', '37'].includes(options.api) || !/^[1-9][0-9]{8,9}$/.test(options.started ?? '') || String(Number(options.started)) !== options.started) throw new EnrollmentRuntimeError('invalid_runtime_arguments');
  options.api = Number(options.api); options.started = Number(options.started);
  const result = verifyEnrollmentRuntimeFiles(options);
  console.log(`${options.suite === 'c5' ? 'C5' : options.suite === 'c2' ? 'C2' : options.suite === 'a22c' ? 'A22c' : options.suite === 'a22b' ? 'A22b' : 'A22a'} verified: ${result.methods} exact methods, ${result.actualStarted} starts, ${result.actualCompleted} completions; API ${result.api}; source ${result.source}; all cleanup joined.`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(process.argv.slice(2)); }
  catch (error) { console.error(`Enrollment verification failed: ${error instanceof EnrollmentRuntimeError ? error.code : 'runtime_verification_failed'}.`); process.exitCode = 1; }
}
