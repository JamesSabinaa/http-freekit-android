// Finite suite selection; the fixed A22a/A23 restart flow lives in the CA driver.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
export { registerEnrollmentReverses, enrollmentOwnedReversesAbsent } from './enrollment-runtime-host.mjs';

export function enrollmentRuntimeOptions(args, env = process.env) {
  const options = { adb: env.ANDROID_HOME ? path.join(env.ANDROID_HOME, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb') : 'adb',
    openssl: env.OPENSSL_BIN ?? 'openssl', suite: 'a22a' };
  const seen = new Set();
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i], value = args[i + 1];
    if (!['--serial', '--adb', '--openssl', '--suite', '--desktop-root', '--desktop-commit'].includes(name) || seen.has(name) || typeof value !== 'string' ||
        !value || value.length > 4096 || /[\0\r\n]/.test(value)) throw Error('invalid_enrollment_arguments');
    seen.add(name); options[name === '--desktop-root' ? 'desktopRoot' : name === '--desktop-commit' ? 'desktopCommit' : name.slice(2)] = value;
  }
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(options.serial ?? '')) throw Error('explicit_enrollment_serial_required');
  if (!['a22a', 'a22b', 'a22c', 'a23', 'c2', 'c5'].includes(options.suite)) throw Error('invalid_enrollment_arguments');
  if (options.suite === 'c2' || options.suite === 'c5') {
    if (!options.desktopRoot || !path.isAbsolute(options.desktopRoot) || !/^[0-9a-f]{40}$/.test(options.desktopCommit ?? '') || options.desktopCommit.length !== 40) throw Error('invalid_enrollment_arguments');
    if (options.suite === 'c5' && options.desktopCommit !== '2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6') throw Error('invalid_enrollment_arguments');
  } else if (seen.has('--desktop-root') || seen.has('--desktop-commit')) throw Error('invalid_enrollment_arguments');
  return Object.freeze(options);
}
export async function runEnrollmentRuntime(options) {
  if (options.suite === 'c5') {
    const { runEnrolledTunRuntime } = await import('./run-enrolled-tun-runtime.mjs');
    return runEnrolledTunRuntime(options);
  }
  if (options.suite === 'c2') {
    const { runCaptureFactoryRuntime } = await import('./run-capture-factory-runtime.mjs');
    return runCaptureFactoryRuntime(options);
  }
  if (options.suite === 'a22c') {
    const { runEnrollmentAdversarialRuntime } = await import('./run-enrollment-adversarial-runtime.mjs');
    return runEnrollmentAdversarialRuntime(options);
  }
  if (options.suite === 'a22b') {
    const { runEnrolledStreamRuntime } = await import('./run-enrolled-stream-runtime.mjs');
    return runEnrolledStreamRuntime(options);
  }
  const { runInterceptionCaRuntime } = await import('./run-interception-ca-runtime.mjs');
  return runInterceptionCaRuntime(options);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { if (!(await runEnrollmentRuntime(enrollmentRuntimeOptions(process.argv.slice(2)))).ok) process.exitCode = 1; }
  catch { console.error('Enrollment runtime driver failed; inspect bounded reports when available.'); process.exitCode = 1; }
}
