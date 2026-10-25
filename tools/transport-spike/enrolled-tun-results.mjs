import { createEnrollmentSuiteInvocationParser, EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { enrolledTunMethod } from './enrolled-tun-descriptor.mjs';
export * from './enrolled-tun-descriptor.mjs';

export function createEnrolledTunInvocationParser({ onPhase } = {}) {
  return createEnrollmentSuiteInvocationParser(enrolledTunMethod, { onPhase, suite: 'c5' });
}
export function parseEnrolledTunInvocation(output, commandResult) {
  const parser = createEnrolledTunInvocationParser();
  try { parser.push(typeof output === 'string' ? Buffer.from(output) : output); }
  catch (error) { if (!(error instanceof EnrollmentRuntimeError)) throw error; }
  return parser.finish(commandResult);
}
