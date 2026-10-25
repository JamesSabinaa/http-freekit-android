import { createEnrollmentSuiteInvocationParser, EnrollmentRuntimeError } from './enrollment-runtime-results.mjs';
import { captureFactoryMethod } from './capture-factory-descriptor.mjs';
export * from './capture-factory-descriptor.mjs';

export function createCaptureFactoryInvocationParser({ onPhase } = {}) {
  return createEnrollmentSuiteInvocationParser(captureFactoryMethod, { onPhase, suite: 'c2' });
}
export function parseCaptureFactoryInvocation(output, commandResult) {
  const parser = createCaptureFactoryInvocationParser();
  try { parser.push(typeof output === 'string' ? Buffer.from(output) : output); }
  catch (error) { if (!(error instanceof EnrollmentRuntimeError)) throw error; }
  return parser.finish(commandResult);
}
