// Research-only coordination schema agreed for decision0012; no production protocol extension.
export const SCENARIOS = Object.freeze(['gated', 'backpressure', 'cancel', 'expiry', 'binding', 'malformed', 'premature']);
export const LIMITS = Object.freeze({ maxFrameBytes: 4096, maxQueuedBytesPerStream: 8192, maxQueuedBytesPerDevice: 16384,
  maxConcurrentStreams: 2, maxQueuedFramesPerStream: 4, maxOpenedStreamsPerSession: 64 });
export const DESKTOP_ID = 'research-desktop';
export const SCENARIO_HEADER = 'x-freekit-research-scenario';
export const SESSION_HEADER = 'x-freekit-session';
export const RESPONSE_HEADER = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 32787\r\nConnection: close\r\n\r\n');
export const RESPONSE_BODY_LENGTH = 32787;
export const COMMANDS = Object.freeze({
  release_response_tail: '{"command":"release_response_tail"}',
  resume_proxy_read: '{"command":"resume_proxy_read"}',
});
export const pausedScenario = scenario => ['backpressure', 'cancel', 'expiry'].includes(scenario);
export const uploadLength = scenario => pausedScenario(scenario) ? 33554432 : 16421;
export const requestHeader = scenario => Buffer.from('POST http://fixture.invalid/research HTTP/1.1\r\nHost: fixture.invalid\r\n' +
  `Content-Length: ${uploadLength(scenario)}\r\nConnection: close\r\n\r\n`);
export function pattern(offset, count, response = false) {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isInteger(count) || count < 0 || count > 4096) throw Error('invalid_pattern_bound');
  const result = Buffer.allocUnsafe(count);
  for (let index = 0; index < count; index++) result[index] = response ? ((offset + index) * 7) % 253 : (offset + index) % 251;
  return result;
}
