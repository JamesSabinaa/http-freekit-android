export const enrolledStreamingClass = 'com.httpfreekit.interop.DraftEnrolledStreamingInteropTest';
const prefix = ['input-consumed', 'strict-csr-reserved', 'pending-proof-observed', 'awaiting-host-approval',
  'credential-saved-and-reloaded', 'bounded-stream-ready', 'application-writer-blocked'];
const suffix = ['terminal-owner-observed', 'admission-policy-verified', 'stream-resources-closed', 'owned-state-forgotten'];
export const enrolledStreamingCases = Object.freeze([
  ['revocationClosesSavedCredentialBlockedSession', 'revocation', 'awaiting-host-revocation', 120000],
  ['credentialExpiryClosesSavedCredentialBlockedSession', 'credential_expiry', 'awaiting-credential-expiry', 120000],
  ['sessionExpiryClosesSavedCredentialBlockedSession', 'session_expiry', 'awaiting-session-expiry', 15000],
].map(([method, scenario, waitPhase, sessionLifetimeMillis], index) => Object.freeze({ method, scenario, inputScenario: index + 1,
  credentialLifetimeSeconds: 60, sessionLifetimeMillis, phases: Object.freeze([...prefix, waitPhase, ...suffix]) })));
export const expectedEnrolledStreamingMethods = Object.freeze(enrolledStreamingCases.map(value => value.method));
export const enrolledStreamingScenarios = Object.freeze(Object.fromEntries(enrolledStreamingCases.map(value => [value.method, value.scenario])));
export const enrolledStreamingPhases = Object.freeze(Object.fromEntries(enrolledStreamingCases.map(value => [value.method, value.phases])));
export const enrolledStreamingReportPaths = Object.freeze({
  runtime: 'tools/transport-spike/android/build/outputs/androidTest-results/enrollment-streaming/debug/runtime.json',
  xml: 'tools/transport-spike/android/build/outputs/androidTest-results/enrollment-streaming/debug/TEST-enrolled-stream-research.xml',
  html: 'tools/transport-spike/android/build/reports/androidTests/enrollment-streaming/debug/index.html',
  host: 'build/reports/enrollment-streaming/host-cleanup.json',
});
export const enrolledObservationSuffixes = Object.freeze(('Version Scenario CredentialExpiresUtcMillis GatewayExpiresUtcMillis AnchorExpiresUtcMillis ' +
  'PolicyMillis ReadinessObservedUtcMillis SessionExpiresUtcMillis TerminalObservedUtcMillis TerminalObservedElapsedMillis LocalCause ' +
  'ApplicationWriteEntered ApplicationWriteCompleted ApplicationWriteInFlight ApplicationPendingBytes ApplicationChargedBytes ApplicationChargedFrames ' +
  'ApplicationBlockedMillis PrefixBytes LocalTicks ControlInactive StreamInactive SameCredential FreshAdmission OldSessionRejected NewControlAdmitted ' +
  'NewControlObservedUtcMillis SocketsClosed WorkersJoined OwnedThreadsAlive SessionLeases StreamLeases ChargedBytes PendingCallbacks Timers').split(' '));
