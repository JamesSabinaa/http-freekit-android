// Finite C2 Android research contract. These constants do not establish execution.
export const captureFactoryClass = 'com.httpfreekit.interop.DraftCaptureFactoryInteropTest';
export const captureFactoryMethod = 'enrolledHttpOriginUsesProtectedGateway';
export const captureFactoryPhases = Object.freeze([
  'input-consumed', 'strict-csr-reserved', 'awaiting-host-approval',
  'credential-saved-reloaded', 'vpn-consent-bound', 'factory-opened',
  'application-output-shut', 'reply-bytes-eof-validated',
  'factory-resources-joined', 'owned-state-forgotten',
]);
export const captureFactoryObservationSuffixes = Object.freeze((
  'Version CredentialSavedReloaded KeyNonexportable OriginalCredentialUnchanged VpnConsentGranted NoTunEstablished ' +
  'ProtectAttempts ProtectSuccesses BindAttempts BindSuccesses RequestBodyBytes ResponseBodyBytes ResponseBodySha256 ' +
  'ApplicationOutputHalfClosed StrictResponseEof FactoryClosed PendingOpens PendingCalls RetainedTransports LiveWorkers ' +
  'SessionLease StreamLeases ChargedBytes PendingIngressBytes BackendOutputBytes BackendIncomingBytes ' +
  'RelayJoined ServiceObserverJoined ServiceDestroyed OwnedStateAbsent'
).split(' '));
export const captureFactoryPayload = Object.freeze({
  method: 'POST', path: '/factory-research', logicalHost: 'factory-origin.invalid',
  requestBodyBytes: 16421, requestBodySha256: 'd4cc764821eb57cbfff27c890ae26b2648a3f7a5c296698831124f02b25c3529',
  responseBodyBytes: 32787, responseBodySha256: '62a22a63bb850ba7b263fccff99e868133570394d36d6ee16fd32e9d7c1a4601',
});
export const captureFactoryReportPaths = Object.freeze({
  runtime: 'tools/transport-spike/android/build/outputs/androidTest-results/capture-factory/debug/runtime.json',
  xml: 'tools/transport-spike/android/build/outputs/androidTest-results/capture-factory/debug/TEST-capture-factory-research.xml',
  html: 'tools/transport-spike/android/build/reports/androidTests/capture-factory/debug/index.html',
  host: 'build/reports/capture-factory/host-cleanup.json',
});
