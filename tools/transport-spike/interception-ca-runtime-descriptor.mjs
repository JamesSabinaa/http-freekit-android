// Finite A23b Android method; original prepare/reopen A22 invocations remain canonical there.
export const interceptionCaRuntimeClass = 'com.httpfreekit.interop.DraftInterceptionCaInteropTest';
export const interceptionCaRuntimeMethod = 'retrieveSavedApprovedCaAfterRestart';
export const interceptionCaRuntimePhases = Object.freeze([
  'saved-key-approval-validated', 'ca-fetched-and-bound', 'getter-resources-joined',
]);
export const interceptionCaRuntimeObservationSuffixes = Object.freeze([
  'Version', 'FetchAttempts', 'CaBytes', 'SavedApprovalValidated', 'OriginalKeyUnchanged',
  'PrivateKeyNonexportable', 'RecoveryUnchanged', 'ApprovedCaHashMatched',
  'CredentialLeafUnchanged', 'FreshLookupAfterFetch', 'Closed', 'ActiveCall',
  'RawSocketOwned', 'TlsSocketOwned', 'DeadlineAlive', 'TlsCloserAlive', 'CleanupFailed',
]);
export const interceptionCaRuntimeReportPaths = Object.freeze({
  runtime: 'tools/transport-spike/android/build/outputs/androidTest-results/interception-ca/debug/runtime.json',
  xml: 'tools/transport-spike/android/build/outputs/androidTest-results/interception-ca/debug/TEST-interception-ca-research.xml',
  html: 'tools/transport-spike/android/build/reports/androidTests/interception-ca/debug/index.html',
  host: 'build/reports/interception-ca-runtime/host-cleanup.json',
});
