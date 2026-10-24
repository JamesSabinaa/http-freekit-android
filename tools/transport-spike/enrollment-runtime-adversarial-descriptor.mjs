export const enrollmentAdversarialClass = 'com.httpfreekit.interop.DraftEnrollmentAdversarialInteropTest';
const prefix = ['input-consumed', 'strict-csr-reserved', 'pending-proof-observed'];
const suffix = ['local-resources-closed', 'owned-state-forgotten'];
const common = 'Version Scenario OriginalKeyUnchanged CredentialSaved OwnedStateAbsent ClientResourcesClosed'.split(' ');
export const enrollmentAdversarialCases = Object.freeze([
  ['purposeContextAndReplayProofsKeepReservationPending', 'proof_misuse',
    ['purpose-proof-rejected', 'wire-context-rejected', 'signed-context-rejected', 'same-challenge-pending', 'replay-rejected', 'fresh-pending-confirmed'],
    'PurposeHttp PurposeCode WireContextHttp WireContextCode SignedContextHttp SignedContextCode SameChallengeHttp SameChallengeType ReplayHttp ReplayCode FreshStatusHttp FreshStatusType BindingUnchanged'],
  ['wrongGatewayPeerFailsTlsWithoutEnrollmentMutation', 'wrong_tls',
    ['alternate-peer-tls-rejected', 'fresh-pending-confirmed'],
    'TlsFailureType FreshStatusHttp FreshStatusType BindingUnchanged ExpectedTrustUnchanged'],
  ['pendingCancellationRejectsLateApprovalWithoutSavingCredential', 'pending_cancel',
    ['signed-cancel-confirmed', 'cancel-replay-rejected', 'fresh-cancelled-confirmed', 'awaiting-late-approval'],
    'CancelHttp CancelCode ReplayHttp ReplayCode FreshStatusHttp FreshStatusCode BindingUnchanged'],
  ['publishedCancellationRevokesSavedCredential', 'published_cancel',
    ['awaiting-host-approval', 'approved-credential-saved-and-reloaded', 'saved-credential-mtls-admitted', 'signed-cancel-confirmed', 'saved-credential-mtls-denied', 'fresh-cancelled-confirmed'],
    'ApprovalHttp ApprovalType SavedCredentialUnchanged BeforeMtlsHttp CancelHttp CancelCode AfterMtlsHttp FreshStatusHttp FreshStatusCode CredentialExpiresUtcMillis RefusalObservedUtcMillis KeyManagerUsableAtRefusal BindingUnchanged'],
].map(([method, scenario, middle, fields]) => Object.freeze({ method, scenario,
  phases: Object.freeze([...prefix, ...middle, ...suffix]), observationSuffixes: Object.freeze([...common, ...fields.split(' ')]) })));
export const expectedEnrollmentAdversarialMethods = Object.freeze(enrollmentAdversarialCases.map(value => value.method));
export const enrollmentAdversarialPhases = Object.freeze(Object.fromEntries(enrollmentAdversarialCases.map(value => [value.method, value.phases])));
export const enrollmentAdversarialScenarios = Object.freeze(Object.fromEntries(enrollmentAdversarialCases.map(value => [value.method, value.scenario])));
export const enrollmentAdversarialReportPaths = Object.freeze({
  runtime: 'tools/transport-spike/android/build/outputs/androidTest-results/enrollment-adversarial/debug/runtime.json',
  xml: 'tools/transport-spike/android/build/outputs/androidTest-results/enrollment-adversarial/debug/TEST-enrollment-adversarial-research.xml',
  html: 'tools/transport-spike/android/build/reports/androidTests/enrollment-adversarial/debug/index.html',
  host: 'build/reports/enrollment-adversarial/host-cleanup.json',
});
