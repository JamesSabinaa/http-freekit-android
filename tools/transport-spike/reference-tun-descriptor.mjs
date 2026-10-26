// Private, independent reference research contract. No production/C5 acceptance.
export const referenceTunClass = 'com.httpfreekit.interop.DraftReferenceTunInteropTest';
export const referenceTunMethods = Object.freeze([
  'selectedUidHttpReachesReferenceOriginThroughTun',
  'selectedUidH1HttpsReachesReferenceOriginThroughTun',
]);
export const referenceTunPrefix = 'draftReferenceTun';
export const referenceTunVersion = 1;
export const referenceTunPhases = Object.freeze([
  'input-consumed', 'strict-csr-reserved', 'awaiting-host-approval',
  'credential-saved-reloaded', 'authenticated-ca-fetched', 'vpn-consent-granted',
  'tun-native-active', 'selected-uid-route-observed', 'traffic-command-started',
  'traffic-response-validated', 'local-stream-drained', 'gateway-complete-acknowledged',
  'capture-stop-joined', 'non-vpn-route-observed', 'traffic-worker-joined', 'owned-state-forgotten',
]);
export const referenceTunAcknowledgment = Object.freeze({
  path: 'no_backup/draft-enrollment-research/reference-tun-complete-v1.bin',
  pendingPath: 'no_backup/draft-enrollment-research/.reference-tun-complete-v1.pending',
  bytes: 'FREEKIT-REFERENCE-TUN-COMPLETE-V1\n',
});
export const referenceTunPayload = Object.freeze({ address: '198.18.0.2', logicalHost: 'reference-target.invalid',
  method: 'POST', path: '/reference/proof', requestBodyBytes: 4096, responseBodyBytes: 81,
  commands: Object.freeze([20, 21]), ports: Object.freeze([80, 443]),
  gatewayCapabilities: Object.freeze(['tcp-http-origin-connect', 'tcp-https-connect']) });
const flags = ('CredentialSavedReloaded KeyNonexportable OriginalCredentialUnchanged AuthenticatedCaFetched ' +
  'SeparateTrafficUid VpnConsentGranted SelectedUidVpnObserved TunAndNativeObserved ForegroundNotificationObserved ' +
  'RequestBodyValidated ResponseBodyValidated OutputHalfClosed StrictResponseEof SocketClosed LocalStreamsDrained ' +
  'HostCompleteAcknowledged CaptureStopped TunClosed NativeStopJoined ConfigurationAbsent LifecycleJoined FactoryClosed ' +
  'NonVpnRouteObserved TrafficWorkerJoined ConsentUiDestroyed OwnedStateAbsent').split(' ');
const zero = ('DirectTcpFlows UdpTargets Udp443Drops ProtectFailures BindFailures ActiveFlows OwnedSockets PendingOpens LiveWorkers ' +
  'FactoryPendingOpens FactoryPendingCalls RetainedTransports FactoryLiveWorkers StreamLeases ChargedBytes PendingIngressBytes ' +
  'BackendOutputBytes BackendIncomingBytes').split(' ');
// Canonical observation bundle emitted once with STATUS_CODE=3 after the final phase.
// Exact keys are prefix + suffix; booleans are true/false, integers canonical decimal.
// Never emit digests, identity, certificate, provider diagnostics, or traffic bytes.
export const referenceTunObservationTypes = Object.freeze(Object.fromEntries([
  ['Version', 'version'], ...flags.map(key => [key, 'true']), ['SessionLease', 'false'],
  ...zero.map(key => [key, 'zero']),
  ...['TrafficAttempts', 'SelectedPackageCount', 'InterceptedTcpFlows'].map(key => [key, 'one']),
  ...['ProtectAttempts', 'ProtectSuccesses', 'BindAttempts', 'BindSuccesses'].map(key => [key, 'guard']),
  ['ResponseBodyBytes', 'responseBytes'], ['TlsUsed', 'https'], ['TlsPeerVerified', 'https'], ['TlsAlpnH1', 'alpn'],
]));
export const referenceTunFailureCategories = Object.freeze([
  'none', 'assertion', 'timeout', 'cancelled', 'enrollment', 'ca', 'consent', 'capture', 'cleanup',
  ...['configuration', 'connect', 'tls', 'write', 'shutdown', 'reply', 'eof', 'close'].map(value => 'traffic_reference_' + value),
]);
// Failure line: Reference TUN research failed at <phase> type=<AssertionError|IOException|IllegalStateException|SecurityException|TimeoutException|Other> category=<allowlist> cleanup=<true|false>
export const referenceTunFailureTypes = Object.freeze(['AssertionError', 'IOException', 'IllegalStateException', 'SecurityException', 'TimeoutException', 'Other']);
export const referenceTunReportPaths = Object.freeze({
  runtime: 'tools/transport-spike/android/build/outputs/androidTest-results/reference-tun/debug/runtime.json',
  xml: 'tools/transport-spike/android/build/outputs/androidTest-results/reference-tun/debug/TEST-reference-tun-research.xml',
  html: 'tools/transport-spike/android/build/reports/androidTests/reference-tun/debug/index.html',
  host: 'build/reports/reference-tun/host-cleanup.json',
});
export const referenceTunReportFormat = 'http-freekit-reference-tun-runtime';
