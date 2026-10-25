// Finite C5 research contract; these constants do not establish Android execution.
export const enrolledTunClass = 'com.httpfreekit.interop.DraftEnrolledTunInteropTest';
export const enrolledTunMethod = 'selectedUidHttpReachesEnrolledDesktopThroughTun';
export const enrolledTunPhases = Object.freeze([
  'input-consumed', 'strict-csr-reserved', 'awaiting-host-approval',
  'credential-saved-reloaded', 'vpn-consent-granted', 'tun-native-active',
  'selected-uid-route-observed', 'http-command-started', 'http-response-validated',
  'local-stream-drained', 'gateway-complete-acknowledged', 'capture-stop-joined',
  'non-vpn-route-observed', 'traffic-worker-joined', 'owned-state-forgotten',
]);
export const enrolledTunPayload = Object.freeze({
  address: '198.18.0.2', prefix: 32, port: 80, trafficCommand: 19,
  method: 'POST', path: '/factory-research', logicalHost: 'capture-origin.invalid',
  requestBodyBytes: 16421, requestBodySha256: 'd4cc764821eb57cbfff27c890ae26b2648a3f7a5c296698831124f02b25c3529',
  responseBodyBytes: 32787, responseBodySha256: '62a22a63bb850ba7b263fccff99e868133570394d36d6ee16fd32e9d7c1a4601',
  gatewayCapabilities: Object.freeze(['tcp-http-origin-connect', 'tcp-https-connect']),
});
export const enrolledTunAcknowledgment = Object.freeze({
  path: 'no_backup/draft-enrollment-research/tun-complete-v1.bin',
  bytes: 'FREEKIT-C5-COMPLETE-V1\n',
});
export const enrolledTunObservationSuffixes = Object.freeze((
  'Version CredentialSavedReloaded KeyNonexportable OriginalCredentialUnchanged VpnConsentGranted ' +
  'SeparateTrafficUid SelectedUidVpnObserved TunAndNativeObserved ForegroundNotificationObserved ' +
  'HttpAttempts HttpOutputHalfClosed StrictResponseEof LocalStreamsDrained HostCompleteAcknowledged ' +
  'ProtectAttempts ProtectSuccesses BindAttempts BindSuccesses SelectedPackageCount InterceptedTcpFlows ' +
  'DirectTcpFlows UdpTargets Udp443Drops ProtectFailures BindFailures RequestBodyBytes RequestBodySha256 ' +
  'ResponseBodyBytes ResponseBodySha256 CaptureStopped TunClosed NativeStopJoined ConfigurationAbsent LifecycleJoined ' +
  'ActiveFlows OwnedSockets PendingOpens LiveWorkers FactoryClosed FactoryPendingOpens FactoryPendingCalls RetainedTransports ' +
  'FactoryLiveWorkers SessionLease StreamLeases ChargedBytes PendingIngressBytes BackendOutputBytes BackendIncomingBytes ' +
  'NonVpnRouteObserved TrafficWorkerJoined OwnedStateAbsent'
).split(' '));
export const enrolledTunReportPaths = Object.freeze({
  runtime: 'tools/transport-spike/android/build/outputs/androidTest-results/enrolled-tun/debug/runtime.json',
  xml: 'tools/transport-spike/android/build/outputs/androidTest-results/enrolled-tun/debug/TEST-enrolled-tun-research.xml',
  html: 'tools/transport-spike/android/build/reports/androidTests/enrolled-tun/debug/index.html',
  host: 'build/reports/enrolled-tun/host-cleanup.json',
});
