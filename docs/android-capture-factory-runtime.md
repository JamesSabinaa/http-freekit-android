# Android enrolled capture factory research contract

This is the finite reporting contract for the [C2 factory experiment](capture-transport.md).
It does not establish Android execution. It reuses the existing enrollment
input-v1.bin, private run-as input delivery, proof/client/store helpers, strict
clock gate and owned host/ADB/emulator cleanup. The only additional instrumentation
argument is public numeric `webSocketPort`, 1–65535 and distinct from the two
enrollment ports. No private key or pairing material enters arguments, environment
variables, phases, observations, XML or HTML.

## One actual method

Run exactly once on each selected API26/37:
`com.httpfreekit.interop.DraftCaptureFactoryInteropTest#enrolledHttpOriginUsesProtectedGateway`.
Require its actual paired start/completion, terminal success, the ten ordered
phases below and one complete observation. A method failure or missing execution
remains failed even when independent host byte counters happen to match.

Status2 contains exactly `draftFactoryVersion=1` and `draftFactoryPhase`. Phases:

1. input-consumed
2. strict-csr-reserved
3. awaiting-host-approval
4. credential-saved-reloaded
5. vpn-consent-bound
6. factory-opened
7. application-output-shut
8. reply-bytes-eof-validated
9. factory-resources-joined
10. owned-state-forgotten

Only a live complete phase3 bundle may authorize the tracked host approval. Only
a live complete phase7 bundle may schedule response-tail release; the host must
also observe the actual decoded client END_WRITE applied after all request bytes
drained to the desktop transport. A phase alone is insufficient. EOF/residual
parser processing after command close cannot authorize either operation.

Before phase4, explicitly request only tcp-http-origin-connect, validate the
actual approved result, save and reload it. Keep the original nonexportable key
and exact leaf unchanged through final verification. Before phase6, obtain real
platform VPN consent and bind the same-UID service; protect and bind each gateway
raw socket through the real platform APIs and an observed non-VPN INTERNET
Network. This component never creates a TUN, native capture owner or foreground
capture service. NoTunEstablished describes that component scope, not a global
claim about other networks or app selection.

The application uses one bounded loopback-socket relay, buffers at most8192 bytes,
and the existing public factory interface for original numeric127.0.0.2:80. Send
origin-form POST /factory-research with Host factory-origin.invalid, explicit
Content-Length16421 and Connection:close. Body byte i is i%251; SHA256 is
`d4cc764821eb57cbfff27c890ae26b2648a3f7a5c296698831124f02b25c3529`.
Call actual application SHUT_WR and retain the opposite read direction. The host
delays a response tail until the independently observed END_WRITE boundary.

Validate a bounded HTTP/1.1 status200 response with exactly one consistent
Content-Length32787, no conflicting body framing, exact full body and strict EOF.
Response body byte i is (i*7)%253; its SHA256 is
`62a22a63bb850ba7b263fccff99e868133570394d36d6ee16fd32e9d7c1a4601`.
ResponseBodySha256 applies to those32787 body bytes. Desktop header serialization
is not assumed byte-identical to the origin's headers. There is no data retry.

## Exact positive observation

After actual relay/factory/backend/deadline/service joins and owned Forget, emit
one status3 bundle immediately before the final phase. It has exactly30 string
properties: prefix `draftFactory` plus the suffixes in the table. Identity fields
supplied by instrumentation are separately bounded, never substituted for facts.
Do not emit a successful observation after an assertion or cleanup failure.

| Suffix | Required successful value and actual source |
| --- | --- |
| Version | 1 |
| CredentialSavedReloaded, KeyNonexportable, OriginalCredentialUnchanged | true after actual store/key/leaf checks |
| VpnConsentGranted, NoTunEstablished | true after actual consent/binding and component assertions |
| ProtectAttempts, ProtectSuccesses, BindAttempts, BindSuccesses | canonical integer2 each: one control and one stream socket |
| RequestBodyBytes | 16421 completed application body writes |
| ResponseBodyBytes, ResponseBodySha256 | 32787 and the exact body hash above |
| ApplicationOutputHalfClosed, StrictResponseEof | true from actual socket operations/read result |
| FactoryClosed | true from the actual closed factory snapshot |
| PendingOpens, PendingCalls, RetainedTransports, LiveWorkers | canonical integer0 from the same final factory snapshot |
| SessionLease | false from that snapshot |
| StreamLeases, ChargedBytes, PendingIngressBytes, BackendOutputBytes, BackendIncomingBytes | canonical integer0 from that snapshot |
| RelayJoined, ServiceObserverJoined, ServiceDestroyed | true after actual thread/observer/unbind/destroy joins |
| OwnedStateAbsent | true after actual Forget and store/key absence checks |

Finite safe failures retain the original phase/type and bounded project-only
frames, without provider messages, causes, endpoints, headers or payloads. Failed
and unstarted invocations retain their actual method truth and host cleanup.
The C2 invocation's nullable failure object has only phase (one listed phase),
type (AssertionError, IllegalArgumentException, IOException or IllegalStateException)
and cleanup (boolean), parsed only from the exact fixed wrapper. It is never a
positive observation and cannot coexist with a passing invocation. Factory frames
are limited to the exact EnrolledCaptureTcpFactory root/basename in its own package;
other retained frames use the finite known interop-file map, at most16 frames and
line1–100000. Ordinary A22 schemas and frame maps remain unchanged.
The descriptor is [capture-factory-descriptor.mjs](../tools/transport-spike/capture-factory-descriptor.mjs).

## Independent host evidence

The host uses the real enrollment registry/issuer and actual desktop HTTP origin
attachment. Separately verify the exact original numeric tuple, logical Host,
request/response body counts and hashes, actual HTTP capture, negotiated new-only
capability and explicit mode, request END_WRITE before tail release, response
END_WRITE and actual model/backend/transport/fixture joins. Require final
resource counters zero and source/API/clock binding. Export only the four fixed
sanitized runtime JSON, projected XML/HTML and host-cleanup JSON paths from the
descriptor. No raw logs, credential records, invitation material or test keys.

This proves the interface, protection and HTTP composition only after actual
API26/37 execution. TUN routing, selected apps, production HTTPS, the C1 cold EOF
limitation and protocol freeze remain separate gates. Desktop checkout/publication
requires its existing authorization; the local explicit-path check is separate
from ordinary hosted tests until that dependency is available.

## Runtime report and gate

Runtime JSON format is http-freekit-capture-factory-runtime, revision1. Its exact
top-level keys are format, revision, source, api, clock, invocation, input,
approval, host, resources, cleanup and problems. Source, API and the full bounded
clock interval reuse the existing strict enrollment validators. Invocation uses
the existing actual start/completion/terminal/phase/command fields, observation
and the C2-only nullable failure object above. Partial fields remain null until
their actual observation; they cannot make an unstarted/failed report pass.

Input retains byteCount, inputBytes, inputFinished, inputClosed, command and
inputAbsentAfterMethod. Approval has livePhaseObserved, requested, completed,
approvedResponsesDelivered, actualApprovedResponseDrops, issuerCommandsBefore,
issuerCommandsAfter and issuerJobsAfter. After values are nullable until observed;
success needs a real completed approval, delivery, no drop, increased actual
issuer command count and zero active issuer jobs. It does not assume one command
per approval.

Host has desktopCommit, registered, liveReleasePhaseObserved, releaseRequested,
releaseCompleted, gatewayStreamComplete, origin and backend. Origin retains only
connections, requests, requestBodyBytes, requestBodySha256, requestVerified,
responseBodyBytesWritten, responseBodySha256, responsePrefixWritten, responseEof,
tailReleased, clientEndWriteApplied, originalDestinationMatched, captureMatched
and tailReleaseRequested. Success requires exactly one connection/request, the
fixed body counts/hashes and every listed causal flag true.

Backend retains closing, activeOwners, admitted, settled, captures,
clientEndWrites, proxyMode and negotiatedCapabilities. The last two values are
copied from the actual admitted trusted context, never replaced by driver
constants. Success requires one admitted/settled owner, zero active owners,
exactly one actual HTTP capture, one actual desktop-facing client EOF and exact origin mode
with the sole new capability.

Resources retain workerClosed (the existing ten-field actual aggregate),
workerCommand, reverseRemovalExitCodes, ownedReversesAbsent,
privateDirectoryRemoved, gatewayStreamComplete, ownedCommandsClosed and
ownedCommandGroupsClosed. Require all three owned reverse removals, actual
worker/stdio/group joins, all resource counts zero and the actual private-directory
removal. Final cleanup retains forceStopCommand, uninstallCommand,
uninstallConfirmed, ownedCommandsClosed and ownedCommandGroupsClosed. Host
emulator cleanup remains its separate exact suite-c2 record and actual join gate.

The C2 adapter of the existing verifier must additionally bind the explicit desktop source
commit and byte-identical freshly rendered XML/HTML. A host failure preserves
actual method truth in projections; neither a passed testcase alone nor matching
host body counters can substitute for the complete runtime and emulator gates.
