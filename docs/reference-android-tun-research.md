# Android reference selected-UID HTTP/H1 HTTPS research

Status: preparation only; no new Android execution or capture acceptance.
Prerequisite [Kotlin host checkpoint](reference-kotlin-interception-research.md)
is accepted at `65cd93f`/run40316060504. This distinct checkpoint uses the owned
reference backend, NOT the missing reviewed desktop implementation. Existing
C5 pins/methods/workers/reports, command11 plaintext HTTPS_OPAQUE and command19
remain unchanged. Production v1 is unfrozen; app integration, CA installation,
physical USB and desktop C5 are separate gates.

## Fixed execution and trust boundary

Two new exact Android methods, each with a fresh fixture, invitation, Android
Keystore identity, approved saved/reloaded credential, traffic binding and VPN:

- `com.httpfreekit.interop.DraftReferenceTunInteropTest#selectedUidHttpReachesReferenceOriginThroughTun`
- `com.httpfreekit.interop.DraftReferenceTunInteropTest#selectedUidH1HttpsReachesReferenceOriginThroughTun`

The test UID MUST NOT generate the original application transaction or connect
to the local SOCKS listener. Only the separate signature-protected traffic APK
UID generates it, selected by the new VPN service. Use the existing capture
engine, protected/network-bound socket guard and EnrolledCaptureTcpFactory.
No core/native/factory modification is initially assigned.

Both transactions target numeric198.18.0.2, ports80/443 respectively, logical
host `reference-target.invalid`, one `POST /reference/proof`. Request body is
exactly4096 bytes, byte i = `(i * 31 + 7) & 255`. Response body is exactly81 ASCII
bytes, `reference-origin:` followed by SHA256hex(request body). Use bounded
strict H1 parsing (headers<=4096, explicit Content-Length81, no TE/trailers,
Upgrade, pipelining or surplus body). Full response/body/hash validation occurs
in the traffic UID, not merely the instrumentation UID. Digests and traffic
bytes never appear in diagnostics/public evidence.

Instrumentation performs actual HTTPS pairing with its nonexportable Android
key, saves and reloads the exact credential, and fetches the public interception
CA through DraftInterceptionCaSavedCredential/Client with the retained actual
approved recovery binding. Node's software-CSR `enroll` operation is NOT Android
enrollment evidence. Host-provided public DER is NOT a substitute for that fetch.

After verifying all three APK signers and the existing signature permission,
transfer only this bounded authenticated PUBLIC CA through new finite traffic
command3. No key, credential, invitation secret, arbitrary host, port or trust
setting crosses this operation. Retain an instance-scoped context only; never
alter default SSLContext, hostname verification, user/system trust or manifests'
network security trust. Reject duplicate/conflicting configuration. Dispose trust
on FINISH, failure and service destruction, after actual users join.

HTTPS uses a real raw socket to the fixed numeric destination, layered scoped
SSLSocket with the fixed logical verification hostname and valid SNI, platform
chain/name verification and TLS1.2/1.3. No permissive verifier, reflection/hidden
API or direct-network fallback. On API29+ offer only H1 via public ALPN APIs;
API26 may use absent ALPN with strict H1-only application parsing and must not
claim ALPN negotiation or H2. Check the actual platform socket closure behavior:
TLS close and raw SHUT_WR/EOF are separate ownership facts. Do not transplant
JSSE's system property, fake EOF, accept a reset as clean EOF, or infer Android
close_notify verification from JVM evidence. If a platform cannot prove a fact,
report that limitation rather than inventing it. Initial scope is two positive
cases, not Android wrong-trust/wrong-host negative acceptance.

## Frozen traffic API and root hooks

New files in capturetraffic main/test packages are exclusively traffic-owned:
`ReferenceTunTraffic.kt`, `ReferenceTunTrust.kt`, `ReferenceTunHttpResponse.kt`
and their focused tests. Public package-local service API:

- `ReferenceTunTraffic()` creates an inert, closeable owner.
- `configure(caDer: ByteArray)` accepts exactly one canonical DER CA,1..4096
  bytes, validates CA constraints/profile using platform certificate APIs,
  copies input and establishes only scoped trust. No provider text escapes.
- `execute(command: Int, own: (java.io.Closeable) -> Unit): ByteArray` accepts
  only20/21, performs one fixed HTTP/HTTPS transaction respectively, registers
  the actual socket/aggregate owner before connection, returns the validated
  81-byte response only after real directional shutdown/EOF and closure.
- `close()` seals future calls and releases scoped trust after closing users;
  repeated calls are safe. Do not claim a JVM/Android join that did not occur.
- `ReferenceTunTraffic.Failure` exposes only finite `code`, no raw cause/message.
  Codes: `traffic_reference_configuration`, `traffic_reference_connect`,
  `traffic_reference_tls`, `traffic_reference_write`, `traffic_reference_shutdown`,
  `traffic_reference_reply`, `traffic_reference_eof`, `traffic_reference_close`.

Root alone edits TrafficService and the shared CaptureTrafficReply decoder.
Reserve CONFIGURE_REFERENCE=3, REFERENCE_HTTP=20 and REFERENCE_HTTPS=21.
Command3 accepts exactly Bundle key `caDer` with ByteArray1..4096; commands20/21
accept empty Bundles. Keep existing CONFIGURE=1/directPort behavior unchanged;
TrafficClient's existing constructor configures it with the actual gateway port
as before, without performing a direct transaction. Existing WAIT_VPN17 and
WAIT_NON_VPN18 remain inert observations. Preserve exact reply keys
bytes/sha256/failureCode; configuration success is bytes0/null digest, data
success is81 bytes with its actual digest. Extend only exact new command/failure
allowlists; do not broaden legacy lastData observations10..18. Root handles
FINISH/failure/onDestroy trust disposal and actual owned socket publication.

## New reference fixture/worker package

Exclusively new `reference-tun-fixture.mjs`, `reference-tun-worker.mjs`,
`reference-tun-worker-client.mjs` and focused tests. Compose the existing checked
assets/backend/startEnrollmentOriginFixture, both existing capabilities and
provided public interception CA. Owned ephemeral loopback origins/listeners only.
No desktop path/commit, privileged address alias, legacy/scenario fallback or
arbitrary target. Keep the existing peer and enrollment workers unchanged.

Module factory `startReferenceTunFixture({openssl?}={})` returns an owner exposing
existing fixture-compatible `metadata()`, `createInvitation()`,
`waitForRegistered(id, options?)`, `approve(id)`, `readResult(id)` and
`inspectEnrollment(id)`; retain existing material/snapshot types for those APIs.
Only one invitation/enrollment is admitted per owner. Public/private inspection
must not default-print identity, invitation, CA or origin values.

Aggregate `snapshot()` returns defensive `{gateway, backend, assets, stream,
evidence, privateDirectoryRemoved}` using existing finite snapshots and the
same exact nullable stream projection as the accepted private JVM peer.
Track only the actually registered/approved enrollment. Missing stream facts
stay null, never zero/true. Evidence is the existing last-two PRIVATE origin
rows. `close()` synchronously seals admission and joins gateway, backend,
operations, asset users/commands and owned directory removal in safe order;
independent cleanup still runs after another failure. Preserve sanitized primary
and suppressed failures and honest joined flags. Never remove unjoined assets.

Parent factory `startReferenceTunWorker({openssl?}={})` launches only the new
fixed child entry, returning asynchronous `metadata`, `createInvitation`,
`waitForRegistered`, `approve`, `readResult`, `inspectEnrollment`, `snapshot`
and `close` methods corresponding to the module APIs, plus `processSnapshot()`
for actual child/pump/group ownership. Parent material replies must be defensive
plain data, not pretend domain-object instances. Root driver consumes them as
private data. Owner defines/records a canonical finite JSONL request/reply schema
in this profile BEFORE the driver binds it; protocol is PRIVATE, not shared wire.
Bounds:8192 input bytes/line,16384 output bytes/line,262144 cumulative input,
128 requests, at most two business operations outstanding plus reserved close.
Use strict operations/keys/base64url and no raw stderr diagnostics. A360-second
watchdog seals/fails/cleans, never successful Stop. Close/EOF/error seals even
with pending waitForRegistered. Actual child exit, output and reader/writer pumps
join; forced termination is failure, not successful close. Narrow known
ExperimentalWarning suppression may match the accepted private peer, not TLS or
security failures. Do not bypass unavailable SQLite defenses on local Node22.

## Android package and independent finite descriptor

Exclusively new instrumentation files: `DraftReferenceTunInteropTest.kt`,
`DraftReferenceTunService.kt`, `DraftReferenceTunConsentActivity.kt`. Use existing
saved-credential, scoped CA client, consent/notification and capture APIs.
Private enrollment input stays the existing format. Pass only existing actual
webSocketPort through instrumentation arguments. New private phase prefix,
observation fields and completion gate MUST be frozen in the new descriptor by
the validation owner and reviewed by root before instrumentation emits them.
No C5 helper extraction or old-method changes are assigned.

Each positive requires actual saved/reloaded nonexportable key/CA binding,
separate selected UID, VPN consent, real ongoing foreground notification/Stop,
selected-UID route observation, full fixed response and actual natural local
stream/queue drain. Independently observe host gateway COMPLETE, both EOFs,
real1000 Close acknowledgement, released lease/zero charges and joined backend
owner before sending one-shot acknowledgment and before Android notification
Stop. Do not generate COMPLETE from traffic/client/local counters. Require one
intercepted TCP flow and zero direct/UDP traffic. Protected and bound gateway
sockets must be observed. After Stop require native/TUN/factory/worker joins,
non-VPN route, traffic FINISH, destroyed consent UI, cleared configuration and
final Forget/key/recovery absence. Attempt every independent cleanup, preserving
sanitized primary/suppressed failures. Original method failure cannot become
success because cleanup or a later retry succeeds.

Validation owner exclusively adds `reference-tun-descriptor.mjs`,
`reference-tun-results.mjs`, `run-reference-tun-runtime.mjs` and focused tests.
Use separately named exact methods, finite phases/facts, source/clock/command
closure, new gate filename/bytes and new report format/basenames. Publish the
finite descriptor before Android emission code. Source observations copy actual
finite facts only. Include host independent backend/origin/TLS comparison booleans
and byte counts, no private measurements or identities. Do not expand old
run-enrollment-runtime suites or C5 worker/report grammar. Reuse existing bounded
host, reverse and exact APK package/signature owners unchanged where suitable.
No alias ownership requirement is imported from C5's same-address desktop proof.

Root exclusively owns this profile/board, descriptor agreement, additive test
manifest entries, shared traffic hooks/build roots, host CI and new separately
named hosted workflow plus independent report verifier integration. Parallel
owners must communicate dependent interface/descriptor changes before committing.
No subagent is assigned toolchain installs, CI/device dispatch or publication.

## Acceptance gates

1. Inspect/commit each exclusive package after relevant local checks and
   independent review. Preserve actual Node22 failures and local Java/SDK absence.
2. Pinned exact-source full host CI must compile both new Android methods, APKs,
   traffic JVM tests, strict lints and finite driver/worker/verifier regressions;
   every old gate stays mandatory. Hosted positive fixture tests require Node24.
3. Only then run a separately named fresh API26/37 matrix with both ordered
   methods per API, strict owned permission/clock/start/completion and all package,
   reverse/peer/process/native/emulator cleanup. Independently replay original
   JSON/XML/driver/cleanup artifacts. Failures remain failed and require checked
   corrections, not blind reruns, higher deadlines or weakened EOF assertions.
4. No host/emulator result is physical USB, production app capture, C5/desktop,
   user/system CA installation or protocol v1 freeze. Those remain later gates.
