# Kotlin factory/reference interception research

Status: next distinct host-only checkpoint. The preceding Node reference
checkpoint is accepted at `d6ee09c` in run40311327186 after full-host success and
independent original-evidence audit. This Kotlin package is assigned and under
implementation, not compiled/runtime accepted. This is not C5, the
missing reviewed desktop implementation, Android Keystore/TUN execution,
production integration, target-app CA installation or physical USB acceptance.
Protocol v1 remains unfrozen. Preserve all existing C5 pins, methods and reports.

## Actual composition

Use the real `EnrolledCaptureTcpFactory` and a new private Node peer composing
[owned reference assets/backend](reference-interception-research.md) with
`startEnrollmentOriginFixture`. The JVM generates its own software P-256 key
and real CSR; only the public CSR crosses private IPC. Reuse
`enrollOriginCsr(fixture, csrDer, capabilities)` for actual HTTPS pairing and
explicit local approval. The private key remains in JVM memory. Build the
existing credential record/key manager from the exact approved response;
validate public-key and approved interception-CA binding. This is not Android
Keystore or saved-credential persistence evidence.

Fixed existing capabilities are `tcp-http-origin-connect` and
`tcp-https-connect`. The original destination remains `198.18.0.2`, ports80/443,
logical host `reference-target.invalid`, single bounded `POST /reference/proof`.
The factory itself emits/consumes CONNECT; application tests must not emit a
second CONNECT. Independently compute the complete response and compare actual
origin evidence, bytes and both TLS-handshake counts. No canned response,
scenario backend, direct egress, arbitrary forwarding or desktop source exists.

## Frozen private peer API

Node owner adds only `tools/transport-spike/reference-interception-peer.mjs`
and its `.test.mjs`. Export `startReferenceInterceptionPeer({openssl?} = {})`;
create exclusively owned private temporary directories internally. Methods:

- `ready()` returns defensive `{metadata, interceptionCaDer, nodeVersion,
  nodeOpenSsl}`. Metadata is the unchanged existing enrollment metadata including
  actual `webSocketPort`; CA DER is canonical base64url public bytes.
- `enroll(csrDer)` accepts a bounded Uint8Array (1..4096 bytes), exactly once,
  returning `{approved}` with the existing approved status-response material.
  No exported/generated Node device private key or new wire fields.
- `snapshot()` returns defensive `{backend, assets, gateway, stream, evidence,
  privateDirectoryRemoved}`. First three are existing finite snapshots;
  evidence is the existing last-two private origin rows, never default-logged.
  `stream` is null before an actual observed stream probe exists; otherwise
  project only `{phase, resourcesReleased, streamLease, clientEofEmitted,
  gatewayEofEmitted, chargedBytes, fixtureUploadBytesRead,
  fixtureResponseBytesWritten, cleanupComplete}` from the actual probe. Do not
  fabricate absent observations as zero/true. `phase` retains its existing
  finite value; other fields retain actual boolean/count types.
- `revoke()` commits the actual approved enrollment's revocation, returning
  `{revoked:true}`. This does not assert all asynchronous cleanup joined;
  tests must observe actual probe/backend/factory cleanup independently.
- `close()` seals admission, attempts independent cleanup and resolves the final
  snapshot only after gateway, backend, asset commands/users and directory
  removal join. Preserve primary errors and suppressed cleanup failures.
  Never remove assets/directories if any child/user remains unjoined. Repeated
  close calls share the same actual result. Default inspection/serialization is
  redacted; failures are finite with an honest joined bit.

Run the CLI with no arguments (no desktop root, scenario, target or arbitrary
listener configuration). Private stdout contains only canonical JSONL envelopes
`{format:"http-freekit-reference-interception-peer",revision:1,event,...}`.
Ready spreads the exact ready fields; enrolled contains `approved`; snapshot and
closed contain `snapshot`; revoked contains `revoked:true`; failed contains
finite `code` and actual `joined`, never provider text. The private failure-code
allowlist is exactly `peer_configuration`, `peer_input`, `peer_unavailable`,
`peer_enrollment`, `peer_revocation`, `peer_cleanup`, `peer_watchdog`,
`peer_output`; unknown underlying errors never extend it. Commands, exact keys:

```json
{"op":"enroll","csrDer":"<canonical base64url public CSR>"}
{"op":"snapshot"}
{"op":"revoke"}
{"op":"stop"}
```

Bound input to8192 bytes/line,262144 cumulative bytes and64 commands; output to
16384 bytes/line. Require canonical JSON (no duplicate/extra keys, trailing data,
non-ASCII, unknown operations or malformed base64url). Serialize business
operations; stop/EOF/error/watchdog seal admission immediately and join any
in-flight operation without late approval/publication. A180-second watchdog
fails and cleans up, not a successful stop. Output writes, real child/group
closure and all owned callbacks must join. No raw diagnostics/traffic/key/CA
fingerprints appear in stderr or test reports; private IPC is not a public audit
artifact. Node tests exercise actual CSR enrollment, real gateway/backend,
revocation, CLI bounds/failure and successful cleanup, without mocks.

## Kotlin package

Kotlin owner adds only these test-package files under
`tools/capture-spike/transport/src/test/kotlin/com/httpfreekit/capture/transport/`:

- `CaptureReferenceNodePeer.kt`
- `EnrolledCaptureReferenceTest.kt`

Reuse existing enrollment codec/record/key-manager APIs and same-package
`CaptureTransportConfiguration`. Do not instantiate desktop helpers or couple
test source roots between modules. The private process helper owns bounded
stdin/stdout/stderr pumps, actual exit and executor termination. Never print
private JSON, CSR/identity values, certificate fingerprints or origin digests.

Six actual cases: HTTP; H1 HTTPS; wrong scoped interception trust; wrong verified
target hostname with explicitly absent SNI; active-owner revocation with subsequent
credential refusal; Stop with a held backend owner and joined cleanup. The
positive HTTPS case retains valid fixed SNI. For the wrong-host case explicitly
set an empty SNI list so default JSSE HTTPS checks the wrong requested peer host
against the real fixed-host certificate before the backend's post-handshake
absent-SNI refusal. Require a certificate-exception cause and no completed
interception handshake or application/upstream dispatch, not an arbitrary TLS
failure; fresh pinned JVM execution must establish this ordering. Each
uses a fresh peer/identity. Keep the small actual loopback TLS/application bridge
inside these new files. It forwards only actual bytes and EOF with backpressure;
no synthetic stream/COMPLETE event or direct-network fallback. HTTPS uses scoped
trust containing only the approved/bound interception CA, default JSSE
verification, endpoint identification HTTPS, SNI, TLS1.2/1.3 and H1 ALPN. Never
change the default SSLContext or disable certificate checks. Use strict
`com.sun.net.ssl.requireCloseNotify=true` in the explicit JVM task.

For successful cases require the full response, actual upload shutdown, reverse
EOF, bridge joins and remote stream COMPLETE before factory Stop or peer close.
Observe actual both directional EOFs, resourcesReleased, no stream lease,
chargedBytes0 and scenario-fixture traffic counters0. Backend owners must join
before Stop. Negative/Stop cases retain actual failed/cancelled outcomes, not
manufactured COMPLETE. Cleanup attempts every independent owner, retains primary
and suppressed failures and verifies existing factory/gateway/registry/issuer/
backend/asset/process zero-resource and joined-command facts. Forced process
termination never establishes successful closure.

## Root-only integration and gates

Root owns this profile, work board, existing transport `build.gradle.kts`,
`.github/workflows/android.yml`, root contract guard test and evidence documents.
Add a separate fresh noncached `testReferenceIntegration` task filtered to the
new exact test class with strict JSSE close_notify. Exclude that class from all
other Test tasks, preserving all three existing desktop exclusions/prerequisites.
Append the exact Node peer test to the mandatory reference step, add the new
Gradle task to host validation and retain its XML reports. Existing dependencies
suffice; no module, SDK, Android runtime, old worker IPC or shared wire change.

Local Node22 lacks Store SQLite defenses and local Java/SDK is absent. Report
unavailable checks truthfully; no bypass or toolchain installation is assigned.
A new exact-source pinned Node24/JDK17 host run must execute all six JVM cases,
strict TLS and actual gateway/ownership facts before this checkpoint passes.
The Node-only proof, Kotlin host proof, distinct future Android selected-UID
research, exact desktop C5 and physical USB remain separate exit gates.
