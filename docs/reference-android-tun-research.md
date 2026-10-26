# Android reference selected-UID HTTP/H1 HTTPS research

Status: host preparation accepted at `d25dc53`/run40336789126 attempt2;
first runtime40340552254 attempt1 independently passes API26's two methods.
Attempt2 independently passes API37 but fails API26 before HTTPS starts with
`enrollment_input_failed`. Combined runtime acceptance is open.
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
claim ALPN negotiation or H2. The agreed implementation sequence is validated
response and platform TLS EOF, then layered TLS close with autoClose=false,
then actual raw SHUT_WR and independent raw EOF/raw close. Do not assume stock
Android SSLSocket.shutdownOutput support. Check the actual platform socket
closure behavior:
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
Frozen canonical envelopes begin with
`format:"http-freekit-reference-tun-worker",revision:1` in that exact key order.
Requests continue `id:N,op:OP,args:{...}`; IDs are sequential1..128. Operations
metadata/createInvitation/snapshot/close accept exactly empty args.
waitForRegistered accepts exactly `{id:<actual invitation ID>,timeoutMillis:N}`,
N1..10000 (parent default10000, existing helper maximum). approve/readResult/
inspectEnrollment accept exactly `{id:<actual enrollment ID>}`. Preserve the
underlying canonical identifier grammar. Success replies continue
`id:N,ok:true,result:<plain material/snapshot/null>`; failures continue
`id:N,ok:false,code:CODE,joined:boolean`. Startup events continue `event:"ready"`;
fatal events `event:"failed",code:CODE,joined:boolean`. Finite codes are exactly
` tun_configuration tun_input tun_unavailable tun_enrollment tun_closing
 tun_cleanup tun_watchdog tun_output tun_protocol tun_timeout tun_process `
(space-delimited list, no whitespace in the codes themselves).
Reserve close after at most127 business requests, within128 total, including
under count/queue saturation. Do not serialize request IDs as domain IDs.
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
The descriptor at owner `a15a29e` (integrated `7bed346`) is now agreed: prefix
`draftReferenceTun`, Version1, sixteen exact ordered phases, exact typed
observation map with no ALPN fact, report format `http-freekit-reference-tun-runtime`.
The new gate is
`no_backup/draft-enrollment-research/reference-tun-complete-v1.bin`, atomically
published from `.reference-tun-complete-v1.pending`, exact bytes
`FREEKIT-REFERENCE-TUN-COMPLETE-V1\n`. The committed
`tools/transport-spike/reference-tun-descriptor.mjs` is the finite private
emitter/parser contract. Root independently replays both descriptor tests.
No C5 helper extraction or old-method changes are assigned.

Each positive requires actual saved/reloaded nonexportable key/CA binding,
separate selected UID, VPN consent, real ongoing foreground notification/Stop,
selected-UID route observation, full fixed response and actual natural local
stream/queue drain. Independently observe host gateway COMPLETE, both EOFs,
real1000 Close acknowledgement, released STREAM lease/zero charges and joined
backend owner before sending one-shot acknowledgment and before Android
notification Stop. The live CONTROL session lease remains true while the
factory/service is active; do not require its release before Stop. Preserve
that actual pre-ACK value in host evidence. The descriptor's final SessionLease
false and gateway sessionLeases0 apply only after Stop/final cleanup.
Do not generate COMPLETE from traffic/client/local counters. Require one
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

## Accepted host preparation evidence

Exact source `d25dc53459e8b88aa36007f21868750b569270c8` passes all three jobs
in [host40336789126 attempt2](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40336789126/attempts/2).
Independent original-report/log replay verifies375 unique passing JVM methods
in47 XMLs, including22 reference traffic methods and two new shared-decoder
methods; all40 new reference Node cases and84 finite capture cases pass without
failure/cancellation/skip. All46 clean-source CA receipts/peer joins and nine
zero-issue lint XMLs pass. Both new instrumentation methods/APKs compile; the
six fresh strict-JSSE reference factory cases also pass. Observed runtimes are
Node24.22.1, bundled OpenSSL3.5.9 and JDK17.0.20.1+1.

Attempt1 stopped before tests on NDK archive extraction; its original failure
remains retained. One recorded fresh-runner retry used unchanged source/checks.
Earlier clock/annotation/dependency/test-annotation failures also remain failed.
The finite audit and checksum are exported directly in ignored
`dist/reference-tun-host-audit.json`/`.sha256`; audit SHA256 is
`e739d02e8c305ba706a75652de45461fb14b85436fa7f428b8da005910216f22`.
It binds exact source/run/attempt and original log/metadata/report-manifest hashes,
without identity, keys, CA values or traffic digests. Original accepted evidence
is retained at `/tmp/reference-tun-host-accepted.fF0F5a` outside trusted scripts.

This accepts host preparation only. Next is one separately named fresh API26/37
matrix with both exact ordered methods and independent four-file replay per API.
No Android TUN, Android TLS-provider closure, target-app trust, desktop C5,
physical USB, production integration or v1 freeze is inferred from this host pass.

## First Android runtime result

[Runtime40340552254 attempt1](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40340552254/attempts/1)
uses exact host-accepted `d25dc53`. API26 passes both actual ordered methods;
independent replay of all four original artifacts verifies sixteen phases and
56 facts per method, source/strict clock, real HTTP/HTTPS request/reply/EOF,
independent gateway COMPLETE before ACK/Stop, all Android/host/package/process
cleanup and emulator stop/termination/join/exit0. Clock interval is
[-887,118]ms with6ms round trip. This is reference selected-UID Android evidence,
not an Android close_notify or ALPN-negotiation claim.

API37 stops before boot/methods while preparing NDK28.2.13676358:
`Error reading Zip content from a SeekableByteChannel`. It has no runtime result.
Original first-attempt reports/logs/metadata are retained in
`/tmp/reference-tun-runtime-first.iyEdE1`, outside trusted scripts. Attempt1 remains
failed overall. The one recorded full fresh-runner retry, attempt2 at unchanged
source, also fails overall: API37 independently passes all four original files
and both actual methods (job121637778332, verifier start lower bound1793025588).
API26 HTTP passes, but `enrollment_input_failed` prevents HTTPS from starting.
First-method input/ACK absence observations are false; these do not establish the
underlying failed command. Both emulator cleanups terminate/join/exit0; API26's
driver exits1. Original attempt2 evidence is
`/tmp/reference-tun-runtime-second.yHp565`. The finite ignored export is
`dist/reference-tun-runtime-audit.json`/`.sha256`, SHA256
`b970f82c38e04897b5b6fedb73814203c2b85cd0419f1bd20fde197ad48d2581`;
it binds attempt2 metadata/log/four-file hashes and explicitly records combined
acceptance=false. Investigate the input handoff before
another dispatch. Both APIs must pass one same-source attempt; never combine
API26's earlier success with API37's later success. No third retry is dispatched.
No code, SDK version, integrity check, workflow, assertion or deadline is changed
in these two attempts.

## Post-method absence diagnostic follow-up

Source inspection localizes attempt2 API26 to the final combined absence probe,
after the HTTP invocation and host tasks passed. Both absence booleans copy one
conjunction, not two independent file observations. The command checks input,
final gate and pending gate; no retained result identifies which check failed.
No publication race or retained file is established.

The next exclusive driver package adds only bounded diagnostics and deterministic
regressions in `run-reference-tun-runtime.mjs`/`reference-tun-driver.test.mjs`.
Keep revision1 reports, all three-path absence checks, exact success marker,
zero-stderr requirement, command/group closure, deadlines and failure behavior
unchanged. Emit one fixed-prefix `Reference TUN absence probe: ` log line per
actual probe when not quiet, containing only the existing finite command
observation plus boolean `stderrPresent` and `markerMatched`. Do not emit raw
stdout/stderr, serials, paths, input, CA, identity or traffic. No new report field
or shared wire contract is introduced. Failure cases must preserve passed HTTP,
zero-start HTTPS and attempted independent cleanup. Missing command/group close
must also retain `enrollment_cleanup_failed` and false actual command-join facts;
joined failure vectors retain only `enrollment_input_failed`.

Owner `09d2564`, integrated `14a29e5`, implements this two-file package.
Coordinator replay passes25/25 descriptor/results/driver/workflow checks and11/11
independent Python verifier tests, with no skips. Actual diagnostic logging,
quiet/no-probe branches and hostile raw canary privacy checks pass. Independent
exact-commit reviewer `a706195aa04dae520` found no concrete correctness/privacy
defect (static only). Fresh full pinned host40345446373 at exact `ca0b3cc`
fails documentation's existing unroot shared-clock regression
(`enrollment-emulator-clock.test.mjs:130`, actual1/expected124 at29.05s),134/135
Node documentation cases passed. Android/native jobs succeed; original artifact
replay independently verifies375 JVM methods/47 XMLs,46 clean-source CA receipts/
all joins, nine clean lints and43 reference Node/84 capture cases. This is partial
evidence, not full host acceptance. Original evidence:
`/tmp/reference-tun-diagnostic-host-failure.4wRCL3`. Isolated owner
`a803517d6e5f5746a` owns only the clock test for deterministic path regressions;
no production clock/workflow change or blanket acceptance of exit1/124. No new
runtime is dispatched. Historical probe cause remains unknown; corrected full
host acceptance must precede a diagnostic matrix.

Test-only owner `6dcf765`, integrated `38409e5`, deterministically reproduces the
old root/unroot assertions failing1 versus124, then separates exhausted-before-
read exit1 from admitted-read actual timeout124. Production workflow/clock bytes
stay unchanged; no historical path is inferred. Owner full clock29/29 and full
Node documentation162/162 pass; coordinator focused4/4 and finite reference25/25
pass without skips. Independent read-only exact-commit reviewer
`a108c4e4931c4593f` found a concrete test-coverage gap: deriving injected time
from the production deadline masks a30-to60-second budget regression. The same
exclusive owner must independently anchor/assert the original30-second budget
and reject root/unroot enlarged-budget mutations. Host40349604793 at exact
`86499d4` subsequently succeeds in all three jobs (metadata only, no new artifact
audit), but is not runtime authorization because its source predates that repair.
Owner follow-up `5085cb5`, integrated `4663e66`, independently anchors the
pre-assignment clock, asserts exactly30 seconds before reconnect/injection and
rejects four root/unroot60-second mutations. Coordinator focused8/8 and integrated
full Node documentation166/166 pass without skips; owner clock33/33 also passes.
Independent exact follow-up reviewer `a9cc5f4400d6f29c6` found no concrete remaining
finding (static). Production clock/workflow bytes remain unchanged. Fresh full
pinned host validation of the repaired source must precede diagnostic runtime.
