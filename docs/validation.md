# Validation and release plan

## Evidence rules

Record exact Android and desktop commits, Android version and device model, SDK/ADB versions, network topology, commands, results, and relevant sanitized diagnostics. A mock-only test does not demonstrate capture. A VPN connected indicator does not demonstrate proxy delivery. Mark unavailable device tests as unrun and explain the environment requirement.

Documentation-only changes require local Markdown link validation, consistency review, and git diff --check. The foundation now has a pinned Gradle build, parser tests, and a host transport test. Run the commands in [developer instructions](development.md); see [foundation evidence](decisions/0001-foundation.md) for actual results and outstanding gates. Host checks do not demonstrate device capture.

## Host validation workflow

[Android host validation](../.github/workflows/android.yml) runs on pushes, pull requests, and manual dispatch with read-only repository permissions. It uses Ubuntu 24.04, Temurin JDK 17, Node 24.22.1, SDK platform 37.0, build tools 36.0.0 and NDK 28.2.13676358 for the pinned capture library. GitHub Actions are pinned to commit IDs, and the workflow linter download has a pinned SHA-256. Gradle and app dependencies retain the versions committed in the wrapper and catalogue. The workflow does not request release secrets, publish APKs, or run an emulator.

The Android job bootstraps command-line tools build `15859902` into a fresh SDK directory under the runner's temporary directory, verifies the Linux archive SHA-256 against the [official download page](https://developer.android.com/studio#command-tools), and exports the SDK paths before accepting SDK licences and installing the pinned packages. It does not rely on `sdkmanager` or SDK environment variables being preinstalled by the runner image.

Run the source checks locally:

```sh
node --test scripts/tests/check-doc-links.test.mjs
node scripts/check-doc-links.mjs
node --test scripts/tests/enrollment-*.test.mjs
node scripts/check-enrollment-corpus.mjs
python3 -m unittest discover -s scripts/tests -p 'test_keystore_results.py'
git diff --check
```

The [link checker](../scripts/check-doc-links.mjs) checks local Markdown inline links, image links, reference destinations, ATX heading fragments, and explicit HTML anchors. It resolves encoded paths, enforces that targets stay inside the checkout, and reports the document and source line for failures. Code fences and inline code are examples, so plain sibling-repository paths in those examples do not become links to validate. Generated folders, symlink directories, and nested Git repositories/worktrees are not scanned. Remote URLs are intentionally not fetched; external-link availability and non-Markdown fragments require separate review.

After installing the SDK/JDK and locked Node peer dependencies, CI runs:

```sh
npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
openssl version # The research fixture requires OpenSSL 3.
node --test tools/transport-spike/android-peer.test.mjs
node --test tools/transport-spike/instrumentation-results.test.mjs
node --test tools/transport-spike/draft-stream-results.test.mjs
node --test tools/transport-spike/draft-stream-command.test.mjs tools/transport-spike/run-draft-streaming.test.mjs
node --test tools/transport-spike/enrollment-runtime-*.test.mjs
node --test tools/transport-spike/gateway-websocket-peer.test.mjs tools/transport-spike/companion-http-origin.test.mjs tools/transport-spike/capture-factory-results.test.mjs
node --test tools/transport-spike/companion-interception-ca-peer.test.mjs
node --test tools/transport-spike/research-websocket*.test.mjs
node --test tools/transport-spike/companion-stream-peer*.test.mjs
node --test tools/capture-spike/*.test.mjs
python3 -m unittest discover -s scripts/tests -p 'test_capture_runtime.py'
node tools/transport-spike/companion-stream-peer-pressure.mjs
FREEKIT_ENROLLMENT_CRASH_REPORT=build/reports/enrollment-store/crash.json \
  node --test tools/transport-spike/companion-enrollment-*.test.mjs
node scripts/verify-enrollment-crash-report.mjs --source "$(git rev-parse HEAD)" --platform linux
./gradlew --no-daemon --console=plain \
  :core-protocol:test \
  :transport-framing:test \
  :core-security:testDebugUnitTest :core-security:assembleDebugAndroidTest :core-security:lintDebug \
  :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug \
  :transport-interop:testDebugUnitTest :transport-interop:assembleDebugAndroidTest :transport-interop:lintDebug \
  :core-capture:testDebugUnitTest :core-capture:lintDebug \
  :gateway-websocket:test \
  :capture-transport-research:testDebugUnitTest :capture-transport-research:assembleDebug :capture-transport-research:lintDebug \
  :capture-runtime:testDebugUnitTest :capture-runtime:assembleDebug :capture-runtime:assembleDebugAndroidTest :capture-runtime:lintDebug \
  :capture-traffic:assembleDebug :capture-traffic:lintDebug \
  :installed-app-fixture:assembleDebug :installed-app-fixture:assembleRelease \
  :installed-app-fixture:lintDebug :installed-app-fixture:lintRelease
node scripts/compare-enrollment-conformance.mjs
```

Assembling the app and security module's Android instrumentation APKs checks compilation only; no UI, Keystore, or device result is inferred from it.

## Installed-selection capture admission

B5 is a callable, inert app-only boundary, not a service start or capture proof.
Owner `32c92f7`, integrated as `66eb9da`, adds immutable selected-package plans
and typed finite admission results. It requires installed mode, a successful
loaded/nonloading/nonfailed catalog, 1..64 exact selected packages present in the
full inventory, service-compatible syntax and companion exclusion. Search and
filters cannot prune the admitted selection; failed refreshes cannot reuse a
retained old inventory as ready. Package sets are copied/unmodifiable and
plan/result strings redact state. The fixed local policy descriptor is not a
negotiated capability, active enforcement or HTTPS/USB readiness claim.

Twenty-five new JVM test methods cover reducer-produced and hostile inputs,
limits, sample collisions, failed/stale catalog state, mutation isolation,
redaction and fixed policy. Static scope/whitespace/regex-parity checks pass.
Compilation, JVM execution, app/instrumentation assembly and lint are **unrun
locally** because Java/JDK and Android SDK are absent; no toolchain was installed.
Independent read-only correctness/privacy review found no concrete defect and
confirmed service syntax/count and fixed policy parity. Compilation/runtime
validation was pending at implementation handoff. Exact clean source
`5e8d8dae990cb25092e27421723f790eadbf9965` passes
[host run 40223757997](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40223757997).
Independent original artifacts verify 345 unique JVM methods in 43 XMLs,
including all 25 B5 methods, zero failures/errors/skips, 46/46 source-bound CA
receipts and nine zero-issue lint XMLs. The host job also passes app assembly
and instrumentation compilation. B5's compiled inert admission API is checked;
no emulator/device result or new UI/service behavior follows from those checks.
Later capture start still requires platform package revalidation, consent,
trusted transport and target trust; C5, protocol freeze and physical USB are
not established by this local boundary.

## Authenticated public interception CA research

The [A23 contract](protocol-interception-ca.md) is checked by the compiled shared
Kotlin getter over fresh pinned mTLS to the actual reference credential endpoint.
The JVM proof creates a software P-256 identity, enrolls its real CSR, and binds the
returned public DER to the saved approval, original identity and issued credential.
It checks fresh fetches, saved-context reopen, defensive results and unchanged
global TLS defaults. Real authenticated hostile TLS responses exercise framing,
DER/profile and fingerprint refusals; the peer must witness the authorized request
and actual response publication. Marked malformed-DER cases deliberately corrupt
the test recovery fingerprint to match their bytes, so canonical parsing is tested
independently of a hash mismatch. They do not represent valid server approval.

Run the focused compiled proof with JDK 17, pinned Node 24.22.1 and OpenSSL 3:

```sh
FREEKIT_NODE=/absolute/path/to/node OPENSSL_BIN=/absolute/path/to/openssl \
  ./gradlew --no-daemon --console=plain :transport-interop:testDebugUnitTest \
  --tests com.httpfreekit.interop.DraftInterceptionCaTlsTest
```

The proof includes real credential expiry, current registry revocation, wrong
gateway and absent TLS identity, read/whole-exchange deadlines and concurrent
close. Client snapshots and the private peer require actual socket, callback,
worker, issuer and process joins. Its finite report is
`build/reports/interception-ca/jvm-tls.json`; ordinary host CI retains it with the
original JVM XML and runs the separate private-peer tests. No certificates,
fingerprints, private keys, identity values or provider messages enter that report.
This proves software-key host behavior. Android Keystore execution, CA installation,
production approval persistence and protocol freeze remain separate gates.

The separate [A23 saved-credential profile](android-interception-ca-research.md)
uses `--suite a23` with the original A22 prepare and reopen/Forget methods on either
side of the new CA retrieval method. All three must run in that order on one fresh
API 26 or 37 emulator against the same owned worker restart. The driver checks
actual public-asset byte count and private SHA-256 against both approved results
and fixture metadata before and after worker reopen. Only booleans and byte counts
leave the process; the 17 Android CA facts include actual returned DER length and
joined getter resources. The original A22 approval/drop, saved key, process
absence, identity/port/result continuity and selective cleanup gates are reused
without weakening their two-method projection.

Select `--suite a23` with the existing enrollment CLI and independent verifier.
Its four sanitized files are fixed under `interception-ca` for runtime/XML/HTML
and `build/reports/interception-ca-runtime/host-cleanup.json` for host cleanup.
The verifier requires current clean source, exact API and clock, three actual
starts/completions, fresh bounded files and byte-exact XML/HTML projections plus
joined emulator cleanup; it rejects desktop arguments. API 37 explicitly checks
`ACCESS_LOCAL_NETWORK` in the installed self-instrumenting
`com.httpfreekit.interop.test` package's requested permissions, grants it to that
owned package for User 0 and requires a bounded `pm dump` readback of that same
package's User 0 `runtime permissions` entry with `granted=true` before invocation.
The finite mode is `owned_ci_grant`, not a loopback exemption. API 26 records
`not_required` and null grant/readback commands. The developer must use the
pinned Node 24.22.1, JDK 17, Android SDK and OpenSSL 3 toolchain; host guard
checks alone are not emulator evidence.

At published source `8526b0a`, [host run 40189595419](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40189595419)
passes all three jobs. Original artifact replay records 318 JVM methods with
zero failures/errors/skips, 46/46 source-bound actual CA TLS receipts and nine
strict lint XML files with zero issues. The [first A23 matrix
40190998118](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40190998118)
has a complete API 26 pass: all three ordered methods, actual 430-byte DER,
seventeen CA facts, original A22 gates and owned cleanup pass the independent
verifier. API 37 fails **before any instrumentation method starts**: the owned
declaration and `pm grant --user 0` pass, but the unsupported `cmd package
check-permission` readback exits 255. Its sanitized report records three zero
starts, `enrollment_fixture_failed`, a driver exit of 1, and complete package,
worker, command and emulator cleanup. Do not combine the two API results into
A23 acceptance. The correction uses the bounded, exact-package/User 0 `pm dump`
readback described above. Its corrected source `6898ec8` passes pinned
[host run 40207877081](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40207877081)
with 318 JVM cases, 617 Android-job Node cases, 144 documentation-job Node cases,
46/46 actual CA TLS receipts and nine zero-issue lint reports. In the
[second matrix 40209128345](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40209128345),
API 26 again passes the independent three-method and cleanup verifier. API 37
stops earlier during `adb root` clock setup (`unable to connect for root: closed`),
before driver admission. Its only retained report is host cleanup, with driver
exit null, stop0, observed termination/join and emulator exit0. This run contains
no API37 permission-readback or method result. The workflow's bounded observed-UID
transition correction is committed through `cd36f4b` and passes
[host run 40210625804](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40210625804)
with the same 318 JVM cases, 46/46 receipts and nine clean lint reports. The
[third matrix 40211577524](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40211577524)
again independently passes API26. API37 now completes clock setup, declaration,
grant and readback commands (both exit0), but the parser records
`readbackGranted=false`, so all three methods remain unstarted. Package/command
and emulator cleanup join; no CA evidence exists for that API. Independent
[public AOSP source](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/Settings.java)
shows zero-flag granted permissions end immediately in LF; the parser retained
that terminator and rejected `granted=true` with LF/CRLF. A focused correction
removes only the final line terminator while retaining exact package/User0,
installed=true, unique runtime section/permission and true-grant checks. Public
source and host regressions prove that formatting defect, not the actual image's
unretained flags or the cause of its rejection. The correction `02fbca2` passes
[host run 40212541854](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40212541854)
with the same 318 JVM/46 CA receipts/nine clean lint reports. In the
[fourth matrix 40213602618](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40213602618),
API26 passes again, but API37 still records grant0/readback0/readbackGranted=false
and three zero-start rows, with all cleanup joined. The LF/CRLF correction did
not establish the image's rejection cause. Before another runtime, a finite
parser diagnostic now emits only fixed integer counts and boolean structural
facts for owned package, User0, installed status, runtime sections and the target
permission. It emits no dump bytes, paths, package inventory or flags strings and
changes no report schema or positive admission gate. The next checked-source
runtime must establish the actual structural failure before another admission
change. Local diagnostic validation passes 95 non-worker cases, syntax and 270
local links. The initially selected worker file could not load missing `ws`;
after locked `npm ci --ignore-scripts`, three worker cases fail with
`pairing_unavailable` on Node22.22.2 (one passes). These are retained failures,
not acceptance or proven baseline failures. Installing the pinned Node runtime
was denied; the existing authorized pinned hosted workflow must resolve the
full gate before any emulator dispatch. Pinned [host run 40214948784](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40214948784)
at `bf73686` passes all jobs; independent original-artifact audit confirms 318
JVM methods in 41 XMLs, 46/46 clean-source CA receipts and nine clean lint XMLs.
The [fifth matrix 40216075210](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40216075210)
again independently verifies API26's three methods and joined cleanup. API37
has declaration=true, grant0/readback0 and three zero-start rows. Finite facts
are ownedPackageCount=1, user0Count=2 and packageTargetCount=1; later facts remain
zero/false because the unique-user guard exits first. This establishes the
rejection point, not the cause of the second header or the actual grant state.
All package/command/emulator cleanup joins. Package-block scoping is under
review; duplicate users inside the owned block must remain rejected. Public
AOSP [DumpHelper](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/DumpHelper.java)
prints outer `Package Changes:`/`User 0:` sections after package details, while
Settings prints package children deeper than their Package header. A new
regression appending Package Changes/Shared users sections reproduces the old
parser's rejection. The correction stops the owned block at the first nonblank
line with equal-or-less indentation, uses only horizontal header whitespace,
and retains global owned-header uniqueness plus all child User0/grant checks.
LF/CRLF, denied grants, duplicate child users/owned headers and foreign outer
permission material are tested. Independent review and six focused cases pass;
this demonstrates the scoping defect, not the actual image's outer section.
Combined local parser/report/verifier/workflow/documentation regressions pass
69/69, with 270 checked local links and clean diff whitespace. The prior local
Node22 worker failures remain recorded above; this package does not claim to
resolve them. A new pinned host gate and full runtime matrix remain required.
A23 acceptance remains open. Boundary checkpoint `4192a41` fails
[host run 40216911800](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40216911800)
in `:core-capture:testDebugUnitTest`: the original XML records
`realDirectionalEofClosesGracefullyBeforeInterruptAndRetainsChargesUntilJoin`,
`java.net.SocketException: Socket is closed` at `CapturePolicyCompletionTest.kt:33`
while obtaining the peer output stream. Documentation/native jobs pass, but
this is not a passing full host gate. No new A23 matrix was dispatched.
Isolated analysis demonstrates a viable test race: real peer EOF can release
its latch before `shutdownOutput` returns and publishes `outputEnded`. The
immediate flag assertion therefore lacks an ordering guarantee. Separately,
the peer helper closes its accepted socket in failure cleanup and can replace
the original assertion with its later peer exception. The artifact cannot
recover the lost primary failure, so this is not proof of its exact assertion.
The owner is correcting only test synchronization and exception precedence,
with deterministic publication-gap/primary-secondary failure regressions.
Production EOF/half-close/join/charge semantics remain unchanged; no assertion
is skipped and the failed run stays failed. Isolated test owner committed
`5758c20`, integrated as `5a589d4`: actual `shutdownOutput` is deterministically
gated before flag publication, the test witnesses peer EOF in that gap, then
releases and awaits publication. The existing delayed/full reverse reply,
no-interrupt and retained-charge/actual-join assertions remain. Two helper
regressions require primary-failure identity with suppressed peer failure and
peer-only failure propagation. Only the test file changed; static invariant
checks and diff whitespace pass. Local Gradle execution is **unrun**: the
attempted focused JVM/lint command exits immediately because `JAVA_HOME` is not
set and no `java` command is available. Independent read-only review found no
concrete correctness or lifecycle defect in the test correction; it also could
not compile without Java. Fresh pinned host CI must compile and execute these
tests before another emulator dispatch. The integrated clean checkpoint
`fa2d845086e4157dc6d455775fc541a4fc67071f` passes
[host run 40220903154](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40220903154).
Independent original XML/receipt audit confirms 320 unique JVM methods in 41
XMLs (all five EOF/evidence methods pass), zero failures/errors/skips, 46/46
clean-source CA receipts and nine zero-issue lint XMLs.

**A23 runtime research acceptance passes** in fresh
[matrix 40222004218](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40222004218)
at that exact source. Independent replay of both APIs' original runtime, XML,
HTML and host-cleanup files verifies three ordered methods, three starts and
three completions plus every original A22/CA/cleanup gate on each API. API26
returns 432-byte DER and API37 433-byte DER; each retains before/after byte/hash
continuity and all seventeen Android CA facts. API37 finite readback now has
one exact owned package/User0/installed/runtime/target, true grant and successful
commands. API26 remains not_required. Both actual emulator stop/termination/join
records pass with exit0. Earlier failed runs remain failed, not combined into
this acceptance. This proves saved Android Keystore credential retrieval only.
CA installation, target-app trust and physical USB remain open.

## Enrolled HTTP-origin factory research

The [enrolled selected-UID TUN suite](android-enrolled-tun-research.md) is prepared
with real service/factory wiring, a separate finite traffic command and bounded
host/cleanup ownership. Its 179 integrated host checks, APK compilation/signature
audit and strict lint are preparation evidence. Actual API 26/37 selected-UID
enrolled TUN execution remains unrun; ordinary host CI compiles the method only.

The separate [policy composition check](capture-policy-transport-research.md)
uses the production authenticated SOCKS frontdoor with the actual enrolled
factory. Its explicit `:capture-transport-research:testDesktopPolicyIntegration`
task requires the clean pinned desktop and executes freshly; ordinary CI excludes
it. Local JVM completion does not establish selected-UID Android capture.

The [C2 contract](capture-transport.md), [small shared wire vectors](../protocol/fixtures/c2-draft-0.5/README.md)
and [finite Android proof report](android-capture-factory-runtime.md) bind the optional
http-origin-connect mode to its actual negotiated capability. Legacy A19 fixtures,
reports and their digest stay unchanged. Default host checks include the independent
HTTP preface/acknowledgement bytes, the owned Node TLS peer, maintained JVM WebSocket
backend, self-contained enrolled transport seam, finite report/driver/worker tests
and privacy/cleanup negatives. Backend checks use the real scoped TLS peer, actual
write/flush receipts, bounded queues, peer-close evidence and actual worker joins.

Default CI never silently skips or imports an unpublished desktop checkout.
Explicit local suites require an absolute FREEKIT_DESKTOP_ROOT and a reviewed
FREEKIT_DESKTOP_COMMIT. The reviewed desktop implementation for this package is
fd63f6940226c8e3401a165082dfa9325abaca69. Their actual origin uses127.0.0.2:80 with
collision refusal, so coordinate that port with other local factory checks. Run
the gateway-origin-desktop.local.test.mjs, gateway-origin-fixture.local.test.mjs
and gateway-origin-worker.local.test.mjs files explicitly with Node --test and
--test-concurrency=1. They establish actual registry/mTLS, real desktop attachment
and HTTP capture, numeric destination/logical Host separation, complete body/EOF,
END_WRITE/tail ordering, denial/revoke and actual cleanup. The private CSR fixture
transfers only public CSR/approved material while the JVM retains its software key.
These host software-key results do not establish Android Keystore or protection.

The separate mandatory :capture-transport-research:testDesktopIntegration task
requires that same explicitly reviewed desktop source; missing source fails rather
than uses an assumption/skip. It remains outside ordinary host CI. The existing
[manual enrollment workflow](../.github/workflows/enrollment-runtime.yml) adds the
finite c2 choice, keeps a22a as default, checks out only the pinned desktop commit
for c2 and runs that explicit integration task after SDK setup. Dispatch depends
on desktop publication authorization; no C2 device run is attributed to these
local checks.

The C2 driver reuses the existing owned device/worker/ADB/private-input lifecycle,
one actual method and four fixed sanitized artifacts. Live phase3 authorizes
approval; phase7 only schedules tail release after the child independently sees
decoded/applied/drained END_WRITE. The verifier binds both exact source commits,
API, the full strict clock interval, all30 Android facts, exactly one distinct
actual HTTP capture, body hashes, actual normal closure and every resource,
package, command and emulator join. Multiple updates of the same private capture
ID are counted once; identities are never exported. Fixed failures cannot become
passing evidence. These checks make no TUN, app-selection, production HTTPS, C1
cold-reset resolution or protocol-freeze claim.

## Real TUN capture research

The [C1 profile](capture-policy-runtime.md) and [controlled host/traffic applications](../tools/capture-spike/README.md) implement a separate research path through actual selected-UID TUN packets, the pinned native engine and authenticated local SOCKS policy. The production app remains a simulation. Local receiver/parser/verifier tests and APK compilation do not establish device capture; complete API 26/37 policy acceptance remains open.

The [manual capture workflow](../.github/workflows/capture-runtime.yml) invokes five exact standalone policy methods on API 26. API 37 first invokes the actual denied-local-network preflight, then grants that permission to its two owned APKs before the same five methods. The tests require real platform VPN consent, a distinct traffic UID, a second nonempty allowlist, exact TCP bytes/EOF, direct UDP/DNS positive controls, UDP443 no-delivery plus policy drops, preserved original IPv6, notification Stop with a held live flow and fresh restart, and per-flow protect/bind refusal after TUN start. Actual platform events are not inferred from injected guards. Always-on/lockdown support is explicitly disabled for this research service.

The independent gate checks the actual method pairs, finite facts, full measured clock interval, exact host TCP-accept/UDP-receipt and completed-path counter deltas, cumulative continuity, source, permission provenance and all owned cleanup. Missing/wrong local SOCKS authentication must allocate no egress. The host and signature-protected traffic service share only fixed synthetic commands and count/digest results. Controlled listeners fail on collisions; no arbitrary target RPC, map-DNS, companion wire revision or TLS-interception claim is introduced by the raw injected receiver.

Fresh-AVD clock setup issues root once and records its command status, then requires actual UID0 within one 30-second reconnect/read budget before changing automatic time or UTC. Transitional UID2000 may be polled only within that budget; failed waits/reads, unknown identities and expiry reject setup. A nonzero root response alone establishes neither a successful transition nor device failure. The [AOSP client at 1cf2f017](https://android.googlesource.com/platform/packages/modules/adb/+/1cf2f017d312f73b3dc53bda85ef2610e35a80e9/client/commandline.cpp#1056) can return before its reconnect handling when the root-service connection closes; the [daemon operation](https://android.googlesource.com/platform/packages/modules/adb/+/1cf2f017d312f73b3dc53bda85ef2610e35a80e9/daemon/restart_service.cpp#31) requests an adbd restart. This source explains the setup boundary without asserting binary-source identity or a cause for any runtime socket failure. The setter/readback checks, actual restored UID2000 requirement and independent full two-second UTC interval/round-trip gate remain mandatory. Actual Bash regressions exercise both transitions, failure propagation and the shared root deadline; they do not execute Android capture.

Before the two malformed-authentication attempts, the test requires a healthy active native owner with no current flows, sockets or pending opens and an unchanged guard observation for 250 ms within 15 seconds. It then retains the same refusal replies and exact no-extra-egress/guard checks. Stop first requires actual local/native/TUN joins and traffic-client interruption within four seconds of request launch, using the completion timestamp captured by the request thread's own `finally`. Framework shutdown latency does not become client-interruption time; actual lifecycle joins still must finish within the separate 30-second bound. Only afterward does the test explicitly request owned host-fixture cleanup through `/close-held`, require the actual socket-close ledger and zero remaining host data sockets/timers/callbacks, then verify fresh forwarding. Each synchronous HTTP observation includes exactly its own control socket and timer; the driver's independent snapshot after instrumentation requires all three resource counts to be zero. The exact Stop deltas include one `heldCloseRequests` and one actual `heldRequestsClosed`; every other method requires zero new held-close requests. `HeldFixtureCleanupJoined=true` records this explicit cleanup, without attributing remote idle TCP closure to Stop or assuming a second EOF is observable.

The signature-protected traffic APK declares normal `ACCESS_NETWORK_STATE` and accepts only two additional empty commands: 17 waits for its default VPN network, 18 for its default non-VPN network. Each observes the same public `Network.equals` identity, INTERNET capability and requested VPN transport state with a conservative 250 ms lower bound within five seconds: the later query start must be at least 250 ms after the first positive query completion. This excludes getter/response delay from the proved interval, without binding or opening a socket or sending packets. Every START first requires non-VPN observation, then requires the selected traffic UID's expected state after service startup; the pre-VPN UDP443 control also requires non-VPN observation. `RouteTransitionsObserved=true` requires the actual completed check count, two per START plus the extra direct-case control check. These observations never replace the original full payload, EOF, digest, receiver, guard and cleanup checks, and no data request is retried. Exact IPC replies add only nullable finite `failureCode` to bounded byte count/digest/status. Route failures retain fixed presence/INTERNET/VPN boolean enums; TCP failures retain only connect/write/shutdown/reply/EOF/close stage and timeout/IO/protocol/other category. Those codes enter the existing 39-field failure bundle, without provider text or raw network handles.

Negative-only TCP diagnostics additionally normalize known I/O failures to `reset`, `aborted`, `closed`, `bad_fd` or `not_connected`. A pure classifier visits at most eight causes by identity, ignores suppressed exceptions, and prefers a known public `ErrnoException.errno` over exact known Java socket constants. Unknown text remains `io`; timeout status and the required EOF are unchanged. Android 8's [native SocketInputStream](https://android.googlesource.com/platform/libcore/+/android-8.0.0_r1/ojluni/src/main/native/SocketInputStream.c) maps both ECONNRESET and EPIPE to reset text, and its [Java reader](https://android.googlesource.com/platform/libcore/+/android-8.0.0_r1/ojluni/src/main/java/java/net/SocketInputStream.java) can discard the errno cause. A `reset` text category therefore proves neither a specific errno nor a wire RST. Exact [Socket accessor](https://android.googlesource.com/platform/libcore/+/android-8.0.0_r1/ojluni/src/main/java/java/net/Socket.java) constants identify Java closed/not-connected state, without recovering EBADF/ENOTCONN; input shutdown is not normalized to full closure. Only fixed categories enter the existing failure bundle, without copying provider messages or causes. The traffic module's Java exception/privacy/cycle tests run in the host workflow.

Receiver snapshots retain three additional actual-event counters: `deadlineCloseRequests`, `tcpErrorEvents`, and the exact ECONNRESET subset `tcpResetErrors`. Every accepted method requires zero receiver-deadline deltas. Ordinary methods additionally require zero TCP error/reset deltas; Stop retains bounded monotonic aggregate error counts because intentional interruption may reset a connection. Reset counts must not exceed error counts, cumulatively or within a method, and later methods require zero new errors. No aggregate Stop error is attributed to a particular held flow. Complete cumulative continuity preserves these counts through final cleanup; successful bytes or later cleanup cannot erase an ordinary error or any deadline. The ordinary five-second and held sixty-second deadlines, all payloads and EOF checks remain unchanged; these counters distinguish observations without asserting a new cause or behavior fix.

Only `runtime.json`, `TEST-capture-research.xml` and `host-cleanup.json` under `build/reports/capture-runtime/` are uploaded. Raw instrumentation, receiver/configuration credentials, APKs, ADB/emulator logs and packet bodies remain private. Overall acceptance additionally requires actual receiver/command/package cleanup and emulator termination/join; a later host failure preserves the actual method results while failing the gate.

Failure-only diagnostics retain a finite39-field primitive bundle before implicit cleanup, a fixed project check code, and up to16 original project file/line sites. They exclude arbitrary exception text, causes, suppressed exceptions, packages, destinations and credentials. Source-level fixes copy an incoming Messenger command before Android recycles its Message; TCP descriptors are initialized before VPN protect while preserving protect→bind→connect. These fixes do not establish actual routing until a checked follow-up runtime passes. Historical d37b8f2 reports remain unchanged: both common five-method runs failed; API37's separate actual denied-permission/no-TUN preflight passed. Driver package/receiver/command cleanup and emulator termination/join completed.

At exact source `913bafcdb0dbdaf3765936d3852da113ac532394`, [capture run 40149567725](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40149567725) fails before the driver on API26 when `adb unroot` reports a closed transport; only emulator-cleanup evidence exists there. API37 records six actual method pairs: denied-permission, direct TCP/UDP/DNS with UDP443 policy, IPv6 and guard instrumentation pass; auth guard-baseline equality and the remote held-socket await fail. Direct and IPv6 have matching independent receiver evidence. The later guard instrumentation pass inherits the held socket, so its complete receiver gate also fails. All final owned cleanup joins complete. The matching [host run 40149560914](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40149560914) passes 231 unique JVM cases, 413 Node cases and eight clean lint reports, both actual conformance comparisons and eight Linux crash cases. These immutable reports do not prove the later startup-baseline or explicit fixture-cleanup corrections. The clock setup now verifies actual shell UID2000 within a shared bounded restoration interval even when the single unroot command reports transport closure; failed waits, unknown identities and persistent root still prevent driver admission, and the independent full two-second UTC interval/round-trip gate is unchanged.

At `75e23c0bc16736d496705e38bf01e8f6f0b6505d`, [capture run 40150883401](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40150883401) records all five API26 and six API37 method pairs. API26 passes direct traffic and IPv6; UID/nonselected traffic, fresh-start traffic and the second guard owner fail. API37 passes five methods and fails fresh-start traffic. Every failure occurs after a second capture start with reported active/native state and zero route/guard admissions; this correlation does not identify a native, framework or routing cause. Selected HTTP/opaque substeps and the local Stop/client-interruption plus explicit held-fixture cleanup checks succeeded before later failures. Host response callbacks do not prove Android receipt/EOF. Both APIs finish all owned cleanup. The matching [host run 40150875480](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40150875480) passes 231 JVM cases, 420 Node cases, eight clean lint reports, both actual conformance comparisons and eight Linux crash cases. These reports predate the traffic-UID readiness commands and do not establish their actual runtime behavior.

At `0314d1134a95ab2a67513ea7c6a1c12c01f20df4`, [capture run 40152969971](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40152969971) passes all six API37 methods and four of five API26 methods, with exact paired starts/completions, independent receiver evidence and joined final cleanup. API26's nonselected HTTP request validates the full fixed reply, then fails the separate EOF read with `traffic_tcp_eof_io`; it remains a failure. Method elapsed times are not retained, so neither receiver deadline nor network/reset cause can be inferred. The matching [host run 40152966139](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40152966139) passes 246 JVM cases, 421 Node cases, eight clean lint reports, both actual conformance comparisons and eight Linux crash cases. The two-API C1 gate remains open. These immutable reports predate the finer I/O classification and receiver-event counters above; the framework observations do not claim a netd flush/join.

The separate [cold TCP comparison](capture-cold-tcp.md) uses its own [API 26 workflow](../.github/workflows/capture-cold-runtime.yml) and three fresh matching-signer APKs. One standalone method observes the traffic UID's non-VPN route, then sends unchanged HTTP command 10 as its first and only data request, without VPN consent, a capture service or HostReceiver call. Thirteen string facts and an exact receiver vector require the full reply and strict EOF; complete host bytes cannot turn failed EOF into a pass. The [independent verifier](../scripts/verify-capture-cold-runtime.py) checks fresh bounded JSON/XML, source/clock, package/process absence, receiver continuity and actual command/emulator joins. Only three sanitized cold-report files are retained.

The new host checks comprise eighteen parser/schema cases, two driver checks using actual failed children, six actual Bash cleanup paths plus clock-block equality, and twelve independent Python guards. The existing capture Node glob includes these 27 cases; the documentation job runs the Python guards. The local implementation checkpoint compiled the Android method before the actual run below; its projected host totals were 249 JVM and 455 Node cases. A comparison outcome alone does not establish VPN causality or clear C1.

At `f8471970de730ae4f4fb9cc2f7ec8a4c46f0d0b3`, [cold run 40156287722](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40156287722) records one actual API26 transaction without prior VPN activity. All thirteen facts, absent owners, non-VPN route readiness, full host HTTP/TCP byte vector and all actual cleanup joins are retained; strict EOF still fails as `traffic_tcp_eof_reset` after the complete reply check. Receiver deadline/error/reset counters remain zero. The independent audits reject acceptance and establish only that prior VPN activity is unnecessary for this observed failure. The matching [host run 40156269493](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40156269493) independently passes 249 unique JVM cases, 455 Node cases, eight clean lint reports, both actual comparators, eight Linux crash cases and full workflow lint. The [comparison record](capture-cold-tcp.md#actual-cold-result) preserves the clock and exact failure/resource observations. C1, production transport composition and physical USB remain open.

The host job checks OpenSSL 3 explicitly and runs five loopback Node fixture tests for bounded CSR validation, certificate issuance, authenticated WebSocket echo, missing-client rejection, temporary-file cleanup, bounded research certificate times and clock probes, and normal TLS rejection of future or expired gateway certificates. Twenty-nine parser/ownership regressions separately cover exact start/end pairs, terminal status, crashes, missing/duplicate/skipped cases, bounded input, sanitized ADB/server-log diagnostics, explicit reverse-port collisions, and selective cleanup. It also compiles and strictly lints the isolated transport module, retaining its lint reports. It does not run connected Android tests. A local Windows research check can select an installed OpenSSL 3 executable through `OPENSSL_BIN`; no system OpenSSL setting is changed.

The documentation job also runs fifteen stdlib Python regressions for the [exact Keystore result verifier](../scripts/verify-keystore-results.py). They cover the actual AGP wrapper/per-class formats, missing/duplicate/unexpected cases or suites, interrupted XML, skipped/crashed results, inconsistent counters, bounded reports, and CLI failures without dumping report messages.

The host job also runs thirty [draft-stream result/clock regressions](../tools/transport-spike/draft-stream-results.test.mjs) for the separate [authenticated streaming proof](decisions/0012-authenticated-draft-streaming.md). They require seven actual paired instrumentation starts/completions and terminal success, reject skipped/crashed/duplicate/missing results, retain only fixed scenario/phase/type diagnostics and typed observations, and enforce the two-second round trip and entire skew interval, including UTC-second quantization. The failure-only pressure schema and independent case namespaces are checked separately from positive expiry proof. Ten additional process/driver checks cover actual child cancellation/output bounds, process-group teardown after leader exit, explicit CLI arguments, and safe incomplete reports. The verified A21 host baseline contains 243 Node cases, including the 77 enrollment cases described below; the A22 helpers and HTTPS/issuer tests add coverage through the commands above. Historical runs retain their source-specific counts. These host checks do not execute the seven Android streaming methods or establish streaming runtime acceptance; the POSIX process-group branch has actual Linux coverage in host run 40118691291 below.

The separate [research WebSocket framing module](../tools/transport-spike/framing/README.md) and Node framing tests exercise bounded RFC 6455 frame reading, serialized writes, backpressure, cancellation, and resource closure with real loopback sockets. CI runs `:transport-framing:test` and retains its XML/HTML reports. This research layer does not establish HTTP upgrade, TLS, authentication, the draft session grammar over a live connection, or Android transport integration.

The current framing suite has twenty-eight JVM cases, including two gated output-buffer regressions for underlying write/flush completion, binary/text/close ordering, and permanent write/flush I/O failure. Eight additional cases verify conservative peer-snapshot intervals, exact nanosecond boundaries, resets and invalid inputs. The expected complete host JVM total is now 193: 33 app, 65 protocol, 62 security, 28 framing and five research enrollment state-codec cases. The latter run through `:transport-interop:testDebugUnitTest`, with XML under `tools/transport-spike/android/build/test-results/testDebugUnitTest/`. Historical run counts below retain their exact source results.

The A22 host extension tests private bounded stdin, live phase observation, forked-worker IPC, exact binary seed construction and the incremental two-invocation result parser. Six additional documentation-job cases execute the manual workflow's actual Bash cleanup against an owned child, preserving exit statuses 0, 7 and 124 in explicit and EXIT-trap paths. Sixteen runtime-report guards independently reject false approval/drop evidence, missing process absence, identity/port/result changes on restart, unfinished resources, stale or malformed files, trailing token characters and missing/tampered XML/HTML projections. These extend the existing 42 enrollment corpus/comparison/crash guards to 64; the nine Markdown-checker cases remain separate. Host-only fixtures and synthetic report canaries do not establish Android enrollment runtime acceptance.

Unit-test/lint reports and resolved dependency inventories are retained for seven days, including on failed builds when reports exist. The upload paths exclude `dist/`, APK outputs, signing material, and the temporary TLS identities created by the host test. A green workflow establishes only these host checks; Android installation, UI behavior, Keystore use, VPN packet forwarding on Android, and physical-network acceptance remain independent evidence requirements. Workflow syntax is checked locally with actionlint; execution evidence is recorded separately. A hosted run is not claimed until its actual run result is recorded.

The host artifact includes app JVM XML under `app/build/test-results/testDebugUnitTest/`, alongside protocol/security XML and the HTML reports, so individual cases can be audited directly.

[Host run 40101590554](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40101590554) passed at source `bd7b67627d7382a16a32eeae5482b1fec0742c5a`. Downloaded XML confirms 91 unique JVM cases: 19 app, 10 protocol, and 62 security, with zero failures, errors, or skips. Logs confirm 31 Node cases (two peer, twenty-nine parser/ownership), nine documentation-checker cases, and 97 checked local links. App, security, and research lint reports all contain no issues; the hosted actionlint step also passed. The new fifteen-case Keystore verifier regression suite was added after that run and is locally validated, not attributed to this checkpoint.

The separate Linux native-engine job checks the fixtures, fetches HevSocks5Tunnel root commit `c0dfc4b07baa5e48022f5f88ac90488601f05674` and its pinned submodules, then executes the worker. Reproduce both checks with:

```sh
python3 -m unittest discover -s tools/engine-spike -p 'test_*.py'
python3 tools/engine-spike/run_linux.py --engine-root .gradle/engine-spike/hev-socks5-tunnel
```

The runner verifies its source checkout and builds the candidate locally. Its synthetic packet fixtures use a socket pair, a controlled SOCKS adapter, and an explicit-proxy peer. It needs GCC, make, and Python 3, with no sudo, TUN device, network-route changes, SDK, or phone. This isolates native packet-to-stream evidence from Android routing, protected sockets, real desktop proxy integration, and physical-device acceptance. It does not bundle the candidate into the APK or freeze the protocol.

The same hosted run passed 27 Python fixture regressions and the actual native worker's four IPv4/IPv6 HTTP/CONNECT cases. Each transferred 16,421 upload bytes and 32,787 download bytes, with gated streaming and half-close checks, reply SHA-256 `62a22a63bb850ba7b263fccff99e868133570394d36d6ee16fd32e9d7c1a4601`, and the return source/destination address checks active. This is Linux synthetic-packet evidence; Android JNI execution and VPN routing require their own runtime evidence.

[Host run 40103175226](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40103175226) passed at `7e9b1c8c03b4bb925fd894e37cd53c5dc522eff4`. Independent XML/log audit confirmed 91 JVM cases (19 app, 10 protocol, 62 security), 34 Node cases (five peer, twenty-nine parser/ownership), 38 native Python regressions, all fifteen strict-verifier regressions, nine documentation-checker cases, and 103 checked local links. All four real Linux packet flows retained the byte counts, checksum, gated streaming, and half-close checks above. All three lint reports and hosted actionlint passed, with zero test failures, errors, or skips. The actual Ubuntu OpenSSL 3.0.13 executable passed all five peer cases, including future/expired certificate rejection; this is the hosted compatibility evidence for the bounded certificate-time fixture.

## Draft protocol conformance

[Draft appendix 0.3](protocol-streams.md) has independent Kotlin and Node codecs/lifecycle models against the [shared adapter and corpus](../protocol/fixtures/a19-draft-0.3/README.md). The committed set contains 142 codec cases and 73 lifecycle traces covering 704 operations. It covers strict UTF-8/JSON and schema limits, duplicate/escaped members, integer/date/version precedence, capability negotiation, directional byte ordering and deferred EOF, cancellation, deadlines, bounded history, and cross-owner slot/byte accounting. Accepted/in-flight bytes stay charged until actual local-writer acknowledgement or confirmed resource closure; a close observation alone cannot complete a stream or free its lease.

The [corpus validator](../scripts/check-protocol-corpus.py) checks fixed envelopes/IDs, descriptors, references, counts, snapshot accounting and EOF/resource invariants before implementations execute. Sixteen regressions cover its depth/file/rendered-input bounds, duplicate keys, type substitutions, non-executable operations, premature release, local oversize-text causes and static errors even for huge integer tokens. The independent [comparator](../scripts/compare-protocol-conformance.py) has thirteen regressions and requires both complete actual reports to match every expected outcome and each other, including exact ordered IDs, types and the committed-file digest. Neither implementation supplies the expected data.

Run from the repository root:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_protocol_corpus.py'
python3 -m unittest discover -s scripts/tests -p 'test_protocol_conformance.py'
python3 scripts/check-protocol-corpus.py --corpus protocol/fixtures/a19-draft-0.3
./gradlew --no-daemon --console=plain :core-protocol:test
node --test tools/transport-spike/companion-protocol-codec.test.mjs \
  tools/transport-spike/companion-protocol-lifecycle.test.mjs \
  tools/transport-spike/companion-protocol-conformance.test.mjs
node tools/transport-spike/companion-protocol-conformance.mjs
python3 scripts/compare-protocol-conformance.py --corpus protocol/fixtures/a19-draft-0.3 \
  --kotlin build/reports/draft-protocol/kotlin-conformance.json \
  --node build/reports/draft-protocol/node-conformance.json
```

Gradle declares the Kotlin report as an output, so deleting it causes ordinary test execution to regenerate it. CI runs the bounded checks in the documentation job, executes both model suites in the Android host job, and compares reports before recording dependency inventories. Only synthetic actual-result JSON joins the existing retained reports.

[Host run 40107880102](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40107880102) passed at `52ec3466a44b74dc1a395acbac5a4f9845501629`. Independent downloaded XML/log audit confirms 131 unique JVM cases (19 app, 50 protocol, 62 security), 70 Node cases (five peer, twenty-nine parser, thirty-six draft-protocol), 44 script tests (fifteen Keystore verifier, sixteen corpus guard, thirteen comparator), 38 native Python cases, and all four Linux packet flows. All three lint reports, hosted actionlint, nine link-checker tests and 126 local links passed; all test failures, errors and skips are zero. Actual Ubuntu tools were Node 24.22.1 and OpenSSL 3.0.13.

Both retained actual conformance reports were downloaded and independently rerun through the comparator: all 142 codec cases and 73 lifecycle traces (704 operations) match the corpus and the other implementation, with digest `2cfd77c90074facfc1a33c362da46ae3d88d9629a7196f239b4b1814b0b7fab3`. Model interleavings do not prove real concurrency, total-process-memory bounds, authenticated WSS streaming/backpressure/cancellation, registry authorization or actual socket closure. The older research transport proof did not exercise this new session grammar, and full v1 freeze remains open.

[Host run 40110833431](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40110833431) passed at `4b224444ffcced6b22210b13cabe7898d228092d`. Downloaded XML confirms 163 unique JVM cases (33 app, 50 protocol, 62 security, 18 research framing), with zero failures, errors, or skips. Logs confirm 103 Node cases (five peer, twenty-nine parser/ownership, thirty-three framing/peer, thirty-six draft-protocol), all 44 script tests, 38 native Python regressions, four Linux packet flows, nine documentation tests, and 133 local links. All five lint reports are clean, including fixture debug/release, and hosted actionlint passed. Actual tools were Node 24.22.1 and OpenSSL 3.0.13. The independently downloaded Kotlin/Node reports again match all 142/73/704 outcomes at the digest above. The eighteen framing cases include the actual independent Kotlin-to-Node loopback exchange; its scope remains raw framing rather than authenticated WSS or Android transport.

[Host run 40112168842](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40112168842) passed at corrected source `96678cdbbb62a62531748dda834e4211cc3130df`. Independent downloaded XML/log audit repeats all 163 JVM and 103 Node cases, 44 script tests, 38 native Python regressions, four Linux flows, five clean lint reports, nine documentation tests, 133 links, and hosted actionlint. Node 24.22.1/OpenSSL 3.0.13 and the complete 142/73/704 conformance reports retain the same digest and zero failures, errors, or skips.

[Host run 40113196347](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40113196347) passed at `2b307474a9ca65d4f86810dffa3e0a2b0439e896`. Independent XML and complete direct-job logs confirm the same 163 JVM/103 Node/44 script/38 native Python cases, four Linux flows, five clean lint reports, nine documentation tests, and 135 links. Hosted actionlint passed; actual Node 24.22.1/OpenSSL 3.0.13 and the independently compared 142/73/704 conformance reports remain unchanged. GitHub's step-detail view temporarily omitted log sections, so the final count/version audit used complete job-log downloads.

[Host run 40114471877](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40114471877) passed at `0a395e1c01f6156c45df332d703a305385977128`. Final downloaded XML and complete job logs confirm 163 JVM cases (33 app, 50 protocol, 62 security, 18 framing), 103 Node cases, all 44 script tests, 38 native Python regressions, four actual Linux packet flows, five clean lint reports, nine documentation tests, and 135 local links, with zero failures, errors, or skips. Hosted actionlint passed. Actual Node 24.22.1/OpenSSL 3.0.13 and both independently compared 142/73/704 reports retain the committed digest above. The native job's initially unavailable startup view did not indicate a test failure: its completed log confirms all four byte-count/checksum/streaming/half-close flows passed. This host result and the passing eight-case preview run below use the same exact source.

[Host run 40118691291](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40118691291) passed at `277939d72d2d5ad33bc0f5be1e636d5fbe17ca3c`. Downloaded XML independently confirms the same 163 JVM cases and five clean lint reports. Logs confirm 150 Node cases (5 issuer/echo, 29 original parser/ownership, 20 draft-stream parser/clock, 10 owned-process/driver, 33 framing/peer, 17 authenticated streaming peer, 36 protocol), all 44 script tests, 38 native Python regressions, four Linux packet flows, nine documentation tests, and 143 links. The actual Linux leader-exit/TERM-ignoring-descendant regression and hosted actionlint passed. Node 24.22.1/OpenSSL 3.0.13 executed these host checks; the independently downloaded Kotlin/Node reports match all 142/73/704 outcomes at the same corpus digest. This host success does not establish the separate seven-case Android streaming acceptance below.

[Host run 40120281830](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40120281830) passed at `e63c914eb561661660416c2274733c381b1238d6`. Downloaded XML confirms all 163 JVM cases and five clean lint reports. Actual logs confirm 156 Node cases (5 issuer/echo, 29 original parser/ownership, 21 draft-stream parser/clock, 10 process/driver, 33 framing/peer, 22 streaming peer/pressure, 36 protocol), 44 script tests, 38 native Python regressions, four Linux flows, nine documentation tests, 146 links and hosted actionlint. The downloaded Kotlin/Node reports independently match the same 142/73/704 corpus outcomes. Node 24.22.1/OpenSSL 3.0.13 ran the host suite; the separate pressure report below records its actual Linux/JDK measurements without claiming Android acceptance.

[Host run 40121365963](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40121365963) passed at `e0c8c3cd7c7b364c1ba380746e906524d61ee449`. Independent XML/log audit confirms 163 JVM cases, 157 Node cases (the same groups above with 23 streaming peer/pressure cases), 44 script tests, 38 native Python regressions, four Linux flows, five clean lint reports, nine documentation tests, 146 links and hosted actionlint, with zero test failures, errors or skips. Both downloaded conformance reports independently match all 142/73/704 outcomes at the committed digest. Node 24.22.1/OpenSSL 3.0.13 executed the host suite; the revision-2 pressure comparison below is separate from Android runtime acceptance.

[Host run 40122092180](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40122092180) passed at `4416ba64c99b8e01d7c556f5509c059b93e184c6`. Downloaded XML/log audit confirms the same 163 JVM/157 Node/44 script/38 native Python cases, four Linux flows, five clean lint reports, nine documentation tests, 147 links and hosted actionlint, with zero failures, errors or skips. Independent comparison of both downloaded conformance reports again matches all 142/73/704 outcomes. Its clean Linux revision-2 pressure report retained all five profiles, actual joins and zero-resource cleanup; the 1 KiB local-pair profile observed neither writer condition, while the controlled 64 KiB profile observed both. These host checks used Node 24.22.1/OpenSSL 3.0.13.

[Host run 40123568028](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40123568028) passed at `644542de5cf64df79a0d1c1815a2345a847f9351`. Independent downloaded XML/log audit confirms 163 JVM cases, 161 Node cases (including all 25 draft-stream parser/privacy cases), 44 script tests, 38 native Python regressions, four Linux flows, five clean lint reports, nine documentation tests, 147 links and hosted actionlint. There were zero test failures, errors or skips. Both actual conformance reports independently match the same 142/73/704 outcomes. The clean Linux revision-2 report retained all five profiles, actual joins and zero-resource cleanup, with both writer flags false for the 1 KiB local pair and true for the 64 KiB control. Actual tools remained Node 24.22.1/OpenSSL 3.0.13.

[Host run 40124837205](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40124837205) passed at `61ced0ed150497ce2b6303d11e64a6c1a171a529`. Independent downloaded XML/log audit confirms 163 JVM cases, 162 Node cases (including all 26 parser/privacy cases), 44 script tests, 38 native Python regressions, four Linux flows, five clean lint reports, nine documentation tests, 147 links and hosted actionlint, with zero failures, errors or skips. Both actual conformance reports independently match the same 142/73/704 outcomes. The clean Linux revision-2 five-profile pressure report and all joins/zero-resource cleanup were independently validated; the 1 KiB local pair again observed neither writer condition and the 64 KiB control observed both. Actual tools were Node 24.22.1/OpenSSL 3.0.13, with Java 17.0.20.1 recorded in the host pressure report.

[Host run 40125879094](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40125879094) passed at `eb5cd1063c97385701604c6672d054f0b6df8fe6`. Independent XML/log audit confirms 165 JVM cases (33 app, 50 protocol, 62 security, 20 framing), 162 Node cases, 44 script tests, 38 native Python regressions, four Linux flows, five clean lint reports, nine documentation tests, 147 links and hosted actionlint, with zero failures, errors or skips. The two new framing regressions executed, and both downloaded conformance reports independently match all 142/73/704 outcomes. The clean Linux revision-2 pressure report retained all five profiles with actual joins and zero-resource cleanup; actual tools remained Node 24.22.1/OpenSSL 3.0.13, with Java 17.0.20.1 in that report.

[Host run 40127222812](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40127222812) passed at `10b58b4f5560136b9240d0f869237f4a34cee9f9`. Independent downloaded XML/log audit confirms 165 JVM cases, 166 Node cases (including thirty draft-stream parser/privacy checks), 44 script tests, 38 native Python regressions, four Linux flows, five clean lint reports, nine documentation tests, 147 links and hosted actionlint, with zero failures, errors or skips. Both downloaded conformance reports independently match all 142/73/704 outcomes at the committed digest. The clean Linux revision-2 pressure report independently retains five valid profiles, actual joins and zero-resource cleanup; the 1 KiB local pair observed neither writer condition and the 64 KiB control observed both. Actual host tools were Node 24.22.1/OpenSSL 3.0.13, with Java 17.0.20.1 in that report.

[Host run 40128214945](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40128214945) passed at `d6185fc88946dec58391939a304e4b4ac5c0b2f8`. Downloaded XML/log audit independently confirms 173 unique JVM cases (33 app, 50 protocol, 62 security, 28 framing), 166 Node cases, 44 script tests, 38 native Python regressions, four Linux flows, five clean lint reports, nine documentation tests, 147 links and hosted actionlint, with zero failures, errors or skips. All eight conservative observation vectors executed. Both downloaded conformance reports independently match all 142/73/704 outcomes at the committed digest. Actual host tools were Node 24.22.1/OpenSSL 3.0.13. The clean Linux/Java 17.0.20.1 revision-2 pressure report independently passes schema, source, accounting and actual-join/zero-cleanup checks; its timing flags remain reported diagnostics under the limitation below.

## Enrollment foundation validation

[Draft enrollment 0.4](protocol-enrollment.md) has an independent [fixture and adapter contract](../protocol/fixtures/a21-draft-0.4/README.md): 272 codec cases, 39 proof cases and 31 comparison cases. The corpus covers all eight channels, encoding/resource/schema/version precedence, canonical base64url and ECDSA scalar encodings, Unicode byte limits, exact context/purpose binding, proof-byte framing and public comparison fingerprints. CSRs/certificates remain opaque codec inputs; real crypto/profile authorization is tested separately. The digest is `f9ca02fde11c58c286bddb3319e89258a780fdf4f446ee842e46c4e07b9d5fe4`.

The [bounded loader and comparator](../scripts/enrollment-corpus.mjs) reject duplicate JSON, invalid or incomplete coverage, reordered IDs, unsafe types, oversized inputs/reports, stale corpus digests and disagreement with any expected result, including both languages agreeing on the same wrong result. Accepted proof expectations contain exact bytes; actual reports retain only their independently computed SHA-256. Local actual Kotlin and Node reports independently match every case. Gradle declares the Kotlin report as an output so a missing report is regenerated. CI runs the [comparison command](../scripts/compare-enrollment-conformance.mjs) after the actual producer tests and `:core-protocol:test`.

The enrollment Node glob currently contains 77 tests: 16 codec/proof, 16 authority/coordinator, 15 crypto/profile, 20 store, two actual-conformance adapter and eight real-process crash cases. The latter kill a separate database owner before/after reservation, issuer claim, publication and revocation commits, join its actual process/stdio closure, and only then reopen. Before-commit cases require a nonempty rollback journal with a nonzero recovery header. Tests check exact durable tuples, retained owner/reader exclusion, stable publication, API recovery, integrity and foreign keys. Passing local Windows cases do not establish Linux behavior or power-loss durability.

CI sets `FREEKIT_ENROLLMENT_CRASH_REPORT` to `build/reports/enrollment-store/crash.json`. The [independent crash-report gate](../scripts/enrollment-crash-report.mjs) requires its exact eight ordered outcomes, required actual-kill/join/recovery flags, journal facts, current clean source, pinned Node 24.22.1 and Linux platform. It bounds the report to 32 KiB and reported journal lengths to 32 MiB, checks freshness against the test-step start, and rejects extra material or missing cases. The documentation job runs 42 enrollment guards: sixteen corpus, thirteen comparator and thirteen crash-report regressions, including privacy canaries. These guard tests use explicitly synthetic reports and do not themselves kill a process.

Retain only `build/reports/draft-enrollment/*-conformance.json` and the fixed sanitized crash report alongside existing reports. Do not upload registries, rollback journals, temporary inputs, keys, CSRs/certificates, nonces/signatures or raw child/provider logs. The independent wire/proof corpus and actual OS crash evidence remain distinct. This foundation does not establish live enrollment HTTPS, Android Keystore status signing, complete approval/save/reopen, production registry integration or protocol v1 freeze; those remain [A22 and later gates](decisions/0013-enrollment-transactions.md).

[Hosted enrollment checkpoint 40132791278](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40132791278) passed at exact clean source `155f013881ec07ea8b65e49704d69364bccfee67`. Independent downloaded XML/log audit confirms 188 unique JVM cases (33 app, 65 protocol, 62 security, 28 framing), 243 Node cases including all 77 enrollment cases, 42 new evidence guards, 44 existing script tests, nine documentation tests, 161 links and five clean lint reports. Hosted actionlint and the unchanged 38 Python/four Linux packet-flow checks passed. All failures, errors and skips are zero.

Both downloaded actual language pairs independently pass their comparators: A19 retains 142 codec cases/73 traces/704 operations at its existing digest; A21 retains all 272 codec/39 proof/31 comparison cases at the digest above. The Linux crash report passes both the hosted fresh-source gate and an independent replay against the downloaded artifact. All eight fixed cases verify barrier observation, excluded owner/reader, actual kill and process/stdio-close join before reopen, recovery and integrity; test cleanup hooks also passed.

| Operation | Before-commit outcome | After-commit outcome | Before-commit journal bytes |
| --- | --- | --- | --- |
| Reservation | `reservation_rolled_back` | `reservation_retained` | 13824 |
| Issuer claim | `claim_rolled_back` | `intent_reclaimed` | 10752 |
| Publication | `publication_rolled_back` | `exact_publication_retained` | 28160 |
| Revocation | `revocation_rolled_back` | `revocation_retained` | 10752 |

Every before-commit journal had a nonzero recovery header. The sanitized revision-1 report is 3,880 bytes, binds the exact clean source and Linux/Node 24.22.1, and has SHA-256 `9487fdf12cf5076d6da4948fa077c21b9abb7754c9f77771c0b8a719af9cdaf7`. Artifact `12575891313` contains that report and both conformance pairs, with no database, journal, key or APK output. The runner was Ubuntu 24.04.5 with Node 24.22.1, OpenSSL 3.0.13 and Temurin JDK 17; setup resolved `17.0.20+1`, while the separate JSSE diagnostic records its executable's version as `17.0.20.1`. Its completion-time flags remain host diagnostics, not strict Android timing proof. This verifies the A21 foundation host checkpoint and actual Linux process-crash cases, with `powerLossTested=false`; A22 live enrollment and production protocol freeze remain open. No A20 emulator rerun was needed for this unchanged app/streaming source.

## Manual Android native packet runtime

[Native run 40103179435](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40103179435) at `7e9b1c8c03b4bb925fd894e37cd53c5dc522eff4` passed all four IPv4/IPv6 HTTP/opaque-CONNECT cases on each API 26/37 emulator. Each transferred 16,421 upload bytes and 32,787 download bytes with the expected reply checksum above, gated streaming, half-close, native peer EOF, and unchanged original-address checks. Each job also passed fourteen standalone JVM cases (nine carrier, five Stop-gate), strict lint, and the APK source/pin/ABI/manifest/alignment checks.

Both Android executions used x86_64 with a 4096-byte runtime page size. HELLO reported the real native worker running; shutdown evidence confirmed its join, repeated Stop, stopped packet pump, closed descriptors, and four joined/stopped carrier sessions. Instrumentation observed one passing test and terminal exit 0. Research-package force-stop and both owned reverse removals returned 0, with the emulator alive before teardown. The synthetic TUN socket pair, controlled proxy, and typed-EOF carrier remain research components. These results do not establish VpnService routing, a physical phone or physical IPv6 network, ARM64/16 KiB runtime behavior, real HTTPS inside CONNECT, desktop destination policy, final engine selection, or protocol freeze. See [the native packet evidence](decisions/0005-android-native-packet-probe.md).

## Manual Keystore runtime workflow

[Android Keystore runtime](../.github/workflows/keystore-runtime.yml) is a separate `workflow_dispatch` workflow; pushes and pull requests do not launch it. It uses standard public `ubuntu-24.04` runners, with independent API 26 and API 37 AOSP x86_64 images. [GitHub documents Linux Android hardware acceleration](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), and the SDK catalogue lists both images. A runner must expose usable `/dev/kvm`; absent or inaccessible KVM is a failure, with no software fallback or successful skip.

The workflow uses the same verified command-line tools bootstrap as the host workflow, accepts SDK licences explicitly, and installs platform tools, the emulator, the chosen system image, compile SDK 37.0, and build tools 36.0.0. It also installs Ubuntu's `libpulse0` runtime library, which the emulator links even with audio disabled. SDK/emulator versions are printed in the job log. It grants KVM access only inside that ephemeral runner VM, requires `emulator -accel-check`, and starts the AVD with `-accel on` and software graphics. [The emulator's `-no-snapshot` option](https://developer.android.com/studio/run/emulator-commandline#common) disables loading and saving snapshots. No AVD or userdata cache is configured; only Gradle dependencies are cached.

After a bounded boot wait and an API-level check, the job runs:

```sh
./gradlew --no-daemon --console=plain :core-security:connectedDebugAndroidTest
```

The instrumented tests exercise identity reopen, challenge/CSR signing and deletion, refusal to replace an existing key, concurrent key creation, TLS digest authorization, enrolled-client binding, and public credential-record persistence. The Gradle test command must succeed before the [verifier](../scripts/verify-keystore-results.py) requires exactly twelve named `(class, method)` pairs once each across the three expected suites. It rejects empty, missing, extra, duplicate, malformed, truncated, failed, crashed, or skipped reports, and requires suite and aggregate counters to agree with actual cases. Reproduce that report check with:

```sh
python3 scripts/verify-keystore-results.py \
  --results core-security/build/outputs/androidTest-results/connected --api 26
```

Use `--api 37` for that emulator's report directory. The API value labels the summary; the workflow independently checks the booted device API before Gradle runs. Reports are retained for seven days; upload paths exclude APKs, emulator logs, keystores, snapshots, AVD directories, and userdata. Emulator shutdown preserves the test command's exit status.

[Hosted run 40091372512](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40091372512) passed at source commit `1b1b78c2c99d5020cbcc53a12ee27990a6eb09dc`. Downloaded XML reports independently confirmed all three original `AndroidDeviceIdentityStoreTest` cases on both API 26 (Android 8.0.0, AOSP x86_64 image revision 1) and API 37 (Android 17, image revision 6), with zero failures, errors, or skips:

- `nonexportableIdentitySurvivesReopenSignsAndCanBeForgotten`
- `creationNeverSilentlyReplacesAnExistingComputerKey`
- `concurrentStoreInstancesCannotReplaceTheWinningKey`

Both jobs used emulator 37.2.12.0 (build 16428233), reported KVM version 12 usable, and passed the boot-completion and actual API checks before testing. This establishes the tested Android Keystore behavior on those emulator images. Hardware-backed key protection, physical-phone behavior, Android-to-Node mutual TLS, VPN routing, physical USB capture, and cellular WAN acceptance remain separate gates.

[Run 40095225102](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095225102) extends that evidence at source commit `2ab4d7459c6689e22637ba621441eb901e37185a`. Independent XML audit confirmed exactly seven methods on each of API 26 and API 37, with zero failures, errors, or skips: the three original cases above, plus:

- `AndroidDeviceIdentityStoreTest.freshIdentityAuthorizesPrehashedTlsSigningWithoutExportingItsKey`
- `AndroidDeviceIdentityStoreTest.legacySha256OnlyIdentityRequiresPairingAgainWithoutReplacement`
- `AndroidDeviceClientCredentialTest.nonexportableKeyAuthenticatesWithIssuedChainWithoutReplacingItsKeystoreCertificate`
- `AndroidDeviceClientCredentialTest.deletedOrRecreatedAliasCannotBeSelectedByTheOldCredential`

The real Android-local mutual-TLS case passed after fresh keys authorized prehashed TLS signing and restricted legacy keys were rejected without replacement. The earlier five-case attempts at `d43c526` and `c0ed673` passed four methods but failed this TLS 1.2 handshake; diagnostic XML preserved both client I/O and server peer-close errors. The seven-case result supersedes those failures for the tested source. It does not establish Android-to-Node interoperability or hardware-backed key protection.

[Run 40101596957](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40101596957) at `bd7b67627d7382a16a32eeae5482b1fec0742c5a` passed exactly twelve methods on each API 26/37: the seven above and five `AndroidEnrolledCredentialStoreTest` cases:

- `reopenedPublicRecordUsesTheOriginalNonexportableKeyWithoutReplacingItsCertificate`
- `missingReplacedAndLegacyKeysCannotReopenOrPreventForget`
- `interruptedAndCorruptRecordsNeverGenerateOrReplaceTheExistingKey`
- `failedMetadataCleanupLeavesTheDeletedKeyUnusableAndCanBeRetried`
- `separateStoreInstancesSerializePublicationAndForgetWithTheIdentityMonitor`

Independent artifact audit confirmed each full class/method identity once, three suites with counts 2/5/5, consistent aggregate counters, and zero failures, errors, or skips. The new verifier also accepts those downloaded reports locally; it was added after this runtime run. Both jobs used emulator 37.2.12, KVM version 12, and ADB 37.0.1-15733141. The persistence cases reopen stores within one process and use controlled interrupted-file/cleanup fixtures; they do not establish process-death, reboot, power-loss, backup/restore, multi-process, hardware-backed protection, or mutual TLS through a reopened record. See [the persistence evidence and limits](decisions/0008-enrolled-credential-persistence.md).

[Run 40103200664](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40103200664) at `7e9b1c8c03b4bb925fd894e37cd53c5dc522eff4` passed on both APIs with the integrated exact-suite verifier. The actual job logs show successful Gradle execution followed by the new script's summary of twelve cases, three suites, and zero failures, errors, or skips for each API. Downloaded XML also passes that verifier independently. Both jobs used emulator 37.2.12 build 16428233, KVM version 12, and ADB 37.0.1-15733141. This supplies hosted evidence for the stricter gate without extending the persistence scope above.

## Preview runtime evidence

The separate [preview runtime workflow and evidence](android-preview-runtime.md) cover the actual sample-only `MainActivity` UI, simulated consent, Stop, and rotation. Run 40095827316 at `89e5914` passed all four named tests on each API; both original sample PNGs were visually inspected and show readable dark system-bar icons on the light background without header/card overlap. It supersedes the earlier API 37 status-bar contrast finding. These results do not establish real Android permissions, VPN service behavior, or capture.

The manual preview workflow now also prepares four installed-catalog cases on each API 26/37 emulator. It builds and installs the unrelated, headless `com.httpfreekit.fixture.installedapps` debug APK, verifies its fixed label/package, no-code/no-permission/no-component profile, and checks the merged app APK for `QUERY_ALL_PACKAGES`. The fixture's release variant is nondebuggable; host CI assembles both variants and runs strict lint for each, retaining only lint reports.

The new cases exercise real fixture discovery through the public installed-app mode, label/package search, the Development filter, toggle selection, refresh and rotation retention, successful refresh after disabling only that fixture, pruning without reselection, separate sample/installed selections, and the no-capture banner. The runtime gate requires exactly the original four sample cases and four installed-catalog cases with consistent counters and zero failures, errors, or skips. Cleanup enables and uninstalls only the owned fixture, records actual command statuses, and fails an otherwise successful run if fixture cleanup fails. Test diagnostics contain fixed fixture-only messages; installed inventories and installed-mode screenshots are excluded. The original screenshot remains sample-only.

The first installed-catalog checkpoint, [preview run 40110867531](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40110867531) at the same `4b224444` source, failed. All eight exact case pairs executed on each API with zero errors or skips. Headless discovery/search/filter/toggle, actual disabled-fixture refresh/pruning, and the original four sample cases passed on both APIs. The sample/installed separation case failed during its first installed search on both APIs; API 26 also failed the no-capture banner assertion after landscape rotation, while that case passed on API 37. These failures remain open at this checkpoint. The fixture/merged-permission checks passed and actual fixture enable/uninstall cleanup each returned 0 before the owned emulator wait completed. No sample PNG was exported because the failing Gradle command stopped before extraction. Both jobs used emulator 37.2.12.0 build 16428233, KVM 12, ADB 37.0.1-15733141, compile SDK 37.0 revision 2, and build tools 36.0.0; the booted APIs were 26/Android 8.0.0 and 37/Android 17. This is emulator evidence in a fresh default profile, with no physical-device, VPN, capture, or full passing installed-catalog claim.

[Corrected preview run 40112189433](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40112189433) at `96678cdbbb62a62531748dda834e4211cc3130df` executed the same exact eight case pairs per API with seven passes, one failure, and zero errors/skips on each. The strengthened rotation case passed on both: it checked the packaged `adjustResize` mode, required observed real IME visibility and the full banner before/after landscape and portrait rotation, and retained the fixture selection. Both fresh-AVD keyboard settings read back `1`. The selection-separation case still failed in the readiness helper before its first installed search; that combined scroll/wait diagnostic does not isolate a provider error. Fixture/permission guards and actual enable/uninstall cleanup again passed, and the owned emulator wait returned. No new PNG was exported after Gradle failed, and full eight-case acceptance remains open. See the [current workflow and detailed checkpoints](android-preview-runtime.md).

[Preview run 40113213789](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40113213789) at `2b307474a9ca65d4f86810dffa3e0a2b0439e896` passed all eight exact case pairs on API 26, including the independent workflow gate. API 37 executed all eight with one failure and zero errors/skips: sample/installed separation now passed, while the rotation case timed out waiting for IME visibility after landscape rotation, before that orientation's banner assertion. Both jobs passed the fixture/permission/keyboard-setting checks and actual fixture enable/uninstall cleanup. API 26's original 1080 by 1920 sample-only PNG was visually reviewed; its no-capture/ready/Stop/VPN-inactive text and dark system icons are legible without overlap. API 37 exported no PNG after Gradle failed. Full same-source eight-case acceptance on both APIs remains open; the IME timeout is not evidence of a banner geometry failure.

[Preview run 40114495276](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40114495276) passed the complete eight-case suite on both API 26 and API 37 at `0a395e1c01f6156c45df332d703a305385977128`. Downloaded XML independently confirms all eight class/method pairs once each, two consistent suites per API, and zero failures, errors, or skips. Both Gradle commands and independent gates passed, including real headless-fixture discovery/filter/toggle, refresh/pruning, mode separation, and actual window/editor-focus/IME/banner/rotation assertions. Fixture/permission/API guards, keyboard readback `1`, and enable/uninstall cleanup exit `0` passed, and the owned emulator waits returned. Both original sample-only 1080 by 1920 PNGs were visually reviewed with legible warning/ready/Stop/VPN-inactive content and dark icons, without overlap or installed inventory. This completes the tested eight-case checkpoint in fresh AOSP x86_64 default profiles, with physical-device, other-profile, accessibility, real VPN and capture gates still open. Exact artifacts, hashes, and tools are in the [runtime evidence](android-preview-runtime.md#passing-eight-case-checkpoint).

## Manual Android-to-Node transport workflow

The separate manual [Android-to-Node transport workflow](android-transport-runtime.md) runs A5's isolated Keystore/TLS/Node experiment. [Run 40103176026](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40103176026) at `7e9b1c8` passed all four named cases on each API 26/37, with four actual starts/completions, successful terminal status, zero failures/errors/skips, intact ADB mappings, and successful cleanup followed by the independent workflow gate. It proves the tested nonexportable Android identity, enrollment/client binding, mutual-TLS 64 KiB WebSocket echo, and three rejection cases against the controlled Node 24.22.1/OpenSSL 3.0.13 peer. It does not independently force both permitted TLS versions. The loopback fixture and ADB reverse mappings do not establish physical USB capture, VPN routing, production enrollment, or a desktop gateway.

The earlier [run 40101591378](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40101591378) at `bd7b676` executed all four named cases on each API with a usable ADB channel and intact mappings. It failed certificate-validity checks: API 26 failed all four cases; API 37 passed the three rejection cases but failed the positive exchange. Its exact clock skew was not measured. The later passing run uses bounded research certificate dates and a measured clock-skew preflight; it does not establish the earlier skew's magnitude.

The transport workflow prepares a private `ANDROID_ADB_LOG_PATH` under `RUNNER_TEMP` before its first ADB command. This raw server log can include kill-request command-line arguments and is excluded from console output and all artifact uploads. Only the driver's bounded, sanitized marker/source categories may enter test reports; see the [source-backed diagnostic limits](android-transport-runtime.md). No ADB version change or runtime success is implied by this diagnostic setup.

## Manual authenticated draft-stream workflow

[Authenticated draft-stream runtime](../.github/workflows/draft-stream-runtime.yml) is a separate manual-only API 26/37 AOSP x86_64 workflow for [decision 0012](decisions/0012-authenticated-draft-streaming.md). It leaves the existing four-case echo workflow unchanged. Standard Ubuntu 24.04 runners must provide KVM; SDK command-line tools are checksum-verified, compile platform 37.0/build tools 36.0.0 are explicit, Node is pinned to 24.22.1, OpenSSL 3 is required, and `npm ci --ignore-scripts` installs the locked dependencies. No snapshots, AVD cache, signing secrets, release publication, or larger/paid runners are used. The 45-minute job budget includes bounded 600-second boot, 15-minute build and 12-minute instrumentation deadlines; individual test deadlines remain unchanged.

The host workflow runs seventeen new peer/seam/I/O tests through `companion-stream-peer*.test.mjs`. They exercise actual TLS/model/fixture streaming and EOF, 32 MiB backpressure/resumption, blocked-write cancellation and real expiry, binding/authorization/header/admission negatives, callback ownership, and failure cleanup. These remain host-side research checks, not Android runtime evidence.

The Android experiment now wraps only its stream writer's TLS output in a fixed 4,110-byte buffer. A negotiated 4,096-byte masked binary frame reaches the delegate as one 4,104-byte bulk write in the host regression; the existing per-frame flush still completes before model drain. This adds bounded transport storage outside model credit, with no TLS-record or packet-count guarantee. After actual socket closure and successful worker joins, the adapter drops the writer reference before confirming model resource closure; teardown performs no buffer close or extra flush. Host regressions verify local completion and failure behavior; separate Android runtime evidence is recorded below. The control writer, frame/model limits and observation budgets are unchanged.

The current controlled Android comparison requests a 64 KiB raw send buffer only for the normal stream upgrade. All other callers retain the 1 KiB default, including control, enrollment, probes and direct negative upgrade attempts; raw TLS receive requests remain 1 KiB. The six actual buffer getters are failure-only diagnostics, so passing Android reports retain no effective kernel values. This increases transport storage outside model credit; the passing research result below does not isolate a cause for earlier failures.

That glob also runs six [software JSSE pressure checks](../tools/transport-spike/companion-stream-peer-pressure.test.mjs): five real TLS profiles and bounded CLI/privacy handling. The verified A21 baseline contains 243 host Node cases, including thirty parser/clock checks, six pressure checks and the separate 77 enrollment tests; A22 adds independent enrollment runtime helpers and HTTPS/issuer coverage. A separate collection step runs the [pressure CLI](../tools/transport-spike/companion-stream-peer-pressure.mjs) under the unchanged 180-second host deadline. The expanded diagnostic uses binary configuration version 2 and JSON report revision 2, with typed `localBufferBytes` restricted to 1024 or 65536. The first four profiles preserve the settings recorded below; the historical `e63c914` report retains revision 1. The controlled fifth keeps raw TLS at 1 KiB with split writes and changes only the local application's and bridge's requested send/receive buffers to 64 KiB. The draft's wire `protocolVersion` remains 1.

The 15-second observation and 32 MiB upload limits remain unchanged. Only `build/reports/draft-stream-pressure/pressure.json`, capped at 32 KiB, is added to the retained reports. It records public source/tool versions, effective buffers, fixed counters/flags, joined cleanup and explicit software-key/host-JSSE limitations. `observedWithinBudget=false` is a valid diagnostic result when execution and cleanup succeed; setup, process, probe or cleanup failures fail the step. These host observations neither reproduce nor explain the Android failure by themselves, and do not exercise Conscrypt, ADB, the Android client model or Android kernel.

The unchanged revision-2 host probe times completed child/HTTPS observations. A later response can arrive after the state it describes, so its writer flags are producer-reported diagnostics, not independent certificates of a conservative 250 ms interval between remote snapshots. Independent report checks establish schema, source, configuration, counters and actual joins. The Android proxy proof uses the separate exact call-window helper described below.

The retained report from host run 40120281830 is 7,400 bytes, records exact clean source `e63c914eb561661660416c2274733c381b1238d6`, Linux, Node 24.22.1 and Java 17.0.20.1, and has SHA-256 `ee623fe9351cd7856d22ff5284d8717e5861e417e841c6d308ccebed4e7932d5`. Independent schema/type/counter checks confirm these four profiles:

| Requested raw buffer / writes / local pair | Effective raw send / receive bytes | Elapsed ms | Java completed bytes | Peer and Java writer observed |
| --- | --- | --- | --- | --- |
| 1 KiB / split / none | 2304 / 1152 | 1882 | 2,957,429 | Both true |
| 1 KiB / combined / none | 2304 / 1152 | 1868 | 2,977,909 | Both true |
| 64 KiB / split / none | 65536 / 65536 | 672 | 3,059,829 | Both true |
| 1 KiB / split / 1 KiB TCP pair | 2304 / 1152 | 15072 | 147,573 | Both false |

In the first three profiles, each pre-abort peer snapshot had 8,192 charged bytes, 4,096 pending ingress bytes and one unfinished proxy write; each Java writer also had one unfinished write. The fourth profile's local application/bridge sockets reported effective send/receive buffers 2304/1152. Its pre-abort Java writer had 73 entries and 73 completions; the producer remained active after writing 159,861 bytes. The peer had no pending callback, ingress bytes or charged bytes. All four profiles joined their actual writer, producer and process, then reported zero workers, timers, callbacks, leases and charged bytes. The false observation is retained as evidence of this Linux software fixture's behavior within the unchanged budget; it does not establish the cause of the earlier Android failures. Post-abort writer/producer failure flags are separate from the pre-abort observation and do not imply cleanup failed.

Host run 40121365963 retained a five-profile revision-2 report for exact clean source `e0c8c3cd7c7b364c1ba380746e906524d61ee449`, Linux, Node 24.22.1 and Java 17.0.20.1. Its 9,317 bytes have SHA-256 `9c792681e1deff80ad41091658fbc31657e4164b6d1bd6abb5427091e20eb1a9`. Independent schema/type/source/counter checks confirm the controlled local-pair comparison: both profiles keep raw TLS at requested 1 KiB, effective send/receive 2304/1152 bytes, and split writes. Only the local application's and bridge's requested buffers change.

| Requested local buffers | Effective local send / receive bytes | Elapsed ms | Java completed bytes | Peer and Java writer observed |
| --- | --- | --- | --- | --- |
| 1 KiB | 2304 / 1152 | 15097 | 155,765 | Both false |
| 64 KiB | 65536 / 65536 | 9243 | 3,719,285 | Both true |

In the 1 KiB profile, the pre-abort Java writer had 76 entries/completions and the active producer had written 163,957 bytes; the peer had no pending callback, ingress bytes or charged bytes. In the 64 KiB profile, Java had 911 entries/910 completions and the active producer had written 3,956,853 bytes; the peer had 669 writes/668 callbacks, 4,096 pending ingress bytes and 8,192 charged bytes. The unchanged first three raw profiles also observed both writer conditions. All five profiles joined the actual writer, producer and process and reported zero remaining workers, timers, callbacks, leases and charged bytes. The 15-second observation and 32 MiB upload limits were unchanged. This is a controlled Linux software-JSSE fixture result; the effect of an Android local-buffer change still requires its own runtime evidence.

On the fresh selected emulator, the new driver builds/installs only the research test package, starts the ephemeral loopback peer, and owns exactly two successful explicit reverse registrations. Its preflight requires round trip at most 2000 ms and the full device/host skew interval inside ±2000 ms, including the device's whole-second UTC quantization. It does not change a clock, rebase UTC, or accept an unavailable setup as a skip. Run it only on the prepared research device with an explicit serial:

```sh
node tools/transport-spike/run-draft-streaming.mjs --serial emulator-5554
```

The driver must exit successfully after actual selective cleanup. An independent XML gate then requires all seven exact `DraftStreamingInteropTest` methods once each, actual starts/completions `7`, terminal success, consistent passing counters, a fresh bounded report, the current clean source commit, intact ADB mappings/device state, and successful package force-stop/uninstall, two reverse removals, peer close and owned-child/process-group cleanup. It independently derives the skew interval from the recorded device seconds and host before/after values and checks those measurements against the reported bounds. The expiry case must retain its fourteen fixed, typed timing/owner properties: the gate checks a 30–31 second peer lifetime, actual deadline ticks, the 2100 ms early-observation bound, and at least one owner's real UTC or monotonic deadline observation. Arbitrary status text and raw instrumentation output are excluded. Emulator teardown attempts its stop request, then verifies termination and joins the owned process, using signals if needed. Incomplete cleanup fails the step while preserving any original failure.

A separate failure-only status-3 bundle uses version 3 and exactly forty-five `draftPressure` fields while its matching backpressure, cancellation or expiry case is active. `WaitKind` identifies the original 15-second proxy wait or 20-second Android writer wait; both retain their unchanged full predicate and 250 ms stability requirement. Only the first failed wait in a case reports. The parser retains distinct `draftPressureBackpressure`, `draftPressureCancel` and `draftPressureExpiry` property namespaces in XML/HTML, with at most one 45-field group per case and a 48-field pending-status metadata cap. Multiple failures therefore retain their own observations.

The proxy proof uses exact relative monotonic nanoseconds from the same fully validated probe call as each payload. For one unchanged unfinished write ID and a true full predicate, it requires a later call's start minus the first qualifying call's receive time to be at least 250,000,000 ns. Those endpoints conservatively bound separation between peer snapshots, excluding delay after the later snapshot. Changed IDs or a false full predicate reset the candidate; reversed, overlapping or decreasing-ID samples fail closed. Proxy `LongestCandidateMillis` records this conservative lower bound. The Android local writer check, 15/20-second budgets and data/model limits are unchanged.

The fields select bounded canonical integers, fixed phase/cause enums and boolean strings: wait-start/failure UTC and elapsed times, canonical expiry, control/stream state, entered/completed/in-flight writes, charged bytes/frames, pending client bytes, producer/stream-worker flags, deadline ticks, longest full-predicate candidate duration for one actual write ID, and an ever-seen predicate mask. Mask bits 1/2/4 record unfinished writes, bounded pending ingress and bounded model charge for the wait's owner; combined bits do not establish that those conditions coincided. Final atomics are sampled sequentially. `ProducerFinished` marks the local TCP write/flush/SHUT_WR sequence, `WorkerFailed` covers stream workers, and `ApplicationWritten` is one cumulative count.

Additional fields select immutable primitives from the last already completed, validated peer probe: local receive elapsed time, whole probe-call duration, peer phases/causes, actual write counters, pending callback/ingress, backpressure, charged bytes, read-paused flag and upload bytes. The duration includes TLS setup, request, close and validation; it does not isolate network round trip or handshake cost. This cache may predate the failed wait or request; its sample elapsed time cannot exceed failure elapsed time. Without a completed probe, both timing fields are `-1`, phases are `unobserved`, causes are `null`, counters are zero and flags are false. A completed probe may also have no stream, represented by an `unobserved` stream phase and `null` cause. Six actual send/receive buffer getters cover the raw TLS, application and bridge sockets outside the model lock; values are 1–16,777,216 bytes, or zero when unavailable or invalid. These sequential getters are not an atomic socket snapshot. Capture performs no fresh HTTP request, socket setter or model transition, and reporting occurs after releasing the model lock while preserving the original failure.

The bundle contains no IDs, credentials, payloads or exception messages. Duplicate per-case, misplaced, malformed, legacy-version, inconsistent sentinel or passing-case bundles fail parsing. These facts describe a failed observation; they do not replace the unchanged fourteen positive expiry fields or prove a failure's cause. The independent passing-report gate rejects every property whose name starts with `draftPressure`, covering all three namespaces and unknown suffixes.

Only the new sanitized XML/HTML report directories are retained for seven days. Raw instrumentation/ADB/emulator/peer logs, private fixture directories, APKs, keys, AVD data and userdata are excluded. The private task-owned ADB log is configured before the first ADB call and never uploaded. This research setup does not establish VPN/protected sockets, physical networks, production enrollment or registry/destination policy, total-process-memory limits, or protocol v1 freeze.

[First streaming run 40118696378](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40118696378) failed on both API 26 and API 37 at `277939d72d2d5ad33bc0f5be1e636d5fbe17ca3c`. Independent downloaded XML confirms all seven exact class/method pairs started and completed on each API: four passed, three failed, with no errors or skips. The gated half-close, binding, malformed/oversized ingress, and premature-close cases passed. Backpressure failed at `paused-proxy-actual-write`; cancellation and expiry failed at their `observe-real-writers` stages, each with a sanitized `IllegalStateException`. These stage/type observations do not establish the underlying cause. No typed expiry observation was emitted, so blocked-writer cancellation, resumption and actual-expiry acceptance remain open.

Both failed jobs retained healthy ADB device/mapping state and clean source identity. The strict clock intervals were [-490, 519] ms with 10 ms round trip on API 26, and [-1330, -305] ms with 26 ms round trip on API 37. Each driver completed package force-stop/uninstall, both owned reverse removals, peer closure and child/process-group cleanup successfully; emulator stop and join both returned `0`. Actual tools were Node 24.22.1, OpenSSL 3.0.13, emulator 37.2.12.0 build 16428233, KVM 12 and ADB 37.0.1-15733141. Setup and cleanup success do not turn the three failed methods into passing streaming evidence.

[Streaming run 40122092547](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40122092547) at `4416ba64c99b8e01d7c556f5509c059b93e184c6` is terminal failure overall, with a complete passing seven-case checkpoint on API 37. Both APIs actually started and completed all seven exact methods once, with no errors or skips. API 37 passed every case, emitted all fourteen typed expiry properties, and passed both the hosted independent gate and its independent replay against the downloaded XML. API 26 passed six cases, including backpressure resumption and cancellation, but the expiry case failed at `expiry-android-actual-write`. Its retained project frames identify the unchanged 20-second `observedBlockedWriter` wait (`DraftStreamingFixture.kt:243`, `DraftStreamingOwner.kt:421`), after the proxy-pressure wait had returned. No API 26 expiry timing bundle was emitted; the reason its observation predicate never became satisfied remains unproven.

On API 37, peer expiry was verified: terminal monotonic elapsed 30,633 ms exceeded the peer's 30,589 ms lifetime, and terminal UTC was 43 ms after canonical expiry. The local observation recorded 30,681 ms elapsed, 31,365 ms remaining at ready, 1,212 actual deadline ticks, `localExpired=false` and `peerExpired=true`; its 683 ms early local UTC observation fits the bounded clock skew. Both APIs retained clean source/device/mapping state and successful package force-stop/uninstall, two reverse removals, peer closure and owned-child/process-group cleanup. Emulator stop and join each returned `0`. The strict preflight intervals were [-718, 289] ms with 8 ms round trip on API 26, and [-885, 144] ms with 30 ms round trip on API 37. Actual tools remained Node 24.22.1, OpenSSL 3.0.13, emulator 37.2.12.0 build 16428233, KVM 12 and ADB 37.0.1-15733141. API 26 expiry and the combined API 26/37 acceptance remain open.

[Diagnostic streaming run 40123568657](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40123568657) failed overall at `644542de5cf64df79a0d1c1815a2345a847f9351`. Both APIs actually started/completed all seven exact methods once, with zero errors or skips. API 37 again passed all seven cases and the hosted/downloaded-report independent gates. API 26 passed five cases, including expiry, but backpressure and cancellation failed at `paused-android-actual-write` and `cancel-android-actual-write`. Original frames identify the unchanged 20-second `observedBlockedWriter` wait (`DraftStreamingFixture.kt:243`, `DraftStreamingOwner.kt:429`). The failure-only capture was scoped to expiry, which passed on both APIs, so neither report contains a status-3 pressure bundle. The missing predicate component in the two failed cases remains unknown. Complete API 26 acceptance requires all seven cases to pass together at one checked source/run.

Both reports contain fourteen positive expiry fields, independently validated even though the overall API 26 report fails its other two cases. API 26's peer terminal elapsed was 30,956 ms against a 30,953 ms lifetime, with terminal UTC 3 ms after expiry; API 37 recorded 30,750 ms against 30,733 ms and UTC 17 ms after expiry. Both had `localExpired=false`, `peerExpired=true`, and actual deadline ticks. Source/device/mapping checks and all package, reverse, peer, child/process-group cleanup checks passed; emulator stop/join each returned `0`. Strict clock intervals were [-1069, -61] ms with 9 ms round trip on API 26 and [-999, 19] ms with 19 ms round trip on API 37. These positive expiry observations do not establish the failed backpressure/cancellation checks or combined API acceptance.

[Scoped diagnostic run 40124837895](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40124837895) failed overall at `61ced0ed150497ce2b6303d11e64a6c1a171a529`. Both APIs actually started/completed all seven exact methods once, with zero errors or skips. API 37 passed all seven, retained fourteen valid positive expiry fields, and passed the hosted and independently replayed acceptance gates. API 26 passed five, including backpressure, but cancellation and expiry failed at `cancel-android-actual-write` and `expiry-android-actual-write`. Both retained their own independently validated 24-field version-2 groups; API 26 emitted no positive expiry bundle.

Cancellation's wait-start/failure/expiry UTC milliseconds were 1792869797074 / 1792869817079 / 1792869916000; expiry's were 1792869857598 / 1792869877602 / 1792869886000. The monotonic wait durations matched the UTC differences:

| Failed case | Elapsed start / failure ms | Wait ms | Failure before expiry ms | Longest sampled full-predicate interval ms | Write entered / completed / in-flight | Application written bytes |
| --- | --- | --- | --- | --- | --- | --- |
| Cancellation | 2433 / 22438 | 20005 | 98921 | 124 | 1542 / 1541 / 1542 | 6,447,221 |
| Expiry | 2344 / 22348 | 20004 | 8398 | 123 | 1529 / 1528 / 1529 | 6,381,685 |

Both captures showed control `active`/cause `null`, stream `open`/cause `null`, 8,192 charged bytes in two frames, 4,096 pending client bytes, `ProducerFinished=false`, `OwnedStopping=false` and `WorkerFailed=false`. Each recorded 880 deadline ticks, zero expiry ticks and predicate mask 7. The sampled full-predicate stability remained below 250 ms; this metric measures the combined conditions for one write ID, not individual I/O-call duration, and the mask combines observations across samples. One cumulative producer count cannot establish throughput or an ADB cause. Both APIs retained clean source/device/mapping state and successful package, reverse, peer and child/process-group cleanup; emulator stop/join each returned `0`. Strict clock intervals were [-1101, -90] ms with 12 ms round trip on API 26 and [-1233, -217] ms with 17 ms round trip on API 37. The facts were captured before outer cleanup and before canonical expiry. API 26's complete suite and combined API 26/37 acceptance remain open.

[Buffered-writer run 40125879375](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40125879375) failed overall at `eb5cd1063c97385701604c6672d054f0b6df8fe6`. Both APIs actually started/completed all seven exact methods once, with zero errors or skips. API 37 passed all seven, retained fourteen valid positive expiry fields, and passed the hosted and independently replayed gates. API 26 passed four, but backpressure, cancellation and expiry failed at the earlier `paused-proxy-actual-write`, `cancel-proxy-actual-write` and `expiry-proxy-actual-write` stages. Retained project frames identify `DraftStreamingFixture.kt:243` through `Context.awaitProbe`/`awaitProxyBackpressure` at `DraftStreamingInteropTest.kt:236`/`:242`. The later Android-writer wait was never reached, so its 24-field failure capture did not run. No numeric proxy-wait failure facts or positive expiry bundle were retained for API 26; these stages do not establish a cause or an Android buffering resolution.

Both APIs retained clean source/device/mapping state and successful package, reverse, peer and child/process-group cleanup; emulator stop/join each returned `0`. Strict clock intervals were [-1660, -651] ms with 10 ms round trip on API 26 and [-1243, -217] ms with 27 ms round trip on API 37. API 37's peer terminal elapsed was 30,308 ms against a 30,290 ms lifetime, with terminal UTC 18 ms after expiry. API 26's complete suite and combined API 26/37 acceptance remain open; the framing host results establish their measured local write/flush semantics only.

[Diagnostic run 40127223018](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40127223018) failed overall at `10b58b4f5560136b9240d0f869237f4a34cee9f9`. Each API actually started/completed all seven exact methods once, with zero errors or skips. API 37 reported seven passes, fourteen independently valid positive expiry fields, and passing hosted/downloaded-report gates. API 26 passed four, but backpressure, cancellation and expiry failed at their original proxy waits, before the Android-writer waits. All three retained independently validated 45-field version-3 groups with `WaitKind=proxy`; API 26 retained no positive expiry bundle.

| API 26 case | Wait ms | Peer entered / completed | Local entered / completed | Cumulative application bytes | Last whole probe-call ms |
| --- | --- | --- | --- | --- | --- |
| Backpressure | 15039 | 426 / 426 | 427 / 426 | 1,867,893 | 31 |
| Cancellation | 15029 | 445 / 445 | 446 / 445 | 1,998,965 | 32 |
| Expiry | 15005 | 455 / 455 | 456 / 455 | 1,998,965 | 30 |

Each cached peer sample had age zero at capture, read-paused `true`, no pending write, and zero backpressure count, pending ingress or charged bytes. All three waits recorded predicate mask zero and longest full-predicate candidate zero. Local snapshots remained control `active`/stream `open`, with null causes, 8,192 charged bytes in two frames and 4,096 pending client bytes; producer-finished, stopping and stream-worker-failed flags were false. Actual raw socket send/receive getters were 4,608/2,304 bytes; all four application/bridge buffer getters were 131,072 bytes. Failures preceded canonical expiry by 105,711/106,260/15,582 ms respectively, with 597/595/597 deadline ticks and zero expiry ticks. These sampled counts do not identify a transport bottleneck or establish throughput.

Source/clock/channel checks and all selective package, reverse, peer and owned-child/process-group cleanup passed on both APIs; emulator stop/join each returned `0`. Strict clock intervals were [-1018, -9] ms with 10 ms round trip on API 26 and [-811, 205] ms with 17 ms round trip on API 37. API 37's peer terminal elapsed was 30,890 ms against a 30,842 ms lifetime, with terminal UTC 47 ms after expiry. Separately, source review found that the proxy stability check compares completed probe times: a slow later response can overstate separation between peer snapshots. A conservative second-call-start minus first-call-receive interval was not checked by this source. That limitation does not establish that any particular reported pass was false, and it does not explain API 26's observed failures. Complete API 26/37 streaming acceptance remains open.

The strict A20 research gate is verified at `d6185fc88946dec58391939a304e4b4ac5c0b2f8`: [manual run 40128216139](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40128216139) and the matching host run above both passed. Independent downloaded XML audit confirms exactly seven named methods and seven actual starts/completions on each API 26/37 emulator, with zero failures, errors or skips. Each report passes the hosted and independently replayed gate, retains fourteen valid positive expiry properties, and contains no failure-only pressure fields. This source uses the conservative proxy call-window proof, the unchanged Android local writer check, and the requested stream-only 64 KiB send buffer. Passing reports do not retain its effective buffer getters.

| API | Strict clock interval ms | Clock-probe round trip ms | Peer lifetime ms | Peer terminal elapsed ms | Terminal UTC after expiry ms | Local deadline ticks |
| --- | --- | --- | --- | --- | --- | --- |
| 26 | [-138, 870] | 9 | 30684 | 30712 | 28 | 1214 |
| 37 | [-995, 22] | 18 | 30311 | 30326 | 15 | 1199 |

Both record `localExpired=false`, `peerExpired=true` and zero local expiry ticks, with the peer's actual UTC/monotonic deadline independently established. Source, device and owned-mapping checks passed. Research-package force-stop/uninstall and both reverse removals returned `0`; peer and owned-child/process-group closure were verified, and emulator stop/join each returned `0`. Actual tools were Node 24.22.1/OpenSSL 3.0.13, emulator 37.2.12.0 build 16428233, KVM 12 and ADB 37.0.1-15733141. This verifies the seven defined controlled research scenarios together on both emulators. It does not identify a specific TLS/ADB/kernel cause, establish physical-device/VPN/protected-socket or desktop-gateway behavior, or freeze production protocol v1.

## Android enrollment HTTPS runtime

The separate manual-only [enrollment workflow](../.github/workflows/enrollment-runtime.yml) follows the [A22a live HTTPS profile](research-enrollment-https.md) and [runtime report contract](android-enrollment-runtime.md) on standard Ubuntu/KVM API 26 and 37 emulators. It selects exactly `DraftEnrollmentInteropTest.prepareApprovedCredentialForRestart` and, after selective package stop/verified process absence plus graceful host-worker join/reopen, `reopenApprovedCredentialAfterRestart`. Installation occurs once, without clearing app data or replacing the original Keystore identity between invocations. The invitation is a bounded private binary file delivered through owned run-as stdin; it never enters command arguments, environment values, status output or reports.

Each invocation must retain its exact start/completion/terminal result and ordered two-field phase bundles. Host approval is authorized only by the validated live awaiting phase, with drop arming separate from one actual dropped approved response, later successful approved delivery and the reopened worker's delivery. Acceptance independently derives the full UTC-second/round-trip clock interval within two seconds, binds clean exact source/API, checks stable ports/public identity/result hashes across the worker restart, and requires real issuer/socket/worker/command cleanup. The workflow then attempts emulator stop, observes actual termination and joins its owned process before writing the separate cleanup record. Missing KVM, boot, phases or cleanup fail; they never become successful skips.

The final verifier requires fresh bounded runtime/host JSON and byte-exact sanitized XML/HTML projections. Only those four fixed files are retained for seven days. Private inputs, signatures, CSR/certificate bytes, keys, registries/journals, raw instrumentation/ADB/emulator/worker logs, APKs and AVD data are excluded. Compilation, host-only HTTPS/issuer cases and synthetic reports do not establish Android runtime acceptance.

Public source 03f6440f54b08d9445cb139cf06f1ef2b36ef296 passes [runtime run 40137437229](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40137437229) on both API 26 and 37, with matching [host run 40137436672](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40137436672). Independently downloaded reports pass the final verifier and exact XML/HTML projection checks. Each API records two actual starts/completions, terminal success, all seven prepare and three reopen phases, one actual approved-response drop, a later recovered delivery and another delivery after worker reopen. Private input is consumed and absent afterward. Original ports, gateway, authority and approved-result hashes remain unchanged, and saved credentials complete pinned mTLS with the original Keystore identity. All owned issuer/socket/worker/callback/timer counters return to zero; command groups, reverse mappings, package/private files and emulator stop/join checks pass. Both Android processes were already absent before force-stop, so this is process stop/absence and reopen evidence rather than proof of forced process death.

| API | Full device-minus-host clock interval | Clock round trip | Actual methods | Failures/errors/skips |
| --- | --- | --- | --- | --- |
| 26 | -453 to 555 ms | 9 ms | 2 | 0/0/0 |
| 37 | -677 to 348 ms | 26 ms | 2 | 0/0/0 |

The matching host artifact independently confirms 193 JVM cases, 308 Node cases, five clean lint reports, 75 enrollment evidence guards, nine documentation cases and 44 existing Python cases. Its full workflow lint and 168 source-specific local links pass. Replaying the downloaded actual Kotlin/Node reports reproduces both complete A19 and A21 conformance comparisons. All eight fresh Linux enrollment-store crash cases pass exact-source, owner-exclusion, actual process-join, recovery and integrity checks. These are host checks, separate from the Android runtime evidence above.

The earlier [7858e4d runtime run](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40136667229) passed API 37 but correctly refused API 26 before build/install/enrollment: its full clock interval was -5363 to -4340 ms, outside the unchanged two-second gate. Commit 03f6440 aligns only the fresh owned AVD clock before execution, verifies ordinary ADB shell privileges are restored, and leaves the independent driver/verifier bounds intact. Eleven executable setup regressions check order, failures and invalid readbacks. The subsequent acceptance above comes entirely from one source and one fresh two-API run.

That A22a result alone does not establish active WSS lifetime acceptance. The following extension records its separate evidence. Additional Android adversarial enrollment cases, production/VPN/physical-device gates and protocol v1 freeze remain open; the live research path changes no draft 0.4 wire fields.

The same manual workflow now has a finite `suite` choice: `a22a` remains the default above, while `a22b` selects the separate [enrolled stream lifetime report contract](android-enrolled-stream-runtime.md). It invokes exactly the three `DraftEnrolledStreamingInteropTest` revocation, credential-expiry and session-expiry methods, each with twelve ordered live phases and one exact 35-field positive observation. Its independent verifier requires actual saved-credential enrollment/delivery, retained application and proxy pressure evidence, the conservative later-call-start minus first-receive 250 ms lower bound, committed revocation or the exact isolated certificate/policy deadline, admission refusal or same-credential new control, and all actual resource joins. A normally completed stream, a shorter substitute deadline or an unsettled final terminal write cannot satisfy the destructive scenarios.

The existing host globs include the nineteen A22b descriptor/projection/parser/gate cases. The shared file/CLI guard module now includes eight cases, including finite selection of all three enrollment suites. Eighteen actual Bash cleanup cases cover the three suites, explicit cleanup/EXIT traps and original statuses 0/7/124; the eleven clock-alignment regressions retain the unchanged strict two-second interval. The workflow selects only its suite's four bounded sanitized files, and `scripts/verify-enrollment-runtime.mjs --suite a22b` requires their exact source, freshness, formats and byte-identical XML/HTML projections. Those verifier regressions use synthetic reports and host processes; actual Android acceptance is separate below.

Public source 54edefde9c861455f7c5696aec0fffd828e52910 is verified in [A22b run 40141196496](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40141196496), [A22a regression 40141198672](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40141198672), [A20 regression 40141201074](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40141201074) and [matching host run 40141196521](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40141196521). Independent downloads and gate replays confirm all three, two and seven actual methods, respectively, on each API: 24 starts/completions with no failure, skip or incomplete method. A22a/B reports pass exact schemas and XML/HTML projection checks, and all package, reverse, process-group, peer and emulator stop/join evidence passes. A22a retains exact drop/recovery/reopen continuity; its Android process was already absent before force-stop, so no forced-death claim is added.

| A22b API | Full device-minus-host clock interval | Clock round trip | Actual methods | Failures/errors/skips |
| --- | --- | --- | --- | --- |
| 26 | -186 to 818 ms | 5 ms | 3 | 0/0/0 |
| 37 | -841 to 175 ms | 17 ms | 3 | 0/0/0 |

Each enrolled-stream method records twelve phases and one exact 35-field observation. Actual local same-write stalls are 252–255 ms; independent proxy call-window lower bounds are 253.913–256.039 ms. Revocation records committed device_revoked on the host and Android, fresh same-credential HTTP 403 and zero application writes after invalidation. Credential expiry is limited by the actual saved leaf under a 120-second policy, with current host credential_expired observed after its deadline. Policy expiry uses 15 seconds under a still-valid 60-second credential, rejects the old token and admits a new control with the unchanged credential. Original owner resources are retained separately from the new control and released only after actual joins, before Store release.

The API 37 policy case preserves its first local network_unreachable at the advertised deadline minus 9 ms. The host independently records session_expired at deadline plus 19 ms, with 14317 ms elapsed. This is a truthful peer-first expiry race, not a substituted local expiry cause. All cases keep zero post-invalidation application writes and complete callback/socket/worker/timer/model cleanup. The separate five-profile host pressure report remains diagnostic; its completion-time flags do not certify these strict same-write intervals.

The fresh host artifact confirms 203 JVM cases, 351 Node cases, five clean lint reports, 88 enrollment guards, nine documentation cases, 44 Python checks and 176 source-specific links with full hosted workflow lint. Both downloaded actual A19/A21 comparisons match every expectation. All eight fresh Linux process-crash cases pass exact-source/exclusion/join/recovery/integrity gates; this is not power-loss evidence. The unchanged native harness passes 38 host cases and four checked IPv4/IPv6 HTTP/CONNECT flows. Additional Android adversarial proof/TLS/cancel cases, capture policy, v1 freeze, production integration and physical-device acceptance remain required.

The finite `a22c` selection follows the [four-case adversarial contract](android-enrollment-adversarial-runtime.md), preserving `a22a` as default. It checks purpose/context misuse and replay, an actual foreign TLS peer, pending cancellation with an independently observed failed late approval, and cancellation of an approved saved credential with actual mTLS admission followed by still-valid same-credential HTTP 403. Separate compact observations and current host state/cumulative issuer counters support those cases; a generic network failure, zero response delivery or an early Android phase cannot substitute for the required facts. Only its four fixed source-bound sanitized reports are selected, with exact fresh JSON/XML/HTML and actual worker/package/emulator cleanup gates.

The host commands include the thirteen C parser/report cases and five C file/CLI guards through their existing globs. Together with the shared selector and cleanup additions, the enrollment script guard total is 100; historical 54edef counts above remain source-specific. These are synthetic report and owned-host-process checks, separate from the actual Android evidence below.

Public source 074fbfa00a610d4743cacd1f3d811d180ad5971b passes [A22c run 40143815956](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40143815956), [A22a regression 40143818651](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40143818651) and [A22b regression 40143821810](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40143821810). Independent downloaded-report verification confirms four, two and three actual methods per API, respectively: eighteen starts/completions, with no failure, error, skip or incomplete method. All exact phase/observation schemas, fresh source-bound JSON/XML/HTML projections and package/reverse/private-file/worker/process-group/emulator joins pass.

| A22c API | Full device-minus-host clock interval | Clock round trip | Actual methods | Failures/errors/skips |
| --- | --- | --- | --- | --- |
| 26 | -1005 to 1 ms | 7 ms | 4 | 0/0/0 |
| 37 | -1070 to 108 ms | 179 ms | 4 | 0/0/0 |

Each API records purpose, wire-context and signed-context HTTP 403 refusals, then successful pending status on the same challenge, replay refusal and fresh pending status. The alternate TLS identity has the same DNS SAN and valid dates, but a different key: each actual listener records one accept and rejection, zero secure connections/HTTP dispatches and all three auxiliary children/groups joined. The correct gateway stays pending. Pending signed cancellation records replay refusal and fresh cancelled status; the independently tracked late approval returns invitation_used, followed by an actual cancelled host read.

Published cancellation saves/reloads the original credential, completes mTLS HTTP 200, then receives HTTP 403 with the same still-valid leaf after signed cancellation. The refusal precedes exact host-matched leaf expiry by 3597778 ms on API 26 and 3597579 ms on API 37. The original key remains usable until owned Forget. The first three cases retain the actual issuer command counter at 1; the published case moves from 1 to 2 for approval and stays at 2 after cancellation. The baseline includes fixture bootstrap, so unchanged counters are the evidence of no additional signing work.

The same-source A22a regression preserves one actual dropped response, one recovered delivery, one reopened delivery and exact identity/result/port continuity; both processes were already absent before force-stop. A22b retains actual local same-write stalls of 253–256 ms and conservative proxy intervals of 255.893–257.564 ms. All three current methods report the expected local and host causes: device_revoked for explicit revocation and session_expired for credential/policy expiry, with zero post-invalidation writes. Policy expiry denies the old token and admits a new control using the unchanged valid credential. Historical first-cause races at 54edef remain recorded above. Capture policy, renewal/rotation decisions, maintained production WebSocket selection, v1 freeze, production integration and physical-device acceptance remain open.

The matching [host run 40143804977](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40143804977) independently verifies 208 unique JVM cases, 372 Node cases, five clean lint reports, 100 enrollment guards, nine documentation cases, 44 Python checks, 181 source-specific links and full hosted actionlint. Both downloaded actual A19/A21 comparisons match every expectation. All eight fresh Linux crash cases pass exact-source/exclusion/join/recovery/integrity gates, without a power-loss claim. The native host gate passes 38 checks and four IPv4/IPv6 packet flows. All eight new host tests execute: alternate TLS identity/lifetime/failure recovery, signed active-stream cancellation and four private-driver checks. The five-profile pressure report remains diagnostic, separate from the strict Android/proxy intervals above. No production wire fields change.

## Dependency and licence evidence

The workflow records the resolved Gradle debug/release runtime graphs, the core JVM and security test runtime graphs, and the Node peer dependency graph under `build/reports/dependencies/`. To inspect the same inputs locally:

```sh
./gradlew :app:dependencies --configuration debugRuntimeClasspath
./gradlew :app:dependencies --configuration releaseRuntimeClasspath
./gradlew :core-protocol:dependencies --configuration testRuntimeClasspath
./gradlew :core-security:dependencies --configuration debugUnitTestRuntimeClasspath
npm --prefix tools/transport-spike ls --all --json
```

These graphs identify exact resolved modules and distinguish shipped runtime dependencies from test-only libraries. They are inputs to a licence review, not proof that every obligation has been satisfied. [Dependency notices](../THIRD_PARTY_NOTICES.md) currently group dependency families. Before distributing a production app, add a reviewed per-component inventory covering transitive runtime modules, their POM/parent-POM and source-header licences, required bundled notices, native submodules and ABI inputs, and any corresponding-source obligations. Unresolved or conflicting licences must fail that release gate. Build tooling and test dependencies should remain separately identified. No complete release licence audit, device acceptance, or protocol freeze is claimed by the host workflow.

## Automated checks to add

| Area | Required checks |
| --- | --- |
| Protocol | Shared fixtures, malformed and oversized input, version negotiation, expiry, duplicate and concurrent enrollment |
| Security | Wrong pin, wrong client key, forged/revoked/expired certificate, unauthenticated upgrades, stale session, no leaked credentials |
| Capture | HTTP formatting, CONNECT negotiation, bidirectional streaming, cancellation, half-close policy, DNS and IPv6 policy |
| Lifecycle | Denied VPN/camera/notification permissions, consent cancellation, Android VPN revocation, foreground service stop, process restart |
| Desktop | Narrow gateway authorization, local API isolation, per-device attribution, destination policy including DNS rebinding, existing ADB regressions |
| Limits | Concurrent streams, slow reader/writer, reconnect storms, oversized frames, idle sockets, global memory budget |

Keep packet and stream tests based on real captured protocol examples or controlled peers. Avoid tests that only assert calls made by the implementation. Use a test application with a deliberate debug trust configuration for deterministic HTTPS checks.

## Manual acceptance matrix

| Scenario | Pass condition |
| --- | --- |
| USB with phone Wi-Fi disabled | Controlled HTTP and HTTPS appear in desktop capture through the new gateway; no LAN route is needed |
| LAN | Same identity works on configured interface; wrong identity and unauthorized phone fail |
| Direct WAN with phone on cellular | Capture works across different networks using an explicitly reachable gateway; management API remains inaccessible |
| Phone behind CGNAT | Direct mode reports unreachable clearly; relay mode later succeeds with both endpoints outbound |
| Rootless physical phone | HTTP works; configured debug app HTTPS works; unsupported trust/pinning is reported honestly |
| App selection | Selected app captured, unselected app unaffected; selected IPv6 cannot bypass declared policy |
| QUIC and DNS | UDP/443 policy verified, TCP fallback tested, private DNS behavior documented |
| Network transition | Wi-Fi to cellular produces a visible transition and fresh session; existing non-idempotent requests are not replayed |
| Stop and revoke | Notification Stop restores normal networking; desktop revocation closes active streams and blocks reconnect |
| Pairing race and replay | Only the approved public key enrolls; expired and consumed invitations cannot enroll another device |
| Restart and upgrade | Saved key reconnects where valid; missing key requests pairing; migration does not widen access |
| Long capture | At least 30 minutes of mixed idle and streaming traffic without unbounded memory growth or leaked sockets |

Include the selected minimum supported Android version and a recent physical Android version. Include IPv4-only, dual-stack, restrictive firewall, no internet, and gateway shutdown cases. The foundation task chooses exact emulator images after toolchain and engine evaluation.

## Performance evidence

Measure latency against a direct connection, throughput, concurrent-flow memory, reconnect time, CPU, and battery impact on named hardware. Use controlled large downloads, uploads, WebSocket traffic, and slow upstreams. Set regression thresholds after recording the baseline; do not invent performance promises before measuring.

## Build and distribution

Start with reproducible debug APKs and ADB installation. Export deliverables to dist/http-freekit-android-debug.apk and later dist/http-freekit-android.apk, with stable checksum and build metadata filenames directly in dist/. Gradle's standard build directories may remain. Metadata records version, protocol version, source commit, and compatible desktop version or tested commit. Keep signing credentials outside the repository and expose them to CI through its secret mechanism.

CI first runs compile, unit tests, lint, and dependency/licence checks. Add emulator instrumentation once a runner supports it. Signed releases require upgrade-install testing, required notices and corresponding source obligations for included dependencies, checksum verification, and a tested previous compatible release. Do not automatically publish or upload artifacts from a planning task.

## Handoff format

Every package handoff states scope completed, changed files and contracts, commit IDs in each repository, exact checks and results, unavailable checks, integration dependencies, and known failures. The integration owner updates tasks/README.md with evidence and release gates. A package is complete only when its exit criteria pass, not when its branch contains scaffolding.
