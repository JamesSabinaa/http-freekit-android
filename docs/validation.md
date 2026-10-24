# Validation and release plan

## Evidence rules

Record exact Android and desktop commits, Android version and device model, SDK/ADB versions, network topology, commands, results, and relevant sanitized diagnostics. A mock-only test does not demonstrate capture. A VPN connected indicator does not demonstrate proxy delivery. Mark unavailable device tests as unrun and explain the environment requirement.

Documentation-only changes require local Markdown link validation, consistency review, and git diff --check. The foundation now has a pinned Gradle build, parser tests, and a host transport test. Run the commands in [developer instructions](development.md); see [foundation evidence](decisions/0001-foundation.md) for actual results and outstanding gates. Host checks do not demonstrate device capture.

## Host validation workflow

[Android host validation](../.github/workflows/android.yml) runs on pushes, pull requests, and manual dispatch with read-only repository permissions. It uses Ubuntu 24.04, Temurin JDK 17, Node 24.22.1, SDK platform 37.0, and build tools 36.0.0. GitHub Actions are pinned to commit IDs, and the workflow linter download has a pinned SHA-256. Gradle and app dependencies retain the versions committed in the wrapper and catalogue. The workflow does not request release secrets, publish APKs, or run an emulator.

The Android job bootstraps command-line tools build `15859902` into a fresh SDK directory under the runner's temporary directory, verifies the Linux archive SHA-256 against the [official download page](https://developer.android.com/studio#command-tools), and exports the SDK paths before accepting SDK licences and installing the pinned packages. It does not rely on `sdkmanager` or SDK environment variables being preinstalled by the runner image.

Run the source checks locally:

```sh
node --test scripts/tests/check-doc-links.test.mjs
node scripts/check-doc-links.mjs
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
node --test tools/transport-spike/research-websocket*.test.mjs
node --test tools/transport-spike/companion-stream-peer*.test.mjs
node tools/transport-spike/companion-stream-peer-pressure.mjs
./gradlew --no-daemon --console=plain \
  :core-protocol:test \
  :transport-framing:test \
  :core-security:testDebugUnitTest :core-security:assembleDebugAndroidTest :core-security:lintDebug \
  :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug \
  :transport-interop:assembleDebugAndroidTest :transport-interop:lintDebug \
  :installed-app-fixture:assembleDebug :installed-app-fixture:assembleRelease \
  :installed-app-fixture:lintDebug :installed-app-fixture:lintRelease
```

Assembling the app and security module's Android instrumentation APKs checks compilation only; no UI, Keystore, or device result is inferred from it.

The host job checks OpenSSL 3 explicitly and runs five loopback Node fixture tests for bounded CSR validation, certificate issuance, authenticated WebSocket echo, missing-client rejection, temporary-file cleanup, bounded research certificate times and clock probes, and normal TLS rejection of future or expired gateway certificates. Twenty-nine parser/ownership regressions separately cover exact start/end pairs, terminal status, crashes, missing/duplicate/skipped cases, bounded input, sanitized ADB/server-log diagnostics, explicit reverse-port collisions, and selective cleanup. It also compiles and strictly lints the isolated transport module, retaining its lint reports. It does not run connected Android tests. A local Windows research check can select an installed OpenSSL 3 executable through `OPENSSL_BIN`; no system OpenSSL setting is changed.

The documentation job also runs fifteen stdlib Python regressions for the [exact Keystore result verifier](../scripts/verify-keystore-results.py). They cover the actual AGP wrapper/per-class formats, missing/duplicate/unexpected cases or suites, interrupted XML, skipped/crashed results, inconsistent counters, bounded reports, and CLI failures without dumping report messages.

The host job also runs twenty-one [draft-stream result/clock regressions](../tools/transport-spike/draft-stream-results.test.mjs) for the separate [authenticated streaming proof](decisions/0012-authenticated-draft-streaming.md). They require seven actual paired instrumentation starts/completions and terminal success, reject skipped/crashed/duplicate/missing results, retain only fixed scenario/phase/type diagnostics and typed expiry observations, and enforce the two-second round trip and entire skew interval, including UTC-second quantization. Ten additional process/driver checks cover actual child cancellation/output bounds, process-group teardown after leader exit, explicit CLI arguments, and safe incomplete reports. These host checks do not execute the seven Android streaming methods or establish streaming runtime acceptance; the POSIX process-group branch has actual Linux coverage in host run 40118691291 below.

The separate [research WebSocket framing module](../tools/transport-spike/framing/README.md) and Node framing tests exercise bounded RFC 6455 frame reading, serialized writes, backpressure, cancellation, and resource closure with real loopback sockets. CI runs `:transport-framing:test` and retains its XML/HTML reports. This research layer does not establish HTTP upgrade, TLS, authentication, the draft session grammar over a live connection, or Android transport integration.

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

That glob also runs five [software JSSE pressure checks](../tools/transport-spike/companion-stream-peer-pressure.test.mjs): four real TLS profiles and bounded CLI/privacy handling. A separate collection step runs the [pressure CLI](../tools/transport-spike/companion-stream-peer-pressure.mjs) under a 180-second host deadline. It compares requested 1 KiB/64 KiB raw socket buffers, split/combined TLS writes, and an actual 1 KiB local TCP pair, preserving the 15-second observation and 32 MiB upload limits. Only `build/reports/draft-stream-pressure/pressure.json`, capped at 32 KiB, is added to the retained reports. It records public source/tool versions, effective buffers, fixed counters/flags, joined cleanup and explicit software-key/host-JSSE limitations. `observedWithinBudget=false` is a valid diagnostic result when execution and cleanup succeed; setup, process, probe or cleanup failures fail the step. These host observations neither reproduce nor explain the Android failure by themselves, and do not exercise Conscrypt, ADB, the Android client model or Android kernel.

The retained report from host run 40120281830 is 7,400 bytes, records exact clean source `e63c914eb561661660416c2274733c381b1238d6`, Linux, Node 24.22.1 and Java 17.0.20.1, and has SHA-256 `ee623fe9351cd7856d22ff5284d8717e5861e417e841c6d308ccebed4e7932d5`. Independent schema/type/counter checks confirm these four profiles:

| Requested raw buffer / writes / local pair | Effective raw send / receive bytes | Elapsed ms | Java completed bytes | Peer and Java writer observed |
| --- | --- | --- | --- | --- |
| 1 KiB / split / none | 2304 / 1152 | 1882 | 2,957,429 | Both true |
| 1 KiB / combined / none | 2304 / 1152 | 1868 | 2,977,909 | Both true |
| 64 KiB / split / none | 65536 / 65536 | 672 | 3,059,829 | Both true |
| 1 KiB / split / 1 KiB TCP pair | 2304 / 1152 | 15072 | 147,573 | Both false |

In the first three profiles, each pre-abort peer snapshot had 8,192 charged bytes, 4,096 pending ingress bytes and one unfinished proxy write; each Java writer also had one unfinished write. The fourth profile's local application/bridge sockets reported effective send/receive buffers 2304/1152. Its pre-abort Java writer had 73 entries and 73 completions; the producer remained active after writing 159,861 bytes. The peer had no pending callback, ingress bytes or charged bytes. All four profiles joined their actual writer, producer and process, then reported zero workers, timers, callbacks, leases and charged bytes. The false observation is retained as evidence of this Linux software fixture's behavior within the unchanged budget; it does not establish the cause of the earlier Android failures. Post-abort writer/producer failure flags are separate from the pre-abort observation and do not imply cleanup failed.

On the fresh selected emulator, the new driver builds/installs only the research test package, starts the ephemeral loopback peer, and owns exactly two successful explicit reverse registrations. Its preflight requires round trip at most 2000 ms and the full device/host skew interval inside ±2000 ms, including the device's whole-second UTC quantization. It does not change a clock, rebase UTC, or accept an unavailable setup as a skip. Run it only on the prepared research device with an explicit serial:

```sh
node tools/transport-spike/run-draft-streaming.mjs --serial emulator-5554
```

The driver must exit successfully after actual selective cleanup. An independent XML gate then requires all seven exact `DraftStreamingInteropTest` methods once each, actual starts/completions `7`, terminal success, consistent passing counters, a fresh bounded report, the current clean source commit, intact ADB mappings/device state, and successful package force-stop/uninstall, two reverse removals, peer close and owned-child/process-group cleanup. It independently derives the skew interval from the recorded device seconds and host before/after values and checks those measurements against the reported bounds. The expiry case must retain its fourteen fixed, typed timing/owner properties: the gate checks a 30–31 second peer lifetime, actual deadline ticks, the 2100 ms early-observation bound, and at least one owner's real UTC or monotonic deadline observation. Arbitrary status text and raw instrumentation output are excluded. Emulator teardown attempts its stop request, then verifies termination and joins the owned process, using signals if needed. Incomplete cleanup fails the step while preserving any original failure.

Only the new sanitized XML/HTML report directories are retained for seven days. Raw instrumentation/ADB/emulator/peer logs, private fixture directories, APKs, keys, AVD data and userdata are excluded. The private task-owned ADB log is configured before the first ADB call and never uploaded. This research setup does not establish VPN/protected sockets, physical networks, production enrollment or registry/destination policy, total-process-memory limits, or protocol v1 freeze.

[First streaming run 40118696378](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40118696378) failed on both API 26 and API 37 at `277939d72d2d5ad33bc0f5be1e636d5fbe17ca3c`. Independent downloaded XML confirms all seven exact class/method pairs started and completed on each API: four passed, three failed, with no errors or skips. The gated half-close, binding, malformed/oversized ingress, and premature-close cases passed. Backpressure failed at `paused-proxy-actual-write`; cancellation and expiry failed at their `observe-real-writers` stages, each with a sanitized `IllegalStateException`. These stage/type observations do not establish the underlying cause. No typed expiry observation was emitted, so blocked-writer cancellation, resumption and actual-expiry acceptance remain open.

Both failed jobs retained healthy ADB device/mapping state and clean source identity. The strict clock intervals were [-490, 519] ms with 10 ms round trip on API 26, and [-1330, -305] ms with 26 ms round trip on API 37. Each driver completed package force-stop/uninstall, both owned reverse removals, peer closure and child/process-group cleanup successfully; emulator stop and join both returned `0`. Actual tools were Node 24.22.1, OpenSSL 3.0.13, emulator 37.2.12.0 build 16428233, KVM 12 and ADB 37.0.1-15733141. Setup and cleanup success do not turn the three failed methods into passing streaming evidence.

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
