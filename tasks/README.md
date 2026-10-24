# Agent work board

Codex coordinates package A in `../http-freekit-android-a`, with uniquely assigned parallel packages B, D, and F below. Package C production integration and package E remain gated. Use separate branches and worktrees. Update this board through the coordinator to avoid agents racing to edit the same rows.

## Assignments

| Package | Owner | Branch | Status | Dependencies |
| --- | --- | --- | --- | --- |
| A Foundation and contracts | Codex | plan/a-foundation | In progress: native packet proof and credential bootstrap | None |
| B Android interface and lifecycle | Codex UI agent | feat/b-android-shell | Mock UI/lifecycle checkpoint verified; device/production work open | A for final toolchain and interfaces |
| C Capture engine and transport | Unassigned | feat/c-capture | Blocked for production integration | A engine choice and frozen protocol |
| D Desktop gateway and ADB | Codex desktop agent | feat/d-companion-gateway | Proxy route binding verified; production gateway gated | A for production protocol; C for end-to-end capture |
| E WAN and relay | Unassigned | feat/e-wan | Blocked | Authenticated USB milestone and destination policy |
| F Integration and release | Codex validation agent | test/f-integration | Host/native CI verified; runtime/release work open | A for stable fixtures; B C D for device acceptance |

Current ownership: A owns root Gradle configuration, shared protocol, Android manifest/security spike wiring, native-engine research, and decision records. B owns app UI/resources and mocked lifecycle models/tests; manifest and dependency changes go through A. D works only in `../http-freekit-companion-d` on desktop proxy compatibility tests and gateway design; production wire integration waits for freeze. F owns `.github/workflows`, new validation scripts, and `docs/validation.md`; existing build/export script changes go through A. The coordinator alone edits this board and merges reviewed commits.

A subtask A2 checkpoint `aead179` is integrated as `2014b5f`: the scoped TLS factory enforces fresh trust, expiry, exact peer pin, logical hostname, TLS 1.2/1.3, and bounded setup/cleanup per connection. Its 13 new host tests bring security tests to 19 and the combined local JVM total to 48; strict lint, assembly, and instrumentation compilation pass. Android transport and active-stream policies remain unverified. See [TLS evidence](../docs/decisions/0003-scoped-tls-connections.md).

A subtask A3 checkpoint `53a153b` from branch `spike/a-device-client-credential` in `../http-freekit-android-tls` is integrated as `0a3c4fd`. The binding retains the original signing handle, validates a bounded client chain against an explicitly authenticated authority, and rejects expired or deleted identities. All 36 security JVM tests pass, including the host Node WSS exchange; five Android methods compile. The two new enrolled-client tests await runtime execution. See [client credential evidence](../docs/decisions/0004-enrolled-client-credentials.md). Production enrollment, persistence, and active-session revocation remain open. The coordinator retains global build, protocol, native research, and integration ownership.

A subtask A5 is assigned to the UI agent: branch `spike/a-android-node-interop`, worktree `../http-freekit-android-interop`, dependent on `0a3c4fd`, in progress. A5 uniquely owns a separate Android research module under `tools/transport-spike/android`, a loopback-only Node enrollment/WSS fixture and its helpers, and decision record 0006. It must prove actual nonexportable Android-key authentication and ordered binary exchange with Node, through the scoped TLS factory and ADB reverse. This test fixture is not a production enrollment endpoint or frozen wire contract. Root settings/catalogue and TLS-factory composition remain coordinator-owned; a separate manual workflow will be assigned to F.

A subtask A6 is owned by the coordinator: branch `spike/a-scoped-client-tls`, worktree `../http-freekit-android-client-tls`, dependent on `0a3c4fd`, in progress. A6 uniquely owns optional client-key-manager composition in GatewayTlsConnectionFactory, focused host tests, and the existing TLS decision record. It must preserve per-connection gateway validation, fail closed for unavailable credentials, and verify that TLS actually used the expected client leaf. A5 is delegated only the single research-module inclusion in root settings; the coordinator retains catalogue and other global configuration.

A5 checkpoint `944fc88` is integrated as `afb9f3f`, and A6 checkpoint `ebaf024` is integrated directly. The security suite now passes 40 host cases (69 JVM cases across modules); research instrumentation compiles and lint passes. F's manual transport workflow is integrated as `30ea165`, with automatic host research checks added in `8d4b8aa`. First transport runtime `40094676455` failed and is under investigation; no Android-to-Node pass is claimed. These checkpoints leave production framing and enrollment draft.

A runtime follow-up A7 is assigned to the UI agent: branch `fix/a-android-client-tls` in its existing `../http-freekit-android-interop` worktree after the committed A5 handoff. [Run 40094266244](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40094266244) executed five Keystore methods per API, with four passes and one client-handshake failure on both API 26 and 37. The original three identity tests and deletion/recreation test pass. Diagnostic checkpoint `0f9a0ac`, integrated as `c0ed673`, surfaces both peers without changing authentication. A7 uniquely owns AndroidDeviceClientCredentialTest, its synthetic shared issuer fixture, AndroidDeviceIdentityStore and its Android tests, and decision record 0007. The coordinator explicitly extends its scope to authorize TLS prehashed signing on new keys, check loaded key capabilities, and require explicit re-pairing for old restricted keys without replacement. It must retain all supported TLS versions and authentication assertions. Host run 40094266059 passed all 65 JVM tests; it does not resolve this Android failure.

A8 runtime diagnosis is reassigned exclusively to the UI agent: branch `fix/a-interop-runtime-diagnostics`, worktree `../http-freekit-android-interop-runtime`, dependent on `2ab4d74`. The coordinator created this clean worktree and transfers it without code edits. The first transport run produced only one empty failed testcase (`missingClientCertificateIsRejected`) and did not execute the other three cases on either API. A8 owns bounded diagnostics and fixes in the isolated transport driver/module and decision 0006, while F coordinates workflow/report changes. It must establish the instrumentation/process failure cause and retain the exact four-method gate, scoped TLS, and resource cleanup. No Android-to-Node success is claimed from the failed run.

A8 checkpoint `78a0a7a` is integrated as `1a3e28a`, with parser CI in `b55526f`. Direct instrumentation run `40096496418` at `b55526f` failed on both APIs: one actual start, zero completions, four explicit error entries, and subsequent ADB/reverse queries unavailable. No Java/TLS assertion or root cause was recorded. The UI agent now owns `fix/a-adb-channel-diagnostics` in the same worktree for bounded ADB stderr classification, exit/signal and selected device-query diagnostics. F owns `fix/f-adb-channel-diagnostics` in its own worktree for transport-workflow host emulator liveness, exit status and safe fatal categories, preserving the failed status and existing no-log/no-key upload limits. TLS and test assertions remain unchanged. Host run `40096496255` passed 69 JVM, 12 Node and 14 Python cases plus four Linux native flows; it does not resolve this ADB-channel failure.

A9 is owned by the coordinator in `plan/a-foundation`: correct status-bar icon contrast on API 37, observed in the successful preview screenshot. Scope is MainActivity system-bar appearance and preview evidence. The preview follows the system theme, and its system-bar icons must follow it too. All four preview methods must remain passing, and a new original screenshot must verify system-bar contrast.

A10 is owned by the coordinator in `plan/a-foundation`: strengthen the shared synthetic packet return-address assertions in `run_linux.py` and its driver tests. The native review found that valid checksums/ports alone could accept a packet with incorrect source/destination IPs. A10 must accept correct IPv4/IPv6 replies and reject either wrong address even when checksums remain valid. A4's owner is informed and will not edit these shared files concurrently.

A9 checkpoint `c3426ed` is verified by [preview run 40095827316](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095827316) at `89e5914`: all four methods pass on each API 26/37 and original screenshots show readable system bars without header/card overlap. [Host run 40095826558](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095826558) passes all 69 JVM cases, two Node fixture tests, strict lint and the four real Linux packet cases. Its native job exercises A10's return-address checks and all 14 Python tests. These checkpoints do not accept the failed Android packet or Node transport runs.

Verified A7 runtime: [run 40095225102](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095225102) at `2ab4d74` passes all seven named security methods on each API 26/37, with zero failures/errors/skips. The local real-Keystore mutual-TLS failure is resolved; [decision 0007](../docs/decisions/0007-keystore-tls-digests.md) records scope. Preview run `40095028000` passes four methods on each API with original screenshots reviewed; A9 still requires its corrected system-bar screenshot. Initial A4 native run `40095030716` failed before HELLO with zero packet cases, so JNI/packet runtime is not accepted. A8 and the A4 diagnostic follow-up remain active. A10 checkpoint `6e5dfe5` passes all 14 host packet/driver checks and will apply to the next actual native run.

A subtask A4 is assigned to the desktop agent after its route-binding checkpoint: branch `spike/a-android-engine`, worktree `../http-freekit-android-native`, in progress, dependent on the pinned engine and Linux harness. A4 uniquely owns a standalone Android native-engine research project under `tools/engine-spike/android`, its bridge/driver helpers, and a separate manual native-runtime workflow. It must not add the candidate to the production app or alter root Gradle/shared harness files without coordination. Scope is Android JNI/fake-TUN packet proof, not a VPN/routing/capture acceptance claim.

A4 checkpoint `4efe13b` is integrated as `ed12db3`: standalone ARM64/x86_64 API-26 native compilation, strict lint, exact APK/native hash and 16 KiB alignment gates, retained notices, and 12 host fixture/driver checks pass. [Native runtime 40095030716](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095030716) is dispatched on API 26/37 and awaits execution audit. See [the scoped native evidence](../docs/decisions/0005-android-native-packet-probe.md). Engine selection and actual VPN policy remain open.

A4 diagnostic follow-up is owned by the desktop agent on `fix/a-native-runtime-diagnostics` in the same native worktree, based on `2ab4d74`. The initial native run is terminal failure on both APIs before HELLO, with zero packet cases; JNI startup/Stop/bridge phase is not yet known. This follow-up owns safe phase and instrumentation/cleanup diagnostics plus failure-path native Stop/descriptor lifetime, retaining the descriptor until native shutdown is confirmed or host force-stop. It must avoid concurrent Stop calls and preserve the packet checks. Shared `run_linux.py` and `test_driver.py` stay coordinator-owned under A10.

A4 diagnostic checkpoint `d9779d6` is integrated as `d8b4707`: five native-Stop lifecycle JVM cases, assembly, strict lint and APK verification pass. Combined with A10, all 20 Python checks pass. The coordinator also retains the standalone JVM XML/HTML in the report-only workflow artifacts. Android phase, exact ADB exit/signal, emulator liveness and bounded fatal-category diagnostics await a new run; no JNI forwarding pass is claimed by these host checks.

F runtime subtask: branch `test/f-keystore-runtime` in the F worktree, owned by the validation agent, dependent on the verified SDK bootstrap `6407c41`. Its workflow checkpoint `7467ab6` is integrated as `0a8afb9`, with runtime dependency correction `1b1b78c`. [Run 40091372512](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40091372512) passed all three identity tests on each of API 26 and API 37. Scope is a manual-only hosted Linux KVM workflow on standard public runners, without paid/custom runners, snapshots, signing uploads, or local Windows changes. These are emulator identity results; enrolled-client TLS and physical hardware protection remain separate gates.

B runtime subtask B2 is assigned to the validation agent: branch `test/f-android-preview-runtime` in the F worktree, in progress, dependent on the scoped TLS/preview checkpoint and working hosted emulators. Its four Compose tests and workflow are integrated as `6165437`; [run 40093068781](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40093068781) passed all four tests on API 26 with a visually reviewed original screenshot. API 37 failed before test bodies in transitive Espresso 3.5.0; the coordinator pins stable 3.7.0, whose documented fix removes the reflective InputManager call. Both APIs require a fresh run after that change. B2 owns app instrumentation tests, a separate manual preview-runtime workflow, host workflow instrumentation-compilation coverage, and preview runtime documentation. The coordinator owns catalogue/app build wiring and production UI; B2 must exercise actual preview UI while making no VPN/capture claim, and may retain only synthetic preview screenshots and test reports.

Preview compatibility fix `7bf2d94` passed local instrumentation assembly and strict lint with Espresso 3.7.0 selected. [Preview run 40095028000](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095028000) at `ed12db3` awaits both API results and screenshot review. A7's digest correction `c552141` is locally integrated with 40 passing JVM cases, strict lint and seven compiled instrumentation methods; actual TLS and new-key/legacy-key runtime evidence is still required.

Package A checkpoint: pinned Kotlin/Compose Android build, draft pairing parser and fixtures, nine passing host tests including Node mutual-TLS/WebSocket interoperability, clean Android lint, verified debug APK export, and native candidate API 26 compilation on ARM64/x86_64. See [foundation evidence](../docs/decisions/0001-foundation.md) and [build commands](../docs/development.md). The emulator stayed offline; no device, Keystore, or packet-forwarding proof is claimed. Engine selection, authenticated Android interoperability, and protocol freeze remain open; A is not complete.

Next A checkpoint `481c63f` adds Android Keystore/PKCS#10 code, scoped platform gateway trust, a public-certificate draft payload extension, and a Linux native-engine harness. See [credential evidence and limits](../docs/decisions/0002-device-identity-and-bootstrap.md). B's mock UI checkpoint `c68b890` is integrated as `4fda617`; the combined build passes 35 JVM tests (19 lifecycle, 10 protocol/transport, six security), app/security lint, app assembly, and compilation of three unrun Keystore instrumentation tests. Three native fixture/adapter host tests also pass. Desktop checkpoints `d573251` and `cad06c0` pass 461 proxy/Android/layout tests and are integrated locally in the desktop checkout; their gateway design remains unimplemented. F is preparing host/native CI, whose hosted results must be checked separately. No package is marked complete by these checkpoints.

Hosted checkpoint: [run 40089622832](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40089622832) passed all three jobs at `6407c41`, including the 35 JVM tests, strict lint/assembly, and four real native-library packet fixtures for IPv4/IPv6 HTTP/CONNECT streaming and half-close. Keystore tests remain compiled/unrun. Desktop is now locally integrated through `59023d0`, with 470 passing proxy/Android/layout tests; full logical-authority routing and the production gateway remain open. A2 and F runtime work continue independently.

Latest verified checkpoint: [host run 40091372436](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40091372436) passed 48 JVM tests and all three jobs at `1b1b78c`. The Keystore run above supersedes the historical compiled/unrun identity status. Desktop route-binding commits `91c9b54` and `aade5cb` are integrated locally, with 576 passing tests across 94 files; logical-authority routing is implemented there, while companion policy and production gateway work remain open. [Detailed evidence](../docs/decisions/0002-device-identity-and-bootstrap.md) records scope and remaining limits. A3, A4, and B2 remain active; production C and protocol freeze remain gated.

The branch names are suggestions, not existing branches. For desktop tasks, create the branch and worktree inside the desktop repository. Record paired repository commits during integration. Each owner requests contract changes through A, rather than silently editing shared fields.

## Starting an agent

After the coordinator assigns a package, create its isolated worktree from the current repository HEAD. For example, run these commands from http-freekit-android for A and B:

```powershell
git worktree add ../http-freekit-android-a -b plan/a-foundation HEAD
git worktree add ../http-freekit-android-b -b feat/b-android-shell HEAD
```

Start each agent with its worktree as the working directory. Give it the package prompt below, its assigned owner name, the relevant dependency commits, and this instruction: Read AGENTS.md, complete only your package, coordinate shared contracts, run applicable checks, commit your changes, and return a handoff with exact evidence. Do not mark mocked functionality as working capture.

For D, run the worktree command from ../http-freekit and pass the Android plan's absolute path. Desktop worktrees are siblings of the desktop repository, so ../http-freekit-android remains the canonical planning checkout; do not assume an Android document change in one worktree is visible in another. Share committed contract updates through the coordinator and merge them explicitly before dependent work.

Integrate each branch deliberately after review; do not ask agents to merge one another's unfinished branches. The public repository is now hosted at `JamesSabinaa/http-freekit-android`. Package A is establishing the local build toolchain; no CI runner or release signing has been provisioned.

## A Foundation and contracts

Suggested agent prompt: Read AGENTS.md and the planning documents. Own the stage 0 foundation. Audit the available Android/JDK/ADB environment and select an implementation strategy and forwarding engine based on actual compatibility and licence evidence. Prove a small packet-to-proxy stream path and Android-to-Node authenticated transport. Freeze v1 only after these spikes pass. Do not spend this package building the full interface or relay.

Owned files: Gradle wrapper and root build configuration, dependency catalogue, shared model/protocol interfaces, protocol fixtures, docs/protocol.md, and docs/decisions/. Coordinate ownership of any desktop spike with D. Record why alternatives were rejected and exactly which upstream files/dependencies, if any, will be used.

Exit criteria: reproducible debug build; chosen min/target SDK and app ID; licence inventory and implementation decision; demonstrated IPv4/IPv6 and DNS strategy; HTTP and CONNECT byte compatibility; scoped TLS pinning and client-key proof; frozen pairing/session/error schemas; test fixture version; documented limits and half-close behavior. If a dependency cannot implement the declared capture policy, resolve that before freeze.

## B Android interface and lifecycle

Suggested agent prompt: Build the native Android companion interface and lifecycle using mocks until A freezes shared interfaces. Implement computer pairing UI, app selection, permission flows, foreground VPN lifecycle, connection state, diagnostics, and Stop. Treat successful capture as a separate state from pairing or VPN setup.

Owned files: Android UI, resources, lifecycle coordinator, service entrypoint, UI tests, and app-facing setup documentation. C owns the packet and socket implementation; expose lifecycle hooks instead of editing C's internals. Coordinate manifest and application wiring changes through the integration owner; avoid simultaneous edits to root build files.

Exit criteria: denied permissions, cancelled consent, unavailable camera, malformed QR, pending/rejected pairing, existing VPN conflict, notification Stop, VPN revocation, process restart, missing credentials, and changing networks all have tested states. No real capture claim from mock counters. No secrets in UI diagnostics. Device evidence includes the chosen minimum and a recent Android version where available.

## C Capture engine and transport

Suggested agent prompt: Implement the selected packet forwarding engine adapter and the frozen secure transport. Translate selected TCP traffic into the explicit proxy stream protocol; enforce app selection, DNS, UDP/443 and IPv6 policy. Integrate Keystore credentials and protect outbound sockets. Keep UI work in B and gateway work in D.

Owned files: core-capture, core-transport, core-security implementation, engine native integration, and packet/transport tests. Shared interfaces require A's coordination. Do not copy an upstream VPN implementation before its licence strategy is resolved.

Exit criteria: real HTTP and debug-app HTTPS reach the proxy; streaming upload/download and WebSockets work; no loop or selected-app IPv6 leak; bounded backpressure and resource use; cancellation releases TUN/sockets/jobs; reconnect does not replay requests; wrong desktop pin and revoked credentials fail. Record engine limitations and performance baseline.

## D Desktop gateway and ADB

Suggested agent prompt: Work in ../http-freekit under its AGENTS.md. Add a dedicated authenticated companion gateway, enrollment registry, desktop pairing/device controls, device attribution, destination policy, and FreeKit companion ADB activation. Preserve loopback management defaults and existing HTTP Toolkit companion compatibility. Coordinate the protocol with A.

Owned files: new desktop gateway/security modules and tests, companion desktop UI, narrow interceptor changes, configuration, and local API additions. Prefer new modules to broad proxy rewrites. Any changes to shared proxy routing policy must include targeted regression coverage. This package has no implementation files to create in the Android repository except handoff documentation and contract proposals.

Exit criteria: pending approval and one-time enrollment work; a valid active device can stream only to the configured proxy; revoked devices disconnect; gateway credentials cannot access management; WAN destination policy covers actual egress and rule-driven targets; ADB reverse ownership and cleanup are preserved; existing Android tests pass; enabling a gateway never exposes the existing API or raw proxy unintentionally.

## E WAN and relay

Suggested agent prompt: Start after authenticated USB capture and gateway egress restrictions pass. Deliver direct WAN mode first using the same identity and device credentials. Test cellular-to-desktop operation and failure diagnostics. Then spike a relay carrier with TLS terminating at Android and the desktop, and write its separate contract before implementation. Do not provision or publish infrastructure without explicit authorization.

Owned files: WAN endpoint selection and connectivity diagnostics, later relay carrier adapter and separate relay repository if chosen, deployment documentation, and WAN tests. Coordinate transport changes with C and gateway changes with D.

Exit criteria for direct WAN: successful separate-network capture, wrong pin rejection, revocation, bounded reconnect, private-target policy, and clear NAT/firewall errors. Exit criteria for relay: both endpoints outbound behind CGNAT, relay cannot decrypt or substitute the paired endpoint, bounded routing/quotas, and documented metadata visibility. WSS terminating at the relay alone does not satisfy this gate.

## F Integration and release

Suggested agent prompt: Own acceptance evidence and reproducible developer/release instructions. Add contract fixtures with A, a controlled Android debug traffic app, lifecycle and network tests, CI, artifact checks, and upgrade tests. Integrate B C D only after their contract compatibility is demonstrated.

Owned files: integration test harness, controlled test application, CI, build/export scripts, docs/validation.md evidence, release documentation, and final application wiring agreed with B. Do not rewrite another package's implementation to make a test pass without coordinating the change.

Exit criteria: stage matrix includes exact paired commits and device/network evidence; automated checks pass; APK export follows dist/ conventions; no signing secrets or SDK paths are committed; licences/notices are present; compatibility and rollback are documented; remaining unrun tests are explicit. Publish only when separately requested.

## Parallel execution order

First wave: A owns foundation, B builds mocked interface states after an initial toolchain agreement, D investigates desktop seams, and F prepares the test matrix. This describes independent work packages, not a requirement to run four agents.

Second wave: after A freezes the engine and contract, B C D implement against it; F integrates fixtures and acceptance tests. A remains contract coordinator. Shared-file edits must be serialized even when owners work concurrently.

Third wave: F verifies USB and LAN; E starts direct WAN after the gateway security gate. Relay development begins after direct WAN acceptance. Avoid giving multiple agents the same app manifest, build files, or protocol document without one designated merger.

## Task handoff checklist

- Owner and branch/worktree are assigned before edits.
- Dependencies and shared-file ownership are agreed.
- Contract change proposals include compatibility impact.
- Relevant checks pass, with unrun device checks listed.
- git status, git diff, and staged diff are reviewed.
- Only package changes are committed; commit IDs and evidence are recorded.
- Coordinator updates this board and the milestone gate.
