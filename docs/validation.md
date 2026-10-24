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
git diff --check
```

The [link checker](../scripts/check-doc-links.mjs) checks local Markdown inline links, image links, reference destinations, ATX heading fragments, and explicit HTML anchors. It resolves encoded paths, enforces that targets stay inside the checkout, and reports the document and source line for failures. Code fences and inline code are examples, so plain sibling-repository paths in those examples do not become links to validate. Generated folders, symlink directories, and nested Git repositories/worktrees are not scanned. Remote URLs are intentionally not fetched; external-link availability and non-Markdown fragments require separate review.

After installing the SDK/JDK and locked Node peer dependencies, CI runs:

```sh
npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
./gradlew --no-daemon --console=plain \
  :core-protocol:test \
  :core-security:testDebugUnitTest :core-security:assembleDebugAndroidTest :core-security:lintDebug \
  :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
```

Assembling the security module's Android instrumentation APK checks compilation only; no Keystore or device result is inferred from it.

Unit-test/lint reports and resolved dependency inventories are retained for seven days, including on failed builds when reports exist. The upload paths exclude `dist/`, APK outputs, signing material, and the temporary TLS identities created by the host test. A green workflow establishes only these host checks; Android installation, UI behavior, Keystore use, VPN packet forwarding on Android, and physical-network acceptance remain independent evidence requirements. Workflow syntax is checked locally with actionlint; execution evidence is recorded separately. A hosted run is not claimed until its actual run result is recorded.

The separate Linux native-engine job checks the fixtures, fetches HevSocks5Tunnel root commit `c0dfc4b07baa5e48022f5f88ac90488601f05674` and its pinned submodules, then executes the worker. Reproduce both checks with:

```sh
python3 -m unittest discover -s tools/engine-spike -p 'test_*.py'
python3 tools/engine-spike/run_linux.py --engine-root .gradle/engine-spike/hev-socks5-tunnel
```

The runner verifies its source checkout and builds the candidate locally. Its synthetic packet fixtures use a socket pair, a controlled SOCKS adapter, and an explicit-proxy peer. It needs GCC, make, and Python 3, with no sudo, TUN device, network-route changes, SDK, or phone. This isolates native packet-to-stream evidence from Android routing, protected sockets, real desktop proxy integration, and physical-device acceptance. It does not bundle the candidate into the APK or freeze the protocol.

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
