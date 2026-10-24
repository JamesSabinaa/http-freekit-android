# Validation and release plan

## Evidence rules

Record exact Android and desktop commits, Android version and device model, SDK/ADB versions, network topology, commands, results, and relevant sanitized diagnostics. A mock-only test does not demonstrate capture. A VPN connected indicator does not demonstrate proxy delivery. Mark unavailable device tests as unrun and explain the environment requirement.

Documentation-only changes require local Markdown link validation, consistency review, and git diff --check. The foundation now has a pinned Gradle build, parser tests, and a host transport test. Run the commands in [developer instructions](development.md); see [foundation evidence](decisions/0001-foundation.md) for actual results and outstanding gates. Host checks do not demonstrate device capture.

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
