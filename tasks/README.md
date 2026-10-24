# Agent work board

All packages below are unclaimed. These files prepare work for agents; no implementation agents have been started. The coordinating user or agent assigns unique ownership before concurrent work begins. Use separate branches and worktrees. Update this board through the coordinator to avoid agents racing to edit the same rows.

## Assignments

| Package | Owner | Branch | Status | Dependencies |
| --- | --- | --- | --- | --- |
| A Foundation and contracts | Unassigned | plan/a-foundation | Ready | None |
| B Android interface and lifecycle | Unassigned | feat/b-android-shell | Ready for mocked work | A for final toolchain and interfaces |
| C Capture engine and transport | Unassigned | feat/c-capture | Blocked for production integration | A engine choice and frozen protocol |
| D Desktop gateway and ADB | Unassigned | feat/d-companion-gateway | Ready for design and spike | A for production protocol; C for end-to-end capture |
| E WAN and relay | Unassigned | feat/e-wan | Blocked | Authenticated USB milestone and destination policy |
| F Integration and release | Unassigned | test/f-integration | Ready for planning and fixtures | A for stable fixtures; B C D for device acceptance |

The branch names are suggestions, not existing branches. For desktop tasks, create the branch and worktree inside the desktop repository. Record paired repository commits during integration. Each owner requests contract changes through A, rather than silently editing shared fields.

## Starting an agent

After the coordinator assigns a package, create its isolated worktree from the current repository HEAD. For example, run these commands from http-freekit-android for A and B:

```powershell
git worktree add ../http-freekit-android-a -b plan/a-foundation HEAD
git worktree add ../http-freekit-android-b -b feat/b-android-shell HEAD
```

Start each agent with its worktree as the working directory. Give it the package prompt below, its assigned owner name, the relevant dependency commits, and this instruction: Read AGENTS.md, complete only your package, coordinate shared contracts, run applicable checks, commit your changes, and return a handoff with exact evidence. Do not mark mocked functionality as working capture.

For D, run the worktree command from ../http-freekit and pass the Android plan's absolute path. Desktop worktrees are siblings of the desktop repository, so ../http-freekit-android remains the canonical planning checkout; do not assume an Android document change in one worktree is visible in another. Share committed contract updates through the coordinator and merge them explicitly before dependent work.

Integrate each branch deliberately after review; do not ask agents to merge one another's unfinished branches. A local Git repository has been initialized for these documents, but no remote, hosting service, CI runner, or Android SDK has been provisioned by this planning work.

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
