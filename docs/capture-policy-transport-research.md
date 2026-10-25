# Capture policy and enrolled transport research

## Scope and ownership

C4 composes the existing numeric authenticated SOCKS boundary in `core-capture`
with the real enrolled factory and the local reviewed desktop. It follows the
[C2 factory profile](capture-transport.md) and [C3 HTTPS profile](https-transport-research.md).
This is isolated research against the draft contract. It changes no wire bytes,
capabilities, production app integration or protocol-freeze gate.

D owns `CapturePolicyServer.kt` and its focused core unit regressions. F owns the
existing Node origin fixture and focused tests for one additive `http-h1` profile
using the same C3 desktop pin and default two capabilities; preserve all existing
C2/C3 profiles. Root owns the transport module's test-only composition facade,
integration cases, build wiring and this profile. Each owner works in a separate
Android worktree. The desktop checkout remains clean at
`2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6`;
no desktop edits or publication are assigned.

## Directional completion and Stop

A normal TCP flow must observe actual input EOF in both directions, apply the
corresponding output half-close successfully, and join the reverse relay worker
before asking the transport connection to close gracefully. Leaving a copy loop
because a socket closed, admission sealed, Stop arrived or an operation failed
does not establish EOF. Normal closure must not call `interrupt()` first: the
enrolled connection treats interruption as cancellation and requires COMPLETE
for graceful close.

Stop, watchdog expiry and abnormal I/O must still interrupt blocked reads and
writes promptly. Independent cleanup attempts must run even after another
cleanup fails. Retain socket/transport budget charges until the associated real
close and worker joins succeed; a timeout or failed join must not erase ownership.
Do not relax the shared 32-socket bound or hide cleanup failure.

## Acceptance

The core regression uses an actual authenticated SOCKS client and a strict
transport connection backed by a real loopback peer. Send a deterministic body,
perform client SHUT_WR, consume the delayed complete response and actual opposite
EOF. Gate the strict connection's close before its actual join. At that gate both
EOF/half-close effects must be observed, interruption must not have occurred,
and the flow and transport charges must remain held. Release the gate in all
outcomes and require actual peer and policy joins. The unchanged regression must
fail on the old interrupt-before-close implementation. Paired abnormal/Stop
checks must prove interruption and attempt-all cleanup without false joins.

The composed JVM check must use the production `CapturePolicyServer`, without a
second relay implementation, public production visibility changes, reflection
or private APIs. A test-only Java facade may call its public JVM bytecode while
keeping Kotlin's internal source boundary. Use the existing scoped software-key
enrollment fixture and factory's default two capabilities. Exercise HTTP80,
verified IPv4/IPv6 HTTPS443 and HTTP/WSS Upgrade through actual SOCKS
authentication and original numeric destinations. Preserve deterministic bodies,
actual TLS close notification, maintained WebSocket decoding and real peer Close.
Wrong CA and hostname must fail before origin egress without direct fallback.

Successful flows must reach zero policy flows and zero factory stream charges
naturally, before explicit session Stop. Assert no factory failure, no direct or
UDP egress and actual final policy/factory worker joins. Run the explicit task
freshly, serially on controlled loopback ports, only with the exact clean desktop
input. Ordinary self-contained tests must not require unpublished desktop code;
existing C2 and C3 tasks and their assertions remain available unchanged.

These host checks do not prove Android Keystore, VpnService protect/bind, selected
UID routing, real TUN capture, USB or physical-device behavior. The old cold C1
reset remains unexplained; this source-level lifecycle mismatch is not evidence
of its cause. Android strict inner-TLS and actual enrolled TUN composition remain
subsequent gates. No local emulator retry is assigned.

## Running the local composition

After configuring the [developer toolchain](development.md), use the same clean
reviewed desktop input as C3:

```powershell
$env:FREEKIT_DESKTOP_ROOT = '<absolute path to the local reviewed desktop checkout>'
$env:FREEKIT_DESKTOP_COMMIT = '2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6'
./gradlew.bat :capture-transport-research:testDesktopPolicyIntegration
```

The seven methods comprise the six inherited C3 exchanges plus normal HTTP80.
Positive exchanges observe the existing gateway's actual stream-complete fact
before Stop, with bounded snapshot observations. The Java facade counts actual
connection interruption, successful half-close and successful close, and rejects
even attempted direct egress. Final cleanup still closes the session, joins the
policy accept/watch workers and destroys its temporary authentication secrets.
This task requires fresh execution and is excluded from ordinary host tests.

## Local evidence and limits

Core fix `1de0d698`, integrated as `2fc4dcd`, preserves normal transport completion
and retains both charges until actual joins. The identical frozen regression
fails on the old source with `[interrupt, close]` and passes with `[close]`.
All 35 core cases and strict core lint pass. Its finite before/after metadata
SHA256 is `70065b4ab3b2033a24e49bd405126720983e37f79da2f0e52d0d5444e7ceb227`.

Fixture `b7ecbfe`, integrated as `45ab200`, passes the six unchanged C3 cases plus
the new ordinary HTTP case on exact desktop `2ee70e86`. All nine C2 regressions
also pass on their unchanged `fd63f694` input. The HTTP tail stays gated on
actual client END_WRITE; no early release or capability waiver is introduced.

The first composed JVM run passes all seven C4 cases with zero failures, errors
or skips in 37.493 seconds. Precommit XML SHA256 is
`dd823fb0661e1646c2d59ff5ccb8b882f0dbe5c6636098dc1ee75fbc65083acf`.
It exercises the real policy frontdoor, both default capabilities, deterministic
HTTP/HTTPS bodies, actual TLS closure, both maintained Upgrade exchanges and
certificate rejection before origin egress. Positive flows require zero
interruptions and actual gateway COMPLETE before explicit session Stop. Both
policy and factory cleanup must join; refused direct attempts also fail.

The integrated check also passes 35 core and six runtime JVM cases, strict
core/runtime/transport lint with zero issues, and runtime instrumentation APK
compilation. The separate direct-factory six-case C3 regression passes in
28.735 seconds after the shared test seam and peer-completion gate were added.
These are local software-key JVM checks and compilation evidence. Android
Keystore/protection, actual selected-UID TUN, physical USB, H2, production trust
retrieval/binding and v1 freeze remain open. No C1 reset cause is established.
