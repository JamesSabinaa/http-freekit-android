# Capture policy and enrolled transport research

## Scope and ownership

C4 composes the existing numeric authenticated SOCKS boundary in `core-capture`
with the real enrolled factory and the local reviewed desktop. It follows the
[C2 factory profile](capture-transport.md) and [C3 HTTPS profile](https-transport-research.md).
This is isolated research against the draft contract. It changes no wire bytes,
capabilities, production app integration or protocol-freeze gate.

D owns `CapturePolicyServer.kt` and its focused core unit regressions. Root owns
the transport module's test-only composition facade, integration cases, build
wiring and this profile. Each owner works in a separate Android worktree. The
desktop checkout remains clean at `2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6`;
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
