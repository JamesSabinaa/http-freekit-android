# Delivery roadmap and progress

Updated 25 October 2026. Implementation has resumed from the [checkpoint](resume-checkpoint.md).
The full scope remains the [implementation plan](implementation-plan.md). The
recorded Windows F worktree and ignored backup are absent in this Linux checkout;
the eight uncommitted A23b files have not been recovered here. Their assigned
owner is reconstructing the package from checked source in an isolated worktree.

## Current position

The app has a verified installed-app selector and certificate-help preview.
Production pairing and capture in the main app remain pending. Much of the
authentication, transport and capture foundation exists as executable libraries
and isolated research tests; those tests do not establish a finished capture app.

| Area | Verified progress | Remaining work |
| --- | --- | --- |
| App interface | Installed-app discovery, selection, keyboard/rotation and certificate-help checks on API 26/37 | Connect the interface to real pairing, capture, recovery and diagnostics |
| Identity and enrollment | Keystore identity, scoped TLS, approval, saved credentials, restart/recovery, revocation and expiry research | Production credential/approval binding and remaining v1 decisions |
| Capture and proxy transport | Native packet checks and local policy/HTTP/HTTPS H1/Upgrade composition | Actual enrolled selected-UID TUN execution, production integration and physical USB |
| Public interception CA | Compiled getter and real Node TLS endpoint; 35 integrated JVM methods and 46 receipts in the actual TLS proof pass; APK assembly and strict lint pass | Execute the new Android saved-credential method on API 26/37 |
| Android CA runtime driver | The paused Windows worktree recorded 244 passing selected Node checks, but its eight uncommitted files and backup are unavailable in this checkout | Reconstruct and independently review/commit the driver, check clean-source CLI refusal, wire workflow and execute real emulator run |
| Desktop dependency | Reviewed local ten-commit branch through `2ee70e86`; local integration checks pass | Separate publication approval; production desktop UI/gateway wiring |

The latest completed code checkpoint is `94a47c7` (CA proof input/source binding).
The accompanying documentation checkpoint brings this work onto `main`.
The last independently audited hosted baseline is `1065657` in
[run 40177081047](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40177081047).
New checkpoint CI must be inspected before claiming hosted validation of later code.

## Next milestones, in order

1. **Finish Android CA retrieval acceptance.** Review and commit the preserved
   A23b driver, check its clean-source refusal path, wire the `a23` workflow
   selection, and run all three required invocations on each API 26/37 emulator.
   Require real Keystore enrollment, worker restart, CA/hash continuity, final
   Forget and joined cleanup. This uses the reference gateway and needs no desktop
   publication. See the [Android CA profile](android-interception-ca-research.md).
2. **Prove enrolled selected-app capture.** Resolve the separate desktop
   publication decision, then run the prepared factory and selected-UID TUN
   checks against the exact reviewed commits. Preserve original destinations,
   complete bytes, EOF, notification Stop and all actual ownership joins.
   See [C5](android-enrolled-tun-research.md). Its Android runtime remains unrun.
3. **Close the foundation contract gates.** Resolve production approval/CA
   persistence, credential lifetime/renewal and identity-rotation decisions;
   verify the required capture/transport behavior and record an explicit protocol
   v1 freeze. Broader HTTPS/H2 owner isolation remains open. Production wire
   integration continues to depend on that freeze.
4. **Wire the real application and desktop.** Replace simulated pairing and
   connection state with the verified implementations, connect selected apps to
   the actual foreground VPN lifecycle, and implement desktop approval/device
   controls and ADB activation while retaining legacy compatibility.
5. **Deliver the USB developer preview.** On a physical phone with Wi-Fi disabled,
   verify selected-app HTTP and trusted debug-app HTTPS through ADB reverse into
   the desktop proxy. Check consent, trust guidance, reconnect, Stop, revocation,
   nonselected traffic and documented DNS/IPv6/UDP policy. Emulator or host passes
   cannot substitute for this exit gate.
6. **Add LAN, then direct WAN, then relay.** Reuse the same authenticated identity
   and gateway. Verify wrong-host refusal, reachability, destination restrictions,
   active revocation and separate-network behavior before moving to the next
   stage. Hosting/deployment decisions remain separately authorized.
7. **Complete release acceptance.** Finish the device/network matrix, upgrade and
   rollback checks, notices, signing process and reproducible artifacts/checksums.

## Working and reporting policy

`main` is the delivery branch. Agents use separate branches/worktrees as required
by [AGENTS.md](../AGENTS.md), then merge checked checkpoints onto `main` promptly.
Keep unfinished changes isolated and preserve their exact location in the resume
checkpoint. Update this roadmap after a completed milestone with its evidence,
remaining limitations and next action. Do not replace implementation with more
planning once an executable next step is available.

Desktop publication approval, a physical-device test opportunity and later
network/hosting decisions are external dependencies. See the checkpoint for their
exact scope; the Android repository's public status does not authorize desktop
publication or paid infrastructure.
