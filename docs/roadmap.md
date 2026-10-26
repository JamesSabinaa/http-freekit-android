# Delivery roadmap and progress

Updated 26 October 2026. Implementation has resumed from the [checkpoint](resume-checkpoint.md).
The full scope remains the [implementation plan](implementation-plan.md). The
recorded Windows F worktree and ignored backup are absent in this Linux checkout;
the eight uncommitted A23b files were reconstructed from checked source in an
isolated worktree, not recovered from the original Windows worktree.

## Current position

The app has a verified installed-app selector and certificate-help preview.
Production pairing and capture in the main app remain pending. Much of the
authentication, transport and capture foundation exists as executable libraries
and isolated research tests; those tests do not establish a finished capture app.

| Area | Verified progress | Remaining work |
| --- | --- | --- |
| App interface | Installed-app discovery, selection, keyboard/rotation and certificate-help checks on API 26/37 | Connect the interface to real pairing, capture, recovery and diagnostics |
| Identity and enrollment | Keystore identity, scoped TLS, approval, saved credentials, restart/recovery, revocation and expiry research | Production credential/approval binding and remaining v1 decisions |
| Capture and proxy transport | `4cd60b8`: audited host40351833250 and same-matrix40354503342 API26/37 real selected-UID HTTP/H1 HTTPS TUN methods/cleanup independently verified | Exact reviewed desktop source/C5, production integration and authorized physical USB |
| Public interception CA | `fa2d845`: 46/46 source-bound CA receipts, 320 JVM host methods, nine clean lint reports and saved-credential Android retrieval on API26/37 | CA installation, target-app trust and production integration remain open |
| Android CA runtime driver | Fresh matrix 40222004218 passes both APIs; independent original four-file replay verifies three ordered methods and all cleanup on each | A23 runtime research acceptance complete; preserve scope limits and advance to enrolled selected-app capture |
| Reference interception | Accepted Node and Kotlin host composition, followed by independently verified Android selected-UID HTTP/H1 HTTPS on API26/37 at `4cd60b8` | Not C5/desktop/physical USB, general target-app trust or production freeze |
| Desktop dependency | User authorized publication of the reviewed ten-commit branch ending `2ee70e86` | Exact desktop checkout/review patch is absent from this Linux workspace and that commit is not on GitHub; obtain and verify it before publishing or running C5 |

The original completed code checkpoint is `94a47c7` (CA proof input/source
binding); the accompanying documentation checkpoint brought it onto `main`.
The reconstructed A23b and workflow commits passed ordinary pinned host CI at
`8526b0a` in [run 40189595419](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40189595419):
318 JVM methods, 46/46 actual TLS CA receipts and nine zero-issue lint reports.
The first [A23 matrix 40190998118](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40190998118)
passes API 26's three ordered methods and cleanup, but API 37 stops before any
method when unsupported `cmd package check-permission` exits 255 after a
successful owned grant. Both emulator cleanups join; A23 is not accepted. The
bounded owned-package/User 0 `pm dump` readback correction is committed as
`6898ec8` and passes [host run 40207877081](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40207877081):
318 JVM cases, 617 Android-job Node cases, 46/46 CA receipts and nine clean lints.
The [second matrix 40209128345](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40209128345)
again passes API26, but API37 exits at the ADB root clock-setup transition before
any driver invocation. Its sole cleanup report confirms stop0 and emulator
termination/join/exit0. No API37 readback result exists in that second run.
The bounded transition correction `cd36f4b` passes
[host run 40210625804](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40210625804).
[Third matrix 40211577524](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40211577524)
again passes API26; API37 completes clock setup, declaration, grant0/readback0,
but readbackGranted=false stops all methods. All cleanup joins. A concrete
public-AOSP zero-flags LF/CRLF parser defect is corrected in `02fbca2` without
relaxing ownership/grant checks. Its [host run 40212541854](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40212541854)
passes, but [fourth matrix 40213602618](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40213602618)
still fails API37 readback with both commands exit0 and zero method starts;
API26 passes again and all cleanup joins. The formatting defect was not the
established image failure. The next diagnostic logs only fixed structural
counts/booleans, never dump text, and retains the strict grant gate.
Diagnostic source `bf73686` passes [host run 40214948784](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40214948784)
with 318 JVM methods, 46/46 CA receipts and nine clean lint reports.
[Fifth matrix 40216075210](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40216075210)
independently passes API26 but API37 stops before methods with one owned package,
two User0 headers and one target line in the current scope. All cleanup joins.
Public source and red/green regressions show the parser incorrectly includes
outer dump sections after the owned package block; they do not prove which
section the actual image printed. The narrow block-boundary correction keeps
exact ownership and duplicate-user rejection inside that block. It needs pinned
host validation followed by a new full matrix. Boundary checkpoint `4192a41`
fails [host run 40216911800](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40216911800)
in the JVM directional-EOF test (`Socket is closed`, peer output-stream access
at line33). Investigate and correct the concrete failure without weakening EOF
or join assertions; no new matrix has been dispatched. Test-only correction
`5758c20` (integrated `5a589d4`) adds deterministic publication-gap and exception
retention regressions without production changes. Local JVM/lint execution is
unavailable (no Java); require independent review and fresh pinned host CI.
The integrated checkpoint `fa2d845` passes [host run 40220903154](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40220903154):
independent artifact replay confirms 320 JVM methods including all five EOF tests,
46/46 clean-source CA receipts and nine clean lint XMLs. Fresh
[matrix 40222004218](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40222004218)
passes both API26 and API37; independent original four-file replay verifies all
three ordered methods and all report/cleanup gates on each API. **A23 runtime
research acceptance is complete at this exact source.** Earlier failed runs
remain failed. This is not CA installation, target-app trust, production capture
or physical USB acceptance.
The older audited baseline is `1065657` in
[run 40177081047](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40177081047).
New checkpoint CI must be inspected before claiming hosted validation of later code.

## Next milestones, in order

Independent Android work is active while exact desktop C5/physical USB remain
gated: [B6 selected-app preflight](selected-app-preflight.md) adds a real
installed-mode exact-package check with off-main-thread PackageManager observations
and stale-result rejection, never capture readiness. Platform owner `c4ebbce`
(integrated `91c1c33`) and app owner `d4bcc1c` (integrated `e711b47`) are committed;
independent exact-commit reviews found no concrete defect. The separate offline
APK/checksum/metadata integrity verifier is owner `21def75` (integrated `b39d539`),
also independently reviewed, with 24/24 focused and 102/102 total Python checks
passing locally. Host40360223955 at `0edf95b` passes documentation/native but fails
one of89 app JVM cases: Compose adds a nonsynthetic static integer `$stable` field
to the state-reflection assertion. All13 platform and17 other state cases pass.
Root's test-only correction excludes exactly that named primitive static compiler
metadata; production bytes and the exact retained-field assertion remain intact.
Fresh full host/lint and actual app/platform runtime remain pending. Authored
instrumentation tests are not execution. The work board tracks
additional real PackageManager adapter test source and exact runtime report gates.
Approval-bound combined credential persistence is the next verified foundation
gap; it is not an excuse to declare production v1 frozen or silently reuse
research storage. Existing service/native lifecycle is reusable, not duplicated.

1. **Android CA retrieval acceptance — complete.** Source `fa2d845`, host run
   40220903154 and fresh API26/37 matrix 40222004218 pass independent artifact
   replay. Real Keystore enrollment, worker restart, CA/hash continuity, final
   Forget and joined cleanup pass on both APIs in the same matrix. See the
   [Android CA profile](android-interception-ca-research.md).
2. **Prove enrolled selected-app capture — next, externally blocked.** Android-only
   B5 selection admission is implemented as owner `32c92f7`, integrated `66eb9da`:
   a callable inert, immutable plan from a successful installed catalog, with
   fail-closed validation and 25 passing JVM cases. Independent review and
   [host run 40223757997](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40223757997)
   at `5e8d8da` pass; original artifacts independently verify 345 JVM methods,
   46/46 CA receipts and nine clean lints. App assembly and instrumentation
   compilation pass on the host, not locally (no Java/SDK).
   There is no VPN/network/service wiring; this does not establish capture or unblock
   C5. A distinct [reference HTTP/H1 HTTPS host proof](reference-interception-research.md)
   is implemented in parallel: owned ephemeral trust domains, bounded actual
   interception/forwarding and enrolled reference-stream tests. Corrected TLS
   assets and the actual backend pass 48 combined local tests, including both
   verified TLS legs and hostile trust/hostname refusal. Authenticated composition
   does not yet pass: all six local cases stop at gateway startup on Node22,
   which lacks required SQLite defenses. Independent static backend review found
   no concrete defect. First pinned Node24 run 40308827831 reaches all six
   authenticated cases: HTTP and four rejection/revocation cases pass, but HTTPS
   positive fails with a WebSocket `cancelled` error. C's carrier correction
   `8ba2ecd` and B's reproduced delayed-END correction `6b6c1ff` are integrated;
   last-two evidence retention is corrected as `530e14a`. Combined local
   regression checks pass 50/50, with no skipped case. Fresh pinned host
   composition/compilation/lint validation was required. Corrected source
   `d6ee09c` now passes all three jobs in run40311327186; independent original
   evidence verifies all six authenticated reference cases, 48 passed reference
   tests/one root-only filesystem skip (separately passed locally), 345 JVM
   methods, 46 CA receipts and nine clean lint XMLs. The Node-only host checkpoint
   is accepted. The distinct [Kotlin factory composition](reference-kotlin-interception-research.md)
   has committed Node peer `5f9c6b4` (integrated `a49bba5`) and six-case Kotlin
   package `bffd873` (integrated `dc7dbc0`). Independent Node peer review found
   no concrete defect; independent Kotlin exact-commit review also found no
   concrete defect. Local guards
   pass 14/14, reference assets/backend/contract regressions 44/44 and peer
   configuration/CLI checks 15/15. The new exact-source pinned host run40316060504
   at `65cd93f` now passes all three jobs. Independent original reports/logs
   verify all six fresh strict-JSSE JVM cases, all 23 private Node peer cases,
   351 unique JVM methods, 46 clean-source CA receipts and nine clean lint XMLs.
   Reference Node totals are 72 passes/one root-only filesystem skip, zero
   failures/cancellations. The Kotlin host checkpoint is accepted; local Java/SDK
   remains absent. Next is separately scoped
   [Android selected-UID reference preparation](reference-android-tun-research.md):
   two new instrumentation methods/service/consent, real scoped HTTP/TLS traffic,
   private fixture/worker and finite driver/report packages are integrated on the
   coordinator branch, not runtime accepted. Source review passes for Android,
   root IPC hooks and driver. Traffic/worker review found two defects, corrected
   as `d57d749` (per-handshake CA validity) and `ec420bc` (negative child cleanup
   evidence); independent corrective reviews found no concrete defect. Independent verifier
   `9112e5c` passes11/11 tests and synthetic actual-producer replay on both APIs.
   Root finite/doc/contract checks36/36 and eight actual workflow
   shell checks pass. New host compilation/positive Node24/JVM/lint acceptance
   must precede a fresh two-API dispatch. Provisional `5f2207f`/host40324585202
   passes all40 new Node cases but fails an existing capture shared-deadline
   regression (`1 !== 124`) before Kotlin/lint. Test-only `673b119` reproduces
   and separates both deadline paths with unchanged production bytes, passing
   focused2/2 and clean full84/84 locally; independent exact-commit review found
   no concrete defect. Fresh `6e1a68c`/host40328901621 passes all84 capture and40
   new Node cases; retained partial artifacts verify374 JVM methods/46 CA receipts,
   but strict lint fails two API annotation errors. Correction `ddd5a7f` adds
   truthful SDK guards/RequiresApi bridges and direct JVM ALPN coverage; root
   source review found no concrete defect. `37ba80e`/host40332128274 then fails
   earlier app lint on outdated annotation1.9.1; root corrects to stable1.11.0
   without suppression. `3827a5f`/host40334229107 verifies375 passing JVM methods,
   but fails `UseSdkSuppress` on the JVM-only test annotation; root removes only
   that unnecessary annotation, without skip/assertion/production changes.
   Fresh `d25dc53`/host40336789126 attempt1 stops before tests on NDK ZIP
   extraction; one recorded failed-job retry on a fresh runner is attempt2 at
   unchanged source. **Attempt2 passes all three jobs.** Independent original
   evidence verifies375 JVM methods/47 XMLs,22 new traffic/two decoder methods,
   40 new reference Node/84 capture cases,46 CA receipts/all joins and nine clean
   lint XMLs. Host preparation is accepted at exact `d25dc53` and published with
   evidence on main `7e87724`. First runtime40340552254 attempt1 at exact
   host-accepted `d25dc53` independently passes both API26 methods/all four
   artifacts and cleanup; API37 stops before boot on NDK ZIP extraction. One
   recorded full fresh-runner attempt2 is terminal failure at unchanged source.
   API37 independently passes all four original artifacts/two methods; API26
   HTTP passes but `enrollment_input_failed` prevents HTTPS from starting.
   Both emulator cleanups join/exit0. Investigate the input handoff before any
   further dispatch; require both APIs in one same-source attempt, never combined
   across retries. Historical failures remain failed; combined acceptance is open.
   Finite log-only diagnostic owner `09d2564`, integrated `14a29e5`, preserves
   reports/gates/deadlines and passes25 finite Node/11 independent verifier cases.
   Independent static review found no concrete defect. Fresh pinned
   host40345446373 at exact `ca0b3cc` fails existing enrollment unroot clock test
   (`1 !== 124`,29.05s); documentation134/135 pass. Android/native pass and original
   evidence verifies375 JVM/46 CA receipts/nine clean lints/43 reference Node cases,
   but the full host gate stays failed. Test-only owner `6dcf765`, integrated
   `38409e5`, reproduces old assertions red and separates both deadline paths;
   owner clock29/29/full Node documentation162/162 and coordinator focused4/4 /
   finite reference25/25 pass. Independent review found deadline-relative injection
   masks an enlarged budget; the owner must independently anchor/assert30 seconds
   and reject root/unroot60-second mutations. Host40349604793 at `86499d4` passes
   all jobs (metadata only), but predates repair `5085cb5`, integrated `4663e66`.
   Repaired coordinator focused8/8/full documentation166/166 and owner clock33/33
   pass; independent corrective review found no concrete remaining finding.
   Fresh repaired-source host40351833250 at exact `4cd60b8` now passes all jobs
   and independent original-artifact replay:375 JVM/46 CA receipts/nine clean lints,
   43 reference Node/84 capture/141 enrollment documentation cases, including all
   three diagnostic/eight budget mutation cases. Checked evidence is published
   on main `439b1ed`; fresh diagnostic matrix40354503342 attempt1 at exact
   host-accepted `4cd60b8` is now independently accepted on both APIs in that
   same matrix. Original four-file replay verifies both actual HTTP/H1 HTTPS
   methods per API,16 phases/56 facts each and all owned cleanup/emulator exits0.
   All four absence probes pass. **Reference Android TUN research is complete**;
   its earlier missing-probe cause remains unknown and failed attempts stay failed.
   Runtime audit SHA256 `8618ea63b0d5fa1b78c20936d2744436edf79862b12b6a920f49e37cdfb59d4f`.
   Production clock bytes stay unchanged; no control is weakened.
   It is not the missing desktop backend, C5 or USB acceptance.
   Obtain and verify the exact already-authorized reviewed desktop source
   (currently absent), then publish that branch and run the prepared factory and
   selected-UID TUN checks against the exact reviewed commits. Preserve original destinations,
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

The user separately authorized publishing the reviewed desktop ten-commit
branch ending `2ee70e86` as `codex/android-companion-trusted-https` on
`JamesSabinaa/http-freekit`. Its checkout and recorded review patch are absent
from this Linux workspace, and GitHub does not have that commit. Obtain and
verify the exact source before publication; approval does not authorize a
substitute, paid infrastructure, signing upload or deployment. A physical-device
test opportunity and later network/hosting decisions are separate external
dependencies. See the checkpoint for the reviewed source's exact scope.
