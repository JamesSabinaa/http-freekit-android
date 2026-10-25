# Resume checkpoint

Updated 25 October 2026 after resuming in Linux. Read [AGENTS.md](../AGENTS.md),
[README](../README.md), the [roadmap](roadmap.md), required architecture/security/
protocol documents and the [work board](../tasks/README.md) before editing.
The original goal is active and incomplete.

## Current Linux resume position

- Android public `main` is `6898ec8b08f4835e5ffa0b655ad53b94f2450610`.
  The original Windows F worktree and ignored archive below are absent here;
  no original unfinished files were overwritten. The eight-file A23 package
  was reconstructed in an isolated branch and merged through `91c2a85`.
- Corrected source `6898ec8` uses bounded exact-owned-package/User 0 `pm dump`
  grant readback; the earlier unsupported `cmd package check-permission` path
  is preserved as failed history, not acceptance.
- [Pinned host run 40207877081](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40207877081)
  passes all three jobs. Independent original-artifact/log audit: 318 JVM cases,
  617 Android-job Node cases, 144 documentation-job Node cases, 46/46 source-bound
  actual TLS CA receipts and nine zero-issue lint XMLs. The finite ignored export
  is `dist/a23-host-audit.json`, SHA256
  `2dbf81ad568bc3fc027cff902805b55269626731c47f792f458da3a503d972c1`.
- [First A23 matrix 40190998118](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40190998118)
  at `8526b0a`: API26 independently passes all three methods; API37 stops with
  zero starts at unsupported permission readback exit255, after a successful
  declared permission and owned grant. All cleanup joins.
- [Second matrix 40209128345](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40209128345)
  at `6898ec8`: API26 again independently passes all three methods. API37 stops
  at `adb: unable to connect for root: closed` during fresh-AVD clock setup,
  before driver admission. Only its host-cleanup record exists: driver exit null,
  stop0, observed termination/join and emulator exit0. No API37 permission or
  method result exists for this run. **A23 two-API acceptance remains open.**
- Workflow owner has the exclusive two-file root-transition correction in their
  isolated worktree: `.github/workflows/enrollment-runtime.yml` and
  `scripts/tests/enrollment-emulator-clock.test.mjs`. Reuse capture-runtime's
  bounded exact-UID observation, without repeating root/unroot or weakening the
  clock gate. Root owns this checkpoint, evidence documents and integration.
  Test/commit/review and ordinary host CI must precede another fresh full matrix.
- User explicitly authorized Android main publication and hosted validation,
  and separately authorized publication of the reviewed desktop ten-commit tip
  `2ee70e86` as `codex/android-companion-trusted-https`. This supersedes only the
  pending publication decision below. The exact desktop checkout/review patch is
  absent here and that tip is absent from GitHub. The user said they can provide
  it; await the actual file/checkout path, verify the original hash/tree and do
  not substitute source. C5, physical USB, production freeze and deployment
  restrictions remain in effect.

## Historical Windows pause record

The sections below preserve the original Windows-workspace inventory and
unfinished-file provenance from the pause. They are not a claim those paths or
ignored artifacts exist in this Linux workspace.


## Source locations

Paths below are relative to this repository's parent directory on the current
Windows workspace. Inspect their actual Git state before changing anything.

| Location | Branch/base | State at pause |
| --- | --- | --- |
| `http-freekit-android` | `main` | Canonical public checkout; receives this completed code/documentation checkpoint |
| `http-freekit-android-a` | `plan/a-foundation` | Coordinator checkout; completed code through `94a47c771ae4993c9ee788ceac95a2067d3bf04b`, followed by this documentation checkpoint |
| `http-freekit-android-f` | `test/f-a23-android-ca` at `dd02648ba85fd02480d211c3fa3ff2ac48697fa4` | Eight uncommitted A23b task files; preserve them |
| `http-freekit-android-interop-runtime` | `feat/ui-a23-android-ca` at `15fc870` | Clean; new Android method already integrated |
| `http-freekit-android-carrier` | `test/d-a23-ca-observation` at `3e69c0c` | Clean; observation parser already integrated |
| `http-freekit-companion-c3` | Desktop source `2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6` | Clean local reviewed desktop source; unpublished |

The public Android repository is
[JamesSabinaa/http-freekit-android](https://github.com/JamesSabinaa/http-freekit-android).
Do not reset, clean or overwrite the F worktree. Assign a single agent ownership
of that existing worktree before editing its unfinished package.

## Exact unfinished package

The immediate task is the [A23b Android CA runtime](android-interception-ca-research.md),
not a new investigation. These eight files in the F worktree are the preserved work:

```text
docs/validation.md
scripts/verify-enrollment-runtime.mjs
scripts/tests/enrollment-interception-ca-runtime.test.mjs
tools/transport-spike/run-enrollment-runtime.mjs
tools/transport-spike/run-interception-ca-runtime.mjs
tools/transport-spike/interception-ca-runtime-results.mjs
tools/transport-spike/enrollment-runtime-interception-ca-driver.test.mjs
tools/transport-spike/enrollment-runtime-interception-ca-report.test.mjs
```

Current implementation moves the fixed A22a/A23 restart flow once into
`run-interception-ca-runtime.mjs`; the base CLI imports it. This corrected an ESM
cycle that previously produced exit 13. It uses fixed suite branches, not generic
injected lifecycle hooks. Late-approval fences are implemented and tested before
registration, drop-arm and approval dispatch after asynchronous replies.

The report uses `http-freekit-a23-runtime`, three ordered invocations and a strict
projection to the original A22a verifier plus the new CA invocation. CA evidence
publishes byte counts and comparison booleans, never digest values. API 37 uses
an explicit owned-package `ACCESS_LOCAL_NETWORK` grant, declaration check and
bounded exact-package/User0 readback. Its finite permission mode is
`owned_ci_grant`; API 26 uses `not_required` with null command observations.
This describes the fixture configuration, without establishing a loopback exemption.

Last selected check: **244/244 passed**, zero failures/cancellations/skips/todo,
28.1460179 seconds. Session `85614` was observed terminal exit 0 and joined.
The private log is `build/reports/interception-ca-runtime/preparation-tests.tap`
in F, SHA256 `fb4ea832b6a2e4b435fae9c3dbffdd30f7ffa7e889b5d1840c2a02992f70d876`.
These changes have not yet been committed or exercised on Android.

## Resume sequence

1. Verify the worktree/branch/file inventory above and confirm no old process is
   live. Review the final eight-file diff, especially fixed-flow extraction,
   late-approval fences, permission evidence and exact report projection. UI/D
   reviews found the timing gap; its correction is now in the preserved changes.
   Address concrete findings, run affected checks, and commit only this package.
   Use the [developer toolchain](development.md): pinned Node 24.22.1/JDK 17 and
   explicit OpenSSL 3 for local checks (the recorded issuer was 3.6.1).
2. From clean source, exercise the actual CLI's unavailable-device refusal.
   It must exit 1 with all three invocation counts zero, rather than the former
   exit 13. Dirty-source checks previously stopped earlier at `source_not_clean`;
   they do not prove the clean-source unavailable-device branch.
3. Integrate the checked F commit. Root owns the remaining
   `.github/workflows/enrollment-runtime.yml` `a23` selection and its focused
   workflow tests. Runtime/XML/HTML use the `interception-ca` report root;
   host cleanup uses **`interception-ca-runtime`**. Keep C2/C5 desktop pins,
   original suite defaults, clock bounds and owned emulator cleanup unchanged.
   A23 must reject desktop arguments and perform no desktop checkout or alias setup.
   Document the explicit API 37 fixture permission setup in its profile.
4. Run the meaningful combined checks, inspect status/diff, commit the task files,
   merge checked progress onto `main`, and inspect the new ordinary host CI result.
   The [last audited hosted run](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40177081047)
   is at `1065657`; it must not be relabelled as validation of later A23 code.
5. Only after the host proof, APK/lint and finite guards pass, execute the hosted
   `a23` matrix on fresh API 26/37 emulators. Require all three same-run invocations:
   original prepare, new CA retrieval after worker restart, original reopen/Forget.
   Independently verify JSON/XML/HTML, actual CA evidence and every cleanup join.
   No A23 Android runtime or permission grant had occurred at this checkpoint.
6. Continue the [roadmap](roadmap.md) and full [implementation plan](implementation-plan.md).
   Do not mark the application complete from these research checks.

## Completed evidence to retain

- Coordinator check `54537`: 35 JVM methods in six original XML reports, zero
  failures/errors/skips; all 46 receipts in the actual TLS proof pass; APK assembly
  and strict lint pass. Gradle finished in 4m56s. Actual tested source was `dd02648` plus the
  input-wiring change subsequently committed as `94a47c7`; the finite report
  truthfully has `sourceDirty=true`. Report SHA256:
  `97f7207fafb6241f4ef3b5061f06fcb7153dc06c40f745d885a9e47fababeaae`.
- Root's 138 enrollment Node checks and eight actual Windows crash-recovery gates
  pass at clean `59f3b53`; seven real C3 and nine C2 local desktop regressions pass.
  The later peer/evidence ownership check passes 10/10. These are host checks.
- F's earlier six-method/46-receipt proof and failed run 22162 remain separately
  recorded. Its original passing report binds `ddf37f6` plus precommit test files;
  do not rewrite it as execution after a later commit. The CLI stdin/exit cycle
  is fixed, with an unchanged before/after valid-stop regression.
- The new single Android method and exact 17-field/three-phase parser are committed.
  Its APK compiles and strict lint passes; the parser passes 80 checks. Both original
  `DraftEnrollmentInteropTest` methods remain byte-identical.
- The ordinary host suite at `1065657` passed 298 fresh JVM and 574 Node checks,
  nine lint reports and native/conformance/cleanup gates. Its audit and older C5
  preparation/APK audits remain source-specific ignored `dist/` exports.

## Local recovery backup

The eight unfinished source files are also saved, with relative paths, in the
canonical checkout's ignored `dist/a23-runtime-work-in-progress.zip`:

```text
ZIP SHA256  2c20a53ad04a12d683bca253415af3b2478054fe492be2c0d424aeda7e9d7cfa
Manifest    dist/a23-runtime-work-in-progress.json
Manifest SHA256  c0679edb6d9e8f391c9a8bf60f88240e0fcea5f4715f6d7ebde61a120bb97734
```

The manifest records the branch/base and every member's size/hash; both files
have checksum sidecars. The archive is local, not committed or uploaded. Use the
existing F worktree first. If it is missing, verify the archive/manifest and
restore only those files into a separate clean worktree at the recorded base.
Never extract over unrelated or pre-existing changes. Carry the backup to another
machine if resuming outside this workspace.

## Boundaries that persist

- The separate ten-commit desktop publication decision remains pending:
  `JamesSabinaa/http-freekit`, proposed branch
  `codex/android-companion-trusted-https`, tip `2ee70e86`. The older eight-commit
  `fd63f694` proposal does not authorize publishing this expanded branch. Check for
  an actual user reply before acting; do not infer approval from the Android repo.
  The concrete local review patch is
  `../http-freekit-companion-c3/dist/desktop-https-review.patch`, SHA256
  `f231a2d978490f31273740812f37f4bd58ad2f2d68a377b8aa85519723960369`.
- No local Windows emulator retry. Use the checked hosted matrix; no device was
  attached at the last inventory, so recheck before proposing physical tests.
- No production wire integration before the recorded v1 freeze. Production
  approval persistence, selected-UID enrolled TUN acceptance, H2 scope, physical
  USB, LAN/WAN/relay and release acceptance remain open.
- Keep the documented permission-only `QUERY_ALL_PACKAGES` lint exception;
  remaining checks stay strict. Never upload signing keys or enable paid
  infrastructure without explicit authorization.
- The historical `freekit-origin-gateway-dCJ45c` TEMP deletion was automatically
  rejected as "blocked by policy". Do not retry/bypass it or attribute later
  fixture cleanup to that old failed run.

## Suggested goal text

```text
/goal Continue implementing HTTP FreeKit Android according to docs/implementation-plan.md. Start with docs/resume-checkpoint.md and docs/roadmap.md, preserve the eight unfinished A23b files, finish and verify Android CA retrieval, then deliver selected-app HTTP/HTTPS USB capture and continue the remaining roadmap. Keep checked progress on main, use isolated agent worktrees as required, commit only task files after validation, and update the roadmap at each milestone. Respect the recorded publication, device and signing restrictions; do not treat research tests as a finished app.
```

For this existing paused thread, `/goal resume` resumes its current objective;
see [official OpenAI documentation](https://developers.openai.com/cookbook/examples/codex/using_goals_in_codex).
