# Selected-app platform preflight (B6)

Status: latest corrected source `0605472` is host accepted in
[run40365851244](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40365851244),
with independent406-JVM/nine-clean-lint replay. Fresh exact-source
[matrix40367969116](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40367969116)
is dispatched, not accepted yet. Earlier host acceptance at exact `4ce72be` in
[run40361791894](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40361791894)
remains valid, but its runtime failed below. Not production capture or wire integration.
Independent original reports/logs verify 406 JVM methods/49 XMLs, including all13
platform/all18 state cases, nine clean lints, app/instrumentation compilation,
46 clean-source CA receipts/all joins and24/24 delivery checks. The prior
`0edf95b` host fails only the reflection assertion on Compose's static integer
`$stable`; test-only `4ce72be` fixes that without production changes. Independent
corrective review found no issue. API26/37
[matrix40363807230](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40363807230)
fails: API26 passes19/21 and API37 passes20/21. All eight controlled B6 and three
actual PackageManager methods pass on both; old catalog Refresh touch reachability
fails at line93 on both and line120 on API26. Both original cleanup receipts join/
exit0 with fixture enable/uninstall0, but runtime exits1. This is not full app
acceptance. Test-only owner `4c7708c` (integrated `9b6243e`) extends the existing
vertical LazyList reset to all non-fixture catalog controls before nested horizontal
scrolling, preserving all old assertions/scenarios; finite Refresh geometry is
added. Production bytes stay unchanged. The exact historical image cause remains
unproven. Independent exact-commit review found no concrete defect. Fresh
host40365851244 now passes and a full new matrix is dispatched as above;
old tests and assertions remain mandatory.
Platform owner `c4ebbce` is integrated `91c1c33`; app owner `d4bcc1c` is integrated
`e711b47`. Independent exact-commit reviews found no concrete defect. Thirteen
platform and eighteen pure state JVM methods plus eight controlled Activity
methods are authored and host-compiled; the JVM methods execute and pass in the
pinned host, not locally (Java/SDK absent). Three additional
actual PackageManager adapter methods (owner `4248ace`, integrated `cd0b8ee`) and
the exact 21-method preview workflow gate (owner `6c959d3`, integrated `2af62db`)
are committed. This package adds real
current-user PackageManager observations to the running app without starting a
VPN, requesting permissions, connecting sockets or changing simulated pairing.

## Frozen local seam

B5 `SelectedCaptureAdmission`/`SelectedCapturePlan` remain unchanged. Add in the
existing `com.httpfreekit.android.apps` package:

- `enum class SelectedPackageAvailability { AVAILABLE, NOT_INSTALLED, DISABLED, UNAVAILABLE }`.
- `fun interface SelectedPackageProbe { fun availability(packageName: String): SelectedPackageAvailability }`.
- `enum class SelectedCapturePlatformRejection { SELECTION_REJECTED, PACKAGE_NOT_INSTALLED, PACKAGE_DISABLED, PACKAGE_LOOKUP_FAILED }`.
- `sealed interface SelectedCapturePlatformResult` with nested `Checked(val plan: SelectedCapturePlan)`
  and `Rejected(val reason: SelectedCapturePlatformRejection)`. Both redact toString.
- `SelectedCapturePlatformAdmission.check(selection: AppSelectionState, companionPackageName: String,
  probe: SelectedPackageProbe): SelectedCapturePlatformResult` first calls B5 admission.
  B5 rejection makes zero platform calls. An accepted immutable plan probes only its
  exact selected packages; every successful selection is checked, never filtered or
  silently pruned. Any absent/disabled/unavailable package rejects the whole check.
  Runtime/security failures become finite lookup failure, never provider text.
- `PackageManagerSelectedPackageProbe(context: Context)` implements the interface
  using application context/current-user PackageManager. Use guarded public API33
  overloads and API26-compatible calls, installed flag, effective enabled setting,
  enabled/suspended state. Missing lookup is NOT_INSTALLED; unknown/error is
  UNAVAILABLE. Do not query labels, signatures, UIDs or a new full inventory.

A Checked plan is a past observation, not durable start authorization. A future
capture Start must revalidate again and retain CaptureVpnService's final package,
consent, permission and ownership checks.

## App behavior and ownership

Add an explicit installed-mode Check selected apps action. It runs the frozen
admission off the main thread, using applicationContext.packageName (including
debug suffix), with finite idle/checking/checked/rejected presentation. State must
not retain raw exception text, inventory or package identifiers. Checked always
says capture unavailable/not started; no connected/gateway/CA readiness inference.
Sample-mode simulation remains unchanged and visibly separate.

Use a bounded owned worker and main-thread publication, consistent with existing
ViewModel catalog loading. One active/requested check at a time. Pure testable
generation/state logic rejects old completions after selection, mode, refresh,
locking/Stop, background return or ViewModel clear. Cancellation alone is not a
freshness check. Invalidate when the activity leaves/returns; do not auto-launch
permissions or auto-start checks/capture. Check cannot publish while selection is
locked or inventory is loading/failed. Search/filter projections never change the
whole admitted selection. Preserve existing callers with safe inert defaults
where constructor/composable signatures evolve; real MainActivity injects the
platform probe. No new dependency, manifest service or production transport.

## Unique packages and validation

Root owns this profile/board, docs, build/CI integration and main promotion.
Platform owner exclusively adds the two main seam files and focused JVM tests;
app owner exclusively edits ViewModel/MainActivity/PreviewApp/strings and adds
pure state tests plus focused instrumentation source. Coordinate using the frozen
seam above; neither owner edits B5, core capture/security or research profiles.

JVM tests cover whole-request failure, all B5 failures making zero probes,
current-package disappearance/disable/errors, exact selection versus filters,
redaction/immutability and stale completion/cancel/lifecycle/clear races. Authored
Android tests use controlled existing fixtures, not real-device inventory.
Compilation is not execution; runtime UI/platform tests stay unrun until a
separately gated emulator/device validation. Require independent source review,
full pinned host unit/build/instrumentation-compilation/lint and existing gates
before checked main promotion. Local Java/SDK absence remains explicit.

## Separate delivery integrity package

An independent stdlib-only receiving-side verifier may add
`scripts/verify-debug-delivery.py` and `scripts/tests/test_debug_delivery.py`.
It reads only existing stable dist APK/checksum/metadata files and an explicit
expected source commit; no build, device, network, publication or writes. Strict
bounded duplicate-rejecting metadata/checksum validation and streamed APK hashing
must reject missing/nonregular/symlink files, unsafe/mismatched filenames, modified
bytes, mixed hashes/source, malformed flags and unknown metadata fields. Root's
receiving-side policy requires `sourceDirty` exactly boolean false and exact
matching expected source commit; the producer may export dirty builds, but this
gate refuses them. This is validation of self-reported metadata, not source or
signing attestation. Keep other current producer schema/values; null
compatibleDesktopCommit stays unavailable.
Use safe no-follow reads and before/after file identity checks. Tests use opaque
bytes, not purported valid APKs. Success means bundle integrity only, not APK
signing, embedded manifest/version, provenance attestation, desktop compatibility,
USB or device acceptance. Root alone integrates usage/CI; producer changes are
not assigned in this package.
