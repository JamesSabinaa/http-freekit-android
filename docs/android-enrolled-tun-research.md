# Enrolled selected-UID TUN research

## Scope and ownership

C5 composes the actual Android `CaptureVpnService`, native engine, shared SOCKS
policy and saved-credential enrolled factory. It follows the verified local
[policy transport composition](capture-policy-transport-research.md). The single
initial method proves selected-UID HTTP80; HTTPS, IPv6, revocation, physical USB
and production integration remain separate requirements. Do not infer those
results from this method or freeze v1 before the remaining foundation gates.

Root owns this profile, the [finite descriptor](../tools/transport-spike/enrolled-tun-descriptor.mjs),
build/manifest integration, shared traffic-source extraction, the additive
desktop fixture profile and hosted workflow wiring. UI owns only new `DraftEnrolledTun` Android test/service/
consent files in the existing transport-interop research APK. D owns only the
synthetic traffic app's new finite command and focused response-reader tests,
plus the additive `startTunOrigin` operation in the existing private worker and
parent wrapper with focused tests. F owns the finite report/driver, alias and
acknowledgment ownership helpers after the C4 host audit.
After the worker handoff, D also owns only the new fixed research-package owner
helper and focused tests: verify all three APK signers, install/clean up the two
extra packages and grant only the fixed research permissions. The existing host
continues to own the interop test APK; no existing driver ownership is replaced.
Each source owner uses a separate branch/worktree from
this committed contract; root alone edits shared docs/build files.

## Actual destination and input

The traffic UID opens exactly `198.18.0.2:80`. The desktop fixture must bind and
dial that same numeric destination. Never substitute `127.0.0.2`, rewrite the
original destination or use Android loopback as the capture proof. The initial
Linux host driver checks the exact `/32` alias absent before setup, creates only
that alias on loopback and records creation ownership after the command succeeds.
Acceptance separately requires the exact address to be observed; failed
verification does not discard the created alias's cleanup ownership. It removes
only its owned alias after fixture/process
joins and confirms absence. A pre-existing alias, missing bind permission,
unsupported platform or failed setup is an explicit refusal, never an optional
pass. Every external setup/cleanup command has a deadline and kill-after bound.

The additive fixture profile is `tun-http-h1`, IPv4 only, on the existing clean
desktop `2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6`. Preserve all C2/C3/C4 profiles,
source pins and assertions. Use the same complete deterministic HTTP bodies,
existing trusted desktop parser and actual original-destination authorization.
Default required capabilities remain `tcp-http-origin-connect` and
`tcp-https-connect`; request exactly those during real enrollment.

Reuse the existing fixed private seed and CSR/proof/operator-approval flow in
`com.httpfreekit.interop.test`. Save/reload the credential in that UID's store and
prove its key remains nonexportable. No identity, credential, certificate, secret
or arbitrary destination is passed through service intents or diagnostics.
The service receives only an in-process fixed desktop ID and resolved numeric
gateway endpoint. Its `captureRequest` reopens the saved credential and transfers
the actual factory to `CaptureStartRequest` with only the traffic package selected.
Use the real supplied protect/bind guard; no relay or direct receiver is injected.

## Android and traffic ownership

The interop test APK owns the consent Activity and real foreground VPN service.
The service uses the shared core lifecycle and retains its factory for snapshots;
only the service closes the live factory after successful ownership transfer.
The test must not open the original flow itself, configure an HTTP proxy, bind the
traffic socket to another Network, or directly call the policy frontdoor.

Reuse the existing signature-protected TrafficClient/finite reply decoder through
one narrow shared source directory. Preserve all old command10 behavior and C1
acceptance. New command19 opens the fixed tuple, sends the descriptor's complete
request, flushes and performs actual SHUT_WR, then verifies bounded HTTP framing,
the exact response body/hash and strict EOF. Keep traffic-worker and IPC joins.
Install the existing capture-runtime main APK solely as the signature permission
owner; never start its old service. Verify all three research APK signers match.
Add only the exact traffic package query and existing control permission to the
interop manifest. No broader installed-package permission is assigned.

Require different traffic/test UIDs, real platform consent, an active native/TUN
owner, the actual ongoing notification and the traffic UID's unbound WAIT_VPN
observation. Before Stop, require the service still active with no failure,
exactly one intercepted flow and no direct/UDP flows, natural zero policy flow/
socket charges and zero factory pending/stream/byte queues. The factory's control
session remains live then; do not require all session workers to be gone early.

## Host completion barrier and evidence

The [descriptor](../tools/transport-spike/enrolled-tun-descriptor.mjs) freezes the
method, fifteen ordered phases, exact observation suffixes, bodies and report
paths. Android sends phase status under `draftTunPhase`, and its one final finite
observation uses the `draftTun` prefix. Boolean true values represent actual
observations; SessionLease is false after Stop. Version, selected-package count,
intercepted-flow count and HTTP attempts are1; guard attempts/successes are2;
other resource/failure counts are0. Body sizes/hashes must match the descriptor.
The Android observation reports the actual returned response bytes/hash only.
The host independently records actual received request bytes/hash; Android must
not label fixed request-profile constants as measured upload observations.
Command19 success establishes that its actual upload, flush, SHUT_WR and strict
response checks returned successfully; preserve the existing three-field traffic
reply. Its old CONFIGURE readiness uses the validated ephemeral gateway port
(1024..65535), which command19 never uses as its destination.

At `http-command-started` the driver starts the existing response-tail release;
the fixture still requires actual decoded/drained client END_WRITE. A control
probe may not exist yet: wait for its admission rather than rejecting legitimate
lazy startup. C5's release gate has a finite 15-second deadline; existing profiles
retain their 5-second gate. Traffic connect/read and
IPC deadlines remain unchanged. At
`local-stream-drained`, the driver independently polls the existing actual
`gatewayStreamComplete` fact and verifies exact origin/capture/body/destination
facts. Only then may it write the descriptor's fixed one-shot acknowledgment
through bounded existing `run-as` stdin. Write an absent-before-use owned private
temporary entry, finish and close the write with mode0600, then atomically rename
within that directory to the absent fixed gate. Never expose a partial final
file or replace a prior acknowledgment. Android validates the app-private
directory/file owner, no symlink, permissions and exact bounded bytes, consumes
that fixed file once, then emits `gateway-complete-acknowledged` before Stop.
Android does not fabricate a remote COMPLETE observation from local counters.

Finally require actual service lifecycle, native, policy, factory and TUN joins,
configuration removal, traffic UID WAIT_NON_VPN, traffic worker/IPC joins, and
owned credential/key/private-file removal. Failed cleanup remains failed and
owned; successful status or killed processes alone do not attest all joins.
Failure reports contain only finite phase/type/category and bounded known source
frames. The host report separately records observed COMPLETE before the
acknowledgment and actual alias/reverse/worker/process cleanup outcomes.

No runtime is dispatched by this package assignment. ADB currently has no
attached device, local emulator retries remain disallowed, and the desktop
publication approval is still pending. Prepare, compile and validate the real
components without claiming device success. Do not publish desktop code, upload
keys or create paid infrastructure. Execution requires the actual device/runner
and exact clean desktop inputs; physical USB acceptance remains independent.

## Preparation evidence

The implementation is prepared at `eea64c32352c7df3fd0bf8f28a9e1e7a0ee52cb0`.
The integrated host check passes all 179 cases with zero failures, cancellations,
skips or todo cases in 41.219 seconds, using Node 24.22.1 and explicit external
OpenSSL 3.6.1. It includes parser/report/CLI and fake-command ownership checks,
actual owned-child shell checks and existing issuer regressions. It does not
execute the C5 Android method or create a real Linux alias.

The three research APKs assemble and strict interop/runtime/traffic lint reports
contain zero issues. The 31 preserved JVM cases remain green (15 interop, 7 runtime,
9 traffic); their source bindings and original timestamps are retained rather
than relabelled as one fresh run. Independent inspection verifies the actual APK
packages, min26/target37, protected VPN service, exact traffic-control permission
and matching verified public debug signers. The original APK audit preserves its
`0e75bd4` plus dirty-manifest/test-before-commit provenance; the same manifest is
now committed as `7b52233`, and all three APK hashes remain unchanged.

A real ordinary-HTTP regression requests response release before control
admission. The old fixture fails with release already failed instead of pending;
the identical frozen test passes with the correction. The seven C3 cases plus
two mocked alias-preflight cases pass, as do all nine C2 regressions on their old
desktop pin. The frozen test SHA256 is
`576015e2dc08fa6ac67c455ab1aaed501d0ab00e972f868c4fea0abfd5d96826`.

Workflow checks cover 12 actual extracted cleanup/status combinations and four
selection/dependency checks. All 11 extracted LF shell blocks pass standalone
ShellCheck 0.11.0 and both embedded JavaScript blocks pass syntax checks. Local
actionlint 1.7.12 checks grammar/expressions with integrated ShellCheck/Pyflakes
disabled; full unsuppressed Linux actionlint remains a hosted check. The shared
Kotlin roots use the documented [variant source API](https://developer.android.com/build/migrate-to-built-in-kotlin).

The independent preparation audit SHA256 is
`96cd1f0151defa39e652c68e26798730d936fde7c80e320f5f62c5a4a62c04c0`;
the actual TAP SHA256 is
`c7cdfccd9810850a808d23f01b9bc5a06185e9af1b6d19e66223323544fa2bb1`.
Stable ignored exports live directly in `dist/`, including
`capture-enrolled-tun-preparation-validation.json` and
`capture-enrolled-tun-apk-validation.json` with checksums.

Actual C5 Android runtime remains UNRUN. The real CLI preflight retains zero
started/completed Android invocations, unsupported-Windows refusal and no alias
commands. A separate ADB inventory finds no attached devices. A GitHub read of
the exact desktop `2ee70e86` commit returns HTTP 422/commit not found. Hosted execution needs
its separately authorized publication; the earlier eight-commit fd63 question
does not cover this ten-commit input. No emulator, alias or desktop publication
was performed by this preparation package. Physical USB, Android HTTPS/H2,
production integration and v1 freeze remain open.

## Running the prepared method

Use a dedicated Linux research host, a selected API 26 or 37 device, the pinned
[developer toolchain](development.md), OpenSSL 3 and the exact clean local desktop
checkout. The driver requires the fixed alias absent and noninteractive
permission to add/remove only that alias. The three research packages must be
absent before setup. It installs and cleans up only its own research packages.

```bash
set -euo pipefail
export OPENSSL_BIN=/usr/bin/openssl # Must report OpenSSL 3.
serial='<selected ADB serial>'
desktop='<absolute path to the reviewed desktop checkout>'
api="$(adb -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r')"
started="$(date +%s)"
node tools/transport-spike/run-enrollment-runtime.mjs --suite c5 --serial "$serial" \
  --desktop-root "$desktop" --desktop-commit 2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6
node scripts/verify-enrollment-runtime.mjs --suite c5 --source "$(git rev-parse HEAD)" \
  --api "$api" --started "$started" --desktop-source 2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6
```

The manual [hosted workflow](../.github/workflows/enrollment-runtime.yml) offers
the same `c5` suite for API 26/37. It installs the pinned NDK required by the native
APK, consumes the exact authorized desktop commit and retains only the four
sanitized report files. It creates no alias outside the finite driver. A local
Linux run can consume an already reviewed local checkout without publishing it;
the hosted checkout additionally requires separate desktop publication approval.
