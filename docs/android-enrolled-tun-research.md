# Enrolled selected-UID TUN research

## Scope and ownership

C5 composes the actual Android `CaptureVpnService`, native engine, shared SOCKS
policy and saved-credential enrolled factory. It follows the verified local
[policy transport composition](capture-policy-transport-research.md). The single
initial method proves selected-UID HTTP80; HTTPS, IPv6, revocation, physical USB
and production integration remain separate requirements. Do not infer those
results from this method or freeze v1 before the remaining foundation gates.

Root owns this profile, the [finite descriptor](../tools/transport-spike/enrolled-tun-descriptor.mjs),
build/manifest integration, shared traffic-source extraction and the additive
desktop fixture profile. UI owns only new `DraftEnrolledTun` Android test/service/
consent files in the existing transport-interop research APK. D owns only the
synthetic traffic app's new finite command and focused response-reader tests,
plus the additive `startTunOrigin` operation in the existing private worker and
parent wrapper with focused tests. F owns the finite report/driver, alias and
acknowledgment ownership helpers, and hosted wiring after the C4 host audit.
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
