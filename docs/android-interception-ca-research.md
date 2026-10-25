# Android saved-credential public CA research

Status: A23b implementation assignment, no Android execution claimed. This adds
an actual API 26/37 check of the [authenticated public-CA getter](protocol-interception-ca.md).
The checked software-key host proof remains a prerequisite for dispatch. This
suite uses the existing reference enrollment gateway and needs no desktop
checkout, Linux alias or production app wiring.

## Ownership and sequence

Root owns this profile, the [finite descriptor](../tools/transport-spike/interception-ca-runtime-descriptor.mjs),
shared build/manifest integration, work board and hosted workflow selection.
After the current getter follow-up, UI owns only the new Android
`DraftInterceptionCaInteropTest.kt`. D owns the additive zero-argument private
worker evidence operation, its wrapper/tests and the narrow reference-fixture
evidence method. After that checked handoff, D also owns the new finite CA
observation decoder, the additive shared-parser `a23` case and focused parser
tests. F first completes the actual A23 JVM-to-Node proof, then owns the combined
three-invocation Android report/driver, independent verifier and their tests.
Agents use separate branches/worktrees and leave existing A22 methods unchanged.

Use one fresh owned API 26 or 37 runtime, one actual Android Keystore identity,
one reference enrollment and these three real instrumentation invocations:

1. Existing `DraftEnrollmentInteropTest#prepareApprovedCredentialForRestart`.
   Preserve its real CSR, pending proof, host-only approval, deliberate lost
   response, fresh-proof recovery and saved credential. The host then observes
   package force-stop, actual process absence and joined worker shutdown, and
   reopens the same gateway identity, ports, registry and approved result.
2. New `DraftInterceptionCaInteropTest#retrieveSavedApprovedCaAfterRestart`.
   Read the existing private recovery record and open
   `DraftInterceptionCaSavedCredential` against the resolved reversed credential
   port. Execute the same compiled getter, compare its actual DER hash against
   saved approval, and close/join it. Reopen the existing key/record evidence
   afterward without generating a key or issuing another network request.
3. Existing `DraftEnrollmentInteropTest#reopenApprovedCredentialAfterRestart`.
   Preserve its independent fresh proof, exact result/mTLS checks and Forget.
   It remains the owner of final key/credential/recovery removal.

Require all three starts/completions in this order, with every original A22
phase and assertion intact. Do not assemble acceptance from separate runs or
replace Android enrollment with host-generated device keys/software CSR enrollment.

## Android observations

The new method emits only three ordered `draftCaPhase` values from the descriptor:
`saved-key-approval-validated`, `ca-fetched-and-bound`, then
`getter-resources-joined`. Its final `draftCa` observation has exactly the
descriptor's seventeen suffixes. Version and FetchAttempts are1; CaBytes is the
actual returned DER size in 1..4096. The seven saved-key/binding/continuity facts
and Closed are true; ActiveCall, RawSocketOwned, TlsSocketOwned, DeadlineAlive,
TlsCloserAlive and CleanupFailed are false.

FetchAttempts increments when the real getter is called. Binding facts require
the actual returned certificate/hash and validated saved approval. Original-key
and leaf facts compare the existing owners before/after; the original Keystore
chain must never be replaced by the issued client chain. Both saved-credential
lookups must check nonexportability and saved recovery context. Compare canonical
recovery bytes before/after. The second lookup must close without a fetch.
Snapshots attest actual client cleanup; a requested close alone is insufficient.

No certificate, fingerprint, key, desktop/device identifier, URL, search text or
free-form provider message enters instrumentation output or intents. Use fixed
failure categories and the same bounded known-source-frame approach as the other
research suites. The new method creates no extra private witness file or trust
record. It installs no CA and leaves Forget to the existing final method.

## Independent host evidence

Add only `interceptionCaEvidence` with exactly empty arguments to the existing
private enrollment worker/wrapper. It is available for the active plain HTTPS
fixture used by this suite. It reads the already owned public CA through the
fresh validated asset getter and returns only actual `certificateBytes` and
complete-DER `certificateSha256` through private RPC. No path, certificate, key,
new listener, issuer or operator endpoint is exposed. Existing snapshot and
metadata schemas, worker operations and admission/cleanup owners stay intact.

Before shutdown and after same-port worker reopen, the driver checks this
actual evidence against the corresponding approved result and retained metadata.
Require unchanged approved digest and equal actual byte counts. The new Android
CaBytes observation must equal that owned asset size. The new CA evidence
publishes only finite booleans/counts; its private digest values stay in memory.
Preserve all original approval-drop, process, identity, port, clock, command and
selective-cleanup evidence. The new getter is accepted only alongside the same
run's successful original prepare and reopen/Forget invocations.

## Driver, reports and runtime gate

Add finite `--suite a23` routing to the existing enrollment CLI and independent
verifier. Reject desktop arguments for this suite. Reuse the current owned host,
private seed input, two absent-before-use ADB reverses, operator approval,
force-stop/restart and cleanup helpers. Preserve all old suite choices, defaults,
source pins and report paths. A failure remains failed even when cleanup passes;
unavailable devices produce truthful zero-start reports.

The descriptor fixes four distinct sanitized report paths. The new report must
verify exact source/API/freshness, three actual invocations and their phases,
seventeen CA facts, current owned public-asset evidence and all existing A22
approval/restart/cleanup gates. JSON/XML/HTML and the host-cleanup gate must agree.
Hostile parser, missing/duplicate/late observation and ownership tests precede a
runtime. Ordinary host CI compiles the new method and tests guards only.

The hosted enrollment workflow's `a23` choice uses its existing fresh API 26/37
images, pinned toolchain, strict bounded clock setup and actual retained emulator
termination/join. It performs no desktop checkout or alias setup. On API 37, the
owned research package must declare `ACCESS_LOCAL_NETWORK`; after installing that
package, the driver grants the permission only to its exact package in User 0 and
requires a bounded exact-package readback before the three invocations. This is
an explicit fixture permission setup (`owned_ci_grant`), not proof that loopback
is exempt. API 26 requires no such grant (`not_required`) and records null grant
command observations. Dispatch waits for checked source, the actual A23 host
proof, APK/strict lint and finite verifier checks; no local Windows emulator
retry is assigned.

This establishes saved Android Keystore/pinned-mTLS/public-CA retrieval evidence
only when actually executed and independently verified. CA installation, target
app trust, production approval persistence/migration, real TUN/selected-UID
capture, HTTPS/H2, physical USB and protocol v1 freeze remain separate gates.
