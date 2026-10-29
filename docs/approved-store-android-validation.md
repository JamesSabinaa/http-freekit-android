# Real Android approved-store lifecycle validation (B8)

Status: scoped 29 October 2026 against B7 source `fdd00f8`. B7 host40843095033
is still running; B7 runtime acceptance remains separate. This is test-only work,
not production authenticated enrollment or app integration. The existing
[B7 profile](approved-credential-persistence.md) and draft [protocol](protocol.md)
keep their meanings. No production API, dependency, build or workflow edit is
assigned. Local Java/SDK absence remains explicit.

## Frozen test package

One owner adds ONLY
`core-security/src/androidTest/kotlin/com/httpfreekit/security/AndroidApprovedEnrolledCredentialStoreTest.kt`.
Use package `com.httpfreekit.security` and exactly these six methods:

1. `reopenedApprovalUsesOriginalNonexportableKeyAndPreservesOriginalEvidence`:
   use the public context constructor, real owned Keystore identity and real files.
   Save, reopen fresh store/identity instances, compare the complete encoded
   envelope/approval, verify the returned issued client chain and a real challenge
   signature, and require privateKey.encoded null. Compare original public chain
   DER hashes before/after; original evidence is distinct from the issued leaf.
   Verify the hashed record in noBackupFilesDir/approved-enrolled-credentials-v1.
2. `issuedChainCannotSubstituteForOriginalApprovalEvidence`: otherwise valid
   envelope with issued-leaf hash substituted for original-chain evidence must fail
   save INVALID_CREDENTIAL without first publication or key replacement. Alter an
   existing valid saved envelope to the same mismatch; reopen/load must reject.
3. `missingReplacedAndExpiredIdentityStatesFailClosedWithoutRepair`: separate
   deleted-key, explicitly replaced-key and injected-clock leaf-expiry cases. Load
   fails INVALID_CREDENTIAL and never repairs/replaces keys; expired save rejects.
   Retained key managers cannot select deleted/replaced identities. Use fixed
   Instants and public Clock injection, not device clock changes or sleeps.
4. `corruptEnvelopeAndInterruptedPendingCannotReplacePublishedApproval`: actual
   files with orphan pending do not displace a complete published generation.
   Truncated/oversized published envelopes reject without key changes. Restore
   exact bytes and reopen successfully; Forget removes owned pending files.
   This is pending simulation, not a real crash or power-loss test.
5. `legacyNeverSynthesizesApprovalAndForgetInvalidatesOnlyItsSharedIdentity`:
   generic-only record yields approved load null; explicit combined approval may
   later save against that same key. Approved Forget removes shared key/new
   metadata; leftover generic metadata cannot load. Repeat Forget, while a second
   computer's key and approved envelope remain usable. Clean generic metadata too.
6. `metadataCleanupFailureDeletesKeyFirstAndCanBeRetried`: inject only file-delete
   failure through the existing internal constructor/backend interfaces while
   using a real identity and actual bounded atomic files. Assert key absent before
   failing delete, STORAGE_FAILURE with redacted/cause-free error, unusable leftover
   metadata, and successful normal public-store retry after key deletion.

Reuse existing sharedTest TestEnrollmentCertificates server/authority/client
builders and Android credential/evidence tests' owned-ID cleanup patterns. Small
private helpers belong in the new file; do not move/copy the software fake JVM
fixture wholesale. Build synthetic approval from actual original SPKI/ordered DER
hashes, actual issued leaf/authority hashes and exact leaf expiry, canonical pin,
finite IDs/capabilities and a synthetic interception-CA digest. This assumes the
caller previously authenticated approval; it does not prove that precondition.
The CA digest is not CA profile/trust evidence.

For failure injection, test-local ApprovedCredentialIdentities delegates all
transaction/load/delete/originalCertificateChain operations to the real
AndroidDeviceIdentityStore. Wrap real AtomicCredentialRecordFiles(directory,
32768), overriding only the requested failing delete. Do not introduce production
seams. Report any API defect to root rather than changing another owner's files.

Use fresh per-test UUID computer IDs and finally cleanup that attempts every owned
key/file even after prior cleanup failure, then fails with fixed redacted text.
No alias scan/derivation, shell, network, permissions, clock mutation, inventory,
provider text or secret/material logging. No weakened assertions or ignored cleanup.
No duplicated exhaustive JVM codec/race suite. No unbounded waits.

## Frozen verifier package

A distinct owner edits ONLY `scripts/verify-keystore-results.py` and
`scripts/tests/test_keystore_results.py`. Preserve all fifteen existing exact
methods/four suites and add the six above, requiring exactly21 methods/five suites
once each. Retain strict bounded XML, structure/nesting/counter/zero-failure gates.
Regress old-fifteen-only, each missing/duplicate new method, each new failure/error/
skip, wrong suite and counter mismatches. Synthetic fixtures are not device proof.
No workflow edits or dispatch belongs to this owner.

## Coordination and acceptance

Root owns this profile, board/roadmap/validation, integration, independent reviews,
host/runtime dispatch, original evidence replay and main promotion. Claims and
unique owners live on the [work board](../tasks/README.md). Implementations may be
authored while B7 runs, but must not change the exact B7 runtime source or verifier
in place. Preserve B7's fifteen-case gate for that checkpoint.

Require independent exact-source review, fresh full pinned host JVM/build/
instrumentation-compilation/lint and every existing regression, then fresh
same-source API26/37 Keystore matrix. Existing unfiltered connectedDebugAndroidTest
and bounded emulator cleanup apply unchanged. Independently replay original XML
for all21 methods/five suites and source/API-bound truthful cleanup on both APIs
in one attempt. Never combine partial passes across runs or infer execution from
compilation. Deliver audit/checksum metadata directly in ignored dist with stable
filenames; never commit artifacts/keys/local SDK paths.

Fresh-instance reopen is not Android process death. This scope proves no current
registry authorization, authenticated approval provenance, downloaded CA profile
or trust, renewal, production pairing/capture, app readiness, v1 freeze, desktop
C5 or physical USB. Those remaining gates stay open.
