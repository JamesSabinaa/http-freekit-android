# Approved public interception-CA preparation (B9)

Status: library host ACCEPTED at exact `b835bc3561be8d0444e5a68571805ad8d6434691`,
run41856346443 attempt1. Independent original XML/API-log replay verifies all35
new methods once,487 JVM methods/53 XMLs/zero failure-error-skip, all46 B7 methods,
research CA binding/client/TLS suites7/7/6, nine clean lints,46 CA receipts/all joins,
security/interop instrumentation compilation,16 Lifecycle2.11.0 selections and
all retained host assertions. Native original replay verifies39 Python tests and
four IPv4/IPv6 HTTP/CONNECT flows, complete bytes/half-close/gated streaming.
Original `/tmp/b9-host-accepted.NyfKX6`; trusted `/tmp/audit-b9-host.py`; stable ignored
`dist/approved-ca-preparation-host-audit.json` SHA256
`cbb020a8695df3ccc719b8910af871a1f6103789ba8f7fd7b75900546001137f`.
An incorrect planned client-suite count1 caused initial audit rejection; checked
source and XML establish7, now required by exact method manifest. No host gate
removed or run retried. Checked main promotion is ready. No new Android execution,
production integration or wire contract claim; local Java/SDK remain unavailable.

Implementation owner557340c integrated65c6143; independent exact profile/security
reviews found no concrete defect. Independent35-method tests47ab322 integrated
80f270f; confirmed snapshot-assertion gap corrected57c561a ->e1885a5 and independently
re-reviewed with no remaining concrete defect. Provider identity is not promised;
mutation isolation assertions execute successfully in the accepted hosted JVM.

Depends on checked B8 milestone `4e9a4f5`, independently verified on published main.
The [B7 envelope](approved-credential-persistence.md) retains an authenticated-caller
CA digest commitment; it deliberately does not validate supplied CA bytes. Existing
strict CA validation lives in research source roots, not a public core-security API.
This package composes that commitment with caller-supplied public DER only.

## Frozen public boundary

Add to package `com.httpfreekit.security`:

```kotlin
object ApprovedInterceptionCaPreparation {
    fun prepare(
        loaded: LoadedApprovedEnrolledCredential,
        certificateDer: ByteArray,
        clock: Clock = Clock.systemUTC(),
    ): ApprovedInterceptionCa
}

class ApprovedInterceptionCa internal constructor(/* validated public snapshot */) {
    val certificateDer: ByteArray
    val certificateSha256: ByteArray
    val certificate: X509Certificate
}
```

Every returned byte array and certificate is a defensive snapshot; fixed redacted
`toString`. The certificate getter reparses retained copied DER, but distinct
certificate object identity is not promised: providers may intern immutable
certificates. Mutation of returned DER/hash/encoded/signature arrays or mutable
Date values must not alter retained material or subsequent getter observations.
Reject invalid input with fresh cause-free
`IllegalArgumentException("Invalid approved interception CA")`, without provider
text, identifying material, paths or nested exceptions. Take one injected time
observation per preparation. No network, files, trust-store mutation or key-manager
calls. The loaded object's approval is the ONLY expected CA digest; no independent
fingerprint/header argument or synthesized research recovery record.

Validate the bounded copied bytes against that exact SHA-256 commitment and the
existing research CA profile, adapting project-authored MIT code narrowly:
`DraftInterceptionCaDer.requireCanonical`, `DraftInterceptionCaChecks.certificate`
and the CA-only portion of `DraftInterceptionCaBinding.bind`. Preserve canonical
single DER certificate/no trailing bytes, 1..4096 bytes, self-issued/self-signed CA,
nonempty current validity, keyCertSign if KU exists, exactly serverAuth if EKU
exists, P-256 or RSA 2048..4096. Do not introduce a different CA profile or weaken
research checks. Existing research source remains unchanged in this package.

Recheck validity of the saved gateway, enrollment authority and every issued-chain
certificate at the same injected instant. Reject mathematical public-key reuse with
gateway, enrollment authority, original-device SPKI and every issued-chain key,
including equivalent parameter encodings. Reuse B7's existing `samePublicKey`
comparison by changing ONLY its visibility from private to internal; do not alter
its behavior. Internal bounded CA DER/profile helpers belong in new files only.

A retained loaded snapshot does NOT revalidate live key possession, Forget,
revocation or registry authorization. B7 retains hashes, not every original-chain
certificate: this loaded-only API cannot repeat research's additional comparisons
against other original-chain public keys. Document that limit, not a stronger
separation claim. Construction/loading does not authenticate approval provenance.

## Exclusive packages and acceptance

Root owns this profile, board/roadmap/validation/resume, integration, hosted checks,
evidence replay and checked main promotion. Each agent uses a separate branch and
worktree; unique names/IDs are recorded on the [board](../tasks/README.md).

- B9-I: new `ApprovedInterceptionCa.kt`, `InterceptionCaValidation.kt` and, if needed,
  `InterceptionCaDer.kt` under core-security main. Existing
  `ApprovedEnrolledCredentialRecord.kt`: ONLY helper visibility change above.
- B9-T: new `ApprovedInterceptionCaTest.kt` and optionally
  `ApprovedInterceptionCaTestFixture.kt` under core-security test. Independent
  fixtures, tests against the frozen public API, no production edits.
- B9-R: read-only profile/research-equivalence review, then exact implementation.
- B9-S: read-only snapshot, redaction, expiry and mathematical-key separation review.
- B9-V: read-only validation-gate/evidence planning; no workflow/dispatcher edits.

Independent JVM tests must exercise valid distinct P-256 and RSA CA; wrong approved
digest; malformed/trailing/oversize/noncanonical DER even under its approved hash;
expired/future CA and stale saved gateway/authority/client using fixed clocks;
wrong role/signature/KU/EKU/curve/RSA size; otherwise valid CA certificates reusing
each forbidden owner's key; defensive arrays/certificate snapshots, redacted
cause-free errors and no key-manager invocation. Reuse existing test builders
where practical; additions specific to this profile stay in the owned new fixture.
Do not weaken old tests or infer Android Keystore behavior from software fixtures.

Require independent exact-source implementation/test reviews, existing B7/B8 and
research CA regressions, fresh full pinned host JVM/build/instrumentation compilation/
strict lint and every retained baseline gate. Local Java/SDK absence stays explicit.
This pure library package does not require a new emulator matrix to claim its JVM
behavior; B8's exact-source runtime acceptance remains separate evidence. No build
outputs committed. Audits/checksums belong directly in ignored dist with stable names.

## Explicit exclusions

No authenticated enrollment or CA fetching, production wire/app/UI/service/capture
integration, trust/readiness/install state, CA installation, renewal, live registry
or key validation, protocol freeze, desktop C5 or physical USB. No global TLS
changes, secrets/logging, signing uploads, deployment or paid infrastructure.
The original full implementation plan remains incomplete.
