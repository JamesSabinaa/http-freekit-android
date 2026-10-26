# Approval-bound local credential persistence (B7)

Status: main code is implemented locally after accepted [B6](selected-app-preflight.md),
not host/runtime validated. Model/codec owner `4558923` is integrated `fffd98e`;
identity/validator owner `a893faf` is integrated `12a0629`; store owner `febe5bb` is
integrated `d944baf`. Independent contract and all M/I/S implementation reviews found
no concrete defect; independent test authoring is active. Local Java/SDK are
absent: no compilation/JVM/lint/runtime claim.
This is an opt-in core-security library increment, not app wiring,
authenticated enrollment implementation, production wire integration or v1 freeze.
[Protocol](protocol.md) remains canonical and draft. Existing generic credential
records and research recovery formats keep their current meaning.

## Trust and legacy boundary

The caller must already have authenticated and validated the approved enrollment
response and its setup/request context. Constructing or decoding the new approval
snapshot does NOT authenticate its provenance. Storage cannot recover that fact
from arbitrary bytes, a legacy credential, or a fetched CA. No production caller
is added. No draft research dependency is introduced into core-security.

Current `EnrolledCredentialRecord`/FKCR v1 lacks the approved interception-CA hash
and grant/owner evidence. A separate research recovery sidecar can disagree with
it. B7 stores one combined public-material envelope in one atomic generation.
Legacy data never synthesizes approval: explicit repair/re-pair is required. No
automatic migration, sidecar merge, CA adoption, renewal or identity replacement.

## Frozen model/API package

Add in `com.httpfreekit.security`:

```kotlin
class AuthenticatedEnrollmentApproval(
    desktopId: String,
    logicalServerName: String,
    gatewaySpkiSha256: String,
    enrollmentId: String,
    deviceId: String,
    originalDeviceSpki: ByteArray,
    originalKeystoreCertificateHashes: List<ByteArray>,
    clientCertificateSha256: ByteArray,
    authorityCertificateSha256: ByteArray,
    interceptionCaCertificateSha256: ByteArray,
    capabilities: List<String>,
    credentialExpiresAtMillis: Long,
)
class ApprovedEnrolledCredentialRecord(
    val credential: EnrolledCredentialRecord,
    val approval: AuthenticatedEnrollmentApproval,
)
internal object ApprovedEnrolledCredentialCodec {
    const val MAX_RECORD_BYTES = 32768
    fun encode(record: ApprovedEnrolledCredentialRecord): ByteArray
    fun decode(encoded: ByteArray): ApprovedEnrolledCredentialRecord
}
```

Approval getters have exactly the constructor parameter names/types. Snapshot
all binary/collection inputs defensively, including bounded iteration rather than
trusting caller collection size; binary getters return fresh copies, collection
getters cannot mutate retained state. All new public material/result toString
methods redact identifiers, hashes, capabilities and certificates. Model/codec
errors are fixed/redacted without provider/caller exception causes; fatal JVM
Errors are not converted into success or finite recoverable failures.

Bounds: desktop/enrollment/device IDs each `[A-Za-z0-9_-]{1,128}` (local storage
bounds, not a change to wire identifier syntax); logical name uses the existing
1..253 ASCII/SNI rule; pin is canonical unpadded base64url of exactly32 bytes.
Original device SPKI is exactly91 canonical DER bytes decoding to P-256 EC,
matching the existing identity profile. Each hash is exactly32 bytes; original
chain hash count1..4. Capabilities are unique1..16 strings matching
`[a-z][a-z0-9-]{0,31}`, exposed in deterministic sorted order. Expiry is positive
Unix milliseconds; actual leaf expiry must match exactly. No setup ports,
invitation secrets/challenges or reservation/result deadlines are retained.
Historical setup TTLs must not expire an otherwise active credential.

Combined record construction/decoding must reject mismatches between approval
and credential desktop/name/pin, actual gateway SPKI, leaf SPKI, exact leaf DER
hash, exact authenticated-authority DER hash and leaf expiry. Require distinct
gateway/enrollment-authority/device public keys. Clock/key-dependent validation
also runs on save/load below. A CA hash alone does not prove CA profile/key
separation: eventual supplied CA DER needs separate exact-hash/profile/validity/
key-separation checks. No CA material is fetched or installed here.

### Local binary format (not wire)

All integers are big endian. A blob is a signed int length followed by bytes,
validated before allocation. ASCII fields are blobs with strict printable ASCII.
Exact order: magic int `0x464b4152` (FKAR), version int1, legacy credential blob
(maximum existing FKCR limit), approval desktop/name/pin/enrollment/device ASCII
blobs, original SPKI blob, original-chain hash count int then each hash blob,
client/authority/interception-CA hash blobs, capability count int then ASCII
capability blobs, expiry long. Reject unknown magic/version, zero/negative or
oversize lengths/counts, truncation, malformed/canonicality failures and trailing
bytes. The new format does not reinterpret legacy FKCR v1.

## Frozen identity/validation/backend package

Only this owner edits existing `AndroidDeviceIdentityStore.kt` and
`AndroidEnrolledCredentialStore.kt`. Add public
`AndroidDeviceIdentityStore.originalCertificateChain(desktopId: String): List<X509Certificate>?`.
It reads ONLY the existing owned alias under the existing transaction lock,
returns defensive original Keystore-chain public evidence (1..4, each<=4096 bytes,
total<=16384), verifies the first key matches the current loaded identity, and
never scans aliases, creates/replaces keys or substitutes the issued client chain.
Null means genuinely absent owned identity. Invalid state/provider failures must
be fixed/redacted and must not reveal provider text/causes.

Extract existing credential checks, unchanged, into new internal
`EnrolledCredentialValidation.validate(record: EnrolledCredentialRecord,
identity: DeviceIdentity, clock: Clock): X509ExtendedKeyManager`. Generic store
loads the existing identity, then delegates instead of duplicating validation.
Its legacy namespace, format, failures, ownership and behavior stay unchanged.
The new validator retains gateway pin/SAN/validity and full enrolled-chain/key
binding/possession checks; no TLS or trust settings change.

Parameterize `AtomicCredentialRecordFiles` with an internal second constructor
parameter `maximumRecordBytes: Int = EnrolledCredentialCodec.MAX_RECORD_BYTES`.
Require the configured bound in1..32768. Use that bound for both read and publish;
retain same-directory sync/atomic-move/no-fallback and current pending cleanup.
Generic-store default stays unchanged. No power-loss/directory-fsync or multi-
process guarantee is added by this package.

## Frozen store package

Add `AndroidApprovedEnrolledCredentialStore.kt`, containing:

```kotlin
internal interface ApprovedCredentialIdentities : ExistingCredentialIdentities {
    fun originalCertificateChain(desktopId: String): List<X509Certificate>?
}
class LoadedApprovedEnrolledCredential internal constructor(
    val record: ApprovedEnrolledCredentialRecord,
    val clientKeyManager: X509ExtendedKeyManager,
)
class AndroidApprovedEnrolledCredentialStore internal constructor(
    identities: ApprovedCredentialIdentities,
    files: CredentialRecordFiles,
    clock: Clock = Clock.systemUTC(),
) {
    constructor(context: Context, clock: Clock = Clock.systemUTC())
    fun save(record: ApprovedEnrolledCredentialRecord)
    fun load(desktopId: String): LoadedApprovedEnrolledCredential?
    fun forget(desktopId: String)
}
```

Use new app-private no-backup directory `approved-enrolled-credentials-v1` and
existing hashed-desktop `.credential` filename rule, with configured32768-byte
backend. Keep new interface/backend adapters internal; no new dependencies.

Save/load run under ONE existing identity transaction; no nested public stores.
Load current identity, apply shared credential validator, compare exact original
SPKI and original chain DER hashes to saved approval, and retain current chain/
key/expiry checks every time. One complete envelope is published atomically only
after validation. Null is only genuinely absent NEW record; old store contents
are never read/merged. Malformed/mixed/replaced/expired/missing-key states fail
closed using existing finite `EnrolledCredentialUnavailableException` and enum
(no provider/cause/identifier disclosure). Save invalid input=>INVALID_CREDENTIAL;
publication failure=>STORAGE_FAILURE; unusable load=>INVALID_CREDENTIAL.

Forget is explicitly computer-identity Forget: under the same transaction delete
the shared key FIRST, then new metadata/pending files. It invalidates generic
records for that desktop too; leftover legacy metadata cannot revive a deleted
key. Metadata cleanup failure is STORAGE_FAILURE and retry remains possible even
when the key is already absent. Do not delete unrelated computer records. No
registry authorization, automatic renewal or future network readiness follows
from successful load.

## Focused original-alias Android validation extension

Root assigns two additional nonoverlapping validation packages so the new public
owned-alias evidence method can be exercised rather than merely compiled. This
adds no production behavior or wire contract. Add ONLY new instrumentation class
`com.httpfreekit.security.AndroidOriginalDeviceEvidenceTest` with exactly:

- `originalPublicEvidenceSurvivesReopenAndCopiesCannotMutateIt`
- `absentAndDeletedIdentityEvidenceNeverCreatesOrReplacesAKey`
- `evidenceRemainsBoundToTheRequestedComputer`

Use real AndroidDeviceIdentityStore and originalCertificateChain, fresh owned test
desktop IDs, real sign/verify/reopen checks and defensive public-chain comparisons.
No alias scan/alias derivation, issued-chain substitution, shell, permissions,
network or provider-text logging. Always delete every owned test key in finally;
cleanup failures must not be silently ignored. These tests do not prove the full
approved-store Android lifecycle or authenticated provenance.

The separate verifier owner edits only `scripts/verify-keystore-results.py` and
`scripts/tests/test_keystore_results.py`: retain every old exact twelve case,
add the three exact methods above (four suites/fifteen cases), and regress
original-twelve-only/missing/new-duplicate/new-failure/new-skip refusal without
weakening structure/counters or old cases. Existing manual keystore workflow
already runs all core-security instrumentation and this verifier; no workflow
change or automatic dispatch is assigned. Synthetic verifier fixtures are not
runtime evidence. Root requires review and fresh pinned full host before a fresh
API26/37 matrix, then independent original XML/log/cleanup evidence inspection.

## Unique ownership and validation

Root owns profile, board, docs/build/CI/integration and main promotion. Model owner
adds only the two model main files (`AuthenticatedEnrollmentApproval.kt` and
`ApprovedEnrolledCredentialRecord.kt`, codec in latter). Identity/validator owner
owns the two existing main files above plus new `EnrolledCredentialValidation.kt`.
Store owner adds only the new store file. Independent test owner adds only NEW
`AuthenticatedEnrollmentApprovalTest.kt`, `ApprovedEnrolledCredentialCodecTest.kt`,
`ApprovedEnrolledCredentialStoreTest.kt` and optional `ApprovedCredentialTestFixture.kt`
in existing core-security JVM test package; no existing fixture/test edits.
Contract reviewer is read-only. Shared signatures above let these owners execute
in parallel; each must report dependent API defects instead of editing others'
files. No owner changes research, app, wire, manifests, build files or docs.

Tests cover defensive snapshots/redaction/bounds/canonical format; every owner/
name/pin/SPKI/hash/expiry/key substitution; original versus issued chain; unchanged
legacy behavior/no approval synthesis; key replacement/missing/expiry; complete
prior generation retained on interrupted replacement; mixed envelope rejection;
both serialized save/Forget orders; key-delete/metadata cleanup failures/retry;
and safe bounded atomic backend. Add meaningful adversarial mutations, not just
round trips. Existing generic store/TLS/chain tests remain mandatory regressions.
Local Java/SDK are absent; do not claim local Kotlin/lint/device execution. Require
independent implementation review and fresh pinned full host/build/JVM/lint and
all old gates before checked main promotion. Original-alias Android execution is
separately gated; host compilation is not device execution. No app capture,
production authenticated approval, C5/USB, renewed credential or freeze claim.
