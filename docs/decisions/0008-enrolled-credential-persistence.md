# Public enrolled-credential persistence

Status: internal foundation implementation, starting at `4b2aaf6b144e31d78b6d63c282dd6878b0768aaa`. Host tests and Android compilation are recorded below. The new Android persistence cases have not executed on a device. This does not implement enrollment, app connection wiring, gateway endpoints or a frozen wire schema.

## Public material and validation

[AndroidEnrolledCredentialStore](../../core-security/src/main/kotlin/com/httpfreekit/security/AndroidEnrolledCredentialStore.kt) fixes its directory beneath the supplied app context's `noBackupFilesDir`, in `enrolled-credentials-v1`. Filenames are SHA-256 desktop-ID hashes. Its public constructor does not accept an arbitrary storage directory. The app-private record contains only the computer ID, logical gateway DNS name, gateway leaf certificate and SPKI pin, issued client certificate chain, and separately supplied authenticated enrollment authority. Invitations, invitation/status secrets, private keys, routes and sessions have no fields in this format. No encryption-at-rest or protection against a compromised application process is claimed for this public metadata.

[EnrolledCredentialRecord](../../core-security/src/main/kotlin/com/httpfreekit/security/EnrolledCredentialRecord.kt) takes immutable snapshots of canonical DER bytes. Public certificate/list getters return defensive material; validation and serialization use the same frozen bytes. Its internal binary format has a magic value and version 1, a 24 KiB total bound, ASCII IDs/names/pins, four client certificates at most, 4096 bytes per certificate, and the existing 16 KiB client-chain-plus-authority budget. The decoder bounds lengths/counts before allocation and rejects unknown versions, trailing bytes, malformed/noncanonical certificates and unused fields. A decoded record must match the requested desktop ID, including when a different record is copied under its hashed filename. Unsupported formats require explicit repair; there is no automatic migration or fallback parser.

`save(record)` and `load(desktopId)` each require an existing usable identity. They reapply [gateway pin/leaf validity and purpose checks](../../core-security/src/main/kotlin/com/httpfreekit/security/GatewayTrust.kt) and require an exact case-insensitive DNS SAN matching the logical name, without CN or wildcard fallback. They then use [the existing enrolled-client binding](0004-enrolled-client-credentials.md) to validate the chain, explicit authority, P-256 SPKI and live private-key possession. This checks all certificate expiry intervals, including both trust anchors. The stored authority's authenticated provenance remains a precondition of the save caller; storage cannot prove that provenance from a CA supplied beside a chain. It never infers an authority from the last chain certificate or from the interception CA.

`load` returns null only when no published record exists. Missing, replaced or [legacy](0007-keystore-tls-digests.md) keys, corrupt/expired material and gateway mismatches fail closed. It never creates, replaces or imports a key. A successful load returns the validated public snapshot and a fresh client key manager retaining that lookup's original existing signing handle. It does not replace the Keystore certificate entry. Across independent lookups Android may return different wrapper objects for the same nonexportable key, so cross-reopen object identity is not an acceptance criterion.

Public storage failures expose fixed `INVALID_CREDENTIAL` or `STORAGE_FAILURE` codes without retaining provider/certificate/I/O exception causes, whose messages could reveal names, pins, certificates or paths. Public record/result `toString` methods redact their material. The returned manager retains its existing liveness/expiry checks; callers must still use [scoped gateway TLS](0003-scoped-tls-connections.md). Previously obtained handles, established sessions, revocation and active-session expiry remain separate lifetime gates.

## Publication, races and Forget

The narrow internal `AndroidDeviceIdentityStore.withExistingIdentityTransaction` hook holds the existing process-wide identity monitor across public-record read/validation/publication or deletion. It validates the computer ID without eagerly loading a key, so an unusable legacy entry remains forgettable. All identity-store instances already use that monitor for create/load/delete. The persistence adapter never invokes creation. This is a single-process transaction; another Android process requires a stronger coordination design.

Publication writes an owned temporary file in the same directory, syncs its file descriptor, then uses `ATOMIC_MOVE` with replacement. Failure to support atomic move is an explicit storage failure, with no non-atomic fallback. An interrupted pre-publication write leaves a temporary file that is ignored by load; readers see only a complete published record. A failed replacement preserves the previous published record where the atomic filesystem operation has not succeeded. Temporary files from completed failed writes are removed; Forget also removes only that record's matching pending files and leaves unrelated files untouched.

This establishes the intended process-crash publication boundary. The parent directory is not fsynced, and there is no claim that acknowledged metadata changes survive sudden power loss or filesystem rollback. Atomicity and power-loss durability are distinct. App-private storage is the local integrity boundary; the format has no separate MAC and does not authenticate arbitrary modifications made by a compromised application process.

`forget(desktopId)` deletes the Keystore key first, then published and pending metadata under the same monitor. If key deletion fails, the metadata remains and the operation reports failure. If metadata cleanup fails after key deletion, the dangling record cannot reopen, and a later Forget safely retries even when the key is absent or legacy. Save cannot publish a usable stale record after Forget: it either finishes before key deletion, or observes the missing/replaced key and fails. Explicit creation of a replacement identity cannot make the old leaf match it. No cleanup path recreates a key or restores credentials automatically.

## Validation and limits

Reproduce the scoped host/compilation checks with JDK 17 and the documented Android SDK:

```sh
npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
./gradlew --no-daemon --console=plain :core-protocol:test \
  :core-security:testDebugUnitTest :core-security:lintDebug :core-security:assembleDebugAndroidTest
node --test scripts/tests/check-doc-links.test.mjs
node scripts/check-doc-links.mjs
git diff --check
```

Local Windows/JDK-17 validation passes 62 security JVM cases (22 new persistence cases) and all 10 protocol cases, with zero failures, errors or skips. The full command also passes strict security lint and assembles its Android test APK. After strengthening the real-monitor contention assertion, security lint and Android assembly pass again. The nine documentation-checker regressions, all 97 local links and whitespace checks pass. These checks use the existing pinned Gradle 9.8.2/AGP 9.4.1 toolchain and compile SDK 37; they execute no Android persistence test.

[Host persistence tests](../../core-security/src/test/kotlin/com/httpfreekit/security/EnrolledCredentialStoreTest.kt) exercise defensive snapshots, bounded/noncanonical decoding, identity/record mismatch, missing/replaced/legacy keys, gateway/authority/client validation and expiry, actual atomic-file replacement, interrupted temporary writes, storage redaction, both key/metadata deletion failures, recovery/idempotence, and both save/Forget race orders across instances. Their software keys are generated only at runtime in tests; they do not establish Android Keystore behavior.

Five new [Android persistence tests](../../core-security/src/androidTest/kotlin/com/httpfreekit/security/AndroidEnrolledCredentialStoreTest.kt) cover actual no-backup reopen and nonexportable signing with unchanged Keystore certificate bytes, missing/replaced/legacy keys, orphan/corrupt files, metadata-cleanup failure/recovery and serialization using the real identity monitor. Compilation is not device execution. An actual API 26/37 run must execute these five methods together with the existing seven identity/client cases, with no failures, errors or skips, before Android persistence is accepted. Physical-device behavior, authenticated enrollment/CA provenance, production migration/renewal, multi-process coordination and capture remain open.
