# Android Keystore digest authorization for TLS

Status: compatibility correction with host checks and instrumentation compilation. Actual Android TLS execution remains pending; the earlier failure may have an additional fixture cause. This change does not establish capture or freeze the protocol.

The first enrolled-client instrumentation run reached the real TLS handshake and failed on both API 26 and API 37. The three original identity cases and deletion/recreation case passed. Its client read-abort exception hid the server's diagnostic. The test now preserves both peers' failures, labels the attempted protocol, and bounds the server-result wait; cleanup failures cannot replace the original error. Neither TLS versions nor identity assertions are relaxed.

Separately, primary sources establish a compatibility mismatch: the original identity policy authorized only SHA-256, while Conscrypt's delegated EC signing path uses `NONEwithECDSA` to sign a transcript digest already computed by TLS. Android explicitly documents that private keys used by TLS normally need `DIGEST_NONE` authorization. See [Android KeyGenParameterSpec.Builder.setDigests](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setDigests(java.lang.String...)) and [Conscrypt CryptoUpcalls](https://github.com/google/conscrypt/blob/master/common/src/main/java/org/conscrypt/CryptoUpcalls.java). This explains why successful SHA256withECDSA enrollment/challenge signing alone cannot prove TLS usability; the precise cause of the observed run still requires its improved diagnostics and another Android execution.

New identities authorize exactly `DIGEST_NONE` and `DIGEST_SHA256`, retain P-256 and SIGN/VERIFY purposes, and remain nonexportable Android Keystore keys. Enrollment requests and bounded application challenges continue to use `SHA256withECDSA`. Authorizing NONE does not disable TLS hashing or change certificate verification: TLS performs hashing before the delegated signature.

This is a broader signing capability than a SHA-256-only key. Trusted code holding the standard key-manager/private-key handle can request a raw prehashed EC signature; the handle is not a TLS-only sandbox. Keep it scoped to the intended computer and trusted application components. No application API for arbitrary raw signatures is added. The existing key manager remains a trusted signing-handle capability, as described in [decision 0004](0004-enrolled-client-credentials.md).

`AndroidDeviceIdentityStore.load` retrieves Android Keystore `KeyInfo` and requires both digest authorizations. If metadata cannot be read, or an older key lacks the required capability, loading fails explicitly with a message ending in “pair again”. It never deletes, replaces, reimports, or silently regenerates that key. Existing computer identities keep their alias/public key/certificate until the user explicitly forgets and pairs again. A missing key still returns null. There is no in-place permission migration or durable credential recovery claim.

Two new Android identity cases compile:

- `freshIdentityAuthorizesPrehashedTlsSigningWithoutExportingItsKey` inspects the exact authorization set, signs a controlled SHA-256 digest with NONEwithECDSA, verifies against the original message using SHA256withECDSA, and rechecks nonexportability/reopen identity.
- `legacySha256OnlyIdentityRequiresPairingAgainWithoutReplacement` installs a SHA-256-only key under only its own fixture identity, requires explicit rejection from two store instances, rejects implicit creation over it, and verifies the original public key/certificate chain remains unchanged.

The existing real TLS 1.2/1.3-as-supported test remains intact, with the new two-peer failure diagnostics. Seven total `core-security` instrumentation methods now compile; compilation does not demonstrate that any new case executes successfully. Reproduce host/compilation checks with:

```sh
npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
./gradlew :core-security:testDebugUnitTest :core-security:lintDebug :core-security:assembleDebugAndroidTest
```

An actual device run must execute all seven methods with zero failures/errors/skips and retain exact commit/API evidence. The separate [Android-to-Node research proof](0006-android-node-interop.md) remains another runtime gate. Hardware backing, physical-phone behavior, active-session expiry/revocation, production enrollment/persistence, and VPN/proxy delivery remain unverified by this correction.
