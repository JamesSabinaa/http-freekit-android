# Enrolled client certificate binding

Status: foundation credential implementation and host interoperability proof. There are no production enrollment endpoints, durable certificate storage, app connection wiring, or frozen wire schemas in this checkpoint.

`DeviceIdentity.bindEnrolledClientCertificate` validates an issued client chain and returns one scoped X509ExtendedKeyManager using that identity's original signing handle. It does not export/import the device private key, generate a replacement identity, or modify an Android Keystore certificate entry. The explicit enrollment authority must already be authenticated for the intended computer; a CA merely received beside an untrusted chain is not a trust bootstrap. It is separate from both the gateway TLS leaf and interception CA described in [the security model](../security.md).

## Validation boundary

The binding snapshots at most four input certificates with bounded iteration, even if a collection misreports its size. Each canonical DER certificate is limited to 4096 bytes, with a 16 KiB budget covering all supplied certificate encodings plus the explicit authority. Trailing data, multiple encodings, duplicates, incorrect ordering, unused extra certificates, and unsupported self-issued path certificates are rejected. An optional final root must be byte-identical to the explicit authority; it is removed from the chain sent by TLS. Inputs are reparsed into private platform certificate snapshots, and getters return fresh arrays.

The leaf must match the device SPKI exactly and use full P-256 parameters. It must be a non-CA certificate with explicit clientAuth-only EKU and digitalSignature usage, without CA signing bits. The binding also signs and verifies a fresh bounded challenge, proving that the original private-key handle matches the certified public key. The key manager offers only EC client aliases, compares acceptable CA names as canonical X500Principal values, and overrides both socket and engine selection. Null or empty issuer hints are permitted; nonmatching hints and all server aliases are rejected.

The ordered leaf/intermediate path is validated by platform PKIX against a singleton explicit trust anchor, without a path builder or default system trust. The anchor is excluded from the CertPath. All certificate validity intervals, including the anchor's, are checked explicitly. The dedicated authority currently requires a self-signed CA certificate with keyCertSign usage. Its path-length limit is checked separately because anchor constraints are outside normal path processing. Unhandled critical anchor extensions and unsupported name/policy constraint extensions are rejected; PKIX checks intermediate path constraints and critical extensions. These profile choices do not freeze the enrollment schema or CA algorithm/renewal policy.

PKIX revocation lookup is explicitly disabled for this local binding operation. There is no CRL/OCSP implementation or revocation claim. The planned desktop registry must still authorize every device and close revoked sessions; a valid certificate path alone does not authorize capture. [PKIXParameters](https://developer.android.com/reference/java/security/cert/PKIXParameters) documents the per-validation revocation setting.

## Key lifetime and scope

AndroidDeviceIdentityStore attaches a live availability check to every loaded identity. Under the existing process-wide lock it reads only the existing entry and compares its public SPKI with the identity's frozen SPKI. Absence, replacement, or lookup failure denies use; it never calls creation or substitutes the current entry's private key. Enrollment requests and challenge signing also fail explicitly when that identity is unavailable.

Every client alias selection and known-alias certificate/key getter rechecks liveness and all certificate expiry intervals. Unknown aliases return null without key access. The key manager keeps the original private-key reference, even though it checks the live entry separately. A recreated alias with another key cannot revive an old credential. This remains a single-process design; supporting other Android processes requires stronger coordination.

The returned [X509ExtendedKeyManager](https://developer.android.com/reference/javax/net/ssl/X509ExtendedKeyManager) is a reusable signing-handle capability, not an enforced “TLS only” sandbox. Trusted application code can call its standard key getter directly. It must be used only in the intended computer's scoped, server-authenticated TLS context. Issuer hints do not authenticate that peer. Certificate/key checks and a later TLS signature cannot be atomic with deletion; already-obtained handles, in-flight handshakes, established-session revocation, and active-stream expiry remain separate lifetime gates.

## Test evidence

Host checks use:

```powershell
npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
./gradlew.bat :core-security:testDebugUnitTest :core-security:lintDebug :core-security:assembleDebugAndroidTest
```

The security suite includes 16 credential-binding tests and one authenticated Node WSS exchange using the new key manager. The credential cases cover direct/intermediate chains, original-handle identity, EC/issuer selection, wrong key/issuer/signature, roles/usages, path limits, critical extensions, leaf/intermediate/anchor validity, expiry after binding, missing/failed liveness, defensive copies, malformed/oversized material, inconsistent collection bounds, and unchanged global providers/TLS defaults. The Node peer requires client-certificate authentication and echoes a 64 KiB binary frame. The client key is never written to its temporary directory; only a freshly generated synthetic server key is supplied to Node and is removed after the peer exits.

Two additional Android instrumentation cases compile: real nonexportable Keystore mTLS on supported TLS 1.2/1.3 while preserving the original Keystore certificate bytes, and deletion/recreation denial by the old credential. Together with the existing identity cases, five instrumentation methods are compiled. This is not evidence that these new cases have executed on Android. The loopback tests' INTERNET permission exists only in the library's androidTest manifest; production manifests are unchanged.

Synthetic CAs/server keys are generated at runtime only in shared test sources, using existing Bouncy Castle ASN.1 and JCA signing APIs. No static private-key fixtures, bcpkix helper, or provider registration is added. Shared source wiring is restricted to host/device test variants; it does not ship a test issuer in the main library.

Remaining gates include Android execution across supported versions, composition with [scoped gateway TLS](0003-scoped-tls-connections.md), authenticated CA provenance, device-registry approval/revocation, credential persistence/recovery/renewal, client-certificate privacy and session lifetime policies, and actual Android-to-desktop capture. The existing TLS connection factory and simulated app flow are not changed by this checkpoint.

Follow-up checkpoints compose this manager with the scoped factory in `ebaf024` and add the isolated Android-to-Node proof in [decision 0006](0006-android-node-interop.md). The first five-method Android run (`40094266244` at `d43c526`) passed the original identity and deletion cases but failed the local mutual-TLS case on both API 26 and 37. This is an unresolved runtime failure, not acceptance evidence. [Decision 0007](0007-keystore-tls-digests.md) corrects an independently verified Keystore digest-authorization mismatch and documents seven compiled instrumentation cases, legacy-key handling, and the required rerun. Production enrollment and capture remain open.

That local mutual-TLS failure is resolved at `2ab4d74`: [run 40095225102](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095225102) executes all seven methods successfully on both API 26 and API 37, with no skips. Decision 0007 records the exact scope. Android-to-Node transport, production enrollment and active-session policies remain separate gates.
