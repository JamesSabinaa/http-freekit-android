# Android Keystore to Node research proof

Status: isolated foundation instrumentation and loopback peer. Host fixture checks and Android compilation are separate from Android execution. This checkpoint adds no production enrollment endpoint, persisted credential, VPN, proxy delivery, desktop management access, or protocol freeze.

The research-only `:transport-interop` library lives under `tools/transport-spike/android`. Its main manifest is empty; only its instrumentation APK has INTERNET permission. It depends on public `core-security` APIs in test code. Ordinary five Keystore tests remain independent of Node. The research task requires a live peer and fails if arguments, connectivity, or any of its four cases are absent; it has no successful skip path.

## Reproduction

Host prerequisites are JDK 17, the repository's pinned Android SDK/build tools, Node 22 or later, OpenSSL 3, and an explicitly selected online API 26+ ADB device. OpenSSL 4 is intentionally outside this fixture's checked version range. If several installations exist, use `OPENSSL_BIN` or the driver's `--openssl PATH` option. No global provider, trust store, or device proxy setting changes are made.

From the repository root:

```sh
npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
node --test tools/transport-spike/android-peer.test.mjs
./gradlew :transport-interop:assembleDebugAndroidTest :transport-interop:lintDebug
node tools/transport-spike/run-android-interop.mjs --serial emulator-5554
```

The driver supports `--adb PATH` and `--openssl PATH`. It uses `ANDROID_HOME/platform-tools/adb` when available, invokes the root Gradle wrapper, sets `ANDROID_SERIAL` for that child, and runs `:transport-interop:connectedDebugAndroidTest`. Its host task deadline is 15 minutes. Do not run that connected task directly without the four public fixture arguments configured by the driver.

The peer starts two ephemeral TLS listeners on host loopback. The driver allocates two `adb reverse --no-rebind tcp:0 tcp:PORT` mappings and supplies only the public gateway certificate/pin and mapped enrollment/WSS ports as instrumentation arguments. Certificate authority and server private keys are synthetic, generated for that run under a verified temporary-directory prefix, with private file modes where supported. They never enter the repository or Android process. The Android client private key never enters the host or Node process. On success or failure the driver removes only its own reverse mappings, closes the peer's sockets/listeners, and deletes its temporary directory. It never removes all device mappings.

## Bounded fixture protocol

This protocol is deliberately separate from the [companion draft](../protocol.md). It is an automatically issuing, loopback research fixture, without invitation approval or replay protection suitable for production.

- Bootstrap HTTPS accepts only `POST /research/enroll` with `application/pkcs10`, exact Content-Length 1–4096 bytes, no transfer encoding, and at most 8 KiB of request headers. Other paths return 404. Issuance is serialized, limited to eight successful requests per run, with a five-second idle limit and ten-second request deadline. Each listener permits at most 16 connections.
- A strict bounded DER envelope reader requires PKCS#10 v0, a bounded subject, empty attributes, canonical P-256 SPKI, and SHA256withECDSA with absent parameters. Node verifies the signature over the exact CertificationRequestInfo encoding before issuance. Altered signatures, trailing material, oversize bodies, malformed encoding, and other curves fail. The profile follows [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986); Node uses its [public key and signature APIs](https://nodejs.org/docs/latest-v22.x/api/crypto.html).
- OpenSSL issues only a non-CA leaf with digitalSignature and clientAuth-only EKU, signed by an ephemeral path-length-zero enrollment CA. CSR extensions are never copied. The issued public key and CA signature are checked again before responding. [OpenSSL x509](https://docs.openssl.org/3.0/man1/openssl-x509/) documents `-req`, explicit extension files, and `-copy_extensions none`.
- Success is a binary envelope of at most 8201 bytes: version byte 1, big-endian unsigned 32-bit CA DER length and CA DER, then equivalent leaf length and DER. Each certificate is at most 4096 bytes. Android bounds lengths before allocation, reparses canonical DER, rejects trailing bytes, and validates/binds the credential through `DeviceIdentity`.
- A second TLS listener requires a verified client certificate against that ephemeral CA. Before `/research/echo` upgrades, Node also compares the peer SPKI against a successfully issued key from this run and rejects browser Origin. Binary WebSockets have a 64 KiB maximum payload and compression disabled. This peer echoes only its received research bytes; it cannot select a forwarding destination. [Node TLS](https://nodejs.org/api/tls.html#tlscreateserveroptions-secureconnectionlistener) documents mandatory client authentication.

Android uses `GatewayTlsConnectionFactory` for both bootstrap HTTPS and authenticated WSS, keeping dial loopback separate from the logical gateway name. The [scoped certificate manager](0004-enrolled-client-credentials.md) supplies the original nonexportable signing handle to the factory. The small instrumentation-only [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) client validates the HTTP upgrade and accept hash, masks outgoing frames, bounds incoming lengths before allocation, exchanges one exact 64 KiB binary payload, and closes. Each application I/O operation has five-second read and ten-second overall budgets; factory connection/handshake budgets are five seconds each. This deliberately limited client is not production streaming/framing code.

## Evidence boundary

Two host Node tests cover CSR proof failures and actual software-key issuance/mTLS/WSS echo, absent-client rejection, and temporary-directory cleanup. They exercise the fixture; they do not establish Android Keystore interoperability.

`com.httpfreekit.interop.AndroidNodeInteropTest` contains exactly four instrumentation cases:

- `nonexportableIdentityEnrollsAndEchoes64KiB`: create a real Keystore key, reject its altered CSR, enroll the valid CSR, validate/bind the issued chain, exchange 64 KiB through the public TLS factory, assert the same unexportable key handle and unchanged original Keystore certificates, then delete only that test identity.
- `wrongPinIsRejected`: establish peer reachability using the correct pin, then reject a different pin.
- `wrongHostnameIsRejected`: establish peer reachability, then reject an incorrect logical server name.
- `missingClientCertificateIsRejected`: establish bootstrap reachability, then require mTLS rejection, including application I/O to observe a TLS 1.3 alert that can arrive after the client's handshake call returns. Read timeouts and initial connection failures do not count as rejection evidence.

XML is under `tools/transport-spike/android/build/outputs/androidTest-results/connected/debug`; HTML is under `tools/transport-spike/android/build/reports/androidTests/connected/debug`. The driver requires fresh XML containing those exact four cases, no duplicates, and zero errors/failures/skips. Hosted execution and its Android versions/commit pair must be recorded independently; compilation is not runtime evidence. [AOSP adb documentation](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/docs/user/adb.1.md) describes ephemeral reverse ports and removal of specific mappings.

Remaining gates include actual API 26/37 execution, physical hardware-backed key behavior, credential approval/persistence/renewal/revocation, active-session policies, cancellation/backpressure and sustained streaming, packet forwarding, real desktop proxy integration, USB capture with phone radios disabled, and LAN/WAN acceptance. This proof does not freeze the production CSR/certificate policy or any companion route.
