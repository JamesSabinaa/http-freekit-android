# Scoped gateway TLS connection factory

Status: foundation transport spike with optional enrolled-client authentication. No companion endpoint, production enrollment transaction, Android capture, or protocol freeze is implemented by this change.

The raw-manager lifetime issue recorded in [decision 0002](0002-device-identity-and-bootstrap.md) now has a public connection boundary: `GatewayTlsConnectionFactory`. `GatewayTrust` is internal. A reusable factory does not expose a reusable trust manager or SSL context.

## Identity and connection lifetime

The factory copies the configured public gateway certificate through its bounded X.509 encoding, verifies the configured SPKI pin and certificate constraints, and retains that private snapshot. Every `connect` call repeats certificate validity and pin checks and creates a fresh in-memory platform TrustManagerFactory and SSL context. No custom X509TrustManager, trust-all handler, global provider registration, default hostname verifier, or global SSL context change is introduced.

The dial address must be a resolved `InetSocketAddress` with a nonzero port. The TCP socket connects to that address while TLS uses the configured logical server name for SNI and normal HTTPS endpoint identification. These are independent inputs: a USB loopback route does not change the authenticated desktop name. [SSLParameters endpoint identification](https://developer.android.com/reference/javax/net/ssl/SSLParameters#setEndpointIdentificationAlgorithm(java.lang.String)) supplies the platform hostname check; it is never replaced with a permissive callback.

Each socket permits only supported TLS 1.2 and TLS 1.3 protocols, failing if neither is available. Default cipher suites remain intact. After the handshake and before returning a socket, the factory rechecks the configured anchor and the actual presented leaf for validity, exact SPKI match, self-signed leaf role, signature, and server/signing purpose. Thus a differently keyed child signed by the pinned non-CA leaf cannot become the accepted peer merely because a platform treats the configured leaf as a trust anchor. The host tests exercise this rejection; Android provider behavior still needs device execution.

A connection that completes after the synthetic certificate clock has expired is rejected before it is exposed, even if the platform accepts the anchor. Reusing the same factory after expiry also fails before another TCP socket is allocated. A fresh platform context is used on each attempt, and the explicit post-handshake leaf checks do not rely on trust-anchor expiry or session-cache behavior.

## Bounded setup and cleanup

TCP connect and TLS handshake have separate default budgets of 15 seconds, configurable only within 1–60,000 milliseconds. Zero never means an infinite timeout. DNS resolution is deliberately outside this factory because constructing an unresolved hostname can perform a blocking lookup before `Socket.connect` applies its timeout. Callers must resolve through a separately bounded resolver on the chosen underlying network.

The TCP phase passes its budget to `Socket.connect`. The TLS phase uses both a socket read timeout and a monotonic deadline watchdog that closes the raw socket. A trickled partial TLS record cannot keep resetting the handshake budget indefinitely. The watchdog uses a shared daemon scheduler; completed/cancelled tasks are removed from its queue. Successful setup cancels the deadline without closing the returned socket. Failed setup closes both the raw and layered TLS sockets, including hostname, pin, certificate, connect, and handshake failures. The raw socket uses no linger delay for deadline cleanup.

The optional raw SocketFactory is a local integration hook for future network binding/protection. It must return a fresh, unconnected, non-TLS socket; an already connected socket cannot bypass the selected dial address and timeout. This change does not implement Android `VpnService.protect` or underlying-network selection.

The caller owns a successful [SSLSocket](https://developer.android.com/reference/javax/net/ssl/SSLSocket) and must close it. Its handshake-specific SO_TIMEOUT is cleared on return; application read/write, heartbeat, idle, and overall transaction budgets must be supplied by the future transport. The two setup budgets do not establish the draft companion control handshake's overall deadline. This blocking API must run off the main thread.

## Enrolled-client composition

The optional `clientKeyManager` constructor argument accepts the scoped manager returned by [DeviceIdentity's validated enrollment binding](0004-enrolled-client-credentials.md). The caller must authenticate that computer's enrollment authority before binding; the factory does not establish CA provenance or approval. Every connection uses that manager in its fresh SSL context alongside the existing pinned gateway trust. No default key manager or global TLS setting is changed.

Before allocating a TCP socket, the factory requires an available EC client alias, private-key handle, and bounded client leaf. After the TLS handshake it checks the manager again and compares both the current leaf and TLS session's actual local certificate with the original encoded leaf. Missing, expired, deleted, changed, or unused client credentials fail before exposing the socket. A server that never requests the configured client certificate cannot appear mutually authenticated. Connections without a client manager retain the pinned server-only bootstrap path.

These setup checks do not make key deletion atomic with an in-flight signature or close established sessions after revocation/expiry. The transport must still own active-session lifetime and cancellation. The app's simulated connection flow is unchanged.

## Evidence and remaining gates

Host validation runs:

```powershell
./gradlew.bat :core-security:testDebugUnitTest :core-security:lintDebug
./gradlew.bat :core-security:assembleDebugAndroidTest
```

The initial security JVM suite passed 19 tests, including 13 new factory cases. Those cases cover logical hostname/SNI over loopback, protocol minimums, unchanged global TLS defaults, factory reuse after clock expiry, expiry during a handshake, wrong pin/name/key, an unpinned child certificate, TCP timeout propagation, failure cleanup, silent and trickled TLS peers, watchdog cancellation, invalid timeout/name/address inputs, and connected-socket injection rejection.

The enrolled-client composition checkpoint passes all 40 security JVM tests with zero failures, errors, or skips. Four new cases authenticate the bound client and pinned gateway together on TLS 1.2 and TLS 1.3, reject unavailable/expired credentials before socket allocation, reject servers that do not request the configured client certificate, and withhold a socket when the credential becomes unavailable after TLS authentication. Strict security lint reports `No issues found.` The five-method instrumentation APK compiles. Local Markdown links and `git diff --check` pass.

The original three identity tests have since executed on API 26/37 emulators as recorded in [decision 0002](0002-device-identity-and-bootstrap.md). Android TLS/provider execution with the composed factory, real Keystore client-certificate handshake use, active-stream certificate expiry and renegotiation policy, renewal/rotation, authenticated session revocation and user cancellation, bounded DNS/network selection, stream I/O budgets, companion routes/framing, and Android-to-desktop capture remain open. The factory is not wired into the simulated app connection flow, and no frozen wire contract changes.
