# Authenticated HTTPS transport research

Status: the local C3 H1 checkpoint is implemented and verified below. This profile extends the isolated [C2 transport proof](capture-transport.md). It uses the existing draft `tcp-https-connect` capability and legacy numeric CONNECT443 preface; it adds no wire fields and does not freeze [protocol v1](protocol.md). Android capture, production integration and physical USB acceptance remain open.

## Desktop ownership

The internal desktop entry point is `attachTrustedHttpsConnectStream(duplex, { negotiatedCapabilities, authorizeDestination, signal })`. Its owner must retain the authenticated stream, raw/TLS sockets, asynchronous certificate work and request operations before starting fallible work. It requires actually negotiated `tcp-https-connect`, parses the bounded numeric CONNECT443 preface, authorizes that original tuple and writes the existing fixed 39-byte CONNECT acknowledgement. The acknowledgement admits a parser attachment, not successful TLS or origin access. Application dispatch waits for its actual write callback and fresh authorization.

Every actual origin dial uses the authorized original numeric IP and port 443. Validated SNI and HTTP authority provide certificate and request identity, never an alternate physical route. Authorization remains attached across CONNECT, TLS, HTTP requests, upgrades, retries and shutdown. No-SNI or IP-literal-SNI input must retain that context; unsupported identity combinations may fail explicitly but must never fall back to ordinary unguarded CONNECT. Conflicting authorities fail before egress.

Use the existing desktop certificate authority and proxy request implementation. Keep ordinary local proxy behavior unchanged. Deny trusted-path upstream delegation, cross-origin rule retargeting, webhook/local-file actions and TLS passthrough. Strictly verify origin certificates; scoped test-origin trust is independent of interception-CA and gateway trust. Disable secondary AIA network recovery for this path unless its actual egress is separately authorized. Never inherit ordinary proxy validation exceptions or client-certificate privileges.

The first subgate may explicitly restrict both inner downstream and upstream ALPN to HTTP/1.1, with no shared upstream agents or H2 pools. H2 owner/pool isolation remains an open requirement for broader supported HTTPS; an H1-only result must say so. HTTP80 Upgrade and WSS443 Upgrade through the enrolled factory remain required preview acceptance, alongside normal HTTPS. Preserve streaming and bounded queues, and distinguish orderly TLS/application EOF from cancellation or a reset. Stop, expiry and revocation must interrupt retained operations and join their actual owners.

## Test composition

Keep the reviewed desktop C2 checkout at `fd63f6940226c8e3401a165082dfa9325abaca69` unchanged. Develop C3 in a separate desktop worktree from that commit; desktop commits and publication authorization remain separate from Android changes.

Reuse the existing private CSR exchange, authenticated gateway, enrolled factory and explicit desktop integration task. The actual interception CA used by the desktop proxy must supply the public certificate and fingerprint bound into enrollment metadata. Only its public certificate crosses private test IPC. Gateway, enrollment, interception and origin trust have distinct owners; a generated but unused CA is insufficient evidence.

Positive local evidence must exercise the factory's default two-capability requirement, original numeric IPv4/IPv6 routing with a logical hostname that cannot resolve, verified inner TLS, complete deterministic bodies, decrypted desktop capture, exact EOF and joined cleanup. Subsequent Upgrade cases exercise real text/binary messages, ping/pong, peer Close and coalesced 101/first-frame bytes. Negative checks cover wrong CA/hostname, authority conflict, destination denial/change, cancellation, expiry and revocation without fallback. Local JVM success does not establish Android Keystore, VpnService protection, TUN, USB or device acceptance.

## Android certificate help

B4 adds actionable help to the existing Setup preview: distinguish gateway identity from interception trust, obtain only the public CA from the trusted computer, compare its SHA-256 fingerprint, explain manual user-CA installation and removal, and show debug-only configuration for the user's own app. On Android 11 and later CA installation is performed through Settings; opening or returning from Settings does not verify installation or traffic. Use the public security-settings action with a finite unavailable state.

The copyable example uses a debug-variant manifest and debug-only XML/public-CA resource. Explicit `overridePins="false"` preserves Network Security Configuration pin checks; independent library pinning can still reject interception. Preserve an existing application's configuration rather than suggesting a blind replacement. No CA downloader, installer, private-key transfer, target-app modification, permission expansion or success simulation is assigned. HTTPS and traffic remain Not verified after navigation, recreation and unavailable-handler outcomes.

Primary references: [KeyChain CA installation](https://developer.android.com/reference/android/security/KeyChain#createInstallIntent()), [security settings action](https://developer.android.com/reference/android/provider/Settings#ACTION_SECURITY_SETTINGS), and [debug trust and pin behavior](https://developer.android.com/privacy-and-security/security-config).

## Local checks and limits

Desktop implementation `3d8b7b1` passes its 719-case Node 26 baseline. Composed testing then exposed premature HTTP `Connection: close` destruction before late client TLS shutdown and typed END_WRITE. Fix `2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6` preserves the input lifetime on the new owned TLS socket; the identical asynchronous virtual-Duplex reproducer fails before and passes after. All 70 relevant cases pass on both Node 24 and 26 after that fix. The old reviewed C2 checkout remains unchanged and unpublished; the new desktop commits also remain local.

The actual enrolled Node composition passes all six C3 cases on that exact fixed desktop, and all nine C2 regressions on `fd63f694`. Its actual public interception CA is bound to enrollment and differs from gateway, enrollment and origin trust. HTTP Upgrade captures distinguish the parent request from validated child frame records. Both Upgrade cases consume final EOF with zero trailing bytes before shutting down client output. The three-file fixture source `aaf3f89` is integrated here as `720b113`. Earlier failed harness/composition attempts remain separate evidence; none is promoted to success.

The first actual JVM run passes six cases with zero failures, errors or skips in 27.459 seconds: verified IPv4/IPv6 HTTPS, wrong CA and wrong hostname before origin egress, HTTP Upgrade and WSS Upgrade. It preserves the factory's default two-capability requirement and uses actual enrolled mTLS, numeric destination routing, complete deterministic bodies, decrypted capture, echoed text/binary, ping/pong, maintained decoding of the peer's Close1000 and joined cleanup. The task sets `com.sun.net.ssl.requireCloseNotify=true` before JSSE initialization, so application TLS EOF cannot be substituted with a bare TCP close. Wrong-host testing explicitly omits SNI, leaving the expected DNS peer unmatched by the desktop's numeric-IP leaf; both negative cases require a certificate-rejection cause. These are JVM software-key checks, not Android Keystore/VpnService proof.

A fresh clean-source run pairs Android `0d3d8d444aa2f6a10d9bd4370151b1f7ffb3ddd6` with desktop `2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6`: all six cases pass in 31.063 seconds. The actual XML SHA256 is `2d7eed46a2d8918c0d30a994c24b6880076f2163ac2d229a139c2c7e7ad18df9`; finite validation metadata SHA256 is `2c71c71ab541b85dfff0937a2e97c321c1699eb1b37eb48eeef264fd40d4f697`. An independent audit verifies both clean trees, all seven source-file hashes against their committed blobs, fresh XML after the Android commit, exact methods/timings and the exported checksums. Its SHA256 is `6c7010a72e8d19d90d1a590fccc094b750db2d11176a7c12a843e7b5a877afa7`. Stable local exports are `dist/capture-transport-c3-validation.json`, `dist/capture-transport-c3-tests.xml` and their checksums. The separate Node evidence is exported as `dist/capture-transport-c3-node-validation.json`. Configured Node 24.22.1 uses its bundled OpenSSL 3.5.9 for TLS; external issuance uses OpenSSL 3.6.1.

After setting up the [developer toolchain](development.md), run the explicit local check against the clean reviewed desktop checkout:

```powershell
$env:FREEKIT_DESKTOP_ROOT = '<absolute path to the local reviewed desktop checkout>'
$env:FREEKIT_DESKTOP_COMMIT = '2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6'
./gradlew.bat :capture-transport-research:testDesktopHttpsIntegration
```

The task requires that exact commit and checks the actual tracked desktop tree independently in the private fixture. Missing or dirty input fails; it is never an optional skip. Every requested proof executes freshly, with up-to-date reuse and build caching disabled for this task. Run it serially with no other owner of controlled loopback ports 80/443. It is excluded from ordinary unit tests and hosted CI, which do not have the unpublished desktop source. The separate C2 task and its original fixed desktop dependency remain intact.

H1-only scope is explicit. Owner-scoped H2, successful Android capture, public-CA retrieval and production credential binding, real TUN/USB, physical-device checks and protocol freeze remain open. Node public readable EOF alone is not independent proof of TLS close_notify; the strict JVM cases provide that separate local gate. No successful Android, emulator cleanup, USB or production result is inferred from these host checks.
