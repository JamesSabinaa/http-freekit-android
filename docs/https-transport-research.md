# Authenticated HTTPS transport research

Status: C3 assigned, not verified. This profile extends the isolated [C2 transport proof](capture-transport.md). It uses the existing draft `tcp-https-connect` capability and legacy numeric CONNECT443 preface; it adds no wire fields and does not freeze [protocol v1](protocol.md). Production capture and physical USB acceptance remain open.

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
