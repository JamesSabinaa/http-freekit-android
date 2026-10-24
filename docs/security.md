# Security model

## Assets and boundaries

Protect captured content, site credentials, gateway identity keys, device private keys, pairing invitations, and the interception CA private key. Treat the LAN, WAN, relay operator, unauthenticated devices, QR payloads, launch intents, and traffic destinations as untrusted. The user deliberately trusts their desktop with decrypted captured traffic; encryption does not conceal that traffic from the desktop operator.

The phone receives only public CA material and its own client certificate. Store its nonexportable private key in Android Keystore where supported. Exclude credentials from Android backup and restore; restoring preferences without the original key must lead to a clear re-pair state. Desktop private keys and device registry require appropriate local filesystem permissions or platform credential storage. Do not claim that application encryption protects against an already compromised desktop.

## Authentication

Use TLS with a desktop identity pinned through the pairing payload, plus a distinct client credential for every device. QR enrollment requires explicit desktop approval and proof of device key possession. Store invitation verifiers or hashes rather than plaintext secrets where possible, compare securely, and expire stale pending enrollments. The complete enrollment transaction and key lifecycle are a stage 0 contract requirement.

A desktop password is not required for the local developer preview. If remote administration or accounts are introduced later, their authentication is a separate feature; it cannot replace gateway authentication. Never allow credentials intended for mobile traffic to authorize desktop settings, command execution, or arbitrary management calls.

Keep raw ADB ports and the management API off the internet. Direct WAN exposes only the opt-in companion gateway. Default it to loopback until the user enables LAN/WAN and selects the intended bind address. No automatic router forwarding.

## Proxy authorization and destinations

Authenticated phones can cause the desktop proxy to make requests; pairing is a privileged grant. Apply a gateway-specific destination policy at the proxy's actual connection and DNS resolution boundary. The WAN default denies desktop loopback, link-local, private network ranges, IPv6 local ranges, metadata endpoints, and desktop management listeners. Resolve and validate every address used and revalidate redirects and new connections to prevent DNS rebinding bypasses. Explicit per-device opt-in can allow selected private development targets, while management endpoints remain prohibited.

Do not enforce policy solely by inspecting a WebSocket open message: the actual destination is inside the explicit proxy protocol, forwarding rules can change it, and CONNECT or rule-driven requests can bypass superficial checks. Package D must identify the proxy seam for this policy before enabling WAN. If reliable enforcement is unavailable, direct WAN remains disabled until implemented; paired-device authentication alone is not destination isolation.

Bind session identity to capture metadata without forwarding internal credentials or device IDs to target websites. Remove any internal transport authorization before passing bytes to the proxy. Reject malformed requests, unauthenticated upgrades, and stream attempts through enrollment paths. Keep existing ordinary local proxy behavior outside the companion session unchanged.

## Certificate trust

Transport encryption and HTTPS interception have separate trust chains. Download the public interception CA only over an authenticated gateway connection and verify its fingerprint. The phone's VPN permission does not grant certificate installation rights. Guide users through platform installation, and verify interception using a debug test app configured to trust that CA.

Modern Android apps generally trust system CAs by default; their configuration can separately opt into user CAs. Certificate pinning can still reject interception. Do not promise universal HTTPS visibility or silently weaken target app TLS settings. Rooted system CA injection, if implemented later, needs Android-version-specific tests, temporary installation ownership, and recovery; it is outside the first app preview. See [Android network security configuration](https://developer.android.com/privacy-and-security/security-config).

## Network and service behavior

Android supports one active VPN per user/profile. The app needs platform consent, an ongoing notification, and protected outbound sockets to avoid loops. Implement the foreground-service requirements appropriate to the chosen target SDK and test revocation through Android settings. These requirements come from [Android VPN guidance](https://developer.android.com/develop/connectivity/vpn).

Do not silently fall back to plaintext, another desktop identity, or direct forwarding for traffic selected for interception when its tunnel fails. Define memory and socket limits, connection timeouts, retry budgets, and jittered reconnects. Explicit Stop restores normal networking. Surface limitations around process death and always-on settings without claiming a system-wide kill switch.

## Diagnostics and releases

Log state transitions, sanitized error codes, negotiated versions, counters, and timing. Default logs exclude URLs, headers, bodies, QR payloads, certificates with identifying extensions, session credentials, and device secrets. Diagnostic export is previewable and opt-in; payload capture remains in the desktop's existing capture store. Never send crash reports automatically with intercepted data.

Signing keys stay out of Git. Debug and release identities must be distinguishable. Verify installed package identity before ADB updates, reject untrusted download sources, and use signed release artifacts with checksums and notices. Do not download and execute an APK merely because a remote pairing payload names it.

## Review gates

Before direct WAN, verify enrollment replay resistance, revoked-device disconnection, wrong-pin rejection, endpoint authorization, destination restrictions, oversized messages, memory bounds, and logs free of secrets. Before relay, verify encryption terminates only at the paired endpoints and that a substituted relay cannot replace desktop identity. Track residual issues and mitigations in release evidence.
