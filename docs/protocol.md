# Companion protocol draft

Status: proposed v1, not frozen or implemented. Package A must prove interoperability and record a freeze decision before production integration depends on these fields. This document is canonical across the Android and desktop repositories. Change the protocol version for incompatible wire changes.

Draft revision 0.2 adds an optional `gatewayCertificateDer` invitation field for native platform trust bootstrap. This additive draft change preserves parsing of older pin-only invitations for review; those invitations are insufficient to start the new native enrollment path. Newly generated desktop invitations must include the public certificate. Whether it becomes mandatory in the frozen schema remains a foundation decision. No production enrollment client or gateway is integrated yet.

## Encoding and identity

Use UTF-8 JSON for bounded control messages and binary WebSocket frames for proxy bytes. JSON timestamps use UTC RFC 3339. IDs are opaque strings; do not trust display names as identities. Unknown required capabilities or unsupported protocol versions produce explicit errors. Ignore unknown optional fields only where the schema permits them. Validate field types, lengths, endpoint syntax, and total payload size before acting.

The desktop has a dedicated persistent gateway key and certificate. A pairing payload supplies its SHA-256 SPKI pin and logical TLS server name. Validate the certificate against this configured identity within the gateway client only; never install a global trust-all handler. The dial address may be device loopback for USB while the logical server name and pin stay stable. Stage 0 must demonstrate this separation without weakening verification for any other request.

Initial proposed limits are 16 KiB for control messages, 64 KiB per binary frame, 64 concurrent streams per device, 1 MiB queued application data per stream, a 15-second handshake timeout, and a 60-second idle timeout with heartbeat support. These are configuration defaults to validate under load, not performance claims. Define a global byte and stream budget as well; per-device limits alone do not bound gateway memory.

## Pairing payload

Desktop creates a pending invitation from its local UI. Proposed QR contents:

```json
{
  "kind": "http-freekit-pairing",
  "protocolVersion": 1,
  "invitationId": "opaque-id",
  "invitationSecret": "base64url-256-bit-random-secret",
  "expiresAt": "2026-10-24T12:05:00Z",
  "desktopId": "opaque-desktop-id",
  "displayName": "Development computer",
  "serverName": "gateway-opaque-id.invalid",
  "gatewaySpkiSha256": "base64url-sha256-value",
  "endpoints": [{ "mode": "usb", "host": "127.0.0.1", "port": 8766 }]
}
```

Port 8766 is illustrative and must be configurable, with collision handling; it is not an assigned or implemented project port. Endpoint values are routing hints, not trusted identities. A copied payload is a pairing credential until used or expired. Do not put it in logs, analytics, browser history, crash reports, or third-party QR services. Prefer in-app scan or paste over external web redirects.

New desktop payloads also include `gatewayCertificateDer`: canonical unpadded base64url of the dedicated self-signed gateway leaf certificate's DER, limited to 4096 decoded bytes within the overall 16 KiB control limit. It is public material, distinct from the interception CA, and contains the logical `serverName` in its SAN. Validate its single-certificate encoding, self-signature, leaf role, validity, and SPKI match before using it as a scoped trust anchor in the platform TrustManagerFactory. Preserve normal TLS hostname and server-purpose verification. Recheck validity on each connection/reconnect; platform trust-anchor validation may omit anchor expiry. Do not install the anchor globally, accept an arbitrary replacement certificate, or use a trust-all callback to retrieve it. Certificate renewal/rotation and active-session expiry handling remain freeze gates.

Invitations expire after five minutes by default, are single-use, and are bounded and rate-limited on the desktop. The phone displays the receiving computer before proceeding. A future short numeric code requires a standard authenticated pairing protocol or trusted lookup channel with explicit threat analysis; do not replace the high-entropy secret with six digits in this flow.

## Enrollment

1. Android generates a device private key in Keystore and a certificate signing request; it never sends the private key.
2. It opens pinned TLS to the gateway and POSTs /companion/v1/pair with invitation ID, secret, CSR, proposed device name, and supported capabilities. The invitation secret is in the request body, never a URL query.
3. The gateway validates limits, invitation expiry, CSR proof of possession, and version. Atomically reserve the invitation for that public key. Repeated requests from the same key may resume; another key cannot take the reservation.
4. The desktop shows a pending request with device name and a comparison fingerprint or phrase derived from both identities. Its local user approves or rejects. Pending requests cannot open proxy streams. Waiting requests use bounded polling with an invitation-and-key-bound status credential, not an unbounded open HTTP request.
5. On approval, issue a device client certificate from a dedicated enrollment authority, register its public key and device ID, consume the invitation atomically, and return the certificate, desktop identity, public interception CA fingerprint, and capability list over the same pinned connection. Rejection, cancellation, or expiry invalidates the reservation and requires a new invitation.
6. Future connections use mutual TLS and the desktop registry. A valid certificate alone is insufficient if its device is revoked. Scope pairing endpoints as the only unauthenticated TLS surface; the gateway must enforce client certificate checks on every authenticated route even when TLS allows enrollment clients without a certificate.

Package A must specify certificate algorithms, validity, renewal, status credential binding, recovery, and crash-safe enrollment persistence before freeze. Renewal requires an authenticated active device and proof of the new key when rotating. Expired or revoked credentials require pairing again. Avoid having Android credentials signed by the interception CA.

## Authenticated endpoints

| Endpoint | Purpose | Authorization |
| --- | --- | --- |
| POST /companion/v1/pair | Start enrollment | Valid invitation and CSR; no traffic access |
| POST /companion/v1/pair/status | Resume enrollment result | Bound pending credential and key proof |
| WSS /companion/v1/control | Session readiness, heartbeat, state, disconnect | Active device client certificate |
| GET /companion/v1/ca | Public interception CA and fingerprint | Active device client certificate |
| WSS /companion/v1/streams | One ordered explicit-proxy byte stream | Active device client certificate and current session |

Each successful control session receives a short-lived opaque session ID bound to that device. Streams present it in a bounded header, must belong to that same authenticated device, and are rejected after session closure. Do not accept browser cookies, generic desktop API tokens, or URL bearer credentials for this surface. Validate or reject browser Origin values; WebSocket upgrade does not bypass authentication.

## Session and stream behavior

Control hello and response carry protocolVersion, message type, capabilities, session ID, desktop ID, and configured limits. Capabilities include tcp-http, tcp-https-connect, app-selection, and direct-wan where implemented; unsupported capabilities must not be advertised. Connection readiness requires successful authentication and proxy availability, not merely a WebSocket upgrade.

Each stream begins with a bounded JSON open message containing protocolVersion and an opaque streamId. After a ready response, client binary frames contain an ordinary explicit-proxy byte stream. HTTP starts with an absolute-form request; HTTPS starts with CONNECT authority and includes the proxy's response before subsequent TLS bytes. Gateway forwards only to its configured local proxy, preserving ordered bytes and backpressure. It does not parse a client-supplied local forwarding address or grant access to the management API.

Specify and test half-close support during the spike. If necessary, use a typed JSON end-of-write message while continuing binary reads; a full WebSocket close represents abort or completed bidirectional shutdown. Do not inject control data into binary payloads. Buffering entire requests or responses is forbidden. Observe total stream budgets, cancellation, and idle timeouts even before any proxy bytes arrive.

Revocation invalidates sessions and immediately closes their streams. Desktop stop closes new enrollment and active sessions. Reconnect establishes a fresh session and new streams; do not replay HTTP requests automatically, since they may have caused side effects already. Credentials and payloads must not appear in close reasons.

## Errors and compatibility

Use stable codes: unsupported_version, invitation_expired, invitation_used, pairing_pending, pairing_rejected, authentication_failed, device_revoked, proxy_unavailable, stream_limit, invalid_message, and network_unreachable. Local diagnostics may add safe detail; public authentication errors must not expose secrets or internal paths. Gateway identity mismatch is a local TLS failure and must never trigger an automatic trust reset.

Protocol fixtures must include success, rejection, malformed JSON, oversize payloads, expiry, duplicate enrollment, concurrent claim, version mismatch, and stream cancellation. Store them under protocol/fixtures when implementation begins. Both repositories run the same committed fixture set or a pinned copy with its source commit recorded. Compatible application versions negotiate capabilities rather than infer features from release names.

## Relay gate

Direct v1 has no relay enrollment or routing API. Add a separate carrier specification after proving inner TLS over a byte carrier. Reuse authenticated application messages inside that end-to-end connection; do not make the relay a CA, an enrollment authority, or a source of desktop trust pins.
