# HTTP origin transport, draft 0.5

Status: additive extension to the [companion draft](protocol.md) and [stream grammar](protocol-streams.md), not a v1 freeze or production integration. It carries the original numeric destination separately from the HTTP Host and leaves application HTTP bytes unchanged. The cold EOF limitation in [capture policy](capture-policy-runtime.md) remains recorded.

## Explicit negotiation and stream mode

`tcp-http-origin-connect` is an implemented traffic capability only when both this preface and the trusted desktop HTTP attachment exist. It may establish a traffic session alongside, or instead of, the two legacy traffic capabilities. Advertising an unimplemented legacy capability merely to pass negotiation is forbidden.

The client `open` message has one new optional field, `proxyMode`. When present its only value is `http-origin-connect`; null or another value is `invalid_message`. A codec validates this field without inferring negotiated support. The lifecycle accepts this open only when `tcp-http-origin-connect` was negotiated; otherwise it fails with `unsupported_capability`. An open without this field retains the legacy explicit-proxy mode and requires negotiated `tcp-http` or `tcp-https-connect`. Check fresh clocks/expiry and sender/open phase before this capability check, then claim the stream ID only after mode support succeeds. No new session ID, destination, device identity or credential is accepted in JSON. Add `unsupported_capability` to the stream error-code set for this extension; ready/END_WRITE schemas and all legacy encodings, fixtures and results remain unchanged.

Only the explicit new mode selects the new desktop preface owner. Never infer it from arbitrary application HTTP bytes or silently retry another mode. HTTP80 in the new capture factory requires the new capability/mode; HTTPS443 continues through the legacy CONNECT capability. This factory does not advertise legacy `tcp-http`, because it does not rewrite requests to absolute form.

## Destination preface

After stream ready, the client writes this ASCII preface as binary application bytes, substituting only the original numeric authority:

```http
CONNECT 203.0.113.10:80 HTTP/1.1
Host: 203.0.113.10:80

```

Every displayed line ends with CRLF; the final empty line makes CRLFCRLF. IPv6 uses brackets, for example `[2001:db8::10]:80`. The encoder accepts only a copied 4- or 16-byte address and port80; it performs no DNS resolution and emits canonical decimal IPv4 or eight lowercase hexadecimal IPv6 groups, without zones. A gateway accepts valid numeric IPv4 or bracketed IPv6 syntax with exact decimal port `80`, a case-sensitive identical Host authority, method CONNECT and HTTP/1.1. There must be exactly one Host header and no other headers, body framing, userinfo, DNS name, zone, extra request or request-target form. Header names may use HTTP case variation. Keep the chosen IP family; no DNS or logical Host can retarget it.

Use the maintained Node HTTP parser for request syntax. Independently bound the raw preface, through CRLFCRLF inclusive, to1024 bytes; native parser options alone are not that raw bound. An ingress chunk and coalesced application head are each at most65536 bytes. Excess input fails before copying/retaining it. Retained head stays owned and charged until passed once, in order, to the attachment. One five-second deadline covers preface receipt, validation, authorization, attachment and the actual200 write callback, including backpressure. No timer resets on input progress.

The gateway checks its still-active authenticated session, explicit mode, capability, cancellation and exact numeric destination authorization before attachment. The authorization callback is synchronous and must return exactly true; exceptions, promises and truthy objects deny. Retain the handle before fallible work. Attach the existing trusted HTTP parser while input is paused; emit exactly `HTTP/1.1 200 Connection Established\r\n\r\n`. Release coalesced/new application input only after the successful write callback and a fresh cancellation/policy check. No origin HTTP request or connection may be dispatched before that callback. On denied admission, malformed input, timeout, failed attachment/write or cancellation, close and join owned resources; never fall back to another proxy path.

This fixed200 acknowledges an authorized, attached HTTP parser. It does not assert origin reachability or a successful origin connection. This meaning belongs only to the negotiated new mode; ordinary CONNECT443 behavior is unchanged. The client consumes exactly the fixed response bytes within its remaining open deadline; any mismatch, truncation or timeout fails that stream. It never consumes or rewrites following application bytes. Preface rejection closes the stream; no diagnostic/provider text is forwarded as application data.

## HTTP stream and authorization

Subsequent bytes are the application's unchanged origin-form HTTP/1.1 or OPTIONS*, including chunking, trailers, keepalive and WebSocket upgrade. The existing desktop attachment validates logical Host, fixes physical routing to the original numeric address:80 and rechecks current authorization at every actual dial/retry. It rejects retargeting, cross-origin rules, upstream-proxy delegation and management access under its existing policy. Do not forward device/session credentials or synthesize identity headers to the origin. The existing eight unfinished-request limit remains mandatory.

Preserve directional EOF. Client END_WRITE follows all earlier binary bytes and ends parser input while the opposite response can continue. A coalesced head plus an already observed FIN is delivered exactly once. Server END_WRITE follows all response writes. Cancellation/revocation/expiry closes pending admission and active streams and joins the preface owner, attachment and actual transport before closure confirmation. Keep previous legacy HTTP/CONNECT443 behavior unchanged. Limits describe owned application/transport buffers, not total Node/kernel/TLS memory.

## Required proof

Kotlin and Node must agree on the new open field and traffic-capability gating while the existing A19 corpus remains unchanged. Small independent wire vectors cover IPv4/IPv6, fragmentation/coalescing, raw bounds, invalid authority/headers/mode, fixed response consumption and following-byte preservation. Desktop tests must actually traverse the new preface and existing proxy to a controlled origin, observe the desktop capture callback, preserve full streaming/EOF, reject DNS retargeting and changed/revoked destination admission, and join blocked200/cancel paths. Bind controlled port80 only when free; do not displace existing services. Model/vector passes alone do not establish this I/O proof.

The actual Android factory proof must use saved enrolled credentials, protected scoped TLS, the maintained WebSocket engine owner and the actual desktop attachment. Verify bytes, destination, delayed reply after EOF, bounded backpressure, blocked-write Stop, revocation/expiry and denied destination without fallback. Production app wiring, the v1 freeze, physical USB and the remaining [implementation plan](implementation-plan.md) are separate requirements.
