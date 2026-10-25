# Authenticated public interception CA retrieval

Status: draft revision 0.6, normative for the A23 foundation implementation only.
This specifies the existing `GET /companion/v1/ca` operation in the
[canonical protocol](protocol.md). Enrollment messages, approval fingerprints,
control/stream bytes and draft-0.5 capture modes remain unchanged. Protocol v1
and production app integration remain gated.

## Purpose and ownership

The [security model](security.md#certificate-trust) requires authenticated public
CA download and fingerprint verification. The current HTTPS proof receives the
public CA through private test IPC; that does not implement this endpoint.
A23 must execute the new getter against the actual reference TLS endpoint and
bind its result to the saved approval and current credential. A credential-only
reopen cannot imply interception trust: `EnrolledCredentialRecord` does not
contain the approved interception-CA fingerprint.

Root owns this profile, canonical links, the work board, build/source-root wiring
and reviewed integration. D owns the Android-repository reference HTTPS
listener/assets changes and new `companion-enrollment-ca` Node tests. UI owns new
`DraftInterceptionCa` Kotlin client/binding sources and focused tests. F owns the
independent actual JVM-to-Node TLS proof, its private peer/report and validation
wiring after completing the ordinary `1065657` host audit. Agents use separate
branches/worktrees; root alone changes shared build files and the board.
The reviewed ten-commit desktop checkout at `2ee70e86` remains unchanged.

## Request and admission

Use a fresh scoped TLS connection to the saved gateway identity, with its logical
TLS name and SPKI pin, the current enrolled client credential, and a separately
resolved dial address. Preserve normal hostname, certificate, key-use and validity
checks. The sole request is HTTP/1.1 `GET /companion/v1/ca`, with the exact logical
Host/port, `Accept: application/pkix-cert` and `Connection: close`. There is no
query, redirect, request body, cookie, bearer token, browser Origin, upgrade or
transfer encoding. An absent Content-Length or the single value `0` is allowed.
Reject duplicate headers, trailers and unsupported request framing under the
existing reference listener's header, connection and deadline bounds.

Only the authenticated credential listener serves this route. Its existing
setup listener cannot serve it. On every request, require the actual TLS client
leaf and exact current registry authorization, including current validity and
revocation. Possession of any certificate from the enrollment CA is insufficient.
Do not use a browser cookie, cached admission or a control-session token instead.

## Successful response

Return HTTP/1.1 status 200 with exactly one of each required header:

| Header | Value |
| --- | --- |
| Content-Type | `application/pkix-cert` |
| Content-Length | Canonical positive decimal length in 1..4096 |
| X-FreeKit-CA-SHA256 | Canonical unpadded base64url SHA-256 of the complete DER |
| Cache-Control | `no-store` |
| Connection | `close` |

The body is exactly one canonical DER X.509 interception-CA certificate, with no
PEM, chain, private key or trailing bytes. No Transfer-Encoding, Trailer,
Content-Encoding, Location or Upgrade is permitted. The client bounds headers to
8192 bytes, 32 fields and 1024 bytes per field, rejects duplicates regardless of
case and obsolete folding, reads exactly the declared body, then requires actual
EOF. A redirect or an informational response is not success.

The reference server reads only its retained public CA asset. Before publishing
the response, validate its canonical DER, CA role, self-signature, current
validity and exact equality with the approval metadata's complete-DER hash.
Accept the existing interception-CA algorithms (P-256 or RSA 2048..4096), rather
than imposing the enrollment authority's separate P-256 profile. When KeyUsage
is present it must allow keyCertSign. Existing interception-CA EKU restrictions
remain in force. A changed, corrupt or expired asset fails closed; never update
approval metadata or return an unapproved replacement automatically.

## Client binding and lifetime

Snapshot and validate the saved recovery approval against the current validated
credential before network admission: desktop ID, logical name, gateway pin,
original device SPKI, original Keystore certificate hashes, enrolled leaf hash
and authenticated enrollment-authority hash must match their actual owners.
Original Keystore certificates are distinct from the issued client chain; obtain
their evidence from the existing device identity, not by substituting that chain.
The recovery's credential expiry must match the actual client leaf. Its old
reservation/result-recovery deadlines do not expire an otherwise active saved
credential. An absent or mismatched approval requires explicit repair/re-pairing.

Use only the recovery's authenticated `interceptionCaCertificateSha256` as the
expected CA hash. Require both the response header and the complete received DER
hash to match it. Validate canonical single-certificate encoding, supported key,
self-signature, CA role, keyCertSign when present and current validity. Keep
interception, enrollment, gateway and device keys distinct. Recheck credential
and CA validity before returning a defensive public snapshot. Do not derive a new
trusted fingerprint from the response or change the gateway pin.

The research getter owns one synchronous request at a time, a fresh raw/TLS
socket and its deadlines. Preserve the existing enrollment client's 5-second
connect/handshake/read bounds and a 10-second whole-exchange deadline. Close
interrupts the raw socket, joins the actual call/deadline/TLS-close owners and
retains failed cleanup; requested closure alone is insufficient. Return a result
only after successful framing, binding, EOF and cleanup. No automatic retry,
redirect, fallback, CA installation or persistent trust update is performed.
Exceptions and diagnostics use fixed categories, excluding certificates,
fingerprints, identities, paths, URLs and underlying free-form provider messages.

## Failures and compatibility

Reuse the existing bounded enrollment `pair_error` response encoding and media
type for errors: invalid syntax/framing is HTTP 400 `invalid_message`, denied
registry authorization is HTTP 403 `authentication_failed`, and unavailable
store/CA material is HTTP 503 `pairing_unavailable`. The setup listener continues
to reject this route. A TLS failure may end before any HTTP response. Clients
never accept a non-200 response as public CA material; errors cannot replace the
saved approval or create trust. Preserve existing credential-probe responses,
enrollment messages and cleanup/accounting semantics.

## Required evidence and limits

Meaningful acceptance requires the compiled Kotlin getter over fresh actual
pinned mTLS to the Node reference endpoint, not only a response parser or mock.
Verify the admitted DER/hash and saved-approval continuity after reopen. Cover
wrong gateway identity, missing/revoked/expired/other client leaf, mismatched
approval context, changed CA, malformed/trailing/oversize/wrong-role/expired DER,
duplicate or invalid framing, finite timeout/cancellation and joined cleanup.
Exercise hostile response cases over real TLS and retain exact source/tool/test
provenance. Existing enrollment/stream/capture checks remain required regressions.

This is a software-key host foundation proof and prepared Android research code.
Android Keystore/device execution, user CA installation, production approval
persistence/migration, HTTPS/H2 capture, selected-UID TUN, physical USB, protocol
freeze and the rest of the [implementation plan](implementation-plan.md) remain
separate gates. No emulator, desktop publication or manual runtime is authorized
by this package assignment. A CA change needs fresh authenticated approval and
explicit trust setup; A23 does not implement automatic CA/key rotation.
