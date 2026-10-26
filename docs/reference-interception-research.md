# Reference HTTP/H1 HTTPS interception research

Status: assigned on 26 October 2026 after A23 acceptance. This is a new,
reference-only host proof toward selected-UID Android research. It is **not C5**,
not the missing reviewed desktop implementation, not production integration,
and not physical USB acceptance. Existing C5 source pins, methods, reports and
workflow selection remain unchanged. Protocol v1 remains unfrozen.

## First executable checkpoint

Use the existing enrolled origin fixture and its trusted backend-owner API to
forward actual HTTP and intercept actual H1 HTTPS into a distinct authenticated
TLS upstream. First check the self-contained Node backend and authenticated
reference-gateway composition. Kotlin factory composition and a separately
named Android selected-UID runtime are later checkpoints, not implied results.

The fixed destination is `198.18.0.2`, logical host `reference-target.invalid`,
ports 80/443 and path `/reference/proof`. Requests are single `POST` transactions
with explicit bounded Content-Length, no transfer encoding, trailers, upgrades,
pipelining or arbitrary forwarding. Headers and bodies are each at most 4096
bytes; at most two backend owners are admitted. Use maintained Node HTTP/TLS
parsers and bounded backpressure. Do not implement a second general HTTP parser.
No DNS lookup, public listener, management route or arbitrary destination exists.

Port 80 uses the existing `http-origin-connect` proxy mode and capability.
Port 443 uses the existing HTTPS capability with absent proxyMode, **not a new
mode string**. Parse the bounded exact CONNECT preface before any upstream dial;
reject other tuples and mode/capability mismatches. Recheck the supplied
`admissionAllowed()` immediately at actual dial and on asynchronous admissions.
Preserve bytes after a fragmented/coalesced preface, including TLS ClientHello.

For HTTPS, the incoming client trusts only the owned interception CA and checks
hostname/SNI. The interceptor presents its leaf for the fixed host. It then
creates a separate verified TLS connection to an owned origin with a distinct
CA/leaf and matching hostname/SNI. Never disable verification or change global
TLS defaults. A raw tunnel or canned interceptor response is not this proof.
The actual origin computes the fixed response from the actual received body;
interceptor and origin independently record bounded measurements.

## Frozen local module interfaces for parallel implementation

These are private research APIs, not wire-contract changes. The coordinator
owns `reference-interception-contract.mjs` and its tests. That module exports
`referenceInterceptionProfile`, finite `ReferenceInterceptionError(code, joined)`
and `referenceInterceptionResponse(body)` (ASCII `reference-origin:` followed by
the SHA256 hex of the bounded actual body). The origin calls that function only
after actually receiving the complete body. Tests compute the same expected
bytes independently; no interceptor-generated response substitutes for origin I/O.

### A: ephemeral assets

Owner scope: new `reference-interception-assets.mjs` and its `.test.mjs` only.

`createReferenceInterceptionAssets({directory, openssl = 'openssl'})` returns an
owned, redacted object. `directory` must be an absolute, empty, nonsymlink,
private directory. Generate separate P-256 interception and origin authorities
and serverAuth leaves, both leaves for the fixed hostname. CA pathlen/key usage,
leaf constraints, canonical DER, key correspondence and current lifetime must
be checked. No upstream code is copied. Use the existing bounded owned OpenSSL
command runner, and require real child/group closes on every command.

Methods:
- `caDer(role)` returns a defensive public DER copy, role `interception`/`origin`.
- `caPem(role)` returns a defensive public PEM copy.
- `tlsOptions(role)` returns fresh private key/certificate copies and scoped
  TLS1.2/1.3, H1-only server options; trusted host callers only.
- `snapshot()` returns only `commandsStarted`, `commandsClosed`,
  `processGroupsClosed`, `closed` (fixed counts/boolean).
- `close()` is idempotent, resolves the final snapshot and clears owned private
  buffers; no subsequent material access. Caller closes TLS users first.

Every key file is mode0600, parent0700. No key, PEM, digest, path or provider
message is serialized/logged. Failure throws the finite shared error with an
honest `joined` bit; do not remove directories with unjoined children. Successful
caller cleanup removes only its owned directory after all users/children join.

### B: bounded interception backend

Owner scope: new `reference-interception-backend.mjs` and its `.test.mjs` only.

`startReferenceInterceptionBackend({assets})` returns an owner with:
- `factory(context)` producing exactly the existing frozen trusted owner shape:
  `{transport: Duplex, start(): Promise, close(): Promise, closed: Promise}`.
  Context and grant remain private; do not add wire fields or material methods.
  Prefer an owned maintained Duplex pair rather than a new exposed proxy port.
- `snapshot()` with only fixed finite counters/booleans: `ownersCreated`,
  `ownersClosed`, `activeOwners`, `activeSockets`, `activeRequests`, `listeners`,
  `upstreamDials`, `interceptedHttpRequests`, `interceptedHttpsRequests`,
  `upstreamHttpRequests`, `upstreamHttpsRequests`, `interceptionTlsHandshakes`,
  `upstreamTlsHandshakes`, `rejectedPrefaces`, `closed`.
- `evidence()` returns defensive bounded private test measurements, at most two
  successful rows `{mode: 'http'|'https', requestBytes, responseBytes,
  requestSha256, responseSha256}` recorded at the actual origin. Never log or
  publish these traffic digests; public reports use counts/comparison booleans.
- `close()` seals admission, closes all owned users/listeners and resolves only
  after actual socket/callback/request/owner joins. It does not close assets.

Own upstream HTTP and HTTPS listeners bind loopback on ephemeral ports. Only
validated fixed original tuples may map to these owned endpoints. They are not
configurable remote forwarding. No request is dispatched upstream before a
valid complete bounded application request; wrong incoming trust must produce
zero decrypted requests/upstream dispatches. Reject unsupported host/path/method,
headers or extra requests. Return finite errors, retain failed ownership until
joined, and do not swallow failures into successful snapshots. Preserve natural
HTTP upload half-close and complete reply/EOF. TLS clean termination and abnormal
cancellation are distinct; no direct fallback exists.

### C: authenticated composition tests

Owner scope: new `reference-interception-enrollment.test.mjs` only. Reuse real
`startEnrollmentOriginFixture`, owned credential helpers and actual enrolled
control/stream clients. Inject B's factory and A's public interception CA.
Exercise actual HTTP and inner TLS through authenticated gateway streams,
correct separate upstream TLS, exact body/response, both END_WRITEs and remote
COMPLETE/normal-close joins. Test absent/revoked credentials, wrong client trust
and wrong target/refused prefaces without legacy fallback. Assert actual owner,
stream, issuer, registry, socket and process cleanup; retain primary failures.
No new fixture worker IPC, JVM or Android method is assigned at this checkpoint.

## Validation and acceptance limits

A and B run real OpenSSL/TLS/socket tests locally where supported. C requires
the documented pinned Node24.22.1 environment; local Node22 failures must be
retained and not called passing or pre-existing without baseline evidence.
Root integrates reviewed commits, adds exact new tests to existing host CI and
requires fresh source-bound host success before claiming this checkpoint.
No Java/SDK is available locally; no Android execution is inferred.

Retain all old A23, origin, capture and C5 guard tests. Documentation requires
local links and diff whitespace checks. Put any finite deliverable audit directly
in ignored `dist/`, without traffic bytes, fingerprints, identity values or keys.
Actual Android selected-UID, debug-app trust, desktop compatibility, CA settings
installation, H2, physical USB/Wi-Fi-off, protocol freeze and release remain open.
