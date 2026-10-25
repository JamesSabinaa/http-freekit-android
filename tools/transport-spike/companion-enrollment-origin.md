# Enrolled origin gateway research seam

`startEnrollmentOriginFixture` composes the existing real enrollment issuer and
durable registry with an explicitly injected byte transport. It advertises only
`tcp-http-origin-connect`; a new enrollment request must request that capability.
The approved record retains the actual requested/supported intersection. The
existing enrollment fixture defaults remain the two legacy capabilities.

The wrapper's public metadata is the existing enrollment metadata plus
`webSocketPort`. It accepts no research scenario header, exposes no research
probe/command HTTP routes, and starts no fixed-payload proxy listener. A legacy
open is rejected before calling the injected factory when no legacy capability
was negotiated. The [draft0.5 mode and destination contract](../../docs/protocol-http-origin.md)
governs the bytes carried by the injected transport.

The trusted synchronous `trustedProxyFactory(context)` returns exactly these own
data properties:

```js
{ transport: byteDuplex, start: () => Promise, close: () => Promise, closed: Promise }
```

The gateway retains the owner and transport before starting asynchronous work.
`close()` must synchronously seal admission and interrupt owned I/O, then return
its actual join promise. Startup settlement, that promise, `closed`, transport
closure and gateway workers all precede model resource confirmation. Failed joins
retain the model lease and fail cleanup. The gateway snapshots validated methods
before any asynchronous startup boundary.

Only the trusted composition initiates a normal WebSocket Close after both queue
writers and both typed END_WRITE tasks actually complete with model phase closing.
Server- and peer-initiated paths share one owned close-write receipt. An actual
valid peer Close response is still required before model confirmation; an EOF or
abort cannot substitute for that response. The legacy finite fixture retains its
existing peer-initiated close behavior.

The frozen context has `proxyMode`, a copied frozen `negotiatedCapabilities`,
`grant` and `admissionAllowed`. `grant` is the existing redacted public snapshot;
its explicit defensive `material()` returns only the six validated registry grant
fields. It adds no capability or destination ACL field to `authorizeCertificate`.
`admissionAllowed()` synchronously rechecks the current exact issued leaf, durable
registry, session clock and owner state, returning an exact boolean. A real
backend must combine it with an exact numeric destination policy before actual
connection and subsequent application-write admissions. Capability compatibility
does not confer destination permissions.

The local tests use real issuer/registry/mTLS and an owned real TCP byte transport
to verify negotiation, revocation, startup cancellation, joins and END_WRITE.
Their controlled upstream is a seam check. Acceptance of the real desktop
attachment, capture, original numeric destination and origin HTTP requires a
separate explicit desktop binding. No desktop source is copied here, and no
Android enrollment, Keystore or socket-protection claim follows from these host
software-key checks.

## Explicit real desktop binding

`createDesktopOriginBackend` in gateway-origin-desktop.mjs requires an absolute
local `desktopRoot`, exact40-hex `desktopCommit`, synchronous destination policy
and optional private capture callback. It validates the exact clean tracked Git
tip using joined bounded commands before importing that checkout's actual
ProxyServer. It starts no desktop listener. Each factory admission owns a bounded
in-process byte-duplex pair and the real trusted HTTP-origin attachment; strict
current registry/session admission is combined with exact destination policy.

The adapter retains public write/end callback owners until their callback or an
actual socket close cancels them with a fixed error. A close never becomes a
successful write receipt. Either pair endpoint's actual close seals/interrupts
the whole attachment. Owner and independent ProxyServer teardown start together,
and every actual join must settle successfully.

The explicit local suite requires FREEKIT_DESKTOP_ROOT and defaults its reviewed
tip to fd63f6940226c8e3401a165082dfa9325abaca69 (override only with an explicitly
reviewed FREEKIT_DESKTOP_COMMIT). Invoke Node with --test and
tools/transport-spike/gateway-origin-desktop.local.test.mjs. It is outside the
ordinary hosted globs while the desktop dependency is unpublished; missing or
dirty/wrong source fails rather than skips. Port127.0.0.2:80 must be free; collision
refuses setup without displacing another service. Coordinate this port with other
local factory tests.

The real local checks establish numeric80 routing with an unchanged logical Host,
actual HTTP capture and full response/END_WRITE, exact destination denial without
origin egress, and durable registry revocation with attachment/model joins. They
use software test keys, with no Android/Keystore/protect/TUN inference. The
[Android proof contract](../../docs/android-capture-factory-runtime.md) specifies
the separate actual device gate.

## Private public-CSR fixture

The explicit local gateway-origin-fixture.mjs starts the real enrollment gateway,
that pinned desktop attachment and the fixed127.0.0.2:80 origin. Arguments are
exactly --desktop-root ABSOLUTE_PATH --desktop-commit COMMIT_SHA (as separate values).
OPENSSL_BIN selects the checked local OpenSSL3 executable. Its90-second lifetime
and fixed origin admission refuse collisions; it does not replace a listener.

The JVM retains its software P256 private key and sends only its real CSR through
private stdin. Lines are compact ASCII JSON followed by LF, at most8192 bytes;
total input is at most32768 bytes and eight commands. Unknown, duplicate,
noncanonical or extra fields fail with a static record. Operations are:

| Input | Explicit stdout result |
| --- | --- |
| Startup | event ready, public nine-field metadata and exact desktopCommit |
| {"op":"enroll","csrDer":"canonical-base64url"} once | event enrolled, actual approved DTO and public metadata |
| {"op":"release"} once | event released after the actual END_WRITE/tail boundary |
| {"op":"snapshot"} | event snapshot with bounded primitive counts/flags/hashes |
| {"op":"stop"} | event closed with actual final joins and private-directory removal |

Every envelope contains format http-freekit-origin-gateway-fixture and revision1.
Enrollment is the actual explicit local approval/issuer/registry path; its
capability intersection is new-only. Public DER/approved material is an explicit
private IPC result, never a default log or artifact. Stdout and stderr must remain
private in its caller. No private signing key leaves the JVM or enters arguments.

The origin accepts only the exact Android contract request/body. It writes a4096
response-body prefix, then holds the remaining tail. Release has a five-second
observational bound and requires the actual gateway client END_WRITE, empty
pending ingress/write, and actual desktop-facing drained read EOF. Its poll task
and timer are owned and joined. No phase or write callback is remote consumption
proof. Response body bytes/hash and strict application EOF remain independently
checked. Ordinary snapshot inspection contains no identity, endpoint, path, key,
header, certificate or traffic body.

The one gatewayStreamComplete boolean additionally requires the original actual
stream phase complete, resourcesReleased true and streamLease false; it is an
inert projection after actual normal-close and resource joins, not a close request.

The explicit gateway-origin-fixture.local.test.mjs verifies that held boundary,
full response/END_WRITE, actual public-CSR child IPC and negative command cleanup.
Run it separately from the other port80 group; neither belongs to the default
host globs before the desktop publication gate.

The existing private EnrollmentRuntimeWorker also accepts startOrigin with only
desktopRoot, desktopCommit and openssl, and releaseOriginTail with no arguments.
Existing metadata/invitation/registration/approval/snapshot/close operations reuse
the same child and reserved cleanup slot. Legacy starts keep their original
schemas. Origin close projects the actual origin plus enrollment resource counts,
issuer/store/listener joins, privateDirectoryRemoved and gatewayStreamComplete;
it waits all pending business replies before actual child/stdio/group closure.
The explicit gateway-origin-worker.local.test.mjs exercises this same owner,
without a second process framework or an optional skipped acceptance path.
