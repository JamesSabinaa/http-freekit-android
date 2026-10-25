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
