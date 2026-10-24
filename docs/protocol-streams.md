# Draft control and stream grammar (A19)

Status: normative appendix to [the canonical companion draft](protocol.md), revision **0.3**, not a frozen production contract. The existing pairing/enrollment proposal is unchanged. Kotlin and Node implement this appendix against one conformance corpus before an authenticated WebSocket streaming proof. No production gateway or capture integration may infer a full v1 freeze from those checks.

## Scope and transport boundary

One mutually authenticated control WebSocket owns a short-lived session. Each proxy flow uses its own mutually authenticated stream WebSocket and the same registry-authorized device. The HTTP upgrade must validate `X-FreeKit-Session`, containing exactly the session ID below, against that device's active control session. Never accept it in a URL or as a desktop-management credential. Registry authorization, TLS, Origin rejection, gateway/proxy socket ownership and timers remain adapter responsibilities; a pure codec or lifecycle model does not establish them.

The lifecycle owner receives a **trusted local device ID**, expected paired desktop ID, shared budget pool and injected clock. Neither a message nor a caller-supplied destination can select that identity or an arbitrary upstream. The gateway connects streams only to its configured local proxy. HTTP bytes use absolute-form original-IP URLs with the original logical Host; CONNECT uses the original IP authority and preserves subsequent TLS bytes. Actual destination policy is enforced at the desktop proxy's connection boundary.

Trusted local device/desktop identifiers use `[A-Za-z0-9_-]{1,128}`. The local implemented-capability collection contains 0–16 unique names with the capability syntax below and is defensively snapshotted; duplicate/excess local values are configuration errors, not silently deduplicated. Empty local support is permitted so negotiation can reject unsupported requirements cleanly, but it can never establish a traffic session without an implemented HTTP/CONNECT capability. This local constructor rule does not define or change enrollment wire fields.

The model observes `client` and `gateway` directions. It performs no I/O and starts no hidden timer. Adapters serialize operations on one owner, run deadline ticks even without input, and close/cancel real resources before confirming closure. A model pass is not network, threading, cancellation or total-process-memory evidence.

## Text decoding

Every application text message is one complete UTF-8 JSON object, 1–16384 encoded bytes inclusive. Reject invalid UTF-8, an initial UTF-8 BOM, trailing non-whitespace, comments, duplicate object members (including escape-equivalent names), unknown fields, and missing fields. Standard JSON whitespace, field order and valid string escapes are accepted. There is no canonical-byte restriction or JCS claim. Encoders produce compact JSON with lexicographically sorted keys and sorted capability arrays for deterministic output; decoders accept the other valid representations.

Before constructing a JSON tree, bound nesting to **three containers** (root depth 1), object members to **16 per object**, and each encoded object-key token to **256 bytes**. A quote/escape-aware structural pass must preserve duplicate-key evidence and reject excess depth before a recursive parser runs. Use the established JSON library for syntax and string decoding; do not create a permissive alternate JSON parser. Strings in this grammar are ASCII identifiers, capability/error codes or fixed UTC dates, not human display names. This restriction does not narrow the existing pairing parser's display names.

All numeric tokens in these messages must use integer spelling `0` or `[1-9][0-9]*`; reject negative forms, `-0`, fractions and exponent forms, including `1.0` and `1e0`. Schema bounds below are checked without numeric overflow or JavaScript precision loss. Booleans, nulls and numeric strings do not substitute for integers. Reject duplicate keys and malformed syntax as `invalid_message` before interpreting the version. After complete schema validation, a well-formed positive version other than 1 yields `unsupported_version`.

Common fields and values:

| Field | Rule |
| --- | --- |
| `protocolVersion` | Required integer 1; syntactically valid versions 2–2147483647 yield `unsupported_version` after schema validation |
| `type` | Exact lowercase literal from the applicable table |
| `desktopId` | `[A-Za-z0-9_-]{1,128}`, equal to the locally paired desktop when accepting readiness |
| `streamId` | `[A-Za-z0-9_-]{1,64}`, opaque within one session |
| `sessionId` | Canonical unpadded base64url of exactly 32 bytes (43 characters); production issuance requires a CSPRNG |
| `expiresAt` | Exact `YYYY-MM-DDTHH:MM:SSZ`, valid Gregorian UTC date in years 2000–2099; no fractions/offsets/normalization |
| Capability | `[a-z][a-z0-9-]{0,31}`; arrays contain 1–16 unique strings unless explicitly allowed empty |

All fields in each table row are required and no others are allowed. Schema-invalid fields take precedence over `unsupported_version`. Unknown message types are `invalid_message`. Malformed/oversized input produces only a fixed code; exceptions, close reasons and default object/string representations must omit raw input, payloads, session IDs and identity material. Explicit wire encoding/header access is allowed to return the intended credential; it must not be default diagnostic output.

## Control messages

| Type | Sender | Fields in addition to `protocolVersion`, `type` |
| --- | --- | --- |
| `hello` | client | `capabilities`, `requiredCapabilities` |
| `session_ready` | gateway | `capabilities`, `desktopId`, `expiresAt`, `limits`, `sessionId` |
| `cancel` | client | none |
| `disconnect` | gateway | `code` |
| `error` | gateway | `code` |

`hello.capabilities` lists what that client actually implements. `requiredCapabilities` is a unique subset, may be empty, and is bounded to 16 entries. Unknown optional capability names can be offered and omitted from the result. An unknown or unsupported **required** capability fails negotiation with `unsupported_capability`. Initial reference implementations support `tcp-http` and `tcp-https-connect`; they must not advertise app selection, direct WAN or other unimplemented features. Supported sets are trusted constructor inputs, allowing later implementations to negotiate deliberately.

The codec accepts any capability name matching the common syntax, including unknown names. Required-subset and uniqueness are schema checks; support/negotiation checks belong to the lifecycle owner after version validation. A codec acceptance is not negotiated feature support.

`session_ready.capabilities` is nonempty, unique, a subset of the client's offer and the local implemented set, and contains every required capability. An unoffered result is `invalid_message`; an unsupported result or unsatisfied requirement is `unsupported_capability`. A desktop-ID mismatch is `authentication_failed`. Its expiry must be strictly later than the current UTC instant and at most 1800 seconds later. An elapsed expiry yields `session_expired`; an invalid/far-future interval yields `invalid_message`. At least one actual HTTP/CONNECT capability is required for this traffic session.

For simultaneous readiness defects after successful decoding/version checks, apply this exact order: sender/phase; paired desktop identity; readiness expiry interval; unoffered capabilities; unsupported/missing-required/no-HTTP capabilities; negotiated frame size fitting the trusted global byte ceiling; session-lease acquisition. The first failing check supplies the code. Schema/calendar defects still precede version and lifecycle checks as specified above.

The exact `limits` object contains:

| Key | Negotiated bound | Default |
| --- | --- | --- |
| `maxFrameBytes` | 1–65536 | 65536 |
| `maxQueuedBytesPerStream` | `maxFrameBytes`–1048576 | 1048576 |
| `maxQueuedBytesPerDevice` | `maxQueuedBytesPerStream`–4194304 | 4194304 |
| `maxConcurrentStreams` | 1–64 | 64 |
| `maxQueuedFramesPerStream` | 1–64 | 64 |
| `maxOpenedStreamsPerSession` | `maxConcurrentStreams`–4096 | 4096 |

The gateway may negotiate lower values. These limits bound application queues/leases, not TLS, WebSocket library, kernel or native-engine buffers. Global trusted pool limits default to 16 live session leases, 256 stream leases and 16777216 queued/in-flight application bytes, with configurable positive lower limits only. The negotiated `maxFrameBytes` must fit the configured global byte limit. Configuration cannot raise any hard ceiling. Slot and byte checks use overflow-safe accounting, shared across every owner using that pool.

`disconnect.code` is exactly `desktop_stopped`, `device_revoked` or `session_expired`. `error.code` is one of `unsupported_version`, `unsupported_capability`, `authentication_failed`, `device_revoked`, `proxy_unavailable`, `session_limit`, `stream_limit`, `invalid_message`, `network_unreachable`, `session_expired`. These codes add explicit draft errors to the root proposal; they are not free-form explanations.

Control phases are `awaiting_hello`, `awaiting_ready`, `active`, `closed`, `failed`:

1. Client `hello` is accepted once in `awaiting_hello`, moving to `awaiting_ready`. Validate required-capability support at this point.
2. Gateway `session_ready` is accepted once in `awaiting_ready`, validates negotiation, identity, time and limits, then acquires a session lease and becomes `active`. A pool already holding that trusted device's live session lease, or its global session ceiling, refuses the new session as `session_limit`; it never evicts another owner.
3. Gateway `error` is allowed in `awaiting_ready` or `active` and fails that session with its code. Client `cancel` is allowed in either phase and closes it. Gateway `disconnect` is allowed only in `active` and closes it with the stated code. All invalidate their nonterminal streams immediately, prohibit new streams and stop forwarding; queues/leases are retained until closure is confirmed below.
4. Wrong direction/order or any application message after a terminal phase returns `invalid_message`. A terminal phase/cause never revives or gets replaced by a subsequent malformed message. Repeated closure confirmation is idempotent.
5. A `ws_closed(code)` observation without an earlier cancel/disconnect/error fails the control session as `network_unreachable` and invalidates its streams. This does not release its lease. `resources_closed()` confirms actual control resources have closed; the control lease is released only after this confirmation **and every stream's resource closure**. Then its bounded stream-ID history is discarded. A reconnect creates a new session and never replays accepted HTTP bytes.

Control client cancellation invalidates owned streams as `cancelled` with local cause `cancelled`; `desktop_stopped` disconnect does so with cause `desktop_stopped`. Revocation/expiry disconnect and control errors fail streams with the corresponding fixed cause. Clock/deadline/protocol control failures likewise fail nonterminal streams with the controller's cause. Already terminal streams retain their earlier cause. These are local invalidation outcomes, not permission to send a stream error with a code outside its wire enum.

## Stream messages and ordered bytes

| Type | Sender | Additional fields |
| --- | --- | --- |
| `open` | client | `streamId` |
| `ready` | gateway | `streamId` |
| `end_write` | either | `streamId` |
| `cancel` | either | `streamId` |
| `error` | either | `code`, `streamId` |

`error.code` is `proxy_unavailable`, `stream_limit`, `invalid_message`, `network_unreachable`, `device_revoked` or `session_expired`. A stream error affects that stream; a control error/closure affects its entire session. All stream messages must match the stream's accepted ID after open. A client-supplied proxy/destination address or session ID in JSON is an unknown-field error.

Create a pending stream only after checking the presented session header against the active session and trusted authenticated device, using a timing-safe equal-length token comparison. A wrong token/device yields `authentication_failed`; an expired session yields `session_expired`; an otherwise inactive session yields `authentication_failed`. A valid attempt first reserves a stream lease, counting against the device's negotiated concurrent ceiling and the global ceiling, **including pending and closing streams**. A refused allocation returns `stream_limit`, changes no existing owner, and creates no lease. Adapters must also bound pre-authentication/upgrade work; these application leases do not bound unauthenticated HTTP sockets.

Fresh clock/deadline failures take precedence on admission, returning the newly detected `invalid_message`, `network_unreachable` or `session_expired`. If the controller was already inactive/terminal, its stored `session_expired` cause yields `session_expired`; another cause yields `authentication_failed` without replacing it. Wrong credentials or capacity refusal must not fail or otherwise mutate an existing active owner or another owner's counters, apart from legitimate clock/deadline checks. This is an admission exception to the generic terminal-operation rule. Control cancellation has phase `closed`, cause `cancelled`; successful stream completion has cause null.

Stream phases are `awaiting_open`, `awaiting_ready`, `open`, `half_closed`, `draining`, `closing`, `complete`, `cancelled`, `failed`:

1. `open` is the only first application event. It binds the stream ID, claims it in that session's history and moves to `awaiting_ready`. An already used ID is `invalid_message`, even after its old stream completed. Otherwise a full `maxOpenedStreamsPerSession` history yields `stream_limit`. Only successfully accepted opens claim IDs; history is bounded and retained until the session lease is released.
2. Gateway `ready` is allowed once in `awaiting_ready`, after the configured proxy is available, and moves to `open`. No binary bytes or END_WRITE are allowed before ready. Duplicate open/ready is `invalid_message`.
3. After ready, a binary message carries 1–`maxFrameBytes` opaque bytes in its sender's direction. Empty or oversized messages are `invalid_message`. Preserve ordering and exact bytes; do not inspect, log, replay or inject control JSON into the byte stream.
4. Each direction has an ordered queue. Accepted bytes are copied/snapshotted, and both queued and in-flight bytes remain charged until the local writer confirms their actual delivery through a positive `drain(direction, count)` acknowledgement. `peek(direction, count)` accepts an integer count from 1 through negotiated `maxFrameBytes` and returns a defensive copy of exactly `min(count, outstanding directional bytes)`, spanning queued message boundaries and empty only when no bytes remain. It releases nothing and records no progress. Exactly one writer per direction may consume this prefix. An invalid peek count, a drain above the outstanding count, a nonpositive drain, or invalid direction is `invalid_message`. This is a **local writer acknowledgement**, not a new wire ACK or proof that a remote target consumed an HTTP request.
5. The combined two-direction byte count obeys the per-stream, per-device and global limits. At most `maxQueuedFramesPerStream` accepted messages may remain partially or wholly queued across both directions. A byte or frame reservation that cannot fit returns local `backpressure`, with no protocol-phase, payload, budget-counter, progress/deadline or history mutation. Clock validation still records its last-observed monotonic watermark; that bookkeeping never counts as progress or extends a deadline. It is not a wire error and must not drop/accept the offered bytes. The adapter retains at most one bounded pending message, pauses its reader/writer and retries that same unaccepted message after space is available, within the existing deadline. Only a successful drain or confirmed abort releases a reservation. Account for partial drains without premature frame release.
6. `end_write` is allowed once per direction after ready. It seals that direction immediately against more binary data while leaving the other direction usable. Its directional write-EOF effect is emitted **once, after all earlier bytes in that direction are drained**. When exactly one direction is sealed, phase is `half_closed`. When both are sealed but bytes remain, phase is `draining`; when both queues are empty and their EOF effects emitted, phase is `closing`. A duplicate END_WRITE or binary after it is `invalid_message`.
7. `cancel` or `error` is allowed in `awaiting_ready` or after ready, including `closing`, and makes the stream `cancelled` or `failed`. Protocol/schema/order failures also fail only that stream. No further forwarding or EOF effect may occur after terminal failure/cancellation. Existing reservations remain until actual resource closure, avoiding admission beyond real closing resources. Repeated text cancel/error is an invalid terminal message, not a second release.
8. `ws_closed(code)` records the actual WebSocket close, with an integer local observation code 1000–4999 (including library abnormal-close sentinels). Only code 1000 in `closing`, with both queues drained and both EOF effects emitted, is eligible for success. It stays in `closing` with `webSocketClosed=true`, retaining its slot until resources close. A premature/non-1000 observation fails it as `network_unreachable` unless an earlier failure/cancellation already supplies its cause. A repeated identical observation is idempotent; a conflicting code fails a nonterminal stream as `network_unreachable`. No wire/queue forwarding operation is allowed after WebSocket closure.
9. The separate `resources_closed()` confirmation means the adapter has closed its WebSocket and local proxy/native sockets, discarded owned queued/in-flight buffers, and joined its owned writers. It releases bytes/frames/slot exactly once. A valid normally closed stream becomes `complete` only at this confirmation, with session/clock/deadline checks still satisfied. Confirmation without a prior WebSocket-close observation implies an abnormal close and fails as `network_unreachable`, but still releases. Already failed/cancelled streams retain their cause. Repeating confirmation is harmless. No model event pretends that setting a flag closes real sockets.

On terminal cancellation/failure, `peek`, drain, binary, text and EOF propagation cannot continue; only ticks/snapshots and idempotent closure confirmation are allowed. The snapshot continues reporting charged bytes/frames/leases until confirmed closure, then reports zero resources and its original terminal phase/cause. Successful completion cannot be inferred from HTTP-looking response bytes, EOF in one direction, a WebSocket upgrade or a timeout.

Valid bounded peek is allowed before stream open/ready as a local inspection of its empty queue. It still checks the existing session/handshake clocks, never counts as progress and cannot extend the handshake. It does not authorize binary data or END_WRITE before ready. A drain without outstanding bytes remains invalid.

A trusted local cancellation operation is also allowed in any nonterminal control/stream phase, including before hello/open. It has the same local cancellation/invalidation result without inventing a pre-open wire cancel. It must still close real resources and confirm their release. The first *wire* message rules above remain unchanged.

## Clocks, deadlines and event precedence

Inject safe-integer UTC epoch milliseconds and nonnegative safe-integer monotonic elapsed milliseconds from a control-owner-local origin. Its streams share that control clock domain; separate control owners do not compare their watermarks. All checks are deterministic and use the same supplied pair for one operation. A monotonic value below the last observed value fails the affected session as `invalid_message`; UTC moving backward never extends a previously established deadline. Use overflow-safe subtraction/comparison. Invalid local clock values fail the affected session with the same fixed code.

- Control application handshake: 15000 monotonic ms from control-owner creation through accepting readiness; hello does not restart it.
- Session lifetime: accepting readiness fixes a monotonic deadline from the lesser of its remaining UTC lifetime and 1800000 ms. Expire when either UTC reaches `expiresAt` or monotonic time reaches that fixed deadline.
- Active control liveness: maintain last valid activity from **each** direction, initialized on readiness. An accepted control message or explicit observed WebSocket ping/pong from that sender updates its timestamp. If either direction has no such activity for 60000 monotonic ms, fail the session as `network_unreachable`. Adapters send ping at most 20000 ms apart and validate WebSocket ping/pong with their established library. Stream traffic does not keep a dead control channel alive.
- Stream open/ready handshake: 15000 monotonic ms from stream lease creation. After ready, 60000 ms without an accepted text/binary event or positive actual writer drain fails that stream as `network_unreachable`. Backpressure, peeks, rejected input and polling do not reset a deadline. Session termination/expiry also invalidates its streams immediately.

Every event, including binary, peek, drain, allocation and explicit tick, first checks clocks and existing session deadlines, then stream deadlines, before decoding/applying new input. If expiry and idle coincide, `session_expired` wins. Once terminal, preserve its original cause; subsequent events return a fixed invalid-operation result without mutating it. For live text events, decoding precedence is size, UTF-8/BOM/structural/syntax/duplicate/integer/schema validity, version, direction/order/identity, then negotiation/resource checks. Oversize text is `message_too_large`; other decoding defects are `invalid_message`. For valid binary offers, schema/size and sealed-direction checks precede capacity/backpressure. Timeouts and invalidations retain resources until confirmed closure.

Snapshots are inert immutable inspection: they read no clock, apply no deadlines and change no state. A snapshot alone is not authorization to forward bytes; operational methods still check time. Ticks/snapshots and repeated closure confirmations on terminal owners succeed without reviving them; other terminal operations return `invalid_message` without replacing the stored cause. Closure confirmation always performs its idempotent release, even if that event also detects expiry, a deadline or bad clock. Such a time failure prevents normal completion but can never prevent cleanup. A control tick checks all its owned stream deadlines as well as its own. A stream operation checks its bound session before its own deadline; it cannot use an otherwise expired/closed session merely because no control tick ran.

If a stream was already terminal before a new wire/queue/local-cancel operation, its result remains `invalid_message` even when the same call newly expires/fails its still-active controller. The controller's clocks are still checked and may invalidate other nonterminal streams; the already-terminal stream preserves its own earlier cause. This differs from a previously live stream, whose newly detected time failure is the operation result.

WebSocket-close observation and full resource confirmation are deliberately separate, so stalled cleanup cannot free capacity or count as completed shutdown. A control resource confirmation without a preceding close observation also implies an abnormal control close, invalidating its streams, before checking whether its lease can be released. Repeated identical WebSocket-close observations on controls are idempotent; other observations never replace an existing terminal cause. After a normal stream close observation, ticks and trusted local cancellation/cleanup remain possible; new wire or queue operations fail that still-nonterminal stream as `invalid_message`.

## Conformance corpus and test adapter contract

F owns `protocol/fixtures/a19-draft-0.3/manifest.json`, `codec.json` and `lifecycle.json`. Each envelope identifies `format: "http-freekit-a19"`, `revision: "0.3"` and its kind; the manifest lists unique codec/lifecycle case IDs. Both implementations must execute every manifest ID exactly once, reject missing/extra/duplicate IDs, and print corpus SHA-256 and executed IDs/counts. These committed, synthetic fixtures contain no usable credentials and are separate from the pairing fixture revision.

Codec cases specify channel (`control` or `stream`), exact byte input and expected normalized message or fixed error. Normalization sorts object keys and capability arrays but retains actual values. Input is `wireHex`, or a single bounded descriptor with `prefixHex`, `repeatHex` (one byte), `repeatCount`, `suffixHex`. Rendered inputs are capped at 65537 bytes; only tests may construct those over wire limits. Include malformed UTF-8/BOM, whitespace/reordered/escaped valid members, escape-equivalent duplicate keys, depth/member limits, number spelling/overflow, exact field/array/date/base64 bounds, wrong channel/type, unknown required versus optional capabilities, version precedence, and exact size boundaries.

Lifecycle fixtures provide a trusted local pool configuration, initial UTC/monotonic clock, local supported capabilities/expected desktop/device IDs, and ordered operations. F defines the small operation names and expected normalized snapshot fields consistently with this appendix before codec owners write their adapters. They must cover normal and reversed directional EOF, deferred EOF behind bytes, empty/oversized/before-ready/after-END binary, duplicate/wrong-ID/direction/order text, cancel/error/close paths, session/header/device mismatch, expiry/idle/handshake boundaries and wall-clock rollback, cross-owner global/device/stream byte and slot contention, partial drains, bounded frame/history counts, and resource retention/release through confirmed closure.

Fixtures and adapters must not compute expected results by calling either implementation. Limit each corpus file to 2 MiB, 256 cases and 2048 operations per lifecycle case. Large payloads use the bounded one-byte-repeat descriptor; no generic executable fixture language is allowed. Explicit multi-owner interleavings prove model accounting, not real concurrency. Meaningful host tests additionally check immutable/defensive payloads, secret-free diagnostics and independent queue ownership. Actual authenticated WSS gated streaming, backpressure and cancellation remain required after corpus agreement.
