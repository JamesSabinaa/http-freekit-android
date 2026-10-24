# A19 draft 0.3 conformance adapter

This document specifies the synthetic test adapter for the [normative draft grammar](../../../docs/protocol-streams.md). It adds no application wire fields, network behavior, or production freeze. Kotlin and Node implement the grammar independently; fixtures must never derive their expected outcomes from either implementation.

## Files and bounds

The three UTF-8 JSON files are `manifest.json`, `codec.json`, and `lifecycle.json`. Each has exactly `format: "http-freekit-a19"`, `revision: "0.3"`, and its respective `kind` (`manifest`, `codec`, or `lifecycle`). The manifest additionally contains `codecIds` and `lifecycleIds`; the other envelopes additionally contain `cases`.

Case IDs match `[a-z][a-z0-9-]{0,79}`, are unique across both kinds, and are listed lexicographically in each manifest array. Case arrays follow that order exactly. Reject missing, extra, or duplicate IDs. Each file is at most 2 MiB; each case array contains 1–256 cases; a lifecycle case has 1–2048 steps. JSON object member names in corpus files must also be unique. Unknown adapter fields are errors rather than optional extensions.

Byte inputs have exactly one of these shapes:

```json
{"wireHex":"010203"}
```

```json
{"prefixHex":"01","repeatHex":"00","repeatCount":3,"suffixHex":"02"}
```

Hex strings contain an even number of lowercase hexadecimal digits, including an empty string where permitted. `repeatHex` is exactly one byte. `repeatCount` is an integer from 0 through 65537. Check the rendered length before allocating: it must not exceed 65537 bytes. No other generator, executable expression, file reference, or network input is allowed. These limits allow negative wire-size tests without unbounded fixture allocation.

## Codec cases

A codec case has exactly `id`, `channel` (`control` or `stream`), `input` (the byte input above), and `expect`.

An accepted outcome is `{"code":"ok","message":<normalized message object>}`. A rejected outcome is exactly `{"code":<fixed decoding code>}`. Decoding codes include the draft's local `message_too_large`, `invalid_message`, and `unsupported_version`; they do not expand a wire error enum.

Normalized objects have lexicographically sorted keys; capability arrays are sorted lexicographically. Preserve all actual field values, including timestamps and integer values. No exception text or supplied raw input belongs in a rejected outcome. The expected normalized message is fixture data, not a decode/re-encode oracle supplied by either implementation.

## Lifecycle inputs

A lifecycle case has exactly `id`, `pool`, `initialClock`, `controls`, and `steps`.

- `pool` has `maxSessions`, `maxStreams`, and `maxBytes`: valid trusted positive lower-or-equal limits for the draft's 16/256/16777216 ceilings. Fixtures do not raise those ceilings.
- A clock has `utcMillis` and `monotonicMillis`, represented as nonnegative safe JSON integers. Every operational step uses its explicit `clock` when present, otherwise the unchanged `initialClock`. There is no implicit clock advancement. Separate controllers do not compare their monotonic watermarks; all streams of one controller share its origin and watermark.
- `controls` maps fixture references to trusted constructor inputs: exactly `deviceId`, `desktopId`, and `supportedCapabilities`. A definition is instantiated only by `create_control`.
- Control and stream references match `[a-z][a-z0-9-]{0,39}` and are immutable adapter-local handles, not wire IDs or credentials. A successful allocation retains its stream reference for later inert inspection even after release. A refused allocation creates no reference or lease. References may not be reused for a different object.
- Every step contains `op`, its operation fields below, and `expect`. A `clock` is optional on operational steps and forbidden on inert `snapshot`. No other fields are accepted.

| `op` | Operation fields | Meaning |
| --- | --- | --- |
| `create_control` | `control` | Construct that unused trusted definition with the supplied clock and shared pool. |
| `control_text` | `control`, `direction`, `input` | Apply one complete control text message from the stated sender. |
| `control_activity` | `control`, `direction` | Observe a WebSocket ping/pong already validated by the transport library; no invented wire message. |
| `allocate_stream` | `control`, `stream`, `deviceId`, `sessionHeader` | Attempt admission using the separately authenticated device and presented session header. |
| `stream_text` | `stream`, `direction`, `input` | Apply one complete stream text message. |
| `binary` | `stream`, `direction`, `input` | Offer the exact rendered opaque bytes; accepted bytes must be snapshotted. |
| `peek` | `stream`, `direction`, `count` | Return up to `count` actual prefix bytes defensively without draining. |
| `drain` | `stream`, `direction`, `count` | Confirm actual local writer delivery of that outstanding prefix. |
| `local_cancel` | exactly one of `control`, `stream` | Trusted local cancellation, including before the first wire message. |
| `tick` | exactly one of `control`, `stream` | Evaluate deadlines; a control tick also evaluates owned stream deadlines. |
| `ws_closed` | exactly one of `control`, `stream`; `closeCode` | Observe actual WebSocket closure, without confirming other resources or releasing reservations. |
| `resources_closed` | exactly one of `control`, `stream` | Confirm all that object's owned sockets, buffers, and writers are closed/discarded/joined. |
| `snapshot` | none | Inspect all created objects and the pool; do not read/update clocks or run deadlines. |

`direction` is passed unchanged to the implementation: valid values are `client` and `gateway`, while negative fixtures may supply another bounded ASCII string. `count` is a safe integer in -1–16777217 so negative and over-limit operations can be represented without allocation. `closeCode` is an integer in 0–65535. `input` uses the same bounded byte shapes as codec cases. An operation on an absent fixture reference is a corpus error, not a fabricated protocol outcome.

Peek's valid count is 1–negotiated `maxFrameBytes`; it may return fewer or zero outstanding bytes. Invalid peek/drain parameters fail the stream as specified. Peek preserves byte/frame reservations, progress, and deadlines. Queued and in-flight application bytes remain charged until positive actual drain or confirmed resource closure. A partial drain frees only its byte prefix; a frame remains charged until its entire accepted message is drained.

`ws_closed(1000)` on a valid `closing` stream sets its WebSocket flag but leaves its phase `closing`. Only subsequent `resources_closed`, with a still-valid session/clock, completes it and releases the lease. A premature/abnormal close fails it while retaining reservations. Resources confirmation without a prior WebSocket close is abnormal, but still releases. Same-code WebSocket-close observations are idempotent; a conflicting code fails a nonterminal object as defined by the draft. Resource confirmation is idempotent and cannot be blocked by expiry or clock failure. Control resource closure releases its session lease only after every child stream also releases; only then is its stream-ID history discarded.

## Operation outcomes and snapshots

An operation's expected/actual outcome has exactly `code`, `effects`, and `snapshot`; a successful `peek` additionally has `peekHex` containing its actual returned bytes. Other outcomes omit `peekHex`.

`code` is `ok`, local `backpressure`, or a fixed rejection/deadline code. New input/admission operations return a newly detected clock/deadline/rejection code. An object already terminal returns its specified terminal-operation code without replacing its stored cause. Admission has the explicit exceptions: stored/new `session_expired` returns `session_expired`; another inactive controller returns `authentication_failed`. Wrong-token/device or capacity refusal does not fail an otherwise active owner or evict another lease.

For test-adapter normalization, `tick`, `ws_closed`, `resources_closed`, and inert `snapshot` report `ok`; their phase/cause/counter changes carry any observed failure. These wrapper outcomes do not prescribe a core public return type or wire response. Control cancellation has phase `closed`, cause `cancelled`; successful stream completion has cause `null`.

`effects` contains only EOF effects emitted by that operation, each exactly `{"type":"write_eof","stream":<fixture reference>,"direction":"client"|"gateway"}`. Sort by stream reference, then direction. A sealed direction emits it once only after earlier bytes drain. Cancellation/failure prevents subsequent forwarding/EOF effects; retained buffers are not drained by inspection or cancellation.

The full immutable `snapshot` has exactly these fields:

```json
{
  "pool":{"sessionLeases":0,"streamLeases":0,"chargedBytes":0},
  "controls":{},
  "streams":{}
}
```

`controls` maps each created fixture reference to exactly:

```json
{"phase":"awaiting_hello","cause":null,"sessionLease":false,"webSocketClosed":false,"resourcesReleased":false,"historyCount":0,"streamLeases":0,"chargedBytes":0}
```

`streams` maps each successfully allocated fixture reference to exactly:

```json
{"control":"control-a","phase":"awaiting_open","cause":null,"streamLease":true,"webSocketClosed":false,"resourcesReleased":false,"chargedFrames":0,"client":{"sealed":false,"eofEmitted":false,"chargedBytes":0},"gateway":{"sealed":false,"eofEmitted":false,"chargedBytes":0}}
```

`streamLeases` and `chargedBytes` on a control sum its retained child reservations, including pending/closing/terminal-but-unconfirmed streams. Directional byte counts sum to the stream's charge; global pool counts include every owner. Completed/released objects remain inspectable with zero resources and their preserved phase/cause. Resource confirmation marks resources released and WebSocket closed, including when it must infer an abnormal close. Snapshots omit wire session IDs, identity values, payloads, exception text, and internal transport objects. Explicit `peekHex` is intentional synthetic test access, never default diagnostic output.

Backpressure changes no protocol state, budget, payload, history, progress, or deadline. It still records the validated monotonic watermark, so a later rollback fails. This bookkeeping is tested through subsequent operational behavior rather than exposing a private clock field in snapshots.

## Actual reports and comparison

Write actual reports to ignored `build/reports/draft-protocol/kotlin-conformance.json` and `build/reports/draft-protocol/node-conformance.json`. Their exact envelope is:

```json
{"format":"http-freekit-a19","revision":"0.3","kind":"results","implementation":"kotlin","corpusSha256":"<64 lowercase hex>","codec":[{"id":"codec-example","actual":{"code":"invalid_message"}}],"lifecycle":[{"id":"life-example","steps":[]}]}
```

`implementation` is `kotlin` or `node`. Codec/lifecycle arrays follow the corresponding manifest ID arrays exactly, once each. Lifecycle result steps correspond one-for-one to that case's operations. Store actual normalized codec/operation outcomes from the independent implementation; do not copy `expect`. Print only the digest, ordered executed IDs/counts and fixed summary codes to console, not full result payloads.

Compute `corpusSha256` in fixed lexical filename order: `codec.json`, `lifecycle.json`, `manifest.json`. For each, update SHA-256 with its UTF-8 filename, one NUL byte, its exact committed file bytes, and one NUL byte. There is no digest field in the corpus files themselves. Formatting changes intentionally change the digest.

The independent comparator verifies both actual reports against the manifest, all fixture expectations, and each other. A missing report, case, step, unexpected/duplicate ID, mismatched digest/outcome or skipped subset fails. Reports are capped at 16 MiB each. Corpus fixtures, model accounting and explicit interleavings do not establish authenticated WSS streaming, actual cancellation, real concurrency or total-process-memory bounds; those remain separate acceptance gates.
