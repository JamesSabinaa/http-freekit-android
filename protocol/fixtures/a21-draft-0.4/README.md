# Enrollment fixture and adapter contract

These independent fixtures test [draft enrollment revision 0.4](../../../docs/protocol-enrollment.md). This document defines only the test adapter and report format, with no additional wire fields. The grammar is normative; implementation output is never an expectation source. The adapter contract was committed before the executable corpus. Validation requires nonzero coverage in every category; conformance requires both actual implementation reports to match every expectation.

## Files and limits

The fixed corpus files are `codec.json`, `comparison.json`, `manifest.json` and `proof.json`. Each is strict UTF-8 without BOM, duplicate JSON keys, nonfinite numbers or unpaired surrogates. Fixture numbers are safe integers; raw protocol numeric/encoding negatives belong in `wireHex`. Outer envelopes and cases reject unknown fields. Input and expected bytes are lowercase, even-length hexadecimal, never filesystem paths or executable descriptors.

Every file is at most 2 MiB. There are at most 512 codec, 256 proof and 128 comparison cases. Each category must be nonempty. IDs are globally unique, match `[a-z][a-z0-9-]{0,79}`, and appear exactly once in their category's manifest array and case array, in the same order. A wire input is at most 65,536 decoded bytes, including deliberately oversized protocol bodies. Context/comparison argument values have at most 4 container levels, 32 members/elements per object/array, and 4096 UTF-8 bytes of compact JSON per argument value. These are fixture bounds, not changes to the wire's 16,384-byte limit.

Executable validation requires accepted and rejected codec cases on every channel, all three decoder rejection codes somewhere in that category, accepted proofs for both purposes plus a rejected proof, and accepted/rejected comparison cases. Empty, skipped or partial category coverage cannot pass.

The exact manifest envelope is:

```json
{"format":"http-freekit-a21","revision":"0.4","kind":"manifest","codecIds":["codec-example"],"proofIds":["proof-example"],"comparisonIds":["comparison-example"]}
```

The other three envelopes have exactly `format`, `revision`, `kind`, `cases`. Their `format`/`revision` are the same; `kind` is respectively `codec`, `comparison` or `proof`. `cases` is the ordered case array described below. Example IDs/envelopes here illustrate the contract, not executable passing cases.

## Codec cases

A codec case has exactly `id`, `channel`, `wireHex`, `expect`. Channel is one of `pair_request`, `challenge_request`, `status_request`, `cancel_request`, `pair_response`, `challenge_response`, `status_response`, `cancel_response`.

```json
{"id":"codec-example","channel":"pair_request","wireHex":"","expect":{"ok":false,"code":"invalid_message"}}
```

Pass the exact decoded bytes to the public decoder on that channel. On rejection, record exactly `{"ok":false,"code":"invalid_message"}` or the corresponding `message_too_large`/`unsupported_version` code. On acceptance, encode that actual message through the public canonical encoder and record exactly `{"ok":true,"canonicalSha256":"<64 lowercase hex>"}`. The accepted fixture expectation has that same shape and hashes the independently specified canonical wire bytes. Do not hash the input bytes unless they actually equal the encoder output. Whitespace, member ordering and valid escape variations are intentional tests.

Wire CSRs/certificates remain bounded opaque bytes at this codec layer. Signature encoding/scalar validation follows the grammar, but codec acceptance is not signature verification, certificate issuance or authorization.

## Proof cases

A proof case has exactly `id`, `context`, `challengeWireHex`, `expect`. `context` is a bounded JSON value used as public proof-builder input. Valid contexts have exactly the six grammar fields: `desktopId`, `gatewaySpkiSha256`, `invitationId`, `enrollmentId`, `deviceSpkiSha256`, `purpose`, all canonical strings. Negative contexts may have missing/extra fields, invalid values or wrong JSON types. Adapters must not silently drop unknown fields or coerce booleans/numbers into strings when constructing the validated typed context.

First decode `challengeWireHex` through the public `challenge_response` decoder. A decode failure records its actual rejection code. Otherwise translate the supplied context to the public validated typed context and invoke the public proof builder with that actual decoded message. Conversion, wrong-message-type or builder mismatch records `{"ok":false,"code":"invalid_message"}`. For example, an accepted `pair_error` response is not a challenge to sign. Context conversion is only a language bridge; identity/purpose matching and proof framing must be performed by the implementation's public validation/builders.

An accepted expectation contains exact independently constructed proof bytes:

```json
{"ok":true,"payloadHex":"<1..1024 decoded bytes in lowercase hex>"}
```

For an accepted actual result, compute SHA-256 over the actual returned payload and record exactly `{"ok":true,"payloadSha256":"<64 lowercase hex>"}`. The comparator derives the expected digest from `payloadHex`; it does not accept a supplied expected digest in its place. Adapters may assert byte equality against the fixture after producing their independent actual results. Rejected expectations use the same `ok:false,code` shape as actuals. Actual report generation must not obtain payload bytes or hashes from `expect`.

Proof vectors test the domain separator, NUL, exact two-byte big-endian lengths, field order, matched purpose/method/path, hashes and nonce bytes. They do not sign with a committed private key, perform enrollment HTTP requests or mutate a registry. All identities, challenges and public material in this corpus are synthetic.

## Comparison cases

A comparison case has exactly `id`, `gatewayPin`, `deviceHash`, `expect`. Positive inputs are the two canonical base64url strings encoding the grammar's 32-byte hashes. Negative values may have wrong bounded JSON types or malformed strings. Invoke the public comparison-code builder, using only the language bridge needed for its validated argument types.

Acceptance records exactly `{"ok":true,"value":"<eight groups of eight lowercase hex digits separated by hyphens>"}`. Rejection records exactly `{"ok":false,"code":"invalid_message"}`. These public synthetic fingerprints are the only non-hash computed material retained in reports; they do not approve an enrollment.

## Actual reports and comparison

Write independently produced actual reports to ignored `build/reports/draft-enrollment/kotlin-conformance.json` and `build/reports/draft-enrollment/node-conformance.json`. Each is at most 16 MiB. Its exact envelope is:

```json
{"format":"http-freekit-a21","revision":"0.4","kind":"results","implementation":"kotlin","corpusSha256":"<64 lowercase hex>","codec":[{"id":"codec-example","actual":{"ok":false,"code":"invalid_message"}}],"proof":[{"id":"proof-example","actual":{"ok":false,"code":"invalid_message"}}],"comparison":[{"id":"comparison-example","actual":{"ok":false,"code":"invalid_message"}}]}
```

`implementation` is exactly `kotlin` or `node`. Each array follows its manifest IDs exactly, once each. Retain only the outcome shapes above: no input bytes, canonical wire bytes, proof bytes, contexts, CSRs/certificates, invitation secrets, challenges/nonces, signatures, provider errors or paths. Reports and console diagnostics never contain private signing keys. Console output is limited to fixed summary codes, counts and corpus digest. An assertion may identify a fixed case ID/category, without dumping actual or expected material.

Compute `corpusSha256` in fixed lexical filename order: `codec.json`, `comparison.json`, `manifest.json`, `proof.json`. For each, update SHA-256 with its UTF-8 filename, one NUL byte, its exact committed file bytes and one NUL byte. There is no digest field in the corpus files themselves. Formatting changes deliberately change the digest. Load bounded fixture files and validate their envelopes/order/IDs before execution. Compare expected outcomes only after computing actual results; write the actual report even when an implementation mismatch will make the test fail.

The independent comparator rejects missing/stale reports, duplicate or unknown keys, type substitutions, wrong format/revision/implementation, wrong digest, missing/extra/reordered IDs, mismatched outcomes and cross-language disagreement. Both reports must independently match every expectation; agreement on the same wrong answer fails.

## Validation tools

Run the independent bounded corpus and report checks from the repository root:

```sh
node --test scripts/tests/enrollment-corpus.test.mjs scripts/tests/enrollment-conformance.test.mjs
node scripts/check-enrollment-corpus.mjs
node scripts/compare-enrollment-conformance.mjs
```

Each CLI accepts `--corpus DIRECTORY`; the comparator also accepts `--kotlin FILE` and `--node FILE`. Defaults are the fixed corpus/report paths above. Missing actual reports fail rather than creating synthetic results.

The shared Node loader is `loadEnrollmentCorpus(root?)` from `scripts/enrollment-corpus.mjs`. It returns a deeply frozen `{digest,codec,proof,comparison}` with ordered case arrays after bounded strict parsing and structural/coverage checks; it throws `EnrollmentCorpusError` carrying only a fixed `code`. Node adapters may consume those exact validated inputs without another parse. `expectedEnrollmentOutcome(kind, expectation)` is an assertion/comparator helper, including the proof-hex digest conversion; it must never construct an actual execution result. Kotlin loads the same committed bytes independently.

These fixtures establish only codec/proof/comparison agreement. Coordinator state, real crypto verification, durable-store transactions, owned-child crash/recovery and actual resource closure require their own tests. Deterministic models are not OS process-crash evidence; process kills are not power-loss proof. A22 live HTTPS/Keystore/approval/save/reopen and production protocol freeze remain separate gates.
