# HTTP origin wire vectors

This small additive set follows [draft 0.5](../../../docs/protocol-http-origin.md). It does not change the A19 corpus or its digest and does not establish transport, authentication or Android capture acceptance. Expected bytes are authored from the grammar, independently of either implementation.

`wire.json` has exactly `format: "http-freekit-http-origin-vectors"`, integer `revision: 1`, and arrays `requests`, `opens`, `responses`, `prefaces`. Every array is nonempty with at most 64 cases. IDs are globally unique lowercase ASCII names, 1–80 characters. The complete UTF8 file is at most 131072 bytes. Hex is lowercase, even-length, with at most 65536 rendered bytes per case; each `chunksHex` list has 1–128 entries and preserves exact order, including empty chunks. Unknown fields, duplicate JSON members, unsafe integers and noncanonical hex are fixture errors, never successful cases.

| Group | Input fields | Expected accepted outcome | Rejection |
| --- | --- | --- | --- |
| `requests` | `id`, `addressHex`, integer `port` (−1–65536) | `expect: {outcome: "accepted", wireHex}` | `{outcome: "rejected"}` |
| `opens` | `id`, `wireHex` | `{outcome: "accepted", canonicalHex}` | `{outcome: "rejected", code}` where code is invalid_message, unsupported_version or message_too_large |
| `responses` | `id`, `chunksHex` | `{outcome: "accepted", remainingHex}` | `{outcome: "rejected"}` |
| `prefaces` | `id`, `chunksHex` | `{outcome: "accepted", family: 4 or 6, addressHex, headHex}` | `{outcome: "rejected"}` |

Every case has exactly the listed input fields plus `expect`; each expectation has exactly its union's listed fields. `requests` passes copied raw address bytes and port to the real producer and compares exact bytes. `opens` decodes with the real stream codec, then re-encodes accepted messages to compare canonical bytes; acceptance does not imply capability negotiation. Direct lifecycle tests independently check negotiated mode, role/phase/clock precedence and claim ordering.

`responses` feeds every chunk to the real fixed-200 consumer. Success requires all 39 acknowledgement bytes, then the exact remaining bytes from the current and every subsequent chunk. A partial prefix after final EOF rejects even if an incremental object has not thrown. Consumption may never steal following application bytes. Mutation/ownership and the larger 65537-byte boundary cases are tested directly without expanding this file.

`prefaces` is for the actual maintained-HTTP-parser desktop binding. It finalizes input after all chunks, compares the exact numeric address family/bytes and preserves coalesced application head once. Do not implement another permissive HTTP parser merely to execute these vectors. Desktop source stays in its own repository; a local binding requires an explicit desktop root and must fail when absent. No optional skip can stand for evidence.

Initial counts are 14 request, 14 stream-codec, 10 response and 23 preface cases. Adapters compute actual outcomes before reading expectations. Ordinary tests/CLI summaries retain only fixed counts, case IDs and the exact wire.json SHA256; they do not dump payloads or create another corpus/report framework. Unit vectors remain separate from real I/O, authorization, cancellation and resource-join proofs.
