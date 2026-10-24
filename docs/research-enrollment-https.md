# Live enrollment research profile

Status: A22 research against [draft 0.4](protocol-enrollment.md), based on verified 109ae16. A22a proves pinned HTTPS, real Keystore proofs, host approval, lost-result recovery and save/process-reopen. A22b must also prove active WSS revocation and composed credential/session-expiry teardown. Additional Android adversarial cases remain required before complete A22 acceptance. This does not freeze production v1.

## Ownership

Root owns this profile, board, new enrollment runtime driver/input helpers and the bounded stdin/live-observer extension to the existing owned-command helper. UI owns only new DraftEnrollment-prefixed files under the existing Android research module. D owns new companion-enrollment-https/issuer/worker-prefixed Node fixtures/tests. F owns new enrollment runtime result verification, separate manual workflow and validation docs. Work in separate branches/worktrees from this committed profile; preserve existing A19/A20 peers, Android streaming helpers, app, core-security and production desktop. The command extension preserves existing callers/checks.

## HTTP and TLS

Two listeners bind only 127.0.0.1: setup HTTPS without a device certificate, and a separate mTLS credential-admission probe. Both use the same pinned gateway identity, TLS 1.2 or later and DNS-only SNI/name. The probe requires provider validation against the enrollment authority plus current exact-leaf Store authorization on every request. Refuse probe session resumption: use SSL_OP_NO_TICKET, retain no session cache and decline resumeSession data. TLS 1.3 may still emit unresumable stateful tickets; do not claim zero ticket emission. Host tests offer prior sessions and require isSessionReused() false plus revalidation of the exact presented leaf.

Host is exactly logicalName + ":" + listenerPort. Reserve equal explicit device/host ADB reverse ports with --no-rebind, fail collisions without replacing prior mappings, and remove only successful registrations owned by this run. Worker restart must rebind the same two ports; it cannot silently change endpoints.

Setup requires HTTP/1.1 and the exact draft POST paths. pair/status dispatch uses the two public strict decoders, never a raw JSON type peek. Every typed success, including pair_ended, is HTTP 200. Only pair_error selects these statuses:

| Code | HTTP |
| --- | --- |
| invalid_message, unsupported_version, unsupported_capability | 400 |
| message_too_large | 413 |
| authentication_failed | 403 |
| invitation_expired, invitation_used | 409 |
| pairing_limit | 429 |
| pairing_unavailable | 503 |

The client requires HTTP status, decoded DTO and response channel to agree. Responses use application/json, exact canonical Content-Length, Connection: close and at most 16384 bytes. The probe is GET /research/enrollment/credential with no body; admission returns exactly {"type":"credential_admitted"}. It grants no stream or management operation.

Check raw headers before normalized lookup. Reject duplicate names, more than 32 headers, Origin/Cookie/Authorization, transfer coding, Expect, upgrade, CONNECT, trailers, queries, absolute-form targets and unknown routes/methods. Setup Content-Type is exactly application/json; Content-Length is canonical decimal in 1..16384. Headers are bounded to 8192 bytes before parsing; body allocation follows length validation. A rejected or incomplete first request causes no state mutation. Never dispatch a second request on that socket. Bytes after a complete valid Content-Length body are a subsequent HTTP message, so rejecting them does not roll back an already-valid first request. Framing rejection may destroy the connection or send one bounded 400/413 then close, without parser/provider detail.

Limits: 16 accepted sockets total, four body readers, five-second TLS/header budgets, ten-second whole-request deadline. Explicitly handle close/drop/client-error/continue; request-count configuration alone does not close sockets. No Android-accessible operator or management route exists.

## Host fixture and private IPC

The driver owns a private temporary directory of research software gateway/authority keys, public certificates and A21 DB. Explicit create/open reject missing/corrupt/mismatched state without regeneration. Keep identities/DB across restart. Default diagnostics redact material.

D exports startEnrollmentHttpsFixture({directory,mode,openssl,setupPort,credentialPort}); mode is create/open, with zero ports allowed only on initial create. metadata() returns a redacted copied snapshot with desktopId,logicalName,gatewayCertificateDer,gatewaySpkiSha256,enrollmentAuthorityDer,interceptionCaCertificateSha256,setupPort,credentialPort. DER/hashes are canonical base64url.

Trusted methods: createInvitation() returns the Store snapshot; waitForRegistered(invitationId,{timeoutMillis}) returns the immutable pair_registered snapshot scoped to this run's invitation; approve(enrollmentId), reject(enrollmentId), revoke(enrollmentId), readResult(enrollmentId), dropNextApprovedStatus(), snapshot(), close(). Registration waits are bounded. readResult is host-only and permits exact-result hashing after reopen without another approval. The drop command suppresses exactly one already-read approved status response, without changing publication or restoring its consumed nonce.

approve owns an asynchronous real issuer child through actual process/stdio closure before publish/abandon. Each OpenSSL ca job has its own private work directory/index/serial file, exact Store serial in hexadecimal, exact dates, fixed UTF8String subject/profile/extensions, SHA256 and copy_extensions=none. No random/automatic serial fallback. The A21 strict validator checks the final candidate.

Close admission first. stop/reject remain processable while signing; do not queue shutdown behind approval. Abort and join all signer groups, sockets, callbacks and timers, abandon joined handles, then close coordinator/Store last. Timeout is failure, never a join; failed teardown retains the lease and denies authorization. Detached signers can survive a killed worker. A22a uses actual graceful worker stop/join/reopen; any forced restart requires a verified no-live-signer barrier. A21 remains separate forced-crash evidence.

Private IPC envelopes are exactly {revision:1,id,op,args}, {revision:1,id,ok:true,result} or {revision:1,id,ok:false,code}; positive safe-integer IDs, 16384 serialized bytes/message, four outstanding commands maximum and static errors. Private invitation/registration data is never printed. Exact operations are:

| op | args | successful result |
| --- | --- | --- |
| start | directory,mode,openssl,setupPort,credentialPort | eight-field public metadata material above |
| metadata | empty object | same metadata material |
| createInvitation | empty object | Store invitation material |
| waitForRegistered | invitationId,timeoutMillis (1..10000) | pair_registered material |
| approve | enrollmentId | pair_approved material |
| reject,revoke | enrollmentId | pair_ended material |
| readResult | enrollmentId | current typed status material |
| dropNextApprovedStatus | empty object | {armed:true} |
| snapshot,close | empty object | fixture resource/counter snapshot |

Each args/result is an object with the exact fields for its operation; rows naming several operations are separate op strings. start is accepted once before other operations; mode is create/open and zero ports only apply to create. Paths/executable values are bounded host configuration with no NUL/newline. Reserve an outstanding-command slot for close while approval runs. close responds after actual fixture cleanup, disconnects only after its IPC send callback, and exits naturally. Parent independently joins its process/stdio/group; an IPC acknowledgement alone is insufficient. Preserve the first worker's actual drop/delivery-after-drop counters and separately require an approved delivery from the reopened worker; counters are never silently carried across workers or rearmed.

## Private Android input and recovery

The self-targeted debuggable package is com.httpfreekit.interop.test. Validate APK metadata and use targetContext. Install once; never clear data/reinstall/uninstall between prepare and reopen. No production app is targeted.

Deliver input through owned adb/run-as stdin with fixed shell commands/restrictive modes to no_backup/draft-enrollment-research/input-v1.bin. Create only that owned directory, which can be absent initially. Invitation bytes never appear in argv/env/command text/status/reports. The command helper supports copied bounded stdin and live bounded output observation, with actual child/stdio/group closure.

Input is at most 16384 bytes: eight magic bytes HFKENR1 followed by NUL; distinct unsigned 16-bit big-endian setupPort and credentialPort in 1..65535; then seven LP16 fields (unsigned 16-bit big-endian byte length plus bytes), in this order:

1. gatewayCertificateDer:1..4096 raw bytes
2. gatewaySpkiSha256:32 raw bytes
3. logicalName:1..253 ASCII bytes, valid DNS/SNI
4. desktopId:1..128 ASCII draft ID
5. invitationId:same ID grammar
6. invitationSecret:32 raw bytes
7. invitationExpiresAt:20 ASCII bytes, valid draft UTC timestamp

Reject truncation, invalid magic/length/value and trailing data. Read bounded bytes, validate gateway trust/identity and unlink before key creation/network use. Requested capabilities are fixed tcp-http and tcp-https-connect; deviceName is Android enrollment research. Persist no invitation secret, challenge, nonce or signature.

Reuse existing nonexportable identity, scoped TLS factory, typed proof builder and validated credential store. Keep A21's random durable deviceId. Validate approved desktop/enrollment/SPKI/cert/authority/capability/deadline bindings before saving. Installing the issued leaf must never replace the existing Keystore key/certificate.

A separate bounded atomic public-only recovery record binds desktop/pin/name/ports, invitation/enrollment/device IDs, original SPKI and original Keystore-certificate hashes, exact client-leaf/authority hashes, capabilities/CA fingerprint and original deadlines. Reopen compares it with the original validated credential/key; missing/corrupt/mismatched state fails closed without regeneration/replacement.

## Exact A22a runtime sequence

Class com.httpfreekit.interop.DraftEnrollmentInteropTest has two exact methods, each invoked separately once, in order:

1. prepareApprovedCredentialForRestart
2. reopenApprovedCredentialAfterRestart

Prepare consumes input, creates the unique fixture desktop's identity, reserves a strict CSR and retries that key without replacing the review, proves pending, waits for host-only approval, observes the intentionally lost approved response, obtains a fresh nonce/proof, validates/saves the exact result and recovery state, then closes local resources. Host approval occurs only after live awaiting-host-approval; root arms the response drop before approving. Retry is bounded and honors one-second challenge issuance.

After prepare completes, selectively force-stop the validated package and observe exact process absence, then actually stop/join the Node worker and reopen the same identities/DB/ports. Exit0 alone, arbitrary pidof failure or empty failed adb output is not absence. Verify selected-device state before/after; inspect only the known process/UID. If it exited naturally, report stop+absence without claiming forced death.

Reopen loads the original key/credential/recovery record, proves status with a new nonce after worker restart, compares the exact stored approved leaf, authenticates using saved credentials over new pinned mTLS, then forgets only owned state. No new invitation/enrollment/key/certificate replacement is allowed.

Status 2 has exactly draftEnrollmentVersion="1" and draftEnrollmentPhase from this ordered list: input-consumed, strict-csr-reserved, pending-proof-observed, awaiting-host-approval, approved-result-validated, credential-persisted, prepare-resources-closed; then reopen-key-and-record-validated, reopen-mtls-authorized, reopen-resources-closed. No IDs/material. Require exact paired method starts/completions, terminal success, actual phases and cleanup; host force-stop is not a fabricated JUnit pass. F commits the final result schema before the driver/report adapter lands.

Separate host tests cover malformed HTTP, unpublished/unknown/revoked exact leaves, issuer races and actual joins. Additional Android adversarial proof/TLS/cancel cases and A22b active WSS revocation/expiry remain required for full A22 acceptance.

## A22b enrolled streaming lifetime

This extension composes the verified enrollment and stream adapters before production integration. It changes no draft 0.3/0.4 wire messages. The existing A22a methods, private input and report revision remain unchanged.

The stream service uses the same owned gateway TLS identity, enrollment authority and live Store. A trusted optional authenticated-service factory on the HTTPS fixture receives only in-process TLS options, copied public metadata and an exact-leaf Store authorizer. A new enrollment-stream adapter exposes its public webSocketPort and host-only inspection/invalidation methods; no operator HTTP route is added. Close and join the service before releasing the Store or TLS assets. Keep existing A20 defaults when the optional integration is absent.

Bind every control owner to the Store's copied desktopId, durable deviceId, enrollmentId, clientCertificateSha256, deviceSpkiSha256 and credentialExpiresAt, retaining the exact leaf internally. Stream attachment requires that same grant and leaf plus the session token. Revalidate against the live Store before admission, enqueue and each new application payload write, and on the existing bounded deadline watcher. No cached fallback is permitted. A committed revoke synchronously invalidates affected owners before acknowledging the operator; actual socket/callback/worker joins remain separately observable. One fixed control disconnect may then be attempted through its existing writer, with a 1000 ms bound and actual completion/abort ownership; it cannot delay application invalidation or operator acknowledgement. A Store failure latches unavailable and closes all affected owners as network_unreachable, without inventing a revoke. Explicit revoke uses device_revoked; credential or session expiry uses session_expired. Already-written OS bytes cannot be recalled; require no new application admission or payload write after invalidation and retain charges until actual joins.

For enrolled sessions, session_ready.expiresAt is no later than the minimum of the trusted policy deadline, exact credential expiry and gateway certificate expiry, rounded down to a whole UTC second. The Android client independently bounds readiness using the validated saved gateway, client chain, enrollment anchor and trusted policy; reject overlong readiness rather than rewriting it. In this measured research context, the caller anchors its policy bound to the same local readiness UTC observation plus the configured duration and the admitted 2000 ms clock skew, using checked arithmetic; certificate bounds receive no allowance. The reusable core helper adds no tolerance. Host evidence separately enforces the strict actual peer-ready-to-expiry duration and the full preflight clock interval. Reuse the existing UTC/monotonic session model and deadline worker so expiry invalidates blocked I/O. A real 60-second issued credential with a 120-second policy proves credential-limited expiry. A separate 15-second policy with a still-valid 60-second credential proves session-limited expiry. All three Android scenarios reuse the existing cancel research header for the paused fixture; trusted configuration controls lifetime independently, without a new wire enum.

Use a fresh host directory/desktop and one actual Android Keystore enrollment per destructive scenario. Save and reload through the existing credential store. Reuse enrollment proof/certificate checks and the existing stream owner's connector, socket pairs, conservative blocked-write observation and joins. Do not change production credential-store identity semantics or duplicate either I/O framework. Actual host TLS clients test two-device isolation, exact-leaf substitution, storage faults and no new forwarding after invalidation.

The Android class is com.httpfreekit.interop.DraftEnrolledStreamingInteropTest, with separate ordered invocations:

1. revocationClosesSavedCredentialBlockedSession
2. credentialExpiryClosesSavedCredentialBlockedSession
3. sessionExpiryClosesSavedCredentialBlockedSession

Each method consumes its seed, reserves/proves pending enrollment, waits for host-only approval, saves/reloads credentials, accepts bounded readiness and observes real proxy/application pending writes. Revocation waits for a validated live awaiting-host-revocation phase before the host commits revoke, then proves affected-owner closure and fresh same-credential admission denial. Credential expiry proves the actual certificate deadline, joins and expired fresh-connect refusal. Session expiry proves the earlier policy deadline, rejects the old session token, and proves the unchanged still-valid credential can establish a new control session. Forget only owned state after these checks. F freezes the finite phase/observation descriptor before driver or instrumentation phase emission is implemented; no raw logs, IDs, tokens, certificate bytes or keys enter reports.

A22b private input is at no_backup/draft-enrollment-research/stream-input-v1.bin, delivered through the same bounded owned run-as stdin mechanism. It is at most 16384 bytes: eight magic bytes (ASCII HFKSTR1 plus NUL), a BE16 stream port, one scenario byte (1 revoke, 2 credential expiry, 3 session expiry), a BE16 embedded-seed length and exactly that many bytes of the existing A22a input. All three ports are distinct and nonzero. Reject truncation, invalid scenario/length/ports and trailing data; validate and unlink before key/network use. No secrets enter argv, environment or status output.

The existing private worker gains startStreaming with the existing start fields plus streamPort, credentialLifetimeSeconds and sessionLifetimeMillis; A22b starts fresh create mode. Public metadata adds only webSocketPort. inspectEnrollment accepts only enrollmentId and returns bounded redacted stream observations through IPC. Closing after rejected configuration explicitly records initializationAttempted false and zero resources, then actually joins the worker; an attempted failed initialization cannot claim this state. Existing operations and A22a behavior remain compatible. The checked-source workflow selects a finite A22a or A22b suite and retains only its four sanitized reports; it does not merge partial results across sources. Additional Android adversarial enrollment proof/TLS/cancel checks remain required for full A22, along with the other foundation and production gates.

## Sources

- [Pinned Node HTTP](https://raw.githubusercontent.com/nodejs/node/v24.22.1/doc/api/http.md)
- [Pinned Node HTTPS](https://raw.githubusercontent.com/nodejs/node/v24.22.1/doc/api/https.md)
- [Pinned Node TLS](https://raw.githubusercontent.com/nodejs/node/v24.22.1/doc/api/tls.md)
- [OpenSSL3.0 CA options](https://docs.openssl.org/3.0/man1/openssl-ca/)
- [OpenSSL3.0 CA configuration](https://raw.githubusercontent.com/openssl/openssl/openssl-3.0/apps/ca.c)
