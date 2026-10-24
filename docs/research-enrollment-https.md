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

Trusted methods: createInvitation() returns the Store snapshot; waitForRegistered(invitationId,{timeoutMillis}) returns the immutable pair_registered snapshot scoped to this run's invitation; approve(enrollmentId), reject(enrollmentId), revoke(enrollmentId), dropNextApprovedStatus(), snapshot(), close(). Registration waits are bounded. The drop command suppresses exactly one already-read approved status response, without changing publication or restoring its consumed nonce.

approve owns an asynchronous real issuer child through actual process/stdio closure before publish/abandon. Each OpenSSL ca job has its own private work directory/index/serial file, exact Store serial in hexadecimal, exact dates, fixed UTF8String subject/profile/extensions, SHA256 and copy_extensions=none. No random/automatic serial fallback. The A21 strict validator checks the final candidate.

Close admission first. stop/reject remain processable while signing; do not queue shutdown behind approval. Abort and join all signer groups, sockets, callbacks and timers, abandon joined handles, then close coordinator/Store last. Timeout is failure, never a join; failed teardown retains the lease and denies authorization. Detached signers can survive a killed worker. A22a uses actual graceful worker stop/join/reopen; any forced restart requires a verified no-live-signer barrier. A21 remains separate forced-crash evidence.

Private IPC envelopes are exactly {revision:1,id,op,args}, {revision:1,id,ok:true,result} or {revision:1,id,ok:false,code}; positive safe-integer IDs, 16384 serialized bytes/message, four outstanding commands maximum, fixed operation/argument schemas and static errors. Private invitation/registration data is never printed. Root/D settle exact worker operation/result schemas before that adapter lands; the direct fixture API can implement first.

## Private Android input and recovery

The self-targeted debuggable package is com.httpfreekit.interop.test. Validate APK metadata and use targetContext. Install once; never clear data/reinstall/uninstall between prepare and reopen. No production app is targeted.

Deliver input through owned adb/run-as stdin with fixed shell commands/restrictive modes to no_backup/draft-enrollment-research/input-v1.bin. Create only that owned directory, which can be absent initially. Invitation bytes never appear in argv/env/command text/status/reports. The command helper supports copied bounded stdin and live bounded output observation, with actual child/stdio/group closure.

Input is at most 16384 bytes: eight magic bytes HFKENR1 followed by NUL; unsigned 16-bit big-endian setupPort and credentialPort in 1..65535; then seven LP16 fields (unsigned 16-bit big-endian byte length plus bytes), in this order:

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

## Sources

- [Pinned Node HTTP](https://raw.githubusercontent.com/nodejs/node/v24.22.1/doc/api/http.md)
- [Pinned Node HTTPS](https://raw.githubusercontent.com/nodejs/node/v24.22.1/doc/api/https.md)
- [Pinned Node TLS](https://raw.githubusercontent.com/nodejs/node/v24.22.1/doc/api/tls.md)
- [OpenSSL3.0 CA options](https://docs.openssl.org/3.0/man1/openssl-ca/)
- [OpenSSL3.0 CA configuration](https://raw.githubusercontent.com/openssl/openssl/openssl-3.0/apps/ca.c)
