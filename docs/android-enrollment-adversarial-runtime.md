# Android adversarial enrollment research

A22c extends the [live enrollment profile](research-enrollment-https.md) with four isolated Android/Node cases. It preserves draft 0.4 wire bytes and adds no production enrollment or capture. The already verified A22a and A22b suites remain separate regressions. This profile specifies required evidence; it is not execution evidence.

## Cases

Each method uses a fresh owned host fixture, invitation, Android Keystore identity and private input. Methods execute once on API 26 and 37. F's finite descriptor fixes method names, ordered phases and compact observations before the Android emitter and driver depend on them.

1. `purposeContextAndReplayProofsKeepReservationPending`: reserve a real CSR and obtain a status-purpose challenge. A status signature submitted to cancel, a changed invitation/enrollment wire tuple, and one valid Keystore signature over an altered locally coherent typed context must each return HTTP 403/authentication_failed. The correct status proof for that same challenge must still return pair_pending, then its replay must return 403/authentication_failed. Stay within the challenge attempt, ten-second lifetime and rolling crypto budgets. Invalid attempts must neither cancel nor approve the reservation; no credential is saved.
2. `wrongGatewayPeerFailsTlsWithoutEnrollmentMutation`: keep the valid expected gateway certificate, pin and DNS name, but actually connect to a different currently valid self-signed P-256 TLS identity with the same DNS SAN. The scoped Android TLS handshake must fail. The alternate listener requests no client certificate. Require an actual alternate-listener connection/rejection and zero HTTP dispatch there, alongside successful pending proofs through the correct gateway before and after. A constructor's pin/hostname preflight rejection is not network evidence. No approval/signing or credential persistence occurs.
3. `pendingCancellationRejectsLateApprovalWithoutSavingCredential`: a fresh cancel-purpose proof must return pair_ended/pairing_cancelled, replay must fail, and a fresh status proof must remain cancelled. A live method phase authorizes a tracked private host approval attempt only after Android observed cancellation. That actual attempt must return invitation_used with no issuer command started; a host read after its completion must still be cancelled. Android status is not claimed to occur after the host attempt unless a real barrier establishes that order. No credential is saved.
4. `publishedCancellationRevokesSavedCredential`: host approval is authorized only by the complete live awaiting-approval phase. Android validates, saves and reloads the exact approved credential under its original nonexportable key and proves successful mTLS. A fresh signed cancel must return pair_ended/pairing_cancelled; the same still-valid saved leaf must then receive HTTP 403 from the credential endpoint. Fresh status remains cancelled, and original key identity is preserved until owned Forget. Host result after the method is cancelled and the cumulative issuer command count has not increased after its single approval.

Each case closes its actual clients and removes only its owned credential/key. Compact status observations retain fixed statuses/codes and assertion/resource outcomes, never IDs, certificates, nonces, signatures or provider text. Missing/unreached facts cannot pass. The host independently records actual readResult state and cumulative issuer counters; zero approved-response delivery is not a substitute for absence of publication.

## Input and resources

Reuse A22a's exact bounded binary seed and fixed private `no_backup/draft-enrollment-research/input-v1.bin` path, transferred only via owned run-as stdin. Unlink it before creating a key. No identity or invitation material may travel in command arguments, environment variables or reports.

The TLS method alone may receive `adversarialPeerPort` as a public instrumentation scalar: canonical decimal 1..65535, distinct from both seed ports. It is only a connection port; expected trust still comes from the private seed. The driver validates and owns all three ADB reverse mappings. Other cases use the original two. No alternate binary wrapper or phone-accessible operator endpoint is needed.

The alternate TLS listener owns its private generated key/certificate, child commands, accepted sockets and callbacks. Validate its dates, exact DNS SAN and different SPKI before publishing its port. Close/join it before the base Store lease is released. Final reports require actual listener/socket/command/worker closure, selective reverse removal, input absence, private-directory removal, package uninstall and the workflow's independent emulator termination/join.

Use the existing enrollment driver, strict incremental parser and manual workflow with finite `a22c` selection. Keep A22a the default. F owns the exact separate sanitized report schema/paths and standalone verifier; reuse existing source, clock, command, private-input and cleanup checks. Host state facts must follow their actual operations, including any late approval attempt.

## Signed cancellation and active streams

The [normative cancellation rule](protocol-enrollment.md#reservation-decisions-and-recovery) atomically revokes the exact published grant if publication won. A focused actual host composition test must check signed cancellation of an active stream and later same-key grant isolation. Reuse the existing stream invalidation/typed terminal/actual join path if a hook is needed; invoke it only after committed successful cancellation. Invalid proofs or cancellation of an older terminal enrollment cannot invalidate a later grant. The Android fourth case proves credential-endpoint denial; it does not claim another Android blocked-WSS proof.

Production VPN policy, maintained production WebSocket selection, renewal/rotation decisions, v1 freeze and physical USB acceptance remain separate work.
