# Enrolled stream runtime adapter contract

This finite A22b test adapter implements the [enrolled lifetime profile](research-enrollment-https.md#a22b-enrolled-streaming-lifetime). It changes no production wire fields and claims no new runtime pass. Preserve the verified [A22a revision-1 contract](android-enrollment-runtime.md), default suite, paths and live-only callback behavior.

## Descriptor and live phases

The class is `com.httpfreekit.interop.DraftEnrolledStreamingInteropTest`. Invoke one JUnit method per owned command, exactly once, in this order:

| Method | Scenario | Input scenario byte | Credential lifetime | Session policy |
| --- | --- | --- | --- | --- |
| `revocationClosesSavedCredentialBlockedSession` | `revocation` | 1 | 60 seconds | 120000 ms |
| `credentialExpiryClosesSavedCredentialBlockedSession` | `credential_expiry` | 2 | 60 seconds | 120000 ms |
| `sessionExpiryClosesSavedCredentialBlockedSession` | `session_expiry` | 3 | 60 seconds | 15000 ms |

Each scenario has a fresh directory, desktop, invitation, Android key and actual enrollment. Install the research package once; consume one bounded private `stream-input-v1.bin` per invocation. Never pass invitation material through arguments, environment, status or reports. Reuse the checked enrollment, connector, stream and cleanup implementations. Do not change A22a's successful Forget behavior to preserve state for A22b.

Status 2 contains exactly `draftEnrolledVersion=1` and `draftEnrolledPhase`. The ordered phases are:

```text
input-consumed
strict-csr-reserved
pending-proof-observed
awaiting-host-approval
credential-saved-and-reloaded
bounded-stream-ready
application-writer-blocked
<scenario wait phase>
terminal-owner-observed
admission-policy-verified
stream-resources-closed
owned-state-forgotten
```

The wait phase is `awaiting-host-revocation`, `awaiting-credential-expiry` or `awaiting-session-expiry`, respectively. All phases follow actual completed assertions, not failure cleanup. `bounded-stream-ready` means the saved credential authenticated the control and original stream, and the client accepted the independently bounded readiness. It starts the driver's private proxy-observation task. `application-writer-blocked` follows the unchanged actual same-write/full-predicate 250 ms check. The scenario wait phase follows that check.

Only a complete LF-terminated valid next phase during a matching live method can call the synchronous `onPhase` callback. No callback from EOF/finish, partial lines, foreign cases, invalid metadata or a previous failure is permitted. Callbacks return undefined and may schedule only tracked driver tasks. Approval occurs only after `awaiting-host-approval`. Revocation additionally waits for both `awaiting-host-revocation` and the successful private proxy proof. Expiry requires no host mutation: a missing preterminal proxy proof fails the host gate even if Android later completes.

The parser retains the current 262144-byte stdout, 8192-byte line and sixteen-problem bounds. A22b pending metadata has at most forty fields; A22a keeps its sixteen-field cap. Every invocation needs one exact start/completion, declared count one, terminal code -1, all phases and one valid observation. Skips/crashes/duplicates remain failures. Diagnostics retain finite types and at most sixteen committed project-file call sites; no provider messages, causes, IDs or raw output.

## Android positive observation

After `admission-policy-verified`, close/join all owned scenario I/O, then emit exactly one status-3 bundle before `stream-resources-closed`. Emit it only after successful assertions. No finally-generated positive observation is allowed. Its exact keys are `draftEnrolled` plus these suffixes:

```text
Version Scenario CredentialExpiresUtcMillis GatewayExpiresUtcMillis AnchorExpiresUtcMillis
PolicyMillis ReadinessObservedUtcMillis SessionExpiresUtcMillis
TerminalObservedUtcMillis TerminalObservedElapsedMillis LocalCause
ApplicationWriteEntered ApplicationWriteCompleted ApplicationWriteInFlight
ApplicationPendingBytes ApplicationChargedBytes ApplicationChargedFrames ApplicationBlockedMillis
PrefixBytes LocalTicks ControlInactive StreamInactive SameCredential FreshAdmission
OldSessionRejected NewControlAdmitted NewControlObservedUtcMillis
SocketsClosed WorkersJoined OwnedThreadsAlive SessionLeases StreamLeases ChargedBytes PendingCallbacks Timers
```

These are 35 string values. Version is `1`; Scenario matches the selected method. Integers use canonical nonnegative decimal, booleans `true`/`false`. UTC values are 2000..2100 epoch milliseconds. `NewControlObservedUtcMillis` is the literal `null` outside session expiry. `LocalCause` is exactly `device_revoked`, `session_expired` or `network_unreachable`, preserving the actual first terminal control cause. `FreshAdmission` is `denied` for revoke/credential expiry and `new_control` for session expiry. It describes the actual same-credential connector attempt; it does not attribute a denial to a particular provider or HTTP layer.

Readiness time is the client's single actual UTC sample used for its bound/model event. Terminal time/elapsed are captured at the first terminal control observation, before cleanup; do not replace an early network failure with a later deadline. Elapsed is relative to readiness and at most 180000 ms. `LocalTicks` is 1..180000. Certificate/gateway/anchor deadlines are exact, with no skew padding. The client policy bound is the same readiness sample + configured policy + at most the measured allowed 2000 ms; arithmetic must be checked. The host's independent policy/whole-second/certificate bound gets no such tolerance.

Application values are the retained tuple from the successful preterminal blocked-writer observation, not post-close counters: entered 1..33570816, completed < entered, in-flight = entered, pending bytes 1..4096, charged bytes 1..8192, charged frames 1..4, same-candidate blocked interval 250..20000 ms. `PrefixBytes` is exactly 4096 validated synthetic body bytes. All other non-time counters are bounded by 33570816 unless constrained here.

Both inactive flags and SameCredential must be true. Session expiry additionally requires OldSessionRejected and NewControlAdmitted true and a new-control observation before the exact credential deadline; these are false/null for other scenarios. New control uses the unchanged saved key/leaf, not a new enrollment. SocketsClosed/WorkersJoined are true only after actual closes/joins. OwnedThreadsAlive, SessionLeases, StreamLeases, ChargedBytes, PendingCallbacks and Timers must all be zero. Report normalized JSON primitive values using the suffix names with their first character lowercased, including version=1, rather than raw bundle strings.

## Private host evidence

`inspectEnrollment(enrollmentId)` remains host-only. Its exact private result is revision, found, available, credentialExpiresUtcMillis, gatewayExpiresUtcMillis, sessionPolicyMillis, grantValid, invalidationCause, revalidations, controlsAdmitted, applicationWriteAdmissions, writesAfterInvalidation, terminalNotification and probe. `terminalNotification` is exactly attempted/completed/aborted booleans. The existing bounded redacted A20 probe is fresh on every IPC call, with no Store/clock mutation. It always targets the original owner. Its pool is global and must not be confused with that owner's leases after a second control is admitted.

The report uses a fixed `HostSnapshot` projection, never raw IPC material. Its exact fields are:

```text
available grantValid credentialExpiresUtcMillis gatewayExpiresUtcMillis sessionPolicyMillis
invalidationCause revalidations controlsAdmitted applicationWriteAdmissions writesAfterInvalidation
controlPhase controlCause sessionLease streamLeases chargedBytes streamPhase streamCause chargedFrames
proxyWriteEntries proxyWriteCompletions proxyWritePending pendingIngressBytes proxyReadPaused
readyUtcMillis expiresUtcMillis terminalUtcMillis terminalElapsedMillis ownerResourcesReleased
cleanupComplete workers timers pendingCallbacks terminalNotification callStartedNanos callReceivedNanos
```

Use the original control's sessionLease/streamLeases/chargedBytes, original stream's phase/cause/chargedFrames, original IO proxy counters/pending ingress and fixture proxyReadPaused, original timing and cleanup. ownerResourcesReleased combines the original control and stream release flags. Never project global pool leases as original-owner leases. The three new admission/write counters and terminalNotification come from the inspector's top-level original-owner records. No identifiers or tokens enter the projection. Missing owner/probe is null evidence and cannot pass.

Before invalidation both proxy snapshots require available/grantValid, active original control, open or half-closed original stream, one control admitted, a held lease/charges/frames, paused proxy read, pending ingress 4096, and the same entered-but-uncompleted pending proxy write. Capture each IPC call's start and receive as exact integer nanoseconds relative to the driver origin (0..3600000000000). The later call start minus first receive must be at least 250000000 ns. This conservative interval spans actual snapshots; completion-time gaps are insufficient. Both snapshots must precede the authoritative invalidation/terminal observation. Completion callbacks may finish after invalidation, but original-owner writesAfterInvalidation must remain zero.

The final original-owner snapshot is taken after scenario assertions, while the service is still open, before worker close. Both owners must be inactive, their leases/charges/resources released, cleanup complete and workers/timers/callbacks zero. Revoke requires acknowledged committed revocation, host invalidation/control cause device_revoked, grant invalid and controlsAdmitted=1. Expiry requires an actual first session_expired owner with its UTC or monotonic deadline proof; the other may truthfully retain network_unreachable. Do not relabel a cause. Host terminal proof is terminalUtc >= expiresUtc or terminalElapsed >= expiresUtc-readyUtc. Local proof uses the corresponding retained local first-terminal values. The independent host session expiry must be a positive whole UTC second no later than floor(min(host-ready+policy, credential, gateway, anchor)/1000)*1000. Device and host session-expiry values must match. Credential expiry is credential-limited; session expiry is policy-limited with a still-valid longer credential.

For credential expiry, after method completion the driver may wait boundedly for the actual host certificate deadline, then use the existing private readResult operation. Require normalized credentialStatus `credential_expired`, its actual observation UTC >= certificate expiry, and credentialStatusAfterMethod=true. This later query is not represented as causing the earlier stream close. Cached inert grantValid is not proof of current credential validity. Session expiry requires controlsAdmitted=2 and actual new-control admission with the unchanged credential; revocation/credential expiry admit no second control. Terminal notifications are retained as consistent attempted/completed/aborted facts, not substituted for actual closure or deadline proof.

## Separate report and shared workflow

The planned `enrollment-runtime-stream-results.mjs` exports the finite descriptor and A22b parser/report/render/verify entry points, backed by shared strict machinery. A22a public defaults and exact schemas remain intact. A22b writes only:

```text
tools/transport-spike/android/build/outputs/androidTest-results/enrollment-streaming/debug/runtime.json
tools/transport-spike/android/build/outputs/androidTest-results/enrollment-streaming/debug/TEST-enrolled-stream-research.xml
tools/transport-spike/android/build/reports/androidTests/enrollment-streaming/debug/index.html
build/reports/enrollment-streaming/host-cleanup.json
```

Runtime format is `http-freekit-a22b-runtime`, revision integer 1, with exactly format/revision/source/api/clock/scenarios/cleanup/problems. Common source, API, strict two-second whole clock interval and command shapes match A22a. Scenarios is exactly three ordered records, each with method/scenario/invocation/input/approval/profile/host/cleanup/problems. Invocation is the A22a observation structure plus the one normalized positive `observation` (null until observed). Method outcomes stay truthful if later host cleanup fails; XML projects exactly three methods, not fabricated host cases.

Input reuses the A22a evidence shape and must be fully written/closed/unlinked. Approval is exactly liveAwaitingPhaseObserved/requested/completed/approvedResponsesDelivered/actualApprovedResponseDrops: booleans true, delivery >=1, drops exactly zero. Profile is credentialLifetimeSeconds/sessionLifetimeMillis/credentialExpiresUtcMillis/gatewayExpiresUtcMillis/anchorExpiresUtcMillis, derived from the configured case and validated actual certificates. Host is awaitingPhaseObserved/blockedFirst/blockedLast/terminal/revokeAcknowledged/credentialStatus/credentialStatusObservedUtcMillis/credentialStatusAfterMethod. Its three snapshots use the fixed projection above. RevokeAcknowledged is true only for revocation. CredentialStatus is credential_expired for credential expiry, revoked for revocation, active for session expiry, or null before reached; only credential expiry requires the after-method status check. Never copy a raw wire result into reports.

Each case cleanup is workerClosed/workerCommand/reverseRemovalExitCodes/ownedReversesAbsent/privateDirectoryRemoved/ownedCommandsClosed/ownedCommandGroupsClosed. Exactly three owned reverse removals return zero. WorkerClosed reuses the exact A22a closure keys but includes all injected WSS/proxy/fixture resources; actual joins precede Store release. Top-level cleanup is forceStopCommand/uninstallCommand/uninstallConfirmed/ownedCommandsClosed/ownedCommandGroupsClosed. All required commands and closures succeed. Failed/unreached evidence may be null but cannot pass. Non-time counts have the finite limits above; cleanup counts are at most 64 and must be zero for acceptance.

The host-cleanup record has A22a's exact fields and actual termination/join rules, with format `http-freekit-a22b-host-cleanup`. Keep 65536-byte runtime, 16384-byte host and 131072-byte XML/HTML bounds. Strict duplicate/unknown/type checks apply throughout. Only finite stage/problem categories enter diagnostics.

Extend the existing manual workflow with a finite a22a/a22b choice, default a22a. The root-owned driver and independent verifier select the same suite and exact four paths. Keep verified fresh-AVD clock alignment before keys/timers, ordinary shell restoration, exact source binding, immutable actions and real emulator cleanup. Retain only the selected four sanitized artifacts; never merge partial sources or suites. No local emulator or new runtime dispatch is authorized by this contract alone.
