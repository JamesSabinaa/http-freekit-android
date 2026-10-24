# Android enrollment runtime report contract

This A22a research adapter/report contract implements the [live enrollment profile](research-enrollment-https.md). It adds no production wire fields. The profile is normative for the two methods and binary private input. The parser, driver and manual workflow are integrated; actual Android runtime validation remains pending. A22 adversarial Android cases and A22b active WSS revocation/expiry remain separate gates.

## Files and ownership

The root-owned driver writes only sanitized results, after actual selective cleanup:

```text
tools/transport-spike/android/build/outputs/androidTest-results/enrollment-runtime/debug/runtime.json
tools/transport-spike/android/build/outputs/androidTest-results/enrollment-runtime/debug/TEST-enrollment-research.xml
tools/transport-spike/android/build/reports/androidTests/enrollment-runtime/debug/index.html
```

The workflow separately writes `build/reports/enrollment-runtime/host-cleanup.json` after terminating/joining its emulator. The driver must not claim emulator observations it cannot make. The final independent verifier requires both JSON records; XML/HTML are method-result projections, not substitutes for host cleanup. Runtime JSON is at most 65,536 bytes, host cleanup JSON 16,384 bytes, and each rendered XML/HTML projection 131,072 bytes. Reject duplicate/unknown JSON keys, nonfinite/unsafe numbers, invalid types and unbounded strings. No raw instrumentation/ADB/emulator/worker output, private input, IDs, nonces, signatures, CSR/certificate bytes, registries, journals or keys enter these records.

## Incremental invocation parser

F supplies `tools/transport-spike/enrollment-runtime-results.mjs`, with:

```text
createEnrollmentInvocationParser(method, {onPhase?}) -> {push, finish}
parseEnrollmentInvocation(output, {method, ...commandResult}) -> Invocation
createEnrollmentRuntimeReport(observations) -> validated copied RuntimeReport
enrollmentRuntimeXml(report), enrollmentRuntimeHtml(report) -> bounded text
```

`method` is exactly `prepareApprovedCredentialForRestart` or `reopenApprovedCredentialAfterRestart` on class `com.httpfreekit.interop.DraftEnrollmentInteropTest`. Each invocation selects one method, declares one JUnit test, and executes once. `push` accepts copied stdout byte chunks, with a 262,144-byte total and 8192-byte line limit, strict incremental UTF-8 and bounded pending status metadata. It handles arbitrary chunk/line boundaries. `finish` flushes the decoder and requires an exact matched start/completion, one terminal code `-1`, successful owned command and every required phase. Missing, foreign, duplicate, overlapping, skipped, crashed, late or malformed events fail closed. Counts and phases describe actual observations; an unstarted method is never a pass.

Pending bundles have at most sixteen fields. `finish(commandResult)` accepts the owned helper's `code`, `signal`, `reason`, `closeObserved` and `processGroupClosed`; `enrollmentCommandObservation` copies these into the report's command shape. The module also exports `expectedEnrollmentMethods`, `enrollmentRuntimeClass`, `enrollmentPhases`, `enrollmentReportPaths`, `enrollmentRuntimeLimits`, `EnrollmentRuntimeError`, and `enrollmentRuntimeProblem` (unknown driver-stage text becomes `host_setup_failed`). `decodeEnrollmentRuntime`/`verifyEnrollmentRuntime` and `decodeEnrollmentHostCleanup`/`verifyEnrollmentHostCleanup` provide strict decoding and independent acceptance separately. Unknown fields or provider text never become new report categories.

Status 2 must contain exactly `draftEnrollmentVersion=1` and one `draftEnrollmentPhase`, while the matching method is active. Prepare phases are exactly:

```text
input-consumed
strict-csr-reserved
pending-proof-observed
awaiting-host-approval
approved-result-validated
credential-persisted
prepare-resources-closed
```

Reopen phases are exactly:

```text
reopen-key-and-record-validated
reopen-mtls-authorized
reopen-resources-closed
```

Only a complete valid next phase terminated by LF during live `push` may call `onPhase(phase)`, once, synchronously. The callback must return `undefined`; it may schedule tracked host approval work but cannot return an untracked promise. Invalid phase input or callback failure is a fixed parser error and aborts the owned command observer. No substring/partial-line trigger can authorize approval. `finish` runs after command closure and cannot authorize a residual phase line; it records a fixed `phase_after_command_close` problem instead. Android emits milestones only after their actual assertions and closes; cleanup after an earlier failure must not invent missing success milestones.

An `Invocation` has exactly `method`, `state`, `actualStarted`, `actualCompleted`, `terminalCount`, `terminalCode`, `phases`, `command`, `problems`, `failureType`, `frames`. `state` is `passed`, `failed`, `incomplete` or `not_started`. Observed counts are integers 0..16; successful counts are all 1 and terminal code is `-1`. `terminalCode` is null when absent, otherwise a bounded signed integer. `phases` is the observed ordered prefix. `problems` contains at most sixteen distinct fixed parser categories, never supplied text. `command` is null if not run, otherwise exactly `exitCode` (0..255 or null), `signal` (null or a fixed signal name), `reason` (null or a fixed owned-command category), `closeObserved`, `processGroupClosed`. Success requires exit 0, null signal/reason and both closure flags true.

`failureType` is null or a finite known exception-type category; arbitrary messages/causes/suppressed text are discarded. At most sixteen frames may contain only project-owned `com.httpfreekit.interop.DraftEnrollment*` class/method tokens, a matching `DraftEnrollment*.kt` basename and bounded positive line number. Do not preserve provider paths or arbitrary stack lines. The last observed phase supplies failure context. The Android sender also keeps thrown diagnostics sanitized; this text channel is not cryptographic attestation of arbitrary provider output.

## Driver runtime JSON

`RuntimeReport` has exactly `format`, `revision`, `source`, `api`, `clock`, `invocations`, `input`, `approval`, `stop`, `restart`, `cleanup`, `problems`. `format` is `http-freekit-a22a-runtime`; `revision` is integer 1. `source` is `{commit,trackedDirty}` with a lowercase 40-hex commit and boolean tracked flag. `api` is 26 or 37. Success requires the verifier's expected clean source/API. Failed setup may retain null for unavailable source/API/clock or an unreached evidence group; it cannot pass. `invocations` always contains the two expected method records in order; absent invocations use explicit not-started records. Global `problems` is a bounded distinct list of fixed driver-stage categories.

`clock` has exactly `deviceEpochSeconds`, `hostBeforeMillis`, `hostAfterMillis`, `lowerBoundMillis`, `upperBoundMillis`, `roundTripMillis`. Times are safe integers. The verifier independently derives lower = deviceSeconds*1000 - hostAfter and upper = deviceSeconds*1000 + 999 - hostBefore, requires both recorded bounds to agree and the entire interval within [-2000,2000] ms, and round trip hostAfter-hostBefore within 0..2000 ms. No clock adjustment or guessed point-only skew is accepted.

Evidence groups have these exact fields. Booleans are actual observations, never defaults implying success; null denotes an unreached group. Counter bounds are finite (0..32 unless noted).

| Group | Fields and successful requirements |
| --- | --- |
| `input` | `byteCount` (1..16384), `inputBytes` (equal byteCount), `inputFinished`, `inputClosed`, `command`, `inputAbsentAfterPrepare`. All booleans true and command successfully closed. Bytes travel only through owned run-as stdin to the profile's fixed private path. |
| `approval` | `liveAwaitingPhaseObserved`, `dropArmAcknowledged`, `requestedAfterArm`, `completed`, `actualApprovedResponseDrops`, `approvedResponsesAfterDrop`, `reopenedApprovedResponses`. Booleans true; first-worker actual drops exactly 1 and successful approved deliveries after that drop at least 1. The reopened worker separately records at least one actual approved-response write callback. Do not rearm or persist the drop across restart. An arm acknowledgment alone is not evidence of a dropped response. |
| `stop` | `forceStopCommand`, `deviceBefore`, `deviceAfter`, `presenceBefore`, `presenceAfter`, `absenceQueryExitCode`, `absenceMarkerVerified`. Device values exactly `device`; presenceBefore `present` or `absent`, presenceAfter `absent`; force-stop command succeeds, query exit 0 and explicit absence marker true. A transport failure/empty failed output is not absence. Do not infer forced death when it had already exited, or require unequal reused PIDs. |
| `restart` | `initialWorkerClosed`, `initialWorkerCommand`, `opened`, `continuity`. Worker closure/command successful; opened true. Continuity shape below proves the same identities, published result and exact endpoints. No forced restart is accepted as this graceful A22a sequence. |
| `cleanup` | `forceStopCommand`, `uninstallCommand`, `uninstallConfirmed`, `reverseRemovalExitCodes`, `ownedReversesAbsent`, `finalWorkerClosed`, `finalWorkerCommand`, `ownedCommandsClosed`, `ownedCommandGroupsClosed`, `privateDirectoryRemoved`. Commands/closures succeed; booleans true; removal array exactly two integer zeros from successful owned registrations only. |

`continuity` has exactly `setupPortBefore`, `setupPortAfter`, `credentialPortBefore`, `credentialPortAfter`, `gatewayCertificateSha256Before`, `gatewayCertificateSha256After`, `enrollmentAuthoritySha256Before`, `enrollmentAuthoritySha256After`, `approvedResultSha256Before`, `approvedResultSha256After`. Ports are 1..65535, both role ports are distinct, and each role is unchanged across restart. Each hash is 64 lowercase hex and before/after values match. The result hash covers the public canonical `pair_approved` wire encoding. These hashes contain no invitation secret or private key.

Each `WorkerClosed` object has exactly `admissionClosed`, `listenersClosed`, `storeClosed`, `issuerChildrenJoined`, `activeSockets`, `pendingCallbacks`, `pendingTimers`, `issuerJobs`, `signerGroups`, `workers`. Success requires all booleans true and counters zero. Counts cover fixture HTTP/TLS/issuer/background resources, excluding the private close-reply IPC dispatch itself; the separate worker command must then actually close stdio and its process group. Decrement socket/child ownership only after actual close/join, not after destroy/stop requests. Issuer work cannot remain live when the Store lease is released or the worker reopens.

The two method outcomes remain truthful even if a later host operation fails. XML always projects exactly the two method names, with errors for unexecuted/incomplete methods and no fabricated host test; successful method XML alone cannot turn a failed runtime/cleanup report into a passing run. Write final reports only after all real cleanup attempts and keep the original failure when cleanup also fails. Driver console output is fixed counts/source/stage categories only.

## Workflow cleanup JSON and acceptance

`host-cleanup.json` has exactly `format`, `revision`, `sourceCommit`, `api`, `driverExitCode`, `emulatorStarted`, `stopAttempted`, `stopExitCode`, `terminationObserved`, `joinObserved`, `emulatorExitCode`. `format` is `http-freekit-a22a-host-cleanup`, revision is integer 1. Source/API must match the runtime/verifier. Success requires driver exit 0, emulator started, stop attempted and actual termination/join true. Command/owned-process exit codes are null when unavailable, otherwise bounded integers; a stop-request failure may use owned-PID SIGTERM/KILL fallback only if termination and join are actually verified. Missing cleanup cannot become a successful skip.

F supplies `scripts/verify-enrollment-runtime.mjs` with `--source`, `--api` and `--started` inputs and optional `--runtime`, `--host`, `--xml` and `--html` paths. It checks all four fresh bounded files, exact schemas/source/API, actual ordered invocations/phases, approval/drop facts, process-absence/restart continuity, and all cleanup. XML and HTML must match the exact renderer bytes derived from the validated runtime record; missing, stale or appended material fails. Default report paths are the fixed paths above. Failure is a static category without input content. A separate manual-only standard Ubuntu/KVM API 26/37 workflow will retain only these sanitized JSON/XML/HTML reports. Its real execution, additional Android adversarial cases and A22b remain required; this contract is not runtime evidence.
