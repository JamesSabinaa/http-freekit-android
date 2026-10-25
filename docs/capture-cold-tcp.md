# Cold TCP comparison

Status: implemented and actually run at f847197; the cold API26 transaction reproduces `traffic_tcp_eof_reset` without prior VPN activity. The [capture policy](capture-policy-runtime.md) remains open: a full reply does not replace the required EOF. This comparison changes no production or companion wire contract.

## Experiment and ownership

Use a separate fresh standard Ubuntu/KVM API26 AVD. Install only the research runtime, its instrumentation APK and the signature-protected traffic APK, after verifying fresh package absence and a common signer. Run exactly `com.httpfreekit.capturetest.CaptureColdTcpInteropTest#coldUnboundHttpRequiresStrictEof` once. There is no preceding app-data transaction, instrumentation, VPN consent request, capture Start or Stop. Do not place this comparison before the existing C1 UID case or change its sequence.

The new method binds `TrafficClient`, whose constructor sends CONFIGURE1 only, observes the unchanged WAIT_NON_VPN18 readiness, sends unchanged HTTP10 once, then closes the client through FINISH2, unbind and actual reply-thread join. HTTP10 remains the first and only data request: the same unbound host-alias TCP80 endpoint, fixed request, SHUT_WR, full reply/content check and separate mandatory EOF read. Preserve all payloads, deadlines, socket order and error classification. Do not call HostReceiver from Android. Inert reads of `ResearchCaptureService.current` and `.configuration` must both be null before and after; do not instantiate/start that service. No packet observer, extra socket, retry or warm-up is added.

Root owns this profile, board and integration. UI owns only new `CaptureColdTcpInteropTest.kt`. D owns only new `tools/capture-spike/capture-cold-results.mjs` and its test. F owns the new cold driver/test, separate workflow, Python verifier/test and narrow host-CI/validation wiring. Each branches from this committed profile in its own worktree. D's checked parser/export contract precedes F's final binding checks. Existing capture test, traffic service/client, fixture, core and production app sources are outside scope.

## Finite Android observation

Send one exact observation bundle after attempted client cleanup: status2 on success, status3 on any failure. Preserve the first finite failure and the command-result tuple before cleanup; a later cleanup failure cannot erase it. A cleanup failure without an earlier failure uses `cold_client_cleanup`. Do not retain provider messages, exception objects, causes, suppressed exceptions or arbitrary source frames. A failed method throws only a fixed project-authored assertion without an original cause. Every field below is present as a string; no other fields are allowed in this status bundle.

| Field | Values |
| --- | --- |
| `coldVersion` | `1` |
| `coldScenario` | `cold-http` |
| `coldOwnerAbsentBefore`, `coldOwnerAbsentAfter` | `true` or `false`, actual inert observations |
| `coldRouteObserved` | `true` only after successful command18 tuple |
| `coldHttpAttempts` | `0` or `1`, increment before the one command10 call |
| `coldTrafficCommand` | `0`, `18` or `10`, latest attempted route/data command |
| `coldTrafficStatus` | `-1` before an actual reply, otherwise `0`–`3` |
| `coldTrafficBytes` | canonical integer `0`–`65507`, actual returned result count, not partial bytes received |
| `coldTrafficSha256` | `none` or lowercase 64-character SHA256, actual returned result |
| `coldFailurePhase` | `none`, `setup`, `route`, `http`, `client-cleanup` or `owner-check` |
| `coldFailureCode` | `none`, finite traffic code below, or fixed local code below |
| `coldCleanupJoined` | `true` only after actual TrafficClient.close succeeds; false when unavailable or failed |

Finite traffic codes are the existing `traffic_tcp_{connect,write,shutdown,reply,eof,close}_{timeout,io,protocol,other,reset,aborted,closed,bad_fd,not_connected}`, `traffic_route_nonvpn_timeout_p{0,1}_i{0,1}_v{0,1}`, `traffic_route_unavailable`, `traffic_command_failed` and `traffic_close_io`. Fixed local codes are `cold_setup`, `cold_route_reply`, `cold_tcp_reply`, `cold_client_cleanup`, `cold_owner_present`. An unexpected exception uses the applicable fixed local code and phase, never its message. A failed finite command uses its actual finite failureCode, or the applicable local reply code if absent. Preserve that first failure if cleanup/owner checks later fail.

Status2 requires both absent-owner observations, routeObserved and cleanupJoined true; httpAttempts1; trafficCommand10/status0/bytes32787/hash `05dfd86ee3ecc0267ceb6234e1955c1e8c80e34b6323b2b1c87c7d1d84042255`; failurePhase/code both `none`. Status3 requires a non-none phase/code and always fails acceptance, even if another bundle or terminal status later claims success. Unknown/duplicate fields, multiple observations, malformed integers, arbitrary failure text, incomplete invocation or any failure observation prevent acceptance. Preserve exact method start/completion counts and normal instrumentation terminal -1; no synthetic pass or skip.

## Separate report and host gates

Use directory `build/reports/capture-cold-tcp/`, format `http-freekit-capture-cold-tcp`, revision1. Retain only `runtime.json`, `TEST-capture-cold-tcp.xml`, `host-cleanup.json`. Raw instrumentation, ADB/emulator logs, APKs, credentials and packet bodies remain private. Bound JSON to131072 bytes, XML to65536 and instrumentation input to262144/8192 per line. Fixed problems are `source_unavailable`, `device_unavailable`, `clock_outside_bound`, `apk_build_failed`, `package_already_present`, `apk_install_failed`, `host_setup_failed`, `fixture_setup_failed`, `research_cancelled`, `cleanup_incomplete`; unknown problems normalize to `host_setup_failed`.

Report keys: `format`, `revision`, `source` (`commit`, `trackedDirty`), `api`, `clock`, `method` (`invocation`, `receiversBefore`, `receiversAfter`), `cleanup`, `problems`, `accepted`. Use API26 only and the same actual source/clean-worktree and full clock-interval/round-trip rules as C1. Invocation uses the existing structural shape: method, state, actualStarted/Completed, terminalCount/Code, observation, failure, command and problems. Only one actual start/completion and terminal -1 with command exit0/signal null/reason null/actual stdio and process-group joins can pass. Failure retains only `{phase, code}`; negative observations stay in observation. Command failure reason is only null or `owned_command_failed`. Parsing problems are fixed `instrumentation_bound`, `instrumentation_structure`, `invalid_cold_facts`, `instrumentation_failed`, `instrumentation_incomplete`.

Reuse unchanged `createCaptureFixture()` and take host snapshots in process. Snapshot keys are all nineteen cumulative fields listed below, the five resources and boolean `closed`; integers are bounded 0–10000000. Before the transaction every cumulative field is0, resources are0 except listeners7, closed=false. After the transaction all resources are0 except listeners7, closed=false; the exact positive cumulative vector is:

| Counter | Required value |
| --- | --- |
| `directHttp`, `tcpConnections` | `1` |
| `uploadBytes` | `16528` |
| `downloadBytes` | `32787` |
| `directOpaque`, `directTcp`, `udp`, `dns`, `udp443`, `interceptedHttp`, `interceptedOpaque`, `interceptedIpv6`, `invalidRequests`, `heldRequestsClosed`, `heldCloseRequests`, `udpDatagrams`, `deadlineCloseRequests`, `tcpErrorEvents`, `tcpResetErrors` | `0` |

The five resource keys are `activeSockets`, `pendingCallbacks`, `timers`, `listeners`, `heldConnections`. Cleanup has exactly `forceStopExitCodes`, `uninstallExitCodes`, `packagesAbsent`, `ownedCommandsClosed`, `ownedCommandGroupsClosed`, `receivers`. Both code arrays have length3 and all0, packagesAbsent requires actual package and process absence, both command joins are true. Receiver cleanup has closed=true, all five resources0 and unchanged cumulative values from after. Snapshot reset errors cannot exceed error events. No control HTTP request is sent from Android or the driver.

The separate host cleanup format is `http-freekit-capture-cold-host-cleanup`, revision1, with the same exact source/API/driverExitCode/emulatorStarted/stopAttempted/stopExitCode/terminationObserved/joinObserved/emulatorExitCode fields as C1. Acceptance additionally requires driver exit0, real emulator start, stop0, termination/join and emulator exit0. Missing/pre-driver reports never become a device result.

D exports immutable `captureColdClass`, `captureColdMethod`, `captureColdSnapshotKeys`, `captureColdCleanupKeys`, plus `captureColdProblem(value)`, `parseCaptureColdInvocation(bytes, command)`, `captureColdReportAccepted(report)`, `captureColdXml(report)`. Snapshot keys include all25 fields; cleanup keys mean the six report cleanup fields above. F implements an independent bounded Python/XML/source/clock/host-cleanup verifier from these tables, without importing Node expectations. The fresh workflow reuses checked SDK, clock-transition and emulator ownership blocks. Host tests exercise actual CLI failure and cleanup with unavailable devices, and parsers/verifiers reject contradictory success, foreign cases, counter errors and missing joins.

## Interpretation

A matching cold failure shows that prior VPN activity is not necessary for this failure. A cold pass alone does not prove VPN causality or clear C1. Even a matching full host reply cannot turn failed EOF into success. Compare actual reports before changing capture behavior. No core change, longer wait, payload change, library switch or new production claim follows from this profile alone.

## Checked implementation

UI's 5f59ec1 is integrated as 721a560 (one new Android test); D's d50822d as 1739874 (new parser/tests); F's 422d45d as 93f6b0d (separate runner, workflow, independent verifier and host checks). Root's integrated check passes six existing runtime JVM cases, host/instrumentation APK assembly and strict lint in 18 seconds. Actual APK IDs, signatures, common debug signer and 16 KiB ZIP alignment are verified again; the comparison installs only its three specified APKs. The combined new Node checks pass 27 cases, including actual CLI/unavailable-child and owned Bash cleanup cases; Python guards pass 12, documentation tests pass nine, and 199 local links resolve. Node-generated XML matches the independent Python verifier in the compatibility fixture. Focused actionlint schema/expressions and all 36 changed-workflow ShellCheck/Bash blocks pass without suppressions; full Linux host and actual Android outcomes remain separate checks. Existing C1, TrafficClient, TrafficService, fixture and core sources are unchanged from c43f0e8. No comparison result or C1 acceptance is established by these local checks.

## Actual cold result

At `f8471970de730ae4f4fb9cc2f7ec8a4c46f0d0b3`, [run 40156287722](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40156287722), job 121058283509 records one actual start/completion and terminal code -1. Its command exits with code 0 and observed stdio/process-group joins. All thirteen fields are retained: both owner/configuration observations are absent, route readiness completes, HTTP attempts=1, command 10 returns status=3/bytes=0/hash=none, and the first failure is `http` / `traffic_tcp_eof_reset`. Client cleanup joins. The unchanged source verifies all 32787 reply bytes and content before entering the separate EOF read; returned bytes=0 is a failed-command result count, not zero network receipt.

Receiver counters begin at zero and finish with exactly `directHttp=1`, `tcpConnections=1`, `uploadBytes=16528` and `downloadBytes=32787`. Every other path and all deadline/error/reset counters remain zero. All host data resources settle before the final receiver/listener close. Three package force-stops and uninstalls exit with code 0, package/process absence is observed, command groups join, and emulator stop/termination/join complete with exit code 0. The measured full clock interval is [-1184,-176] milliseconds with a 9 ms round trip. JSON accepted=false, XML has one failure/one error, and driver exit code 1 preserves the failed EOF. F, UI and D independently inspect the same three original sanitized files and fixed source.

This demonstrates that prior VPN activity is not necessary for this observed failure. It does not identify a specific errno, wire RST, responsible endpoint or general Android behavior, and it does not clear C1. Preserve both negative cases. Further capture-framework changes or unchanged reruns are not justified by these observations. Actual authenticated desktop HTTP transport composition proceeds as separate research while the limitation remains recorded.

The matching [host run 40156269493](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40156269493) at f847197 passes all three jobs. Independent retained-report checks confirm 249 unique JVM cases, 455 Node cases (83 capture cases), eight clean lint reports, both actual protocol comparators and eight fresh Linux crash cases. Documentation checks pass 100 enrollment guards, 67 Python guards, nine checker cases, 199 local links and full hosted actionlint. Native checks pass 39 helper cases and four synthetic packet flows. These host results validate the checked harness and existing foundations; they do not change the failed cold result or establish production/physical-device acceptance.
