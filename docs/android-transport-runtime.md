# Android-to-Node transport runtime

[Android-to-Node transport runtime](../.github/workflows/transport-runtime.yml) is a separate manual-only workflow for the isolated A5 transport experiment. It uses standard public Ubuntu 24.04 runners, with independent API 26 and API 37 AOSP x86_64 emulators. It reuses the verified SDK archive, explicit licences, `libpulse0`, and mandatory KVM checks from the [Keystore workflow](../.github/workflows/keystore-runtime.yml). Missing KVM or boot completion fails the job; there is no software-emulation fallback, snapshot, or AVD cache.

The workflow pins Node 24.22.1, checks for OpenSSL 3, installs the locked transport fixture dependencies using `npm ci --ignore-scripts --no-fund`, and verifies the booted Android API before running the host driver from the repository root:

```sh
node tools/transport-spike/run-android-interop.mjs --serial emulator-5554
```

The driver builds `:transport-interop:assembleDebugAndroidTest` and installs only the research test APK before starting the temporary loopback Node peer or allocating its two ADB reverse mappings. It then invokes the research runner explicitly using `adb shell am instrument -w -r`, with the exact test class and public fixture arguments. This keeps the mappings outside Gradle's test-device preparation. A missing driver or unsupported device fails instead of skipping execution.

Instrumentation has a three-minute deadline and a 256 KiB combined-output limit. The driver requires each expected method's matching start/end status, the final successful instrumentation status, and preservation of its own reverse mappings. It writes only bounded, sanitized XML/HTML containing exception types and allowlisted research call sites; raw instrumentation output, peer logs, and exception messages are not retained. Cleanup stops its owned process, uninstalls only the research test package, removes only its own reverse mappings, stops its peer, and deletes private temporary files. A cleanup failure remains a failed run. The workflow independently shuts down its emulator while preserving the driver or validation exit status.

The regular [host workflow](../.github/workflows/android.yml) checks OpenSSL 3, executes the two `android-peer.test.mjs` cases and fifteen `instrumentation-results.test.mjs` regressions, and runs `:transport-interop:assembleDebugAndroidTest :transport-interop:lintDebug`. Reproduce the Node checks from the repository root:

```sh
node --test tools/transport-spike/android-peer.test.mjs
node --test tools/transport-spike/instrumentation-results.test.mjs
```

These checks validate the controlled peer, strict result parsing, and instrumentation compilation without claiming Android execution.

The expected `com.httpfreekit.interop.AndroidNodeInteropTest` cases are:

- `nonexportableIdentityEnrollsAndEchoes64KiB`
- `wrongPinIsRejected`
- `wrongHostnameIsRejected`
- `missingClientCertificateIsRejected`

After the driver succeeds, the workflow independently requires XML containing exactly those four methods once each, with zero failures, errors, or skips. Reports come only from `tools/transport-spike/android/build/outputs/androidTest-results/connected/` and its HTML report directory. They are retained for seven days. No APKs, peer keys, peer logs, keystores, AVD files, or userdata are uploaded. Only Gradle and locked npm dependencies are cached.

The generated report always describes the four contract cases. A case that never started or did not complete has an explicit error; it is not recorded as an executed or passing test. The `actualStarted` and `actualCompleted` properties report observed status counts separately. Missing, duplicate, crashed, skipped, unfinished, or empty failed results cannot pass. Four XML rows alone do not establish four executions.

After a failed driver exits, the workflow records a small host snapshot before emulator cleanup. It reports the launcher PID's presence, its exact shell exit status when already terminated, and an ADB `get-state` category, with a five-second deadline and one-second termination grace. It scans at most the last 64 KiB of the emulator log for fixed panic, shared-library, KVM, signal-termination, or segmentation-fault categories. No matching line, path, or raw log content enters the JSON. A missing category is not proof that no crash occurred. Only `transport-host-diagnostic.json` is retained alongside the sanitized test reports; the driver's original failure status is preserved even if diagnostic collection fails.

Before any ADB invocation, the workflow creates an empty server log with owner-only permissions inside a private directory under `RUNNER_TEMP` and exports `ANDROID_ADB_LOG_PATH` to later steps. The raw file is excluded from every artifact path and is never printed. This makes a known, job-specific log available to the driver's bounded classifier without searching shared temporary directories or starting another ADB server to discover its location.

The [AOSP log-path implementation](https://android.googlesource.com/platform/packages/modules/adb/+/9084198a2d4b0f6a0f174260fb42da33485b684d/adb_utils.cpp#322) first honors `ANDROID_ADB_LOG_PATH`; otherwise Linux uses `adb.<uid>.log` under `TMPDIR` when that variable is set, or `/tmp` when it is unset. [Daemon startup](https://android.googlesource.com/platform/packages/modules/adb/+/9084198a2d4b0f6a0f174260fb42da33485b684d/client/main.cpp#51) opens the file for append and redirects server stdout/stderr there. The [37.0.1 release notes](https://developer.android.com/tools/releases/platform-tools#revisions) document Linux kill-request command-line chains. Those chains can contain private arguments: diagnostics may retain only fixed markers and allowlisted public source identifiers, never raw lines, arguments, serials, paths, or inferred requester names. The available public source snapshot predates the new chain formatter, so its full record grammar is not assumed. A marker is evidence of an observed log event, not proof of the cause of an interrupted test.

This experiment is intended to compose the real Android Keystore identity, [enrolled client credential binding](decisions/0004-enrolled-client-credentials.md), and [scoped gateway TLS factory](decisions/0003-scoped-tls-connections.md) with a controlled Node peer. An ADB reverse mapping transports test bytes to the host loopback; it does not establish the physical USB capture milestone. No production enrollment, desktop gateway, packet engine, VPN, certificate installer, or WAN route is exercised.

## First hosted attempt

[Run 40094676455](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40094676455) tested source `30ea165bbdb069118f0ea6d06c92be8247349ade` on both emulator APIs. Booted Android versions were 8.0.0 (API 26) and 17 (API 37), with emulator 37.2.12.0, Node 24.22.1, and OpenSSL 3.0.13. SDK/KVM/boot checks passed, and the peer reported two allocated reverse mappings before Gradle began testing.

Both jobs failed. Each downloaded XML reports only `missingClientCertificateIsRejected`, with one failure, zero errors/skips, and an empty failure body. The other three required methods are absent. There is no passing evidence for the complete suite or the positive mutual-TLS/WebSocket exchange. Console output supplies no instrumentation exception or crash cause. Cleanup then reported both owned reverse listeners absent; that later observation does not establish the original cause.

The strict test gate remained unsatisfied. The updated driver in `1a3e28a` changes installation/mapping order and exposes bounded instrumentation diagnostics; its host regressions are not a runtime fix claim. Android-to-Node success remains unverified until a new integrated run provides all four named passing cases on each API, with four observed starts and completions and no run errors.
