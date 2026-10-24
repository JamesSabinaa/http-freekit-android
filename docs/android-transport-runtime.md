# Android-to-Node transport runtime

[Android-to-Node transport runtime](../.github/workflows/transport-runtime.yml) is a separate manual-only workflow for the isolated A5 transport experiment. It uses standard public Ubuntu 24.04 runners, with independent API 26 and API 37 AOSP x86_64 emulators. It reuses the verified SDK archive, explicit licences, `libpulse0`, and mandatory KVM checks from the [Keystore workflow](../.github/workflows/keystore-runtime.yml). Missing KVM or boot completion fails the job; there is no software-emulation fallback, snapshot, or AVD cache.

The workflow pins Node 24.22.1, checks for OpenSSL 3, installs the locked transport fixture dependencies using `npm ci --ignore-scripts --no-fund`, and verifies the booted Android API before running the host driver from the repository root:

```sh
node tools/transport-spike/run-android-interop.mjs --serial emulator-5554
```

The A5 driver owns the temporary loopback Node peer, ephemeral certificate material, two dynamically allocated ADB reverse mappings, and the `:transport-interop:connectedDebugAndroidTest` invocation. It must remove only its own mappings, stop its peer, delete its private temporary files, and retain a nonzero status on failure. The workflow independently shuts down its emulator while preserving the driver or validation exit status. A missing driver or unsupported device fails instead of skipping execution.

The regular [host workflow](../.github/workflows/android.yml) checks OpenSSL 3, executes `node --test tools/transport-spike/android-peer.test.mjs`, and runs `:transport-interop:assembleDebugAndroidTest :transport-interop:lintDebug`. Those checks validate the controlled peer and instrumentation compilation without claiming Android execution.

The expected `com.httpfreekit.interop.AndroidNodeInteropTest` cases are:

- `nonexportableIdentityEnrollsAndEchoes64KiB`
- `wrongPinIsRejected`
- `wrongHostnameIsRejected`
- `missingClientCertificateIsRejected`

After the driver succeeds, the workflow independently requires XML containing exactly those four methods once each, with zero failures, errors, or skips. Reports come only from `tools/transport-spike/android/build/outputs/androidTest-results/connected/` and its HTML report directory. They are retained for seven days. No APKs, peer keys, peer logs, keystores, AVD files, or userdata are uploaded. Only Gradle and locked npm dependencies are cached.

This experiment is intended to compose the real Android Keystore identity, [enrolled client credential binding](decisions/0004-enrolled-client-credentials.md), and [scoped gateway TLS factory](decisions/0003-scoped-tls-connections.md) with a controlled Node peer. An ADB reverse mapping transports test bytes to the host loopback; it does not establish the physical USB capture milestone. No production enrollment, desktop gateway, packet engine, VPN, certificate installer, or WAN route is exercised.

## First hosted attempt

[Run 40094676455](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40094676455) tested source `30ea165bbdb069118f0ea6d06c92be8247349ade` on both emulator APIs. Booted Android versions were 8.0.0 (API 26) and 17 (API 37), with emulator 37.2.12.0, Node 24.22.1, and OpenSSL 3.0.13. SDK/KVM/boot checks passed, and the peer reported two allocated reverse mappings before Gradle began testing.

Both jobs failed. Each downloaded XML reports only `missingClientCertificateIsRejected`, with one failure, zero errors/skips, and an empty failure body. The other three required methods are absent. There is no passing evidence for the complete suite or the positive mutual-TLS/WebSocket exchange. Console output supplies no instrumentation exception or crash cause. Cleanup then reported both owned reverse listeners absent; that later observation does not establish the original cause.

The strict test gate remains unsatisfied. Driver diagnostics and mapping lifetime need investigation before another test attempt; no failure is treated as a supported TLS rejection or a passing security check. Android-to-Node success remains unverified until a new integrated run provides all four named passing cases on each API.
