# Android preview runtime checks

[Android preview runtime](../.github/workflows/preview-runtime.yml) is a manual-only workflow for the actual `MainActivity` developer preview. It runs on standard public Ubuntu 24.04 runners with independent API 26 and API 37 AOSP x86_64 emulators. It reuses the verified SDK bootstrap, explicit SDK licences, `libpulse0` dependency, and mandatory KVM checks from the [Keystore runtime workflow](../.github/workflows/keystore-runtime.yml). It uses no snapshots or AVD cache, and fails when hardware acceleration or boot is unavailable.

The four [Compose tests](../app/src/androidTest/java/com/httpfreekit/android/preview/PreviewActivityTest.kt) use visible resource text and selection/toggle semantics, with no pixel coordinates or production state injection. They check:

- The no-capture warning on Home, Apps, Setup, and Diagnostics, including after scrolling.
- Public sample computer and example-app selections, retained after landscape and portrait rotation.
- The simulated notification and VPN consent dialogs, ready state, and Stop action, with capture still marked unverified.
- Notification denial and VPN cancellation, with clear terminal preview states.

These controls never request an Android VPN, network traffic, or certificate installation. The tests use no real invitation, credential, installed-app list, or user data. They exercise the [local preview](android-preview.md); system permission dialogs, actual service lifecycle, process-death persistence, and production capture remain separate work.

Compile and lint locally with the [pinned toolchain](development.md):

```sh
./gradlew :app:assembleDebugAndroidTest :app:lintDebug
```

On a compatible booted emulator, execute the suite with:

```sh
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true
```

The manual workflow verifies the booted API, executes all four named tests exactly once, and rejects missing XML, failed tests, errors, or skips. The host workflow also compiles the instrumentation APK; compilation is not runtime evidence.

The ready-state test captures an actual rendered screen containing only the built-in sample preview into the debug app's private files. The Gradle property above keeps the debug app installed long enough for binary-safe `adb exec-out run-as` retrieval of that single PNG. The workflow checks its PNG header and dimensions, then retains only instrumentation XML/HTML reports and `sample-preview-ready-api-26.png` or `sample-preview-ready-api-37.png` for seven days. It uploads no APKs, keys, emulator logs, snapshots, or userdata. The emulator is shut down even when a check fails.

## Hosted evidence

[Run 40093068781](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40093068781) tested source commit `61654377005f3a49f369fbf42697481a28e8018d`. Both jobs used emulator 37.2.12.0 (build 16428233), reported KVM version 12 usable, and passed their booted-API check. API 26 booted Android 8.0.0 with AOSP x86_64 image revision 1; API 37 booted Android 17 with image revision 6.

Downloaded API 26 XML contains exactly these four passing `PreviewActivityTest` cases, with zero errors, failures, or skips:

- `noCaptureWarningAppearsOnEveryPreviewPage`
- `sampleComputerAndAppSelectionsSurviveRotation`
- `simulatedConsentReachesReadyAndStopWithoutClaimingCapture`
- `deniedNotificationAndCancelledVpnConsentStayInPreview`

The original `sample-preview-ready-api-26.png` is 1080 by 1920 pixels, SHA-256 `66afc3ba04ad3182acc868a531e6b9b073a810d6ff49c4daccef055591093f93`. Visual inspection at its original size confirmed a clear fixed no-capture banner, simulated ready state, public sample computer, selected-app count, Stop button, and VPN-inactive warning, without overlap or clipping in that card. The lower Setup checks card continues below the scroll viewport. This is one portrait sample frame, not a complete visual or accessibility audit.

API 37 XML reports four initialization failures and no skips. All fail in Espresso's `InputManagerEventInjectionStrategy` before test bodies run: reflective `android.hardware.input.InputManager.getInstance` is unavailable. Dependency inspection shows Compose test 1.12.1 selected Espresso core 3.5.0 transitively. [Official Espresso 3.7.0 release notes](https://developer.android.com/jetpack/androidx/releases/test) document replacement of that reflection with the supported system service. API 37 preview behavior and its screenshot remain unverified until a compatible pinned test dependency passes a new hosted run; no tests or API are skipped to conceal the failure.

[Host run 40093068640](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40093068640) passed at the same source commit, including app instrumentation compilation. Physical-phone layout, accessibility, keyboard behavior, notification Stop, VPN revocation, USB routing, HTTPS interception, and cellular WAN remain unverified.
