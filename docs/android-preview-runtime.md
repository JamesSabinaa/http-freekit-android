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

That first API 37 attempt reported four initialization failures and no skips. All failed in Espresso's `InputManagerEventInjectionStrategy` before test bodies ran: reflective `android.hardware.input.InputManager.getInstance` was unavailable. Dependency inspection showed Compose test 1.12.1 selected Espresso core 3.5.0 transitively. [Official Espresso 3.7.0 release notes](https://developer.android.com/jetpack/androidx/releases/test) document replacement of that reflection with the supported system service.

[Run 40095028000](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095028000) passed after pinning Espresso 3.7.0, at source commit `ed12db3b02451f67898f4ee19bbb80e1d5f42e5b`. Independent downloaded-XML checks confirmed all four named cases above exactly once on **each** API, with zero failures, errors, or skips. Boot logs identify API 26 / Android 8.0.0 and API 37 / Android 17; both used emulator 37.2.12.0 (build 16428233) and usable KVM version 12.

Both original 1080 by 1920 PNGs were inspected at full size. The fixed banner, simulated ready state, public sample computer, selected-app count, Stop button, and VPN-inactive warning were readable without card overlap or clipping. At that source, API 37 had one reported visual issue: white system status-bar clock/icons had low contrast over the light background.

[Run 40095827316](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095827316) verified the system-bar correction at source `89e5914e90f7a9827db52e7855d7191567a46092`. Downloaded XML again contains all four named methods exactly once on each API, with zero failures, errors, or skips. Both original 1080 by 1920 PNGs show readable dark status-bar clock/icons on the light background, readable navigation controls, and no header or card overlap. The previous API 37 contrast issue is resolved in these captured frames. This is portrait sample evidence, not a complete theme, physical-device, or accessibility audit.

Latest reviewed PNG checksums from run 40095827316:

| API | Sample PNG SHA-256 |
| --- | --- |
| 26 | `ffd2e0fba61b430c0843f1fafa25f849d36597fdb1728a07b87df55422447730` |
| 37 | `0f060cd54c52d69551b2e42074f039c4185dcd777f876da1ac3e231d415cfde8` |

[Host run 40093068640](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40093068640) passed at the same source commit, including app instrumentation compilation. Physical-phone layout, accessibility, keyboard behavior, notification Stop, VPN revocation, USB routing, HTTPS interception, and cellular WAN remain unverified.
