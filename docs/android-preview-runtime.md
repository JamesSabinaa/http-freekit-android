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

After the first hosted dispatch, inspect each downloaded screenshot at its original size and record the run, source commit, booted Android versions, four test names and results, and any visual issue. A passing test report does not replace visual review. This workflow is prepared but has not yet established a preview runtime or screenshot result. Physical-phone layout, accessibility, keyboard behavior, notification Stop, VPN revocation, USB routing, HTTPS interception, and cellular WAN remain unverified.
