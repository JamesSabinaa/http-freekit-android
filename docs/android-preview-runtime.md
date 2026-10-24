# Android preview runtime checks

[Android preview runtime](../.github/workflows/preview-runtime.yml) is a manual-only workflow for the actual `MainActivity` developer preview. It runs on standard public Ubuntu 24.04 runners with independent API 26 and API 37 AOSP x86_64 emulators. It reuses the verified SDK bootstrap, explicit SDK licences, `libpulse0` dependency, and mandatory KVM checks from the [Keystore runtime workflow](../.github/workflows/keystore-runtime.yml). It uses no snapshots or AVD cache, and fails when hardware acceleration or boot is unavailable.

The original four [sample Compose tests](../app/src/androidTest/java/com/httpfreekit/android/preview/PreviewActivityTest.kt) use visible resource text and selection/toggle semantics, with no pixel coordinates or production state injection. They check:

- The no-capture warning on Home, Apps, Setup, and Diagnostics, including after scrolling.
- Public sample computer and example-app selections, retained after landscape and portrait rotation.
- The simulated notification and VPN consent dialogs, ready state, and Stop action, with capture still marked unverified.
- Notification denial and VPN cancellation, with clear terminal preview states.

Four additional [installed-catalog tests](../app/src/androidTest/java/com/httpfreekit/android/preview/InstalledAppsActivityTest.kt) exercise real current-profile package discovery through the public UI. They check the unrelated headless fixture's label/package search, Development filter and toggles; refresh/rotation retention; disabled-fixture pruning without reselection; and separate sample/installed choices. The rotation case also checks the packaged `adjustResize` mode, focuses the real search field, observes software-keyboard visibility through `WindowInsetsCompat`, and requires the full no-capture banner before and after landscape/portrait rotation. It does not accept an absent keyboard as a passing keyboard check.

These controls never request an Android VPN, traffic, or certificate installation. The original sample cases use built-in synthetic data. Installed-catalog cases run only in the fresh emulator profile and identify the fixed `com.httpfreekit.fixture.installedapps` package; test reports contain fixed fixture messages and bounded public UI state/geometry, without inventory dumps or installed-mode screenshots. They exercise the [local preview](android-preview.md); system permission dialogs, actual service lifecycle, process-death persistence, and production capture remain separate work.

Compile and lint locally with the [pinned toolchain](development.md):

```sh
./gradlew :installed-app-fixture:assembleDebug :installed-app-fixture:lintDebug \
  :app:assembleDebugAndroidTest :app:lintDebug
```

The workflow installs the unrelated fixture before testing and checks the merged app APK for `QUERY_ALL_PACKAGES`. Its APK guard requires the fixed label/package, debug flag, minimum API 26/target API 37, no application code, permissions, launcher, or other components. It enables `show_ime_with_hard_keyboard` only on the fresh disposable AVD under a timeout and verifies readback `1`, so the emulated hardware keyboard cannot silently disable the real software-keyboard case.

For direct execution, first prepare a fresh selected emulator with that enabled debug fixture and keyboard setting as in the workflow. Then run:

```sh
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true
```

The manual workflow verifies the booted API, requires the Gradle command to succeed, and then requires exactly all eight `(class, method)` pairs once each with consistent XML counters and zero failures, errors, or skips. Cleanup enables and uninstalls only the owned fixture before terminating and waiting for the emulator; actual fixture command statuses are reported, and failed cleanup fails an otherwise successful step. Direct execution needs the same fixture cleanup even after a failed test. The host workflow compiles the instrumentation APK and assembles/lints fixture debug/release variants; compilation is not runtime evidence.

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

[Host run 40093068640](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40093068640) passed at the same source commit, including app instrumentation compilation. Those historical sample frames did not establish keyboard behavior. Physical-phone layout, broad accessibility, notification Stop, VPN revocation, USB routing, HTTPS interception, and cellular WAN remain unverified.

## Installed-catalog checkpoints

[Run 40110867531](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40110867531) at `4b224444ffcced6b22210b13cabe7898d228092d` executed all eight named cases on each API, with zero errors or skips. Discovery/search/filter/toggle, real disabled-fixture refresh/pruning, and the original four sample cases passed on both APIs. The selection-separation case failed during its first installed search on both; API 26 also failed the banner assertion after landscape rotation. The failing Gradle command correctly prevented the success gate and PNG extraction. Both actual fixture enable/uninstall commands returned 0 before emulator teardown completed.

[Corrected run 40112189433](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40112189433) at `96678cdbbb62a62531748dda834e4211cc3130df` again executed exactly eight cases per API with zero errors or skips. Seven passed on each API, including the strengthened real-keyboard rotation/banner case. That passing case required the packaged resize flag, observed IME visibility, retained fixture selection, and the full banner in portrait, landscape, and returned portrait. The fresh-AVD keyboard setting read back `1` on both jobs. The separation case still failed in its readiness helper before the first installed search; that helper combined status scrolling and ready-state waiting at this checkpoint, so this result alone does not identify a provider failure.

Both corrected jobs passed the headless-fixture and merged-permission checks, booted the expected API, and reported fixture enable/uninstall exit 0 before the owned emulator wait returned. Tools were emulator 37.2.12.0 build 16428233, KVM 12, and ADB 37.0.1-15733141; images booted API 26/Android 8.0.0 and API 37/Android 17. No new sample PNG was exported after the failing Gradle command. The full eight-case checkpoint remains open, while the keyboard/banner result is actual evidence within these two fresh AOSP emulator profiles.

[Run 40113213789](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40113213789) at `2b307474a9ca65d4f86810dffa3e0a2b0439e896` included a checked test-harness correction: source-chip touches first reset the vertical LazyColumn, require the control to be displayed/enabled, perform a real touch, and assert the requested source is selected. Downloaded XML confirms all eight exact case pairs on each API, with zero errors or skips. API 26 passed all eight and the independent workflow gate; API 37 passed seven, including selection separation, but its rotation case raised `ComposeTimeoutException` during the 15-second IME-visible wait immediately after landscape rotation. The portrait keyboard/banner assertion had passed; the landscape banner assertion was not reached, so this failure alone says nothing about banner geometry. Full passing acceptance on both APIs remains open.

Both jobs again passed their headless-fixture, merged-permission, booted-API and keyboard-readback checks, and fixture enable/uninstall each returned 0 before the owned emulator wait completed. API 26 artifact `12567940545` includes the original sample-only 1080 by 1920 PNG, SHA-256 `94978d56e4d911c93341eee656f5bdd3b18944b947defb4c4807f43380a166a8`. Visual review confirmed the fixed no-capture banner, simulated ready state, public sample computer, two sample selections, Stop button, VPN-inactive text, and dark system icons without overlap. It contains no installed inventory. API 37 artifact `12567153999` contains test reports but no PNG, because the failing Gradle command prevented export. These are fresh-emulator results, not physical-phone, complete theme, accessibility, VPN, or capture acceptance.

## Passing eight-case checkpoint

[Run 40114495276](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40114495276) passed at exact source `0a395e1c01f6156c45df332d703a305385977128`. Independent downloaded XML checks confirm all eight full `(class, method)` pairs exactly once on each API, two suites per report, consistent aggregate/suite counters, and zero failures, errors, or skips. Gradle and the independent workflow gate both passed. This supersedes the open eight-case results above within the tested emulator scope.

The four `InstalledAppsActivityTest` cases passed alongside all four original sample cases:

- `headlessFixtureSupportsSearchDevelopmentFilterAndToggle`
- `installedSelectionSurvivesRefreshAndRotationWithoutCapture`
- `successfulRefreshPrunesDisabledFixtureAndDoesNotReselectIt`
- `sampleAndInstalledSelectionsRemainSeparate`

The passing rotation case required an attached, laid-out, focused activity window with delivered insets and changed viewport geometry after rotation; actual editor focus and IME visibility; retained fixture selection; and the unchanged banner before and after both rotations. The helper retained its 15-second bound and injected at most one real editor touch when the focused-editor/visible-IME state was not already satisfied. The fixture/merged-permission guards, actual API checks, keyboard readback `1`, and fixture enable/uninstall exit `0` passed on both jobs; their owned emulator waits returned. No assertion was skipped or replaced with a mock.

| API | Artifact | XML SHA-256 | Original sample PNG SHA-256 |
| --- | --- | --- | --- |
| 26 | `12567004784` | `37cc82f4562fb3979a02e32bad182f408ab06db718df1a261087efd4b45787ec` | `97135fb6dc68a016b54b1f6daa2aec4ce2a69a6f6571eb9fa0cdfeb8727b2092` |
| 37 | `12568370625` | `2c8f273f9d894a6807e725637ecdd17ef96cd477988d73d8f88e49d4efde34eb` | `ef16c34e9faa1b9996b24e59496d9badc2e08cca6828740bcc11f5385b6c855c` |

Both original 1080 by 1920 PNGs were visually reviewed: the fixed warning, simulated ready state, public sample computer/two sample selections, Stop action, VPN-inactive text, and dark system icons are legible without overlap. Neither contains installed inventory, and neither is a keyboard/installed-mode screenshot. Runtime tools were Temurin 17.0.20+1, emulator 37.2.12.0 build 16428233, KVM 12, ADB 37.0.1-15733141, compile platform 37.0 revision 2, and build tools 36.0.0. The AOSP x86_64 images were API 26/Android 8.0.0 revision 1 and API 37/Android 17 revision 6. This establishes the eight tested UI behaviors on those fresh default profiles; physical phones, other profiles/OEMs, broad accessibility, process-death persistence, real VPN consent/routing, and capture remain separate gates.
