# A4 Android JNI and synthetic packet probe

Status: the first hosted API 26/37 run failed before packet-bridge readiness. A diagnostic checkpoint passes local validation and awaits its Android run. This does not select the engine for production, establish VPN capture, or freeze the protocol.

## Source and ownership

This isolated checkpoint starts at repository `1b1b78c` and owns only the standalone [research project](../../tools/engine-spike/android/README.md), new helper scripts/tests, its [manual workflow](../../.github/workflows/native-engine-runtime.yml), this record and the research README update. Root Gradle settings, production manifests, shared contracts, [run_linux.py](../../tools/engine-spike/run_linux.py) and its existing driver tests remain unchanged.

Native source remains HevSocks5Tunnel `c0dfc4b07baa5e48022f5f88ac90488601f05674` with core `ef82008f7e2058e56d76a79543a585bba4b7feef`, task-system `4039d2fdbb3577af380fa0096b90d0ad99969dfa`, lwIP `e6d5fc6cdc7c2ab379ffffd13dfdc99fb826a86c` and YAML `94441ec8777eb319936735a58b376963d09c73d4`. [build_android_probe.py](../../tools/engine-spike/build_android_probe.py) imports these existing pins, verifies clean root/submodule source and actual symlinks, rejects ignored/untracked additions, and fetches only absent caches into ignored `.gradle/`. It never resets an existing cache or patches upstream implementation.

The [foundation licence inventory](0001-foundation.md) remains applicable: tunnel/core/tasks/YAML are MIT, lwIP is BSD-3-Clause, and Android makefiles carry Apache-2.0 notices. Research APK assets retain the project's MIT licence, five component licences and public build-file notices from the pinned source. Windows-only Wintun is not packaged. This research distribution is separate from the production app and does not complete a production/transitive licence audit.

## Deliberate JNI boundary

Upstream `src/hev-jni.c` registers four methods on a configurable class. The research [NativeEngine](../../tools/engine-spike/android/src/main/java/com/httpfreekit/engineprobe/NativeEngine.java) matches those methods; [Application.mk](../../tools/engine-spike/android/Application.mk) overrides only `PKGNAME`/`CLSNAME`. No new native JNI implementation or private Android API is needed.

[NativePacketTest](../../tools/engine-spike/android/src/androidTest/java/com/httpfreekit/engineprobe/NativePacketTest.java) uses public `Os.socketpair`, `ParcelFileDescriptor.dup` and `getFd()`. Java owns the duplicated external descriptor throughout native execution, stops/joins the native worker before closing it, shuts down the packet pump, and closes its remaining socketpair end. The upstream engine leaves caller-supplied descriptors to their caller. JNI running state and positive native packet/byte counters are checked after four real native reconstructions; a start boolean alone cannot pass.

The standalone library builds outside root settings, using the existing version catalogue/wrapper. Generated native libraries/notices use the [AGP generated-source API](https://developer.android.com/reference/tools/gradle-api/9.4/com/android/build/api/variant/SourceDirectories). The test APK targets itself, has no launcher/service/provider/receiver and requests INTERNET only. APK verification removes assumptions about transitive manifests: AndroidX's unrelated REORDER_TASKS/UI helper declarations are explicitly removed and the merged result is checked.

## Packet and stream proof design

Two dynamically allocated ADB reverse mappings connect device-loopback sockets to host-loopback peers: one bounded framed packet bridge and one SOCKS endpoint. API-26-era [ADB documentation supports dynamic reverse TCP ports](https://android.googlesource.com/platform/system/core/+/refs/tags/android-8.0.0_r37/adb/commandline.cpp). Cleanup removes only the mappings allocated by this driver and force-stops only the research package.

The unchanged Python packet/proxy peers exercise IPv4 and IPv6, each over port-80 HTTP and port-443 opaque CONNECT. Each case requires original destination IP/port, valid emitted IP/TCP checksums, byte equality, HTTP 100 Continue, upload/download prefix gates, request write EOF before a reply, and native reply FIN. The actual IP-to-stream reconstruction occurs in Android's loaded Hev/lwIP code. Python remains a bounded deterministic packet fixture, not a production TCP stack.

The `freekit-native-probe/1` framing is test infrastructure, not companion wire. It bounds packets to 65535 bytes and control JSON to 4096 bytes, preserves datagram boundaries across arbitrary TCP fragmentation and uses typed Stop evidence. A passing host result additionally requires JNI load/start/running/stats, bounded Stop, idempotent Stop, packet-thread termination, descriptor closure, ADB cleanup and one passing Android instrumentation result. Failures/timeouts cannot be recorded as a successful skip.

## Initial local evidence

On Windows Server 2025 x64 with JDK 17, Gradle 9.8.2, AGP 9.4.1 and NDK 28.2.13676358:

- `python -m unittest discover -s tools/engine-spike -p 'test_*.py'`: 12 passing host tests, including the unchanged three fixture tests. These validate framed fragmentation/EOF/bounds, required stop fields/counters, instrumentation success parsing, source/ignored-file rejection, ELF gates and manifest restrictions. They do not execute Android code.
- `gradlew.bat --no-daemon --console=plain -p tools/engine-spike/android assembleDebugAndroidTest lintDebug`: succeeds with strict lint. Main/instrumented Java and the actual upstream JNI library compile; no Android instrumentation runs locally.
- Native/packaged ARM64 and x86_64 binaries encode API 26, and all three LOAD segments per ABI have alignment 16384. Both uncompressed APK library entries also begin at offsets divisible by 16384. Source cache remains clean, correctly pinned and backed by real symlinks after the build.
- APK verification succeeds: min SDK 26, target SDK 37, self-targeted instrumentation, INTERNET as the only permission, no application components, all native/public notices present and packaged binary hashes matching the verified build.
- Python syntax checks, actionlint 1.7.12 for the new workflow, nine documentation-checker tests, all local Markdown links and `git diff --check` pass.

Build/ELF/APK evidence is in ignored `dist/native-engine-android-gradle.log`, `dist/native-engine-android-apk-check.json` and `dist/native-engine-android-helper-tests.log`. Both Android runtime matrix entries remain unrun here; compilation and a valid APK cannot satisfy them.

Reproduction commands are in the [research README](../../tools/engine-spike/android/README.md). Local deliverables/logs are ignored and use stable names directly in `dist/`; the normal standalone Gradle working output remains under its own `build/`.

## Hosted execution gate and limits

The first [hosted native run 40095030716](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40095030716), at exact source `ed12db3b02451f67898f4ee19bbb80e1d5f42e5b`, failed on both API 26 and API 37 after successful compilation, lint and APK verification. Each artifact has a clean source tree, the expected APK/native identity, zero completed packet cases, and only the instrumentation test-method-start event. The host's bridge accept timed out before HELLO. Neither artifact contains JNI, page-size, native-statistics or Stop proof. API 26 reported two ADB cleanup failures and API 37 three, with their stderr unavailable in that checkpoint. AVD device-description warnings did not prevent boot/API verification/APK installation; they do not identify the cause.

The subsequent diagnostic change starts from `2ab4d7459c6689e22637ba621441eb901e37185a`. It preserves timeouts and assertions, adds fixed Android phase markers around asset/JNI/Stop/connection operations, fails early if instrumentation exits, and retains bounded actual device/ADB cleanup diagnostics. It starts fixture worker threads after HELLO. These changes expose the failure location; they do not establish or assume its cause.

A separate review found an unsafe failure path: timing out a Java Future cannot cancel the native Stop/pthread join, while the old finally block retried Stop and closed its borrowed FD. The new `NativeStopGate` prevents overlapping requests, clears old join evidence before every Stop (including repeated Stop), and retains strong descriptor/peer leases until the current request confirms its join. If it cannot confirm, it leaves the resources for host force-stop rather than closing them under native code. Five focused JVM cases cover initial deadlines/failure, successful idempotence and successful-first/blocked-or-false repeated Stop.

The diagnostic workflow also records emulator PID/liveness and, when already exited, the host wait exit code before its teardown trap. [record_native_host.py](../../tools/engine-spike/record_native_host.py) retains only fixed marker categories from a bounded log tail; it never exports emulator-log contents. These markers are diagnostic observations, not a proven crash cause. Eighteen Python tests cover the existing fixtures/build gates plus fixed phase parsing, early-exit connection handling, actual cleanup error reporting and bounded nonsecret host-emulator classification. All five JVM cases, instrumentation assembly, strict lint, APK verification, Python/syntax checks, workflow actionlint and documentation checks pass locally. Android execution of this diagnostic checkpoint remains pending.

The new manual-only workflow uses free standard Ubuntu 24.04 runners, the established verified SDK bootstrap, JDK 17, NDK `28.2.13676358`, compile/target 37 and API 26/37 AOSP x86_64 images. It installs `libpulse0`, requires accessible KVM and successful acceleration checks, bounds boot/test waits and uses fresh AVD state with snapshots disabled. It uploads only native/JUnit/instrumentation/lint reports, never APKs, signing keys, source caches, emulator logs or AVD data. The coordinator reviews/pushes/dispatches it; no successful hosted A4 runtime result is claimed here.

Even a passing run proves synthetic AF_UNIX datagrams and JNI on those emulator images, not a real TUN/VpnService, selected-app routing, protected sockets/no capture loop, DNS/UDP policy, physical IPv6 networking, actual desktop integration, genuine TLS/HTTPS decryption, real USB traffic or performance. ARM64 is compiled/packaged but this workflow runs x86_64 only. ELF/ZIP 16 KiB alignment is checked; device page size is recorded separately and does not imply a 16 KiB runtime image. Those production/device gates remain open before package C or protocol freeze.
