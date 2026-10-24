# Standalone Android native research probe

This project builds a test-only Android library/instrumentation APK. It is deliberately absent from the root Gradle settings, so normal app/security builds do not fetch an engine or require an NDK. It does not create a VPN, change routes, protect sockets, use production credentials, or integrate companion wire messages. Port-443 fixture data is opaque binary data, not real TLS.

The unchanged Hev JNI registers against `com/httpfreekit/engineprobe/NativeEngine` through compile-time `PKGNAME`/`CLSNAME` overrides in [Application.mk](Application.mk). [NativePacketTest.java](src/androidTest/java/com/httpfreekit/engineprobe/NativePacketTest.java) creates `Os.socketpair(AF_UNIX, SOCK_DGRAM)`, duplicates the native end with public `ParcelFileDescriptor.dup`, and keeps its public `getFd()` alive until native Stop joins the worker. The other end carries synthetic IP datagrams. Only the research test manifest requests INTERNET; merged-APK verification rejects other permissions and application components.

## Local build

Set `JAVA_HOME` to JDK 17 and `ANDROID_HOME` to an SDK containing platform 37.0, build tools 36.0.0 and NDK `28.2.13676358`. The root wrapper/version catalogue supply the pinned Gradle/AGP/test dependency versions.

```sh
python3 -m unittest discover -s tools/engine-spike -p 'test_*.py'
./gradlew --no-daemon --console=plain -p tools/engine-spike/android testDebugUnitTest assembleDebugAndroidTest lintDebug
python3 tools/engine-spike/verify_probe_apk.py \
  --apk tools/engine-spike/android/build/outputs/apk/androidTest/debug/FreeKitNativeResearch-debug-androidTest.apk \
  --output tools/engine-spike/android/build/reports/native-runtime/apk-build.json
```

On Windows use `gradlew.bat`, `python`, and pass `--apkanalyzer "$env:ANDROID_HOME/cmdline-tools/latest/bin/apkanalyzer.bat"` to the verifier. The generated APK is a research test package, not the companion app. Compiling it is not device execution evidence.

[build_android_probe.py](../build_android_probe.py) fetches only the engine commit and submodule revisions recorded in [run_linux.py](../run_linux.py) into ignored `.gradle/engine-spike/hev-socks5-tunnel`. Existing dirty, mismatched or incomplete caches are rejected without resetting them. Ignored files are rejected too because source wildcards must not pick up untracked injected code. Windows requires actual Git symlinks. The build uses API 26 for ARM64/x86_64 and checks ELF API notes, machine IDs, 16 KiB LOAD alignment and the compiled JNI registration class. Build products stay under this project's ignored `build/`.

The APK bundles the project's MIT licence, the five upstream component LICENSE files and public Android makefile notices from the exact checked source. `assets/engine-source.json` records revisions, NDK, ELF properties and binary hashes. [verify_probe_apk.py](../verify_probe_apk.py) checks those actual packaged binaries, uncompressed 16 KiB ZIP alignment, notices and the merged manifest before installation. No upstream implementation is vendored into this repository.

## Android execution

With a booted API 26 or 37 device/emulator and its explicit serial:

```sh
python3 tools/engine-spike/run_android.py --serial emulator-5554 --api 26 \
  --test-apk tools/engine-spike/android/build/outputs/apk/androidTest/debug/FreeKitNativeResearch-debug-androidTest.apk
```

The driver installs only `com.httpfreekit.engineprobe.test`, allocates two owned `adb reverse tcp:0` mappings, and removes those mappings afterwards. The Android test connects outward to device loopback; host bridge/SOCKS/proxy listeners bind host loopback. No network fixture destination is actually dialled. The driver force-stops only its research package during cleanup, and cleanup failure fails the run.

The Android native engine points at the reversed SOCKS peer. The host reuses `PacketFixture`, `socks_fixture` and `proxy_fixture` unchanged. Four IPv4/IPv6 HTTP/opaque-CONNECT cases require correct original IP/port, IP/TCP checksums, HTTP 100 Continue, upload/download prefix gates, EOF-before-reply, complete bytes and native peer EOF. JNI load, duplicate-start refusal, running state, positive native counters, bounded Stop, repeated Stop, packet-thread termination and descriptor closure are checked separately.

The private research bridge `freekit-native-probe/1` uses a one-byte type and a four-byte big-endian length: HELLO=1 (bounded JSON), PACKET=2 (1..65535 raw IP bytes), STOP=3 (empty), STOPPED=4 (bounded JSON). Controls are limited to 4096 bytes. This framing is unrelated to the companion protocol.

Reports are written to `build/reports/native-runtime/` with repository/APK/native identities, API/model/page size, four fixture results and explicit JNI stop evidence. A successful ADB command alone is insufficient: the driver requires all fixture assertions and one passing instrumentation test with a successful final result.

Failure reports include fixed nonsecret Android phase markers, instrumentation exit state, owned reverse mappings, bounded device/mapping/research-process diagnostics, and actual bounded cleanup stdout/stderr. Instrumentation exiting before connection fails immediately; the bridge still has the original 60-second deadline. Fixture worker threads start only after HELLO. The workflow records host-emulator PID/liveness/exit status before teardown and fixed fatal-marker categories from a bounded tail. Report artifacts exclude logcat, emulator logs, traffic payloads and credential dumps.

[NativeStopGate](src/main/java/com/httpfreekit/engineprobe/NativeStopGate.java) allows only one pending JNI Stop and resets join evidence for each request. A deadline does not cancel native `pthread_join`. Borrowed resources have a static strong lease until the current Stop returns successfully; an unresolved Stop is neither repeated nor followed by descriptor closure. The failed research process then relies on the owned host force-stop/emulator teardown. Five JVM tests exercise deadlines, failures, repeated Stop and resource lifetime.

The [manual workflow](../../../.github/workflows/native-engine-runtime.yml) uses standard Ubuntu KVM runners with API 26/37 x86_64 AOSP images, explicit `libpulse0`, no snapshots or AVD caches, a verified SDK bootstrap and pinned NDK/source. It retains reports only, excluding APKs, keys, source caches, emulator logs and AVD data. Its runtime results must be reviewed after dispatch; see the [A4 decision and limits](../../../docs/decisions/0005-android-native-packet-probe.md).
