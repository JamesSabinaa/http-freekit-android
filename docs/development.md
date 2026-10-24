# Developer build

The current build contains a native Kotlin/Compose [local interface preview](android-preview.md), a JVM-tested draft pairing parser, and a separately tested security library. The app does not establish a VPN, enroll a device, or capture traffic, and does not request network or VPN permissions. Keystore code is not wired into the simulated connection flow.

## Requirements

- JDK 17 (a JRE is insufficient).
- Android SDK platform 37.0 and build tools 36.0.0; set `ANDROID_HOME` or create an ignored `local.properties` with `sdk.dir`.
- Node.js 22 or newer and npm for the loopback interoperability test peer.
- Internet access on the first build for the pinned Gradle and Maven dependencies.

In a Windows `local.properties`, escape the drive colon and use forward slashes, for example `sdk.dir=C\:/Android/Sdk`.

Gradle 9.8.2, Android Gradle Plugin 9.4.1, Kotlin 2.4.21, and the Compose BOM are pinned in the wrapper and [version catalogue](../gradle/libs.versions.toml). The wrapper verifies its distribution SHA-256. Android API 26 is the current minimum; API 37 is the compile/target SDK. Native forwarding-engine compatibility remains to be proved before confirming the minimum for capture.

## Build and validate

On Windows, set `JAVA_HOME` to your JDK 17 directory, then run:

```powershell
./scripts/build.ps1
```

The script installs the exact Node test dependency from its lockfile, runs parser, Kotlin/Node transport, security, and app lifecycle host tests, compiles the security and app instrumentation APKs, assembles the app's debug APK, and runs strict Android lint. Compiling instrumentation does not run it. The script exports the app APK, SHA-256, and source metadata directly into ignored `dist/` with stable filenames. A local SDK path and the local Android debug signing key stay outside Git. Metadata distinguishes a dirty source tree and does not claim desktop compatibility.

Equivalent commands on other systems (after installing the SDK and JDK):

```sh
npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
./gradlew :core-protocol:test :app:testDebugUnitTest :core-security:testDebugUnitTest :core-security:assembleDebugAndroidTest :core-security:lintDebug :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug
```

The JVM transport test launches an ephemeral Node process bound only to `127.0.0.1`. It generates test identities in a temporary directory, uses the logical TLS hostname while dialing loopback, verifies a pinned self-signed server, presents a device certificate, and checks that wrong pins, wrong hostnames, and absent/untrusted client certificates fail. A 64 KiB binary frame is checked byte for byte. The process and temporary keys are removed after the test. This does not establish Android Keystore interoperability, pairing approval, proxy forwarding, backpressure, or production protocol compatibility.

`core-security` host tests cover signed PKCS#10 key binding and scoped platform trust built from a public gateway certificate with a matching pin. Real Android Keystore tests can be run with `./gradlew :core-security:connectedDebugAndroidTest` only when a usable device is attached. The [hosted Keystore run](https://github.com/JamesSabinaa/http-freekit-android/actions/runs/40091372512) executed all three identity tests on API 26 and API 37 at `1b1b78c`; see [the recorded evidence](decisions/0002-device-identity-and-bootstrap.md). Local Windows device execution remains unavailable. Emulator results do not establish hardware-backed protection or physical capture.

The [preview runtime workflow](android-preview-runtime.md) separately exercises the actual Compose UI on both emulator versions. The [native engine harness](../tools/engine-spike/README.md) is a Linux research check and does not establish Android VPN behavior.

## Install the foundation APK

```powershell
adb install -r dist/http-freekit-android-debug.apk
adb shell am start -n com.httpfreekit.android.debug/com.httpfreekit.android.MainActivity
```

The debug package is `com.httpfreekit.android.debug`; the reserved release ID is `com.httpfreekit.android`. These are independent from HTTP Toolkit. No release signing identity is provisioned. Device installation and runtime tests must be recorded separately from host builds in [validation evidence](decisions/0001-foundation.md).
