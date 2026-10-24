# Developer build

The first foundation build contains a native Kotlin/Compose launch screen and a JVM-tested draft pairing parser. It does not establish a VPN, enroll a device, or capture traffic. No network or VPN permissions are requested by this build.

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

The script installs the exact Node test dependency from its lockfile, runs parser and Kotlin/Node transport tests, assembles the debug APK, and runs Android lint with warnings treated as errors. It exports the APK, SHA-256, and source metadata directly into ignored `dist/` with stable filenames. A local SDK path and the local Android debug signing key stay outside Git. Metadata distinguishes a dirty source tree and does not claim desktop compatibility.

Equivalent commands on other systems (after installing the SDK and JDK):

```sh
npm --prefix tools/transport-spike ci --ignore-scripts --no-fund
./gradlew :core-protocol:test :app:assembleDebug :app:lintDebug
```

The JVM transport test launches an ephemeral Node process bound only to `127.0.0.1`. It generates test identities in a temporary directory, uses the logical TLS hostname while dialing loopback, verifies a pinned self-signed server, presents a device certificate, and checks that wrong pins, wrong hostnames, and absent/untrusted client certificates fail. A 64 KiB binary frame is checked byte for byte. The process and temporary keys are removed after the test. This does not establish Android Keystore interoperability, pairing approval, proxy forwarding, backpressure, or production protocol compatibility.

## Install the foundation APK

```powershell
adb install -r dist/http-freekit-android-debug.apk
adb shell am start -n com.httpfreekit.android.debug/com.httpfreekit.android.MainActivity
```

The debug package is `com.httpfreekit.android.debug`; the reserved release ID is `com.httpfreekit.android`. These are independent from HTTP Toolkit. No release signing identity is provisioned. Device installation and runtime tests must be recorded separately from host builds in [validation evidence](decisions/0001-foundation.md).
