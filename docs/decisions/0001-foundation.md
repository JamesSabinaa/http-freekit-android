# Foundation decisions and evidence

Status: package A in progress. Protocol v1 remains a draft. This record does not satisfy the stage 0 forwarding or Android interoperability gates.

## Implementation and build

Build an independent Kotlin application rather than fork HTTP Toolkit Android. No upstream VPN implementation is imported. Project-authored code uses the MIT licence, consistent with the desktop project. Dependencies retain their own licences.

Use API 26 as the initial minimum, target/compile API 37, JDK 17, Gradle 9.8.2, AGP 9.4.1, and Kotlin 2.4.21. Keep only `app` and the Android-independent `core-protocol` module initially. Reserve `com.httpfreekit.android` with a `.debug` suffix for local debug installs. Release signing and distribution remain unconfigured. Foreground-service choices will be validated with the actual VPN implementation, not inferred from a successful app build.

The [AGP 9.4 compatibility table](https://developer.android.com/build/releases/agp-9-4-0-release-notes) specifies Gradle 9.6.0, JDK 17, and build tools 36.0.0. The Android module uses AGP built-in Kotlin support. The application currently has no exported network entrypoint, VPN service, backup, or cleartext access. Its only exported component is the launcher activity.

## Forwarding-engine investigation

Candidate: [HevSocks5Tunnel](https://github.com/heiher/hev-socks5-tunnel), inspected at `c0dfc4b07baa5e48022f5f88ac90488601f05674`. The upstream sources advertise Android, IPv4/IPv6, TCP and UDP relay support. Its C library accepts an existing TUN file descriptor and has run/stop entrypoints. Android build files target 16 KiB pages, four ABIs, and default to API 29. An API 26 native compile now passes for ARM64 and x86_64; actual API 26 loading and forwarding remain unverified.

Source inspection found these pinned submodules:

| Component | Commit | Licence found |
| --- | --- | --- |
| hev-socks5-core | ef82008f7e2058e56d76a79543a585bba4b7feef | MIT |
| hev-task-system | 4039d2fdbb3577af380fa0096b90d0ad99969dfa | MIT |
| lwIP fork | e6d5fc6cdc7c2ab379ffffd13dfdc99fb826a86c | BSD-3-Clause |
| yaml fork | 94441ec8777eb319936735a58b376963d09c73d4 | MIT |

The tunnel root is MIT; Android makefiles include Apache-2.0 headers. The Windows-only Wintun directory has a separate licence and must not be imported into an Android distribution. This is a candidate inventory from a separate local research checkout, not an exhaustive shipped dependency audit. None of this native code is currently bundled.

Native build evidence: NDK `28.2.13676358` built the unchanged candidate's shared library and executable with `APP_PLATFORM=android-26`, `APP_ABI=arm64-v8a x86_64`, and `-j4`. `llvm-readelf -l -n` showed all shared-library LOAD segments aligned to `0x4000` (16 KiB), and `.note.android.ident` encoded API 26 for both ABIs. This proves compilation and ELF properties, not runtime compatibility or packet forwarding. The upstream default JNI registration expects its own service class; a deliberate FreeKit bridge is still required.

To reproduce in a separate research checkout, set `$engineRoot` to that checkout, `$nativeBuildRoot` to a scratch build directory, and `$ndkRoot` to the installed NDK above. Clone with Git symlink support, check out the exact root commit above, and initialize its pinned submodules. Then run:

```powershell
& "$ndkRoot/ndk-build.cmd" "NDK_PROJECT_PATH=$engineRoot" `
  "APP_BUILD_SCRIPT=$engineRoot/Android.mk" `
  "NDK_APPLICATION_MK=$engineRoot/Application.mk" `
  "NDK_OUT=$nativeBuildRoot/obj" "NDK_LIBS_OUT=$nativeBuildRoot/libs" `
  'APP_PLATFORM=android-26' 'APP_ABI=arm64-v8a x86_64' -j4
```

The initial Windows checkout had `core.symlinks=false`, so headers were text placeholders and compilation failed. Restoring tracked source symlinks in the clean research checkout fixed it without source patches. Windows reproduction requires permission to create symlinks. Both the root and submodules were clean after the successful build.

Proposed adapter: the engine points at a loopback SOCKS5 adapter in the app; that adapter routes TCP 80/443 to explicit-proxy streams and other traffic through protected sockets. UDP/443 must be blocked, DNS must use the selected underlying network, and IPv6 must either work or be deliberately blocked. Required proofs include protected sockets/no capture loop, selected-app routing, bounded buffering, half-close, cancellation, and packet-to-HTTP/CONNECT compatibility with the actual desktop proxy. A SOCKS5 engine alone does not implement these policies. No engine is selected until the spike proves them.

HTTP Toolkit's AGPL implementation was not copied; adopting a fork would change the intended independent licensing strategy. A new TCP stack is excluded. Alternative engines still need a documented comparison if this candidate fails the gate.

## Host transport spike

The Kotlin/Node spike exercises scoped server trust, a distinct logical hostname, SPKI pinning, a separately issued client certificate, and binary WebSockets. It uses temporary test keys; no shared key, trust-all callback, global trust-store change, or production enrollment route is introduced. It lives in test sources and a loopback-only Node peer.

Host proof is intentionally distinct from the remaining Android proof: Keystore-generated nonexportable key use, Android TLS behavior across USB/IP dial addresses, lifecycle cancellation, streaming backpressure, and Android-to-desktop proxy integration. Enrollment authority algorithms, validity/renewal, invitation persistence, approval races, session bounds, and exact framing still need final schemas and fixtures. No shared wire contract is frozen or changed by this first build.

## Validation evidence

Environment on 2026-10-24: Windows Server 2025 x64; initial PATH supplied a Java 8 JRE, Node 25.2.1, and Python, with no JDK, SDK, Gradle, or ADB. A checksum-verified Temurin JDK 17.0.20.1, Gradle 9.8.2, and Android command-line tools were installed outside the repository. SDK platforms 36 and 37.0, build tools 36.0.0, and platform tools were installed locally. `adb devices -l` returned no attached devices.

Validation passed with `./scripts/build.ps1`: eight pairing-parser tests and one Kotlin/Node transport test; `:app:assembleDebug`; and `:app:lintDebug` with warnings treated as errors. The final lint report says `No issues found.` Node and PowerShell syntax checks, 19 local Markdown links, and `git diff --check` also passed. No lint baseline or disabled checks were introduced. Earlier compile/lint findings were corrected before this checkpoint.

The exported debug APK was verified with `apksigner verify --verbose` (APK Signature Scheme v2), and `aapt dump badging` confirmed `com.httpfreekit.android.debug`, minimum API 26, target API 37, and version `0.1.0-dev-debug`. `aapt dump permissions` showed only AndroidX's app-scoped receiver permission, with no Internet or VPN permission. The export script records the source revision, dirty state, SHA-256, and lack of desktop compatibility beside the APK in ignored `dist/`.

`emulator -accel-check` reported that the Android Emulator hypervisor driver is not installed. An API 26 x86_64 AVD was attempted headlessly in software CPU mode (`-accel off`); it remained offline in ADB and was stopped. Installation, launch, and UI checks are therefore unrun. No system hypervisor settings were changed. Physical USB capture, cellular WAN, Keystore, packet forwarding, and desktop integration also remain unrun. Gradle reports deprecations affecting a future Gradle 10 upgrade; the pinned Gradle 9.8.2 build passes. Stages 0–6 remain open.
