# HTTP FreeKit Android

HTTP FreeKit Android companion, under development. The planned app captures selected application traffic and sends it to HTTP FreeKit on a computer through an authenticated, encrypted connection. USB, LAN, and WAN are delivery stages of the same design.

Status: foundation implementation in progress. The Android app provides local installed-app discovery and selection, including development apps without launcher icons. Pairing review, consent, connection recovery and diagnostics remain clearly labeled simulations. Separate foundation libraries implement Keystore identity, validated credential persistence and scoped client TLS. API 26/37 emulator checks verify those credentials, isolated authenticated Android-to-Node streaming with bounded backpressure, cancellation and expiry, and a native engine's four synthetic IPv4/IPv6 packet flows. Production enrollment, VPN capture, desktop gateway integration, and relay support are not implemented. See [developer build instructions](docs/development.md), [interface preview](docs/android-preview.md), and [foundation evidence and limits](docs/decisions/0001-foundation.md).

The isolated [enrollment foundation](docs/decisions/0013-enrollment-transactions.md) adds matching Kotlin/Node codecs, purpose-bound device proofs and a durable reference approval/credential registry. Local tests cover exact cross-language proof bytes, real signatures, replay/expiry checks and process-crash recovery. The live HTTPS/Android Keystore/approval/save/reopen path is the next integration gate.

## Start here

1. Read [the implementation plan](docs/implementation-plan.md).
2. Read [the architecture](docs/architecture.md), [protocol draft](docs/protocol.md), and [security model](docs/security.md).
3. Select an unclaimed package from [the agent work board](tasks/README.md).
4. Use [the validation and release plan](docs/validation.md) as the definition of done.

The desktop application lives in `../http-freekit`. This repository owns Android code and the canonical companion protocol documentation. Desktop changes belong in the desktop repository and need their own tests and commits. Keeping repositories separate allows independent Android builds, signing, releases, and dependency management.

## Initial direction

- Native Kotlin app, with Jetpack Compose for the interface and Android VpnService for capture.
- First real integration uses USB and ADB reverse. First WAN integration connects to a reachable desktop gateway. A relay follows after direct WAN works.
- Pair a device once, then authenticate using its own revocable credentials. A desktop login does not substitute for authenticating traffic.
- Keep the desktop API and existing proxy local. Add a narrow companion gateway.
- Use an established packet forwarding engine after a compatibility and licence investigation. Do not implement TCP from scratch.
- Build independently unless a deliberate decision is made to adopt AGPL obligations for a fork. HTTP Toolkit's Android repository carries AGPLv3; this repository currently contains no imported upstream implementation.

The foundation currently uses API 26 as the minimum and reserves `com.httpfreekit.android` as the application ID. Project-authored code uses the [MIT licence](LICENSE); see [dependency notices](THIRD_PARTY_NOTICES.md). Packet engine selection, native API compatibility, release signing, and protocol freeze remain open foundation gates. Proposed defaults in the design documents do not establish working capture.

## Sources

- [HTTP Toolkit Android source and licence](https://github.com/httptoolkit/httptoolkit-android)
- [HTTP Toolkit ADB interceptor](https://github.com/httptoolkit/httptoolkit-server/blob/main/src/interceptors/android/android-adb-interceptor.ts)
- [Android VPN development](https://developer.android.com/develop/connectivity/vpn)
- [Android network security configuration](https://developer.android.com/privacy-and-security/security-config)
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools)
