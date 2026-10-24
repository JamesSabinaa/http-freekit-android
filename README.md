# HTTP FreeKit Android

Planning repository for the HTTP FreeKit Android companion. The next delivery is an Android app that captures selected application traffic and sends it to HTTP FreeKit on a computer through an authenticated, encrypted connection. USB, LAN, and WAN are delivery stages of the same design.

Status: planning only. There is no Android app, gateway, relay, or working secure remote connection in this repository yet.

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

Android minimum version, packet engine, final application ID, protocol details, and distribution licence must be resolved in the foundation package before production implementation relies on them. Suggested defaults in the documents are proposals, not evidence of completed decisions.

## Sources

- [HTTP Toolkit Android source and licence](https://github.com/httptoolkit/httptoolkit-android)
- [HTTP Toolkit ADB interceptor](https://github.com/httptoolkit/httptoolkit-server/blob/main/src/interceptors/android/android-adb-interceptor.ts)
- [Android VPN development](https://developer.android.com/develop/connectivity/vpn)
- [Android network security configuration](https://developer.android.com/privacy-and-security/security-config)
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools)
