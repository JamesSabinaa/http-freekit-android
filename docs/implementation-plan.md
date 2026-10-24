# Android companion implementation plan

## Outcome

Deliver a FreeKit Android companion that connects selected apps to a trusted FreeKit desktop over USB, LAN, or WAN. The phone identifies the receiving computer, the computer authorizes each phone, and both show whether traffic is actually reaching the interception proxy. Remote use must not require exposing ADB or the desktop management API to the internet.

The immediate priority is a working Android app and USB capture. Design authentication and transport boundaries first so WAN support extends that app rather than replacing its capture engine.

## Existing integration

The desktop repository already has src/interceptors/android-adb-interceptor.js. It shells out to adb, detects devices, starts the HTTP Toolkit Android app by intent, builds configuration links containing a CA fingerprint, and creates ADB reverse mappings. If the companion is absent it can fall back to the Android global proxy, currently described as HTTP only. The existing recovery logic tracks device changes and tunnel cleanup; preserve it when adding a FreeKit companion path.

This is integration with another app, not an existing FreeKit Android implementation. There is no verified secure WAN gateway. The desktop API currently binds to loopback, and the proxy defaults to loopback. These defaults should remain. adb was unavailable on the planning shell's PATH; the foundation package must verify the SDK and ADB tooling rather than assume device tests can run.

HTTP Toolkit's current source also creates persistent ADB reverse tunnels, so its ADB mode is not inherently restricted to LAN. Its Android app uses Android's VPN facility for packet interception. The FreeKit design follows the same platform mechanism while establishing its own identity, protocol, and security boundary.

## Repository boundaries

| Repository | Owns |
| --- | --- |
| http-freekit-android | Android application, protocol specification and examples, Android tests, APK build instructions, device test evidence |
| http-freekit | Companion gateway, pairing registry, desktop device UI, ADB detection and activation, existing proxy integration |
| Relay repository to be chosen later | Optional rendezvous and encrypted byte forwarding service, deployment and abuse controls |

Do not move existing desktop code into this repository. Match compatible releases using an explicit protocol version and record tested desktop and Android commit pairs. A relay repository is unnecessary until the direct connection milestone passes.

## Delivery scope

The first developer preview includes one desktop identity, multiple independently paired phones, selected-app capture, HTTP and supported HTTPS on TCP ports 80 and 443, WebSocket upgrade traffic through the existing proxy, visible VPN consent, certificate installation guidance, USB setup, reconnect, stop, and device revocation. WAN preview adds direct encrypted access to a configured reachable gateway. A relay is a later milestone required for convenient use behind restrictive NAT or CGNAT.

Initial exclusions are transparent interception of arbitrary UDP protocols, HTTP/3 decoding, automatic certificate pinning bypass, universal HTTPS capture, remote ADB, account systems, and automatic router configuration. Rooted-device system CA injection is a separate later capability. Do not advertise all-device or all-protocol coverage from a selected-app preview.

## Milestones and exit gates

| Stage | Deliverable | Evidence required to advance |
| --- | --- | --- |
| 0 Foundation | Toolchain, licence decision, forwarding engine spike, frozen v1 contract | Reproducible debug build, tested TCP forwarding proof, dependency licence inventory, agreed wire fixtures |
| 1 App shell | Pairing screens, device identity, VPN lifecycle, diagnostics | Consent, cancellation, notification stop, process restart, and denied permissions tested |
| 2 USB capture | New companion plus local desktop gateway | Physical phone sends HTTP and a trusted debug app's HTTPS into FreeKit over ADB reverse with Wi-Fi disabled |
| 3 LAN | Same authenticated gateway over a network | Correct identity verification, wrong-host rejection, reconnect, and documented firewall setup |
| 4 Direct WAN | Phone on cellular reaches desktop gateway | Authenticated capture across separate networks, revocation closes active traffic, hostile requests rejected |
| 5 Relay | Both endpoints connect outward | Capture behind CGNAT, end-to-end identity verification, relay cannot decrypt payloads, quotas enforced |
| 6 Release | Signed artifacts and support documentation | Full release matrix, upgrade and rollback checks, reproducible release instructions, notices and checksums |

Stage 0 must prove packet-to-stream forwarding before the project invests in a large interface. Starting the VPN alone does not prove interception. Stage 4 depends on a reachable gateway, such as deliberate router forwarding or a public host; TLS alone does not solve reachability.

## First app experience

The home screen offers Add computer, saved computers, and a connection button. Pairing uses an in-app QR scanner or pasteable pairing payload; scanning an unknown payload never silently authorizes interception. Show the computer name and identity before connecting. Camera access is optional because paste/manual entry is available.

Setup shows separate checks for pairing, VPN permission, connection, certificate trust, and successful proxy traffic. The user selects apps before capture. Start requires Android's VPN consent. The active screen and ongoing notification show the selected computer, transport, counters, reconnect state, and Stop. Explain that Android allows only one active VPN per user/profile and starting FreeKit can replace an existing VPN.

Certificate help distinguishes installing a user CA, configuring one's own debug app to trust it, and optional future system trust on supported rooted devices. Never label a paired device as fully trusted for HTTPS just because certificate installation was requested. Provide a test endpoint and report successful interception separately.

Stop closes the tunnel and VPN, releases temporary state, and restores ordinary networking. Forget deletes that computer's saved credentials and offers CA removal guidance. Revocation from the desktop disconnects that device. Existing user-installed CAs require explicit Android removal; do not imply credentials deletion uninstalls them.

## Failure policy

While capture remains active, selected-app traffic must not silently bypass interception after a connection failure. Hold new intercepted connections within a short bounded retry budget, fail them if exhausted, and show Reconnecting or Disconnected. The user can explicitly Stop to restore normal networking. This is an application policy, not a guarantee of Android lockdown after force-stop or reboot; always-on lockdown is outside the first preview.

Nonselected apps remain outside capture. For selected apps, nonintercepted protocols use documented direct forwarding; UDP/443 is blocked in the initial capture mode to encourage TCP fallback, with a visible explanation that some apps may fail instead. IPv6 must be supported by the chosen forwarding engine or deliberately blocked inside the capture interface; never silently leak selected IPv6 traffic. DNS behavior is defined in architecture.md and verified separately.

## Decisions before implementation

Package A owns resolving the following in short decision records: independent implementation versus licensed fork; forwarding engine; minimum Android API (proposed 26); tested target SDK and foreground service requirements; application ID and signing identity; client certificate implementation; direct gateway TLS identity; and exact stream framing. Package A freezes the protocol only after Android and Node interoperability succeeds. No assumed calendar estimate replaces these technical gates.

## Immediate work

Assign A first. B may build UI against interfaces and mocks while A resolves the engine and contract. D may design desktop adapters and regression checks against the draft. C and production wire integration depend on A. E starts direct WAN validation after authenticated USB capture passes. F writes fixtures early and performs integration throughout. Detailed scopes and handoff prompts are in tasks/README.md.
