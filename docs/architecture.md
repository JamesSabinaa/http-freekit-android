# Companion architecture

## Components

The Android app contains a Compose interface, pairing and credential storage, a foreground VpnService, a packet forwarding adapter, and a transport client. Keep the UI out of packet processing. Expose service state through a single observable state model and use structured cancellation so Stop closes all sockets and jobs.

Proposed source modules are app, core-model, core-protocol, core-security, core-transport, and core-capture. Start with a small Gradle project and split modules only when the dependency boundaries are useful. Interfaces must allow a fake gateway and fake capture engine for UI and lifecycle testing.

The desktop adds a companion gateway with its own TLS identity, a device registry, and narrowly scoped pairing and stream endpoints. Its stream adapter connects only to the configured local interception proxy. It does not offer arbitrary filesystem, shell, rules, or management API access to phones. Tag desktop capture sessions by authenticated device without injecting identity headers into upstream requests.

## Packet handling

Android VpnService supplies IP packets through a TUN file descriptor. These packets cannot be forwarded as HTTP requests without reconstructing TCP streams. Select a maintained, compatible user-space forwarding engine after proving its JNI/Android support, licence, IPv4/IPv6 handling, flow control, DNS behavior, UDP forwarding, and shutdown behavior. Do not choose a dependency from popularity alone or build a new TCP stack.

The adapter turns intercepted TCP streams into the explicit HTTP proxy protocol already understood by FreeKit: HTTP requests use the proxy's expected absolute-form request format; HTTPS uses CONNECT and then TLS bytes. Confirm both forms with the existing proxy in stage 0. Preserve original destinations, stream ordering, half-close behavior or a documented limitation, and backpressure. WebSocket upgrades and large streaming bodies must remain streaming.

The [draft-0.5 HTTP origin mode](protocol-http-origin.md) adds a versioned alternative for raw HTTP80 capture: explicitly negotiate the mode, convey the original numeric address in a bounded CONNECT80 preface, then preserve origin-form bytes for the desktop's trusted HTTP parser. This avoids a phone-side HTTP rewriter. It leaves legacy modes intact and requires actual authenticated transport/desktop attachment proof before production integration; see the [C2 implementation profile](capture-transport.md).

Select applications with VpnService's app routing controls. Route selected apps through the capture interface; bypass apps outside that set through Android's normal network. Exclude the companion or protect its outbound sockets to avoid capture loops. Protected sockets must bind to the current underlying network where necessary and be rebuilt after network transitions.

For the preview, resolve DNS using the selected underlying network and forward DNS through protected sockets; DNS therefore stays outside the desktop tunnel and remote desktops do not provide split-horizon DNS. Preserve original destination addresses for TLS CONNECT. Test private DNS and IPv6 explicitly. Document that this is HTTP debugging, not a general privacy VPN. Supporting desktop-side DNS later requires a versioned capability and separate tests.

TCP ports 80 and 443 are intercepted. Other selected-app TCP and UDP traffic is forwarded directly through protected sockets, except UDP/443, which is deliberately blocked in capture mode. A forwarding engine that cannot implement the declared policy is not acceptable for the preview. Nonstandard HTTP ports can be added through explicit configuration later.

## Connection paths

| Mode | Phone route | Desktop exposure |
| --- | --- | --- |
| USB | Device loopback mapped by adb reverse to local companion gateway | Gateway can remain loopback only |
| LAN | Direct connection to configured desktop gateway address | Dedicated gateway on a selected interface |
| Direct WAN | Direct connection to reachable gateway DNS/IP and port | Dedicated gateway with explicit firewall and reachability configuration |
| Relay | Outbound carrier connections from both endpoints | No inbound desktop port required |

All paths preserve the same authenticated desktop identity. Do not downgrade to plaintext or unauthenticated proxy access when a secure connection fails. USB reverse maps the new gateway port, rather than silently changing the existing raw proxy mapping. Track mapping ownership, restore previous mappings, and preserve existing desktop cleanup guarantees.

## Transport proposal

Use TLS-protected WebSockets for v1 control and proxy streams, with one WebSocket per proxied TCP flow for a simple initial implementation. Reuse connection pooling where supported, but do not invent multiplexing in the first preview. Authenticate stream requests using a device client certificate. Bound sockets, frame sizes, queued bytes, and handshake timeouts. This has overhead; measure concurrent-flow and WAN performance before optimizing.

Validate the proposal with Kotlin and Node during package A. In particular, prove self-signed desktop identity verification scoped to a configured pin, Android client key use, TLS hostname handling across USB and IP connections, binary streaming, and backpressure. If that proof fails, update the contract before dependent production code lands.

## Relay extension

A relay carries opaque end-to-end TLS bytes between paired endpoints. Outer WSS to the relay protects transport metadata in transit but does not by itself provide end-to-end encryption. An inner authenticated TLS session terminates at Android and the desktop; the relay cannot terminate it. Prototype inner TLS over the carrier using established TLS libraries before choosing the relay implementation. If library support is unsuitable, revisit the carrier rather than invent cryptography.

Use separate short-lived rendezvous credentials, per-session quotas, size limits, idle expiry, and abuse controls. The relay can still observe IPs, timing, and byte counts; document that limitation. Do not queue intercepted payloads for offline delivery or retain them in relay logs. Relay service hosting, costs, account management, and publication are later work with their own explicit deployment authorization.

## Trust separation

The gateway TLS identity authenticates the computer; device credentials authenticate the phone; the interception CA signs certificates for captured sites. Keep these identities separate. Only the public interception CA reaches the phone. Desktop CA private keys and gateway private keys stay on the computer. The phone's device private key stays in Android Keystore. A new computer identity requires pairing again; an interception CA change requires explicit trust setup and must not silently replace the gateway pin.

## Desktop integration

Add FreeKit companion detection ahead of the existing HTTP Toolkit companion path. Keep legacy support during migration. Use explicit package names and intents; never use an untrusted URL to select an arbitrary activity. Prefer a minimal exported launch surface that accepts only bounded pairing setup and requires the app's normal consent flow. ADB activation is not permission to silently install certificates or bypass Android VPN prompts.

Keep existing proxy defaults and the management API loopback binding. Expose device state through existing local desktop API conventions. Avoid broad changes in proxy-server.js until the stream spike identifies the narrow integration seam and device attribution mechanism.
