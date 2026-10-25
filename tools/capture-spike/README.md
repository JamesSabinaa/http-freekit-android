# Real TUN capture research

This isolated host and traffic APK exercise the [C1 capture owner](../../docs/capture-policy-runtime.md). They are separate from the production app and enrollment research. The [manual workflow](../../.github/workflows/capture-runtime.yml) uses fresh standard Ubuntu/KVM emulators on API 26 and 37. Device execution is pending; local compilation and host tests do not prove routing.

The runtime application is `com.httpfreekit.capturetest`; the unrelated traffic application is `com.httpfreekit.capturetraffic`. Their explicit bound Messenger service requires the host's signature permission and matching debug signer. Only fixed command IDs, deterministic synthetic bytes, a bounded private direct-port configuration, and request-bound count/digest/status replies cross that IPC boundary. The existing inert installed-app fixture supplies the second nonempty allowlist; the traffic UID remains unchanged.

The five common standalone methods test selected-versus-nonselected TCP, direct TCP/UDP/DNS with blocked UDP443, intercepted original IPv6, notification Stop with an actual held flow and fresh restart, and protect/bind refusal after TUN start. API 37 first runs `localNetworkDenialPreventsTun` while its local-network permission is still denied. That method obtains real platform VPN consent, requires no factory/TUN/owner, and joins the stopped service. The driver then grants `ACCESS_LOCAL_NETWORK` to its two owned APKs and the normal methods independently check the actual grant. API 26 runs five methods; API 37 runs six. This follows [Android's target-37 local-network permission requirement](https://developer.android.com/privacy-and-security/local-network-permission).

Controlled direct receivers bind host loopback TCP80/443 and UDP53/443, accessible through the emulator's host alias. The fresh hosted runner explicitly permits unprivileged fixed ports; collisions fail without displacing listeners. Other direct TCP, the intercepted receiver and its finite snapshot/hold control use owned ephemeral ports. The intercepted factory admits only three exact original tuples and prepends one fixed research role byte: IPv4 HTTP80, IPv4 opaque443 or IPv6 HTTP80. Application bytes after it remain unchanged. This injected local seam is not a companion wire change, TLS interception, or desktop-proxy integration.

Receivers validate full deterministic bytes and directional EOF; Android independently validates reply lengths/digests. Actual TCP accepts and UDP receipts are counted before completion callbacks, so a reset or failed response cannot disappear from no-connect/no-delivery evidence. Exact per-method path deltas and their cumulative continuity are checked independently. DNS uses a fixed valid question/response over the underlying protected path; no desktop DNS or arbitrary destination RPC exists.

Run host checks with:

```sh
node --test tools/capture-spike/*.test.mjs
python3 -m unittest discover -s scripts/tests -p 'test_capture_runtime.py'
./gradlew :capture-traffic:assembleDebug :capture-traffic:lintDebug \
  :capture-runtime:assembleDebug :capture-runtime:assembleDebugAndroidTest :capture-runtime:lintDebug
```

The driver reuses the existing owned command/ADB helper. It refuses pre-existing packages, verifies all four debug APK signers, invokes exact standalone methods once, retains finite instrumentation facts, and selectively force-stops/uninstalls only attempted owned installations. Reports are written after receiver and command cleanup. The workflow separately stops and joins its emulator and runs the independent bounded Python gate.

Only three sanitized files are retained under `build/reports/capture-runtime/`: `runtime.json`, `TEST-capture-research.xml` and `host-cleanup.json`. Exact source, clock quantization/round-trip bounds, actual start/completion pairs, finite facts, independent receiver counts, permission provenance and real cleanup are required. Raw instrumentation, ADB/emulator logs, APKs, config credentials and payloads remain private. Later host failure preserves actual method outcomes while overall acceptance fails. Actual platform revocation/network-loss events are distinct from injected per-flow guard refusals; the latter cannot be reported as platform events.
