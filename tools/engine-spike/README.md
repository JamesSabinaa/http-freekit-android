# Native packet-to-stream spike

This Linux-only research harness loads the pinned HevSocks5Tunnel shared library and feeds synthetic IPv4 and IPv6 TCP packets through a Unix datagram socket pair acting as a TUN descriptor. It requires no root, TUN device, route changes, or external traffic. It is not an Android VPN, a production capture adapter, or a new TCP implementation: the bounded packet driver supplies deterministic test inputs, while the upstream engine/lwIP reconstructs streams.

The loopback-only test SOCKS adapter checks that original destination IPs and TCP ports survive reconstruction, rewrites a controlled origin-form HTTP request to absolute form, and establishes CONNECT for opaque port-443 bytes. The test proxy gates upload tails until it receives a prefix, gates response tails until the client receives a prefix, and waits for client write EOF before replying. These gates detect full-body buffering and full-close-on-EOF behavior. It also checks byte equality and a `100 Continue` exchange before the request body is sent. Both IP versions exercise both modes. Port-443 bytes are synthetic binary data, not a claim of valid TLS or successful HTTPS interception. Desktop compatibility and Android routing remain separate gates.

Requirements: Linux, Python 3.9+, Git, GCC, and GNU Make. The upstream checkout must be clean and contain exactly commit `c0dfc4b07baa5e48022f5f88ac90488601f05674` and its four pinned submodules. The script verifies all revisions, builds the library and its dependencies from source, then runs a bounded child process with a scoped library search path. No upstream source is copied into this repository or bundled in the app. The candidate and submodule licences are recorded in the [foundation decision](../../docs/decisions/0001-foundation.md).

```sh
git clone --no-checkout https://github.com/heiher/hev-socks5-tunnel .gradle/engine-spike/hev-socks5-tunnel
git -C .gradle/engine-spike/hev-socks5-tunnel checkout c0dfc4b07baa5e48022f5f88ac90488601f05674
git -C .gradle/engine-spike/hev-socks5-tunnel submodule update --init --recursive
python3 tools/engine-spike/run_linux.py --engine-root .gradle/engine-spike/hev-socks5-tunnel
```

Successful cases print JSON records with IP version, mode, byte counts, and a synthetic response checksum. The harness fails on wrong revisions, malformed flow results, timeouts, byte changes, missing EOF, or failure to stop the engine. Windows syntax compilation is insufficient evidence that the native spike passes; inspect the Linux execution result separately.
