# Guest network probe

`cogs-net-probe` is a small static Go binary transferred to the untrusted guest and invoked over SSH. It accepts one bounded JSON configuration on stdin and emits one bounded JSON result. It never emits addresses, URLs, DNS names, headers, payloads, response bodies, credential values, or raw network errors.

Operations:

- `root-check`: records whether the process has guest UID 0;
- `tcp`: direct IPv4/IPv6, alternate-port, metadata, Cogs, proxy-admin, and OpenBao reachability;
- `udp`: UDP/443, QUIC-like, and denial-sensor attempts;
- `dns`: a lookup through an explicitly selected DNS server;
- `http`: HTTP/1.1 or HTTP/2 TLS, DoH, redirects, forged Host, and WebSocket upgrade attempts;
- `raw-tcp` / `raw-tls`: malformed HTTP, nested CONNECT, forged SNI, and parser probes.

The controller supplies targets and payloads; the result includes only categorical outcome/detail codes, status/protocol, bounded byte counts, truncation, DNS answer count, duration, and root status. Redirects are never followed automatically. Received data is discarded.

A network timeout or refusal is not independently sufficient evidence of external default deny. Every denial case must have a positive control proving the target/sensor works and, where applicable, controller-side sensor evidence proving whether the attempt arrived.

## Deterministic build

```bash
./test/egress-conformance/guest-probes/build.sh /tmp/cogs-probe
```

The build uses `CGO_ENABLED=0`, `-trimpath`, no VCS stamping, and an empty Go build ID. It writes the binary plus a SHA-256 file. CI pins the Go toolchain, runs unit/positive-control tests, builds `linux/amd64`, rebuilds it, and compares both artifacts byte-for-byte.

The authoritative Linux/KVM driver must invoke `root-check`, mutate/disable the guest firewall separately over root SSH, then run the bypass group again. The probe does not enforce or repair guest firewall policy.
