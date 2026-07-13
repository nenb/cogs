# Guest network probe

`cogs-net-probe` is a small static Go binary transferred to the untrusted guest and invoked over SSH. It accepts one bounded JSON configuration on stdin and emits one bounded JSON result. It never emits addresses, URLs, DNS names, headers, payloads, response bodies, credential values, or raw network errors.

Operations:

- `root-check`: records whether the process has guest UID 0;
- `tcp`: direct IPv4/IPv6, alternate-port, metadata, Cogs, proxy-admin, and OpenBao reachability;
- `udp`: UDP/443, QUIC-like, and denial-sensor attempts;
- `dns`: a direct DNS wire query through an explicitly selected literal-IP UDP server, without `/etc/hosts`, search domains, or resolver fallback;
- `http`: explicitly selected HTTP/1.1 or HTTP/2 TLS, DoH, redirects, forged Host, and WebSocket upgrade attempts;
- `raw-tcp` / `raw-tls`: malformed HTTP, nested CONNECT, forged SNI, and parser probes.

The controller supplies targets and payloads; network dial endpoints and HTTP URL hosts must be literal IPv4/IPv6 addresses, while Host and SNI are independent fields. HTTP proxy environment variables are ignored. Custom fixture CA mode does not inherit system roots. The result includes only categorical outcome/detail codes, status/protocol, bounded byte counts, truncation, DNS answer count, duration, and root status. Redirects are never followed automatically. Received data is discarded. A timeout or refusal is reported as an observation, never as a claim that policy denied the request.

A network timeout or refusal is not independently sufficient evidence of external default deny. Every denial case must have a positive control proving the target/sensor works and, where applicable, controller-side sensor evidence proving whether the attempt arrived.

## Deterministic build

```bash
./test/egress-conformance/guest-probes/build.sh /tmp/cogs-probe
```

The build uses the local pinned Go toolchain with network dependency resolution disabled, `CGO_ENABLED=0`, fixed `GOAMD64=v1`, `-trimpath`, no VCS stamping, and an empty Go build ID. It writes the binary, SHA-256 file, and a build manifest binding source revision, toolchain, target, and digest. CI verifies each checksum, rejects ELF interpreter/dynamic dependencies, rebuilds `linux/amd64`, compares all artifacts byte-for-byte, and executes a whole-process non-reflection canary.

The authoritative Linux/KVM driver must invoke `root-check`, mutate/disable the guest firewall separately over root SSH, then run the bypass group again. The probe does not enforce or repair guest firewall policy.
