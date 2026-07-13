# Authoritative Linux/KVM driver

`driver.sh` creates a root Debian 13 guest from the immutable 2026-07-12 cloud image pinned by SHA-512. It has no TCG fallback.

The trusted host generates both SSH client and guest host Ed25519 keys before boot. Cloud-init injects the keys, static `192.0.2.2/30` network, and a separately formatted persistent workspace disk. SSH always uses the precomputed host key with no password, agent, forwarding, or TOFU path.

A host-owned TAP interface has no NAT. Host INPUT permits only established SSH return traffic and the fixed candidate proxy port (`18080`); all other IPv4/IPv6 TAP input and forwarding is dropped. Guest root can replace its own firewall without changing host enforcement. Proxy processes, authorization/audit fixtures, real credentials, and CA private keys remain host-side.

Operations are serialized and bounded:

```sh
dev/linux-kvm/driver.sh create
dev/linux-kvm/driver.sh verify
dev/linux-kvm/driver.sh reset
dev/linux-kvm/driver.sh destroy
```

`verify` queries QMP and requires KVM `present=true, enabled=true`, root SSH, the injected host-key fingerprint, a mounted workspace, fixed MAC/address, and no guest default route. `reset` recreates the root overlay and cloud-init seed while preserving the workspace, then requires a distinct successful boot. `destroy` positively removes the VM, TAP/firewall state, and owned runtime directory. The digest-verified base-image cache contains no Cogs secrets.

`ci-smoke.sh` produces authoritative-local driver evidence. Missing KVM, image/checksum failure, key/SSH mismatch, setup, network-control, reset, teardown, or evidence failure fails closed; containers and TCG are never fallback profiles.
