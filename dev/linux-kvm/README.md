# Local Linux/KVM driver

`driver.sh` creates a root Debian 13 guest from the immutable 2026-07-12 cloud image pinned by SHA-512. It has no TCG fallback.

The trusted host generates both SSH client and guest host Ed25519 keys before boot. Cloud-init injects the keys, static `192.0.2.2/30` network, a separately formatted persistent workspace disk, and a dedicated ADR 0037 Git tools disk. The tools disk is built on the host from exactly four pinned Debian packages after size/SHA-256 and package metadata verification, attached read-only, and mounted read-only at `/opt/cogs-git` with `nosuid,nodev`; the guest does not use apt or network to obtain Git. SSH always uses the precomputed host key with no password, agent, forwarding, or TOFU path.

A host-owned TAP interface has no NAT. Host INPUT permits only established SSH return traffic and the fixed candidate proxy port (`18080`); all other IPv4/IPv6 TAP input and forwarding is dropped. Guest root can replace its own firewall without changing host enforcement. Proxy processes, authorization/audit fixtures, real credentials, and CA private keys remain host-side.

Driver operations are serialized by the retained lock. QEMU shutdown uses bounded pidfd observations; network commands have individual deadlines:

```sh
dev/linux-kvm/driver.sh create
dev/linux-kvm/driver.sh verify
dev/linux-kvm/driver.sh reset
dev/linux-kvm/driver.sh destroy
```

`verify` binds QEMU's recorded generation, queries QMP and requires KVM `present=true, enabled=true`, root SSH, the injected host-key fingerprint, a mounted workspace, fixed MAC/address, and no guest default route. `reset` recreates the root overlay and cloud-init seed while preserving the workspace, then requires a successful boot. The digest-verified base-image cache contains no Cogs secrets.

The long-lived driver uses only `-serial null`: guest UART bytes are discarded, not retained in a host log. Create and reset share this launch. The old `serial.log` pathname is unlinked only after stopped-state retirement; there is no logging fallback. SSH readiness and QMP remain separate. `qualify.sh` is a different short-lived marker-capture consumer and is unchanged. Writable guest disks and QEMU stdout/stderr are separate storage sinks, **not bounded by this UART change**. Existing live VMs are not retroactively changed.

Cleanup requires trusted private host custody records. QEMU identity includes host boot ID, proc starttime, executable device/inode/path and exact cmdline. Linux/Python pidfd support is mandatory; TERM/KILL revalidate identity and target a held pidfd, never a saved numeric PID. Missing, legacy, reused, exited-before-adoption or otherwise unobservable identities fail closed and retain state. A held pidfd's exit observation, not PID absence, proves this non-daemonizing QEMU's retirement. This is not a general descendant-process supervisor.

Network setup journals each successful effect and exact inverse, including the original proxy port, TAP ifindex/random alias, configured IPv4 addresses and both complete filter tables (without counters). Teardown removes exact rules in reverse order, never flushes a chain, and checks each before/after snapshot. Successful journaled inverses are idempotent; failed/pending mutations or snapshot drift latch uncertainty and retain all recovery records. No-state destroy fails without touching guessed names or claiming teardown. Legacy states require separately reviewed recovery, not automatic migration.

This deliberately conservative contract requires exclusive trusted host network administration during an operation: the driver lock does not serialize unrelated administrators, and iptables/link snapshots are not an atomic transaction against hostile host root. Even unrelated filter-table edits stop cleanup. Kernel IPv6 link-local/DAD, operational carrier, and live TAP queue/offload/header flags are not ownership fields; TAP deletion retires those kernel-generated resources. Crash/power-loss durable journaling and externally replaced identical resources are not claimed. Do not manually clear failed journals to retry or reuse a generation.

`ci-smoke.sh` retains its historical authoritative-local report format, but no new runtime evidence or qualification is established by these changes. Missing KVM, image/checksum failure, key/SSH mismatch, setup, network-control, reset, teardown, or evidence failure fails closed; containers and TCG are never fallback profiles. UART-flood compatibility and real cleanup still require a separately authorized, disposable isolated harness; ordinary static/fake tests are non-authorizing.
