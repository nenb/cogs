# Development launcher

The issue #70 launcher code under `dev/launcher` is development tooling. It composes reviewed Stage 3 pieces for local development and later smoke/evidence work; it is not a production daemon, scheduler, deployment system, release system, cloud provisioner, or production authentication service.

## Current Envoy egress slice status

The current Envoy egress slice is adapter wiring and Envoy binary provenance only:

- it verifies the pinned local Envoy image digest before extraction;
- extracts the Envoy binary into state-owned runtime storage with strict ownership, mode, hash, and cleanup checks;
- wires launcher options to the production egress runtime manager, OpenBao PKI source, OpenBao revocation mode, Envoy process port, WAL path, and OTLP logs endpoint;
- validates the exact local launch document semantics expected for the Stage 3 localhost credential fixture.

This slice does **not** yet provide an executable full launcher `create` flow and does **not** claim real launcher Envoy smoke/evidence. Tests use seams to validate adapter wiring, binary provenance, and cleanup behavior.

## Host applicability

Full trusted composition currently requires a qualifying Linux host with two separate, externally provisioned runtime roots:

| Runtime root | Purpose | Required state before use |
| --- | --- | --- |
| `/run/cogs/egress` | Production Envoy/runtime-manager private material | Canonical Linux tmpfs, non-symlink directory, mode `0700`, current uid, and empty before and after runtime-manager use. |
| `/run/cogs/ssh` | Truthful launch-bound copy of the selected profile's SSH client key | Canonical Linux tmpfs, non-symlink directory, mode `0700`, current uid, and initially empty. Cleanup removes only the exact recorded key inode, proves the root empty, and leaves the external root mounted. |

Host setup outside the launcher must create and mount both roots. The launcher must not create or mount them through hidden `sudo`.

The production launch schema requires `sandbox.client_key_path` under `/run/cogs/ssh/`, while current development profile drivers retain their source keys in strict profile-owned state. For full trusted composition, the launcher must strictly read the selected profile's source key, pinned `known_hosts` record, and profile-specific port control where applicable. It then exclusively copies through the open source descriptor into one state-named mode-`0600` file under `/run/cogs/ssh`, with owner, mode, link-count, inode, size, reread, fsync, bounded-buffer, and cleanup checks. The validated launch document and SSH manager must use exactly that runtime path. The source key remains profile-owned.

These prerequisites are intentionally strict. The launcher must not loosen either tmpfs check, weaken the launch schema, use a fictitious client-key path, secretly continue using the repo/profile source path, add a symlink or bind fallback, bypass Envoy, fall back to open egress, or silently switch profiles. Runtime key bytes, paths, and digests remain excluded from telemetry, evidence, status, and errors.

| Profile | Host applicability today | Security authority |
| --- | --- | --- |
| `insecure-container` | Functional-only on a qualifying Linux host that satisfies both `/run/cogs/egress` and `/run/cogs/ssh`; native macOS cannot complete full `create` today. | Functional only; no VM/default-deny evidence claim. |
| `linux-kvm` | Linux host with KVM/QMP/root-network prerequisites and both runtime roots. | Sole authoritative local security profile. |
| `macos-vm` | Optional absent-fail profile; full trusted composition is unsupported natively on macOS at this stage. | Functional only if a reviewed driver is later added. |

A missing or invalid host prerequisite is an explicit fail-closed result before trusted services start, not fallback and not a product authority claim. These requirements are accepted design constraints; this docs-only ADR does not claim they are implemented or covered by real launcher smoke evidence.

## Scope reminders

- No AWS, cloud, deploy, release, production daemon, scheduler, or production auth scope.
- No profile fallback or local-tool/runc/open-egress/anonymous-auth fallback.
- Persisted state and snapshots must remain metadata-only and non-secret.
- `linux-kvm` is the only authoritative local security profile.
- `insecure-container` and `macos-vm` remain functional-only profiles.
