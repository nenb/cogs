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

Full trusted Envoy egress composition currently requires a Linux host because the production material writer requires the exact directory `/run/cogs/egress` to be:

- canonical;
- a Linux tmpfs;
- mode `0700`;
- owned by the current user;
- empty before and after runtime-manager use.

This prerequisite is intentionally strict. The launcher must not loosen the tmpfs checks, mount the directory through hidden `sudo`, bypass Envoy egress, fall back to open egress, or silently switch profiles.

| Profile | Host applicability today | Security authority |
| --- | --- | --- |
| `insecure-container` | Functional-only on a qualifying Linux host that satisfies `/run/cogs/egress`; native macOS cannot complete full `create` today. | Functional only; no VM/default-deny evidence claim. |
| `linux-kvm` | Linux host with KVM/QMP/root-network prerequisites and `/run/cogs/egress`. | Sole authoritative local security profile. |
| `macos-vm` | Optional absent-fail profile; full egress composition is unsupported natively on macOS at this stage. | Functional only if a reviewed driver is later added. |

A missing host prerequisite is an explicit fail-closed result, not fallback and not a product authority claim.

## Scope reminders

- No AWS, cloud, deploy, release, production daemon, scheduler, or production auth scope.
- No profile fallback or local-tool/runc/open-egress/anonymous-auth fallback.
- Persisted state and snapshots must remain metadata-only and non-secret.
- `linux-kvm` is the only authoritative local security profile.
- `insecure-container` and `macos-vm` remain functional-only profiles.
