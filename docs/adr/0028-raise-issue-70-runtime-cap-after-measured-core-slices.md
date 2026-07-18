# ADR 0028: Raise issue #70 launcher runtime cap after measured core slices

- Status: Accepted
- Date: 2026-07-18
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0027 accepted the issue #70 development launcher scope and set a hard cap of 4,800 non-test lines under `dev/launcher/**/*.{ts,sh}`. That ADR remains authoritative for scope and security boundaries: issue #70 is development tooling only, not a production daemon, scheduler, auth service, release system, deploy system, cloud provisioner, or AWS implementation.

The clean merged baseline for this decision is exact `origin/main` commit `b0f579a064535627d137801bcea3714d344b8419`, after PR #133. Measured line counts at that baseline are:

```text
dev/launcher/**/*.ts: 2,702 total
src/**/*.ts:          21,295 total
```

ADR 0027's 4,800-line launcher cap leaves only **2,098** non-test launcher lines. The completed slices cover strict state, runner, profile adapters, CLI parsing, loopback API/SSE client, and local prompt/export path helpers. The remaining ADR 0027 work still includes all executable/runtime/inventory/smoke composition:

- trusted OpenBao fixture startup, seeding, loopback/version/digest checks, and cleanup;
- bounded OTLP collector/fixture reset and destroy semantics;
- upstream fixtures and Envoy egress runtime-manager composition;
- one-session lifecycle/Pi/API worker process;
- supervisor operations and worker PID/readiness/control protocol;
- inventory, reverse cleanup, crash recovery, and smoke orchestration;
- development-only entrypoint.

A stop-gate replan measured the remaining realistic implementation at about **4,400** non-test launcher lines. The projected total is therefore about **7,102** lines (`2,702 + 4,400`). A 7,200 cap would leave only 98 lines of headroom despite every prior security-reviewed slice expanding under hostile-seam, redaction, bounded-cancellation, and cleanup-uncertainty findings.

## Decision

Raise the issue #70 non-test `dev/launcher/**/*.{ts,sh}` hard cap from **4,800** to **7,800** lines.

Implementation should still target **at or below 7,200** lines. The new **7,800** hard stop provides a bounded 698-line contingency above the measured 7,102 projected total, approximately 16% of the remaining 4,400-line estimate, so security validation and cleanup code do not need to be compressed.

The production `src/**/*.ts` hard cap remains **22,000** total lines. The current baseline is **21,295** lines. This ADR does not authorize any production `src` change; it only preserves the existing ADR 0027 `src` cap if a later small export is separately justified.

This ADR supersedes only ADR 0027's numeric non-test launcher cap. All ADR 0027 scope, security, profile, persistence, no-fallback, cleanup, and evidence constraints remain in force.

## Required architecture remains unchanged

The launcher may implement a **one-session development worker** that survives the one-shot CLI `create` invocation, so later one-shot operations can call the authenticated loopback API. This worker is not a scheduler or production daemon:

- exactly one local state and one Cogs session per worker;
- no restart loop, multi-tenant scheduling, production authentication service, deployment, release, cloud, or AWS responsibility;
- no arbitrary command, shell, executable path, user-selected image, or generic child argv;
- if the worker exits, later operations enter cleanup/recovery rather than resurrecting an unbounded service.

`create` must still start resources in ADR 0027 order:

1. selected sandbox profile driver and verified SSH host-key pin;
2. actual local OpenBao;
3. bounded local OTLP collector;
4. fixture services;
5. selected Envoy proxy/runtime through existing egress runtime composition;
6. one Cogs lifecycle/Pi/API worker session.

Cleanup must be attempted in reverse order, be idempotent, and prove zero owned inventory before reporting success. Uncertainty is failure and must retain a recovery sentinel.

## Persistence and secrets constraints remain unchanged

Runtime secrets must remain in runtime memory or already-reviewed trusted fixture/material scopes. The launcher must not persist:

- model API keys;
- OpenBao root or scoped tokens;
- integration credentials;
- Envoy internal auth token, proxy private key, or CA private key;
- prompts, model outputs, tool outputs, source text, HTTP bodies;
- account IDs, raw provider IDs, cloud identifiers, or other credential-bearing data.

Persisted local control capabilities remain limited to state-owned `0600` files such as the API bearer token, SSH client key, known-host pin, PID/control descriptors, canonical non-secret manifest, and recovery sentinel. Reports and manifests must remain metadata-only.

## Reuse and extraction constraints remain unchanged

Issue #70 must reuse reviewed production and driver validation instead of duplicating it. Shipped `dev/launcher` code must not import test modules.

Expected reuse/extraction boundaries are:

- existing profile drivers in `dev/insecure-sandbox` and `dev/linux-kvm`;
- existing launcher `state`, `contract`, `runner`, `profiles`, `core`, `cli`, and `api-client` modules;
- production `validateLaunchConfig`, `LaunchLifecycle`, `createApiServer`, Pi session ports, SSH launch dependency, model auth, egress runtime manager, worker telemetry, JSONL history, and local export;
- extraction or copying of minimal real-runtime/KVM relay helper logic into shipped `dev/launcher` code if needed, rather than importing from `test/`.

No new production dependency is authorized by this ADR.

## Measured remaining decomposition

The stop-gate replan estimated the remaining non-test launcher work as follows:

| Area | Estimated lines |
| --- | ---: |
| Dev-only entrypoint and dispatch | 180 |
| Operation implementations | 520 |
| Worker process main | 360 |
| Lifecycle/Pi/API worker composition | 620 |
| Trusted OpenBao fixture helper | 430 |
| Bounded OTLP fixture/reset helper | 300 |
| Upstream fixtures and deterministic fake model stream | 330 |
| Envoy/egress runtime-manager wrapper | 470 |
| KVM relay extraction | 190 |
| Inventory, zero-checks, cleanup, recovery | 520 |
| 0600 control files and worker PID identity | 280 |
| Smoke orchestration | 320 |
| Documentation notes, if counted under launcher | 80 |
| Extensions to current launcher state/contract/core | 300 |
| **Estimated remaining** | **4,400** |

With the exact baseline of 2,702 launcher lines, this projects to 7,102 total. The 7,800 hard cap permits review-driven expansion while preserving a bounded stop gate.

## Security details that must remain explicit

The larger cap is for explicit security and cleanup code, not scope expansion. Implementation must still include:

- no fallback between profiles, to local tools, to runc, to open egress, to anonymous auth, or to another profile;
- `linux-kvm` as the only authoritative local security profile;
- `insecure-container` and optional `macos-vm` as functional-only profiles;
- KVM relay/profile authority labels and host-enforced network evidence only for `linux-kvm`;
- `linux-kvm.lock` classified as a profile-driver coordination lock under repo `.cogs-dev`, not the launcher per-state lock; generic launcher cleanup must not delete it while held or treat it as a leaked runtime resource after driver operations finish;
- WAL sticky fail-closed limit remains 1 MiB / 10,000 records with no in-session recovery claim;
- OTLP collector reset/destroy must be explicit and metadata-only;
- reverse cleanup and zero inventory for worker process, containers, volumes, tap devices, firewall rules/chains, fixture ports, OpenBao, OTLP, relay sockets/ports, persisted API/SSH controls, and launcher state;
- no AWS, cloud, deploy, release, production daemon, scheduler, or production readiness claim.

## Potential small production export gaps

The stop-gate replan identified possible API gaps that may require later, separately reviewed `src` exports under the existing 22,000-line cap:

- a tiny shipped helper/factory for SSH-backed Pi tool ports, if current production SSH/SFTP/Bash exports cannot be composed safely from `dev/launcher`;
- a reusable KVM relay or real-runtime helper only if it is appropriate outside `dev/launcher`; otherwise it should live under `dev/launcher`;
- any small API timeout or worker composition export only if long-running model/API behavior proves the existing asynchronous API contract insufficient.

This ADR does **not** authorize those changes. Any such change must remain under the existing `src/**/*.ts` cap and be justified in its own implementation slice.

## Consequences

Issue #70 may continue after this numeric cap adjustment without compressing security-critical launcher code. The preferred target remains at or below 7,200 lines; exceeding that target requires explicit reporting in the PR. Exceeding 7,800 lines requires another stop-gate replan or superseding ADR.

All ADR 0027 exclusions remain unchanged: no production daemon, scheduler, auth service, cloud lifecycle, AWS, deploy, release, arbitrary command execution, fallback, persistent credentials, test-module imports, or duplicated replacement of reviewed validation.
