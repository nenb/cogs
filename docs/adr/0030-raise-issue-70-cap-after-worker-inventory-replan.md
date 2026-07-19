# ADR 0030: Raise issue #70 cap after worker and inventory replan

- Status: Accepted
- Date: 2026-07-19
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0027 authorized issue #70 development-launcher work under `dev/launcher` and set the original launcher line cap. ADR 0028 superseded only that numeric cap after the core launcher slices. ADR 0029 clarified that full trusted Envoy egress composition currently requires a Linux host with an exact production `/run/cogs/egress` tmpfs prerequisite, and that ADR 0028 contingency must be used for readable security code rather than compression.

The exact baseline for this decision is clean `main` commit `d4003f2f9de5afd3f7c2072efe50dad7f9cdfc98`, after PR #138. Measured line counts at that baseline are:

```text
dev/launcher/**/*.{ts,sh}: 5,939 total
src/**/*.ts:                21,295 total
```

ADR 0028's preferred 7,200 launcher target leaves 1,261 lines. Its hard 7,800 launcher cap leaves 1,861 lines. The remaining issue #70 acceptance work plainly includes the long-lived one-session worker, operation dispatcher, lifecycle/Pi/API composition, crash recovery, inventory, real smoke workflows, and evidence.

Current code has implemented important prerequisites, including strict state/locking, profile adapters, CLI parsing, API client, control-token primitives, OpenBao/OTLP/local fixtures, KVM relay, and Envoy binary provenance/runtime-manager adapter wiring. However, the remaining acceptance is genuinely absent end-to-end: there is no executable full `create`, no long-lived worker that owns trusted services, no prompt/SSE/history/export operation dispatch, no full reverse inventory cleanup, and no real insecure-container or linux-kvm smoke/evidence.

Measured normal-style remaining implementation is about 3,100 non-test launcher lines. The projected total is therefore about 9,039 lines:

```text
current 5,939 + remaining 3,100 = projected 9,039
```

## Decision

Raise the issue #70 non-test `dev/launcher/**/*.{ts,sh}` preferred target to **9,400** lines and hard cap to **10,200** lines.

The production `src/**/*.ts` hard cap remains **22,000** total lines. The current baseline remains **21,295** lines. No production `src` export gap is currently justified by the inspected APIs, and this ADR does not authorize any production `src` change or new dependency.

This ADR supersedes only ADR 0028's numeric issue #70 launcher caps. All ADR 0027, ADR 0028, and ADR 0029 scope, no-fallback, Linux tmpfs, secrets, cleanup, evidence, and readability constraints remain binding.

The hard cap leaves 4,261 lines above the current 5,939-line baseline. That is approximately 37% above the measured 3,100-line remaining estimate. This larger contingency is intentional: remaining work is dominated by crash-safety, descriptor durability, reverse cleanup, and inventory proofs, and the project must not repeat the compression and replan cycle that reduced readability in PR #138. Security-critical launcher code must remain normal, readable TypeScript with descriptive names and explicit control flow.

## Required crash-safe startup protocol

The one-shot supervisor `create` command exits, while OpenBao, OTLP, fixtures, Envoy egress, API, and Pi handles are in-process resources. Therefore the long-lived one-session worker must own those trusted services after admission. Startup must be crash-safe and must not allow a child to become active before durable state binds its identity.

The required protocol is:

1. While holding the state lock, the supervisor durably writes a pre-spawn `starting` descriptor containing the parent pid identity and a startup nonce. This descriptor is canonical, non-secret, state-bound, source-bound, profile-bound, and fsynced before spawn.
2. The child starts blocked on inherited IPC and a bounded deadline. Before starting any trusted resource, it reads and validates the `starting` descriptor, validates the parent identity, validates the inherited IPC channel and nonce, and exits without resources if any check fails.
3. The child reports its own pid and pid identity over the inherited channel. The supervisor independently observes and verifies the child pid identity, then atomically and durably updates the `starting` descriptor to include the exact child identity.
4. The supervisor sends admission only after the child-bound `starting` descriptor is durable. The child revalidates the descriptor and nonce after admission; only then may it start OpenBao, OTLP, fixtures, Envoy egress, SSH, lifecycle, Pi, and API resources.
5. The child remains provisional until the supervisor verifies API/lifecycle readiness, durably promotes descriptor and manifest state to ready, and sends a ready acknowledgement. Parent loss before admission means the child exits with no resources. Parent loss after admission but before durable ready means the child reverse-cleans anything it started and exits. If ready is durable but the ready acknowledgement is lost, the child may re-read the exact ready descriptor and continue.
6. After ready is durable, parent identity is irrelevant. Later operations and cleanup always use exact child pid identity from the ready descriptor. There is no pid-only fallback and no signaling without exact identity match.

State phase and helper compatibility must be adjusted so worker-ready cleanup remains possible. The manifest/descriptor design may add worker-ready phases or equivalent canonical metadata, but it must remain non-secret and must preserve existing strict state ownership, locking, recovery, and cleanup semantics.

## Remaining measured implementation slices

| Slice | Scope | Estimated non-test launcher lines |
| --- | --- | ---: |
| Worker descriptor and startup protocol | Starting/ready descriptor state machine, control-capability association, parent/child IPC, tri-state identity, descriptor promotion, startup crash tests | 240 |
| Worker process shell | Fixed child entrypoint, admission gate, signal handling, provisional cleanup, fatal recovery marker | 360 |
| Service composition | Launch document builder, OpenBao/OTLP/fixture/Envoy/SSH/Lifecycle/Pi/API composition, deterministic `streamFn`, dependency wrappers | 620 |
| Operation dispatcher | Public fixed entrypoint plus create/status/run/abort/history/export/shutdown/destroy/reset dispatch using locks, descriptors, control capability, API client | 680 |
| Inventory and recovery | Process/control/port/container/runtime/tmpfs/profile inventory, tri-state classification, zero proof, recovery sentinel | 420 |
| Reverse cleanup coordinator | Idempotent worker and partial-state cleanup, WAL sticky classification, `linux-kvm.lock` handling, no false success | 360 |
| Smoke orchestration | Fixed smoke operation covering create/run/abort/history/export/shutdown/destroy and failed-prerequisite paths | 260 |
| Existing-file expansion | Contract phases/ops, state/control/core helper compatibility, README updates | 160 |
| **Estimated remaining** |  | **3,100** |

Tests, workflows, and evidence are expected separately and are not counted in the non-test launcher code cap unless placed under `dev/launcher`. They must still be normal readable code and must not import test modules into shipped launcher code.

## Stop gates

Implementation must pause before proceeding if any of the following occur:

- non-test `dev/launcher/**/*.{ts,sh}` would exceed 10,200 lines;
- `src/**/*.ts` would exceed 22,000 lines or any new production `src` export appears necessary;
- a new production dependency is needed;
- any profile fallback, local-tool fallback, runc fallback, open-egress fallback, anonymous-auth fallback, hidden `sudo` mount, or native macOS egress bypass is proposed;
- the Linux `/run/cogs/egress` tmpfs prerequisite from ADR 0029 would be loosened;
- raw model keys, OpenBao tokens, integration credentials, proxy capabilities, private keys, prompts, model outputs, tool outputs, source text, HTTP bodies, account IDs, raw provider IDs, or cloud identifiers would be persisted or reported;
- cleanup uncertainty would report success or remove controls needed for recovery;
- worker startup would allow a child to start trusted resources before a durable child-bound descriptor and admission;
- arbitrary command strings, shell fragments, generic child argv, arbitrary executable paths, or user-selected images are introduced;
- AWS, cloud, deploy, release, production daemon, scheduler, or production authentication service scope is requested;
- issue #70 would be closed before real insecure-container functional and linux-kvm authoritative smoke/inventory evidence is accepted.

## Consequences

Issue #70 can continue in sequenced implementation slices without compressing security-critical code. The increased cap is for explicit crash-safety, cleanup, inventory, and readable reviewability only. It does not expand the launcher beyond development tooling and does not alter the production runtime boundary.
