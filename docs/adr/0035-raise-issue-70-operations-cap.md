# ADR 0035: Raise issue #70 operations cap

- Status: Accepted
- Date: 2026-07-19
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0027 authorized issue #70 development-launcher work under `dev/launcher` with strict development-only scope, exact profiles, no fallback, metadata-only reporting, and no cloud, release, daemon, scheduler, or production authentication-service authority. ADR 0032 most recently raised the issue #70 non-test launcher cap after the trusted-materials hardening slice. ADR 0033 then required Pi-owned runtime cleanup for launcher Pi host files, and ADR 0034 raised only the production `src/**/*.ts` cap needed for that cleanup hardening.

The accepted implementation has now advanced through PR #155. The merged issue #70 work includes the launcher core and profile adapters, authenticated API client primitives, durable worker descriptors, trusted controls and skills, cooperative fixtures, cooperative OpenBao, cooperative Envoy/runtime/KVM relay cleanup, trusted composition with Pi-owned cleanup consumption, retained-handle runtime marker hardening, and trusted worker-entry wiring.

The current exact measured baseline for this decision is commit `dd70eb8529f9bcef6cf72d1be99fc8f52697c35a` on the issue #70 operations branch:

```text
dev/launcher/**/*.{ts,sh}: 10,847 total
src/**/*.ts:                22,475 total
```

The current accepted caps before this decision are:

```text
dev/launcher/**/*.{ts,sh}: preferred 11,600, hard 12,400
src/**/*.ts:                preferred 22,800, hard 23,400
```

A measured applicability-aware remaining-operations plan found that the remaining issue #70 acceptance work is concentrated in launcher operations and supervisor behavior rather than production `src`:

| Remaining area | Estimated non-test launcher lines |
| --- | ---: |
| Operation dispatcher and CLI user flow | 280-380 |
| Supervisor persistent inventory and recovery/leftover reporting | 240-360 |
| Fixed no-real-service smoke operation support | 40-120 |
| **Remaining estimate** | **560-860** |

ADR 0032's preferred launcher target leaves only 753 lines from the current 10,847-line baseline. A very tight implementation could fit only by compressing the operation dispatcher and cleanup/inventory code. A normal readable implementation is likely to exceed the preferred target by about 50-110 lines while still remaining well inside ADR 0032's 12,400-line hard cap.

The remaining operations are security-sensitive. They must start exactly one worker only after sandbox readiness and durable admission, route `run`, `abort`, `history`, `export`, and `shutdown` through the authenticated loopback API, prove exact worker identity before signaling, preserve recovery state on uncertainty, and report leftovers without exposing prompts, source text, credentials, tool output, private paths, or raw identifiers. Compressing that code to preserve the obsolete preferred target would weaken reviewability.

## Decision

Raise only the issue #70 preferred non-test launcher target for `dev/launcher/**/*.{ts,sh}` from **11,600** lines to **12,100** lines.

The issue #70 launcher hard cap remains **12,400** lines.

The production `src/**/*.ts` cap remains the ADR 0034 cap:

```text
src/**/*.ts: preferred 22,800, hard 23,400
```

The current measured counts leave this budget after the decision:

```text
dev/launcher/**/*.{ts,sh}: baseline 10,847; preferred room 1,253; hard room 1,553
src/**/*.ts:                baseline 22,475; preferred room   325; hard room   925
```

This ADR supersedes only ADR 0032's numeric preferred launcher target. It does not change ADR 0032's launcher hard cap, ADR 0034's production `src` caps, or any issue #70 scope, cleanup, profile, evidence, telemetry, or no-fallback boundary.

## Authorized remaining launcher work

The additional preferred-cap room is limited to normal readable implementation of the measured remaining issue #70 operations work:

- a fixed operation dispatcher and CLI user flow for create, reset, status, start, run, abort, history, export, shutdown, destroy, and smoke;
- supervisor-side worker start using the already accepted state, token, startup descriptor, child admission, and trusted runtime wiring;
- authenticated API-client use for run, SSE event tailing, abort, history, export, state/status, and shutdown;
- bounded shutdown and worker cleanup using exact child PID identity, durable descriptors, control cleanup, and recovery preservation;
- metadata-only inventory and leftover reporting for sandbox state, worker descriptor class, worker liveness, recovery state, and profile applicability;
- fixed no-real-service smoke coverage for all profiles and applicability outcomes; and
- concise local-only documentation and evidence updates after implementation.

The increased preferred target exists for readable security and cleanup code. It is not permission to add dependencies, broaden launcher scope, move production logic into `src`, or implement unrelated features.

## Reaffirmed boundaries

All issue #70 constraints from ADR 0027 through ADR 0034 remain binding:

- The launcher is development tooling only, with one local state and one one-session worker. It is not a production daemon, scheduler, production authentication service, cloud provisioner, release system, deployment system, or AWS implementation.
- Exact profiles remain `insecure-container`, `linux-kvm`, and optional absent-fail `macos-vm`.
- `linux-kvm` remains the sole authoritative local security profile. `insecure-container` and `macos-vm` remain functional-only/applicability-gated.
- There is no fallback between profiles or to local tools, runc, open egress, anonymous auth, another profile, symlinks, bind mounts, hidden sudo, or native macOS full egress.
- Full trusted composition requires exact externally provisioned Linux tmpfs roots `/run/cogs/egress` and `/run/cogs/ssh`, both canonical, non-symlink, current-user-owned, mode `0700`, and empty at required boundaries.
- Pi host runtime cleanup remains owned by the ADR 0033/0034 opt-in Pi-owned cleanup API. The launcher consumes only success/failure and must not broadly delete Pi runtime trees.
- Strict state, control-file, inode, path, ownership, mode, link-count, size, mtime, ctime, directory fsync, and cleanup semantics remain mandatory where applicable.
- Exact child PID identity remains authoritative after durable ready. There is no PID-only fallback for signaling or cleanup.
- Raw startup nonces remain callback-scoped only and must not persist, log, snapshot, or appear in errors.
- API contracts remain the authenticated loopback `/v1/*` contracts implemented by the production API server and bounded launcher API client.
- API bearer tokens may persist only in dedicated strict `0600` control files and must be accessed through closure holders.
- Telemetry, status, reports, smoke output, and evidence remain metadata-only and must not include secrets, prompts, model outputs, tool outputs, source content, paths to private material, HTTP bodies, account IDs, raw provider IDs, raw provenance digests, or cloud identifiers.
- Cleanup and inventory must preserve on uncertainty and must not report false success.

## Stop gates

Implementation must pause before proceeding if any of the following occur:

- non-test `dev/launcher/**/*.{ts,sh}` would exceed **12,400** lines;
- `src/**/*.ts` would exceed ADR 0034's **23,400** hard cap;
- a new dependency is needed;
- any production `src` expansion is proposed for the operations slice rather than using accepted launcher/API surfaces;
- any profile fallback, local-tool fallback, runc fallback, open-egress fallback, anonymous-auth fallback, hidden `sudo` mount, symlink or bind fallback, repo-path SSH fallback, or native macOS egress bypass is proposed;
- either exact Linux tmpfs prerequisite, `/run/cogs/egress` or `/run/cogs/ssh`, would be loosened;
- raw model keys, OpenBao tokens, integration credentials, API tokens, startup nonces, private keys, proxy capabilities, prompts, model outputs, tool outputs, source text, HTTP bodies, account IDs, raw provider IDs, raw provenance digests, cloud identifiers, private paths, or inode values would be persisted or reported;
- metadata-only telemetry would be widened;
- cleanup uncertainty would report success or remove controls needed for recovery;
- worker startup would allow a child to start trusted resources before durable child-bound descriptor and admission;
- PID-only signaling or cleanup would be introduced;
- arbitrary command strings, shell fragments, generic child argv, arbitrary executable paths, or user-selected images are introduced;
- AWS, cloud, deploy, release, production daemon, scheduler, or production authentication service scope is requested; or
- issue #70 would be closed before accepted real insecure-container functional smoke/inventory and linux-kvm authoritative smoke/inventory evidence exists.

## Consequences

Issue #70 remaining operations work may proceed without compressing security-critical dispatcher, supervisor, inventory, and cleanup code under ADR 0032's obsolete preferred target. The hard launcher cap remains unchanged and remains the mandatory stop gate.

Future implementation PRs must report current `dev/launcher/**/*.{ts,sh}` and `src/**/*.ts` line counts. Tests, workflows, docs, and evidence remain required separately. This ADR does not authorize scope expansion, dependencies, production `src` work, cloud/AWS behavior, release behavior, daemon behavior, production authentication service behavior, telemetry widening, cleanup weakening, profile fallback, or issue closure without accepted smoke and inventory evidence.
