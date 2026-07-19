# ADR 0032: Raise issue #70 cap after trusted materials

- Status: Accepted
- Date: 2026-07-19
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0027 authorized issue #70 development-launcher work under `dev/launcher` with strict profiles, development-only scope, no fallback, and no cloud, release, daemon, scheduler, or production authentication-service authority. ADR 0028 and ADR 0030 superseded only the numeric non-test launcher cap as measured implementation slices completed. ADR 0029 clarified that full trusted Envoy egress composition requires a qualifying Linux host with exact `/run/cogs/egress` tmpfs semantics. ADR 0031 added the separate exact `/run/cogs/ssh` tmpfs prerequisite so the launcher can truthfully materialize the selected profile's SSH client key under the production launch schema.

The exact baseline for this decision is clean commit `82850cae9fa5ef26ca45938846a1b7e34d5222d6`, after PR #143. Measured line counts at that baseline are:

```text
dev/launcher/**/*.{ts,sh}: 8,536 total
src/**/*.ts:                21,295 total
```

ADR 0030's preferred 9,400 launcher target leaves 864 lines. Its hard 10,200 launcher cap leaves 1,664 lines. The trusted local materials slice completed important prerequisites, but it also showed that strict readable filesystem and cleanup code is more expensive than the pre-slice estimate.

The prior measured trusted-composition plan estimated the trusted controls and trusted skills prerequisites at 450 non-test launcher lines:

```text
trusted-controls.ts: 230
trusted-skills.ts:   220
controls + skills:   450
```

The actual trusted-material implementation added 1,235 launcher lines. The overrun was not scope expansion. It came from legitimate review-driven hardening required by the accepted security boundary:

- exact profile ownership sentinel validation for both implemented drivers;
- strict `/run/cogs/ssh` and `/run/cogs/egress` Linux tmpfs preflights;
- no-follow file and directory handling;
- inode, ownership, mode, link-count, size, mtime, ctime, and path-stability race checks;
- directory-descriptor fsync with reinspection;
- bounded sensitive-buffer reads and wiping on every failure path;
- non-enumerable SSH control handle fields to keep paths and key pins out of snapshots;
- exact state-named runtime key cleanup that preserves on unknown entries or replacement;
- deterministic real empty OCI/private skill provenance using production serializers and stores;
- bounded static skill inventory traversal and exact cleanup; and
- hostile seam, partial-write, partial-read, replacement, unknown-entry, cleanup-uncertainty, and redaction tests.

The remaining issue #70 acceptance work is still genuinely absent. In particular, there is no full trusted one-session worker composition, no launcher-built exact launch document, no deterministic Pi stream, no public operation dispatcher or executable entrypoint, no complete supervisor inventory/recovery/zero proof, no full reverse cleanup coordinator, and no real smoke workflows or accepted evidence.

A post-materials measured stop gate estimated the remaining normal-style launcher work at 2,050 to 2,760 non-test lines:

| Remaining area | Estimated non-test launcher lines |
| --- | ---: |
| Trusted composition and exact launch document | 500-620 |
| Deterministic `streamFn` | 120-180 |
| Public operation dispatcher | 430-520 |
| Fixed executable entrypoint | 80-140 |
| Supervisor inventory, recovery, and zero proof | 360-460 |
| Reverse cleanup coordinator | 300-420 |
| Fixed smoke orchestration | 180-260 |
| Existing-file expansion and launcher README counted under `dev/launcher` | 80-160 |
| **Remaining estimate** | **2,050-2,760** |

Projected final launcher total is therefore:

```text
current 8,536 + remaining 2,050 = 10,586
current 8,536 + remaining 2,760 = 11,296
```

Even a narrower projection using only the next broad categories from the prior lead review reaches or exceeds ADR 0030's hard cap:

```text
current 8,536
+ compose remainder ~530
+ operations 430-500
+ inventory/recovery 600-700
+ smoke/docs helpers 220-300
= projected 10,316-10,566
```

The current ADR 0030 hard cap is no longer credible for readable completion. Compressing security-critical code to fit the cap would repeat the mistake ADR 0029 explicitly rejected.

## Decision

Raise the issue #70 non-test `dev/launcher/**/*.{ts,sh}` preferred target to **11,600** lines and hard cap to **12,400** lines.

The production `src/**/*.ts` hard cap remains **22,000** total lines. The current baseline remains **21,295** lines. No current production `src` export or new dependency is justified by inspected APIs, and this ADR does not authorize any production `src` change or dependency.

This ADR supersedes only ADR 0030's numeric issue #70 launcher caps. All ADR 0027, ADR 0028, ADR 0029, ADR 0030, and ADR 0031 scope, no-fallback, Linux tmpfs, secrets, telemetry, cleanup, evidence, and readability constraints remain binding.

The preferred target leaves approximately 304 lines above the high measured remaining projection of 11,296 lines. The hard cap leaves approximately 1,104 lines above that high projection for review-driven findings in the remaining high-risk areas: trusted composition, cancellation, shutdown ordering, supervisor inventory, zero proof, recovery uncertainty, and hostile seams.

This larger contingency is intentionally evidence-based. It is not permission to expand scope. It exists so the remaining security and cleanup code can stay normal, readable TypeScript with descriptive names, explicit control flow, and reviewable checks. Implementation must not compress, omit hostile checks, loosen filesystem validation, weaken cleanup proof, or move complexity into tests or undocumented behavior to meet a lower number.

## Remaining sequenced implementation slices

### 1. Trusted composition factory, not yet wired by default

Add the launcher-only trusted runtime factory, likely in `dev/launcher/trusted-compose.ts`, with a deterministic stream helper either in the same file or a small adjacent launcher file. The factory must:

- revalidate descriptor, manifest, profile, source revision, authority, and abort generation after every await;
- preflight exact `/run/cogs/egress` and `/run/cogs/ssh` before secrets or listeners;
- use trusted SSH controls and trusted skill inputs;
- start trusted OpenBao, local fixtures, OTLP, metadata-only worker telemetry, model auth, SSH, lifecycle, Pi, API, and Envoy egress in the accepted order;
- build and validate the exact launch document;
- provide a deterministic `streamFn` that exercises the real Pi/API/tool path without real provider calls;
- return only the existing `WorkerProvisionalRuntime` surface, `{ apiPort, close }`;
- expose no paths, key pins, secrets, tokens, prompts, model outputs, tool outputs, component IDs, raw digests, or raw provider IDs through snapshots, status, telemetry, or errors; and
- reverse-clean all acquired resources with uncertainty preserving recovery state.

`worker-entry.ts` must still retain `unavailableWorkerRuntime` by default until the complete trusted factory and hostile seam tests pass.

### 2. Worker-entry wiring after factory proof

Only after the complete factory passes focused hostile tests may `worker-entry.ts` replace `unavailableWorkerRuntime`. The existing worker admission contract must remain unchanged:

- no trusted resource starts before durable child-bound descriptor and supervisor admission;
- raw startup nonce remains callback-scoped and never persists or logs;
- durable ready remains controlled by authenticated API/lifecycle readiness proof and supervisor promotion;
- exact child PID identity remains the authority for later signaling and cleanup; and
- the worker entry remains the sole process SIGTERM owner.

### 3. Public operation dispatcher and executable entrypoint

Add fixed public operation wiring, likely in `operations.ts` and `main.ts`, using the already reviewed CLI parser and API client. Implement create, status, run, abort, history, export, shutdown, reset, destroy, and smoke only through fixed arguments and state locks.

The dispatcher must not accept arbitrary command strings, shell fragments, executable paths, generic child argv, user-selected images, unauthenticated API access, or profile fallback.

### 4. Supervisor inventory, recovery, and reverse cleanup

Add complete supervisor-side inventory and cleanup for worker PID identity, controls, API listener, fixture ports, OpenBao, OTLP, Envoy/runtime material, KVM relay, `/run/cogs/ssh`, `/run/cogs/egress`, profile resources, state, locks, and recovery sentinels.

Uncertainty is failure. Unknown entries, unavailable identity, replacement races, failed fsync, incomplete cleanup proof, or malformed controls must preserve recovery state and must never report success. `linux-kvm.lock` remains profile-driver coordination state under repo `.cogs-dev`, not generic launcher-owned cleanup debris.

### 5. Fixed smoke, workflows, docs, and evidence

Add fixed smoke orchestration and Linux workflows/evidence only after the implementation proves cleanup and inventory. The issue remains open until both real insecure-container functional smoke/inventory and linux-kvm authoritative smoke/inventory evidence are produced and accepted.

## Stop gates

Implementation must pause before continuing if any of the following occur:

- non-test `dev/launcher/**/*.{ts,sh}` would exceed 12,400 lines;
- `src/**/*.ts` would exceed 22,000 lines or any new production `src` export appears necessary;
- a new dependency is needed;
- any profile fallback, local-tool fallback, runc fallback, open-egress fallback, anonymous-auth fallback, hidden `sudo` mount, symlink or bind fallback, repo-path SSH fallback, or native macOS egress bypass is proposed;
- either exact Linux tmpfs prerequisite, `/run/cogs/egress` or `/run/cogs/ssh`, would be loosened;
- the production launch schema would be made untruthful by using a fictitious client key path or secretly configuring SSH from another path;
- raw model keys, OpenBao tokens, integration credentials, API tokens, startup nonces, private keys, proxy capabilities, prompts, model outputs, tool outputs, source text, HTTP bodies, account IDs, raw provider IDs, raw provenance digests, or cloud identifiers would be persisted or reported;
- metadata-only telemetry would be widened;
- cleanup uncertainty would report success or remove controls needed for recovery;
- worker startup would allow a child to start trusted resources before durable child-bound descriptor and admission;
- PID-only signaling or cleanup would be introduced;
- arbitrary command strings, shell fragments, generic child argv, arbitrary executable paths, or user-selected images are introduced;
- AWS, cloud, deploy, release, production daemon, scheduler, or production authentication service scope is requested; or
- issue #70 would be closed before real smoke and inventory evidence are accepted.

## Reaffirmed constraints

All existing issue #70 constraints remain unchanged:

- The launcher is development tooling only, with one local state and one one-session worker. It is not a production daemon, scheduler, production authentication service, cloud provisioner, release system, deployment system, or AWS implementation.
- Exact profiles remain `insecure-container`, `linux-kvm`, and optional absent-fail `macos-vm`.
- `linux-kvm` remains the sole authoritative local security profile. `insecure-container` is functional-only. `macos-vm` remains optional absent-fail and functional-only if later reviewed.
- There is no fallback between profiles or to local tools, runc, open egress, anonymous auth, another profile, symlinks, bind mounts, hidden sudo, or native macOS full egress.
- Full trusted composition requires exact externally provisioned Linux tmpfs roots `/run/cogs/egress` and `/run/cogs/ssh`, both canonical, non-symlink, current-user-owned, mode `0700`, and empty at the required boundaries.
- Strict state, control-file, inode, path, ownership, mode, nlink, size, mtime, ctime, directory fsync, and cleanup semantics remain mandatory.
- Exact child PID identity remains authoritative after durable ready. There is no PID-only fallback for signaling or cleanup.
- Raw startup nonce remains callback-scoped only; it must not persist, log, snapshot, or appear in errors.
- API contracts remain the authenticated loopback `/v1/*` contracts implemented by the production API server and bounded launcher API client.
- API bearer tokens may persist only in dedicated strict `0600` control files and must be accessed through closure holders.
- Telemetry, status, reports, and evidence remain metadata-only and must not include secrets, prompts, model outputs, tool outputs, source content, paths to private material, HTTP bodies, raw IDs, provider account IDs, or cloud identifiers.
- Cleanup and inventory must preserve on uncertainty and must not report false success.

## Consequences

Issue #70 may continue after this docs-only decision without compressing security-critical code under ADR 0030's obsolete numeric cap. The larger cap does not broaden issue #70. It preserves the existing dev-only launcher boundary while acknowledging measured implementation cost after the trusted-materials hardening slice.

Future implementation PRs must report current `dev/launcher/**/*.{ts,sh}` and `src/**/*.ts` line counts. Tests, workflows, and evidence remain required separately and must not import test modules into shipped launcher code. Production `src` remains unchanged unless a later stop gate proves a real export gap under the unchanged 22,000-line cap.
