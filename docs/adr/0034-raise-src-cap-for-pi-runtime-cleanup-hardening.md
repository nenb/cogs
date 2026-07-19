# ADR 0034: Raise src cap for Pi runtime cleanup hardening

- Status: Accepted
- Date: 2026-07-19
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0033 authorized a narrow opt-in production Pi-owned final cleanup API for exact host runtime files created beneath supplied `agentDir` and `sessionRoot` for one session. It kept the production `src/**/*.ts` hard cap at **22,000** lines.

The ADR 0033 baseline was:

```text
src/**/*.ts: 21,295 total
```

A first local implementation measured:

```text
src/**/*.ts: 21,712 total
```

That local implementation was rejected in exact-head review because it was not safe to push. The review found that it:

- recorded only names and booleans instead of exact creation-time inode ownership;
- pattern-deleted export trees discovered at cleanup time;
- could unlink path replacements after early checks;
- abandoned destructive cleanup work after timeout while the operation continued in the background; and
- lacked startup rollback and hostile disposal/concurrency coverage.

A remeasurement of normal readable fixes found that hardening the implementation requires about **540-800** additional production lines beyond that rejected local implementation. The projected final production count is therefore:

```text
21,712 + 540 = 22,252
21,712 + 800 = 22,512
```

That exceeds the existing **22,000** cap. Compressing inode-bound cleanup code to fit the old cap would weaken readability and repeat the security-review compression cycle that ADR 0029 and ADR 0032 rejected.

## Decision

Raise only the numeric production `src/**/*.ts` cap for ADR 0033 Pi-owned runtime cleanup hardening.

The new issue #70 production `src/**/*.ts` targets are:

- preferred: **22,800** lines;
- hard cap: **23,400** lines.

The preferred target leaves 288 lines above the high measured projection of 22,512. The hard cap leaves 888 lines above that projection for review-driven hardening of inode-bound cleanup, startup rollback, and hostile tests without compression.

This ADR supersedes only the numeric production `src/**/*.ts` cap retained by ADR 0033. It does not change ADR 0032's non-test launcher caps:

- launcher preferred: **11,600** lines;
- launcher hard cap: **12,400** lines.

The current launcher count remains about **8,974** lines on the measured branch.

## Required hardening scope

The increased production budget is only for ADR 0033 Pi-owned runtime cleanup hardening. The implementation must include normal readable code for:

- exact creation-time inode ledgers for native Pi JSONL, Git map sidecar, export final artifacts, export temp artifacts, and export backup artifacts;
- recording/adopting exact dev, inode, uid, mode, link-count, type, and bounded stable attributes when entries are created or explicitly adopted;
- internal-only ownership hooks/results in the native session integration, Git map store, and local exporter;
- full read-only preflight of the complete recorded tree before the first unlink;
- parent-directory binding, revalidation, fsync, and absence proof for every unlink and rmdir;
- no deletion of path replacements, unrecorded files, pattern-matched export trees, unknown temp/backup directories, symlinks, hardlinks, unsafe types, or wrong-owner/mode entries;
- cooperative absolute cleanup deadlines that do not abandon destructive work in the background;
- startup rollback that uses the same ownership tracker and preserves artifacts on uncertainty;
- idempotent same-promise final disposal and safe interaction with normal `dispose()`; and
- hostile tests for resume, Git map, export temp/backup, shutdown, symlink, hardlink, FIFO/socket, wrong mode/link count, JSONL replacement, file replacement, directory replacement, unknown entries at every level, fsync/unlink/rmdir failures, timeout-with-no-background-delete, startup rollback, non-owned retention, no-leak serialization, and matching attacker export filenames that must survive failed cleanup.

## Boundaries unchanged

No other production growth is authorized. This ADR does not authorize:

- broad deletion or recursive discovered-tree deletion;
- a generic filesystem deletion API;
- launcher-visible paths, inodes, inventories, raw IDs, raw digests, prompts, outputs, or credentials;
- telemetry widening;
- a new dependency;
- profile fallback, local-tool fallback, runc fallback, open-egress fallback, anonymous-auth fallback, hidden `sudo` mount, symlink/bind fallback, repo-path SSH fallback, or native macOS full-egress fallback;
- AWS, cloud, deploy, release, production daemon, scheduler, or production authentication-service scope;
- worker-entry wiring;
- workflow/smoke evidence; or
- unrelated `src` refactoring or feature work.

All ADR 0027 through ADR 0033 scope, no-fallback, tmpfs, PID identity, startup nonce, authenticated API, metadata-only telemetry, cleanup uncertainty, and evidence constraints remain binding. Issue #70 remains open until accepted real insecure-container functional and linux-kvm authoritative smoke/inventory evidence exists.

## Stop gates

Implementation must pause before proceeding if any of the following occur:

- `src/**/*.ts` would exceed **23,400** lines;
- the implementation would need broad deletion, pattern-based deletion, or cleanup success after uncertainty;
- a generic deletion API or launcher-visible cleanup inventory/path/inode export is proposed;
- a new dependency is needed;
- current Pi SDK behavior creates host files under `agentDir` or `sessionRoot` that cannot be recorded or bounded safely;
- destructive cleanup would need to race against an unjoined timeout;
- telemetry would include more than metadata;
- secrets, prompts, model outputs, tool outputs, source text, HTTP bodies, account identifiers, raw provider identifiers, raw provenance digests, private paths, or inode values would be persisted or reported; or
- any issue #70 profile, tmpfs, PID, nonce, API, dev-only, no-cloud, or no-fallback boundary would be weakened.

## Consequences

ADR 0033 implementation can continue without compressing security-critical inode-bound cleanup code. The larger cap is deliberately limited to Pi-owned runtime cleanup hardening and does not broaden issue #70. Future implementation PRs must report `src/**/*.ts` and launcher line counts and must stop rather than weaken cleanup ownership if the hard cap is reached.
