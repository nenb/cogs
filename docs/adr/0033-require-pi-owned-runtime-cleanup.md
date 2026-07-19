# ADR 0033: Require Pi-owned runtime cleanup for launcher Pi host files

- Status: Accepted
- Date: 2026-07-19
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0027 through ADR 0032 authorize issue #70 as development-only launcher work with strict profile boundaries, no fallback, exact Linux tmpfs prerequisites for `/run/cogs/egress` and `/run/cogs/ssh`, metadata-only telemetry, and no cloud, release, daemon, scheduler, or production authentication-service scope. ADR 0032 kept the production `src/**/*.ts` hard cap at **22,000** lines and stated that no current production `src` export or dependency was justified at that time.

The trusted composition factory review found a concrete cleanup blocker: the launcher cannot safely remove native Pi host runtime files by recursively discovering files under the supplied Pi `agentDir` and `sessionRoot`. Native Pi JSONL, Cogs history, Git map sidecars, and raw local export artifacts are required during run, history, export, and shutdown. They must not be removed before final shutdown/export obligations are complete. However, after final worker cleanup, the development launcher needs a zero-inventory proof without broad deletion.

Current measured production line count is:

```text
src/**/*.ts: 21,295 total
```

The measured stop gate estimates a normal readable implementation at about **350-510** production lines, leaving the repository below the existing **22,000** hard cap. Tests are excluded from that cap. If the estimate or API assumptions fail, implementation must stop rather than compress or broaden deletion.

## Decision

Authorize a narrow opt-in production Pi-owned final cleanup API and behavior for exact host runtime files created beneath supplied `agentDir` and `sessionRoot` for one Cogs Pi session.

This supersedes ADR 0032 only where ADR 0032 said no current production `src` change was justified. It does not change ADR 0032's numeric `src/**/*.ts` hard cap of **22,000** lines, issue #70 launcher caps, or any issue #70 scope boundary.

The API must be opt-in. Existing callers and non-owned `dispose()` behavior remain unchanged. The implementation may add a distinct final operation such as `disposeOwnedRuntime()` to `CogsPiSessionPorts`, or an equally narrow opt-in behavior, provided that it:

- waits for normal session disposal and is same-promise/idempotent;
- is final, meaning native JSONL/history/export are no longer available after successful owned cleanup;
- returns only a bounded success/failure result, not paths, inodes, inventories, digests, prompts, outputs, credentials, raw IDs, or arbitrary deletion authority; and
- rejects generically on uncertainty.

## Ownership and cleanup requirements

When enabled, Pi/Cogs must record exact owned host entries and inode identities as they are created or explicitly adopted. Final cleanup removes only those recorded exact entries, bottom-up, with parent-directory fsync and absence proof.

The owned runtime may include only exact expected files and directories beneath the supplied `agentDir` and `sessionRoot`, such as:

- the owned session directory under `sessionRoot`;
- the active/resumed native Pi JSONL file recorded from the native session manager;
- the Cogs Git mapping sidecar when created;
- raw export files and directories created by the Cogs local exporter; and
- empty owned roots/directories if the caller explicitly supplied them for this one session.

Native JSONL/history/export must remain available until final owned disposal. No hidden checkpoint or export deletion semantics are authorized beyond existing owners and this final owned cleanup operation.

Cleanup must preserve artifacts and reject generically if it observes any of the following:

- unknown or unrecorded entry;
- path replacement, inode mismatch, crash-lost inventory, or uncertain identity;
- symlink, hardlink, unsafe type, wrong owner, wrong mode, wrong link count, or unbounded tree;
- failed unlink, rmdir, fsync, reinspection, absence proof, timeout, or cancellation uncertainty.

There must be no broad recursive discovered-tree deletion, arbitrary filesystem deletion API, launcher-visible paths/inodes/inventory, secret/prompt/output/raw-ID leakage, telemetry widening, new dependency, or fallback.

## Startup algorithm

For opt-in owned runtime sessions, implementation must:

1. Snapshot the caller's Pi runtime options from own data properties before side effects.
2. Require canonical current-user-owned mode `0700` roots supplied by the caller, or create only exact configured direct children under a canonical owned parent when that mode is explicitly implemented.
3. Record root and session-directory identities using no-follow, path/open/path-stability checks with device, inode, uid, mode, and link-count data.
4. Register each created/adopted file or directory immediately after acquisition and before the next await.
5. Keep native session JSONL, Git map sidecar, and export artifacts available for history/export/shutdown until final owned cleanup.
6. Avoid using Pi SDK or Cogs helper behavior as implicit deletion authority unless that helper records exact owned entries and exposes only a narrow internal cleanup result.

## Final disposal algorithm

The final owned cleanup operation must:

1. Enter one idempotent same-promise cleanup coordinator with an absolute deadline.
2. Abort or await any active run, export, or shutdown-preparation state through existing session-disposal semantics.
3. Dispose the native Pi session, local exporter, Git binding/observer/checkpointer, prepared guest skills, auth storage, and in-memory secret holder.
4. Refresh and validate the exact recorded inventory after normal disposal.
5. Remove only recorded entries bottom-up, with stable dev/inode/uid/mode/nlink checks before removal.
6. Fsync parents and prove absence after each removal group.
7. Return success only after complete absence proof.
8. Preserve all artifacts and reject generically if any uncertainty occurs.

A successful final owned cleanup must not remove launcher worker descriptors, API-token control files, manifests, profile resources, driver resources, state locks, `/run/cogs/ssh`, `/run/cogs/egress`, or `linux-kvm.lock`. Those remain launcher/supervisor or externally provisioned responsibilities.

## Crash and partial-state semantics

If the worker crashes before final owned cleanup, native JSONL, export artifacts, and sidecars remain for recovery. Later supervisor cleanup must not fabricate ownership by recursive traversal. If exact ownership records are unavailable or stale, cleanup is recovery-required and artifacts are preserved.

Partial export state may be cleaned only if the exporter or Pi-owned runtime tracker recorded exact entries and identities. Unknown temp or backup directories preserve and reject.

## Launcher consumption

The later issue #70 trusted composition must create exact empty Pi runtime roots, call the opt-in Pi-owned runtime API, and consume only cleanup success or failure. After Pi reports successful final owned cleanup, the launcher may remove only its separate exact owned runtime root/sentinel using its own inode-bound proof.

The unsafe broad runtime-tree cleanup attempted in the trusted composition branch must be removed. `worker-entry.ts` remains unavailable/unwired until a later reviewed slice wires a safe factory.

## Required tests

Implementation must include hostile tests for at least:

- non-owned callers preserving current `dispose()` behavior;
- owned no-prompt, prompt-settled, resumed-session, Git-map, export, and shutdown-preparation cleanup paths;
- history/export availability before final owned cleanup and unavailability/removal after success;
- exact removal of recorded JSONL, Git map, export bundle, temp/backup, and owned empty directories;
- unknown entries in `agentDir`, `sessionRoot`, session dir, `exports`, or bundle dirs preserving and rejecting;
- symlink, hardlink, unsafe type, wrong owner/mode/nlink, inode replacement, directory swap, JSONL growth/replacement, failed fsync, timeout, and crash-lost inventory;
- idempotent same-promise cleanup and no double unlink;
- hostile option shapes with getters, prototypes, symbols, and `toJSON` rejected before side effects; and
- no serialization leak of paths, credentials, prompts, outputs, raw IDs, raw digests, or inode values.

## Stop gates

Implementation must pause before proceeding if any of the following occur:

- `src/**/*.ts` would exceed **22,000** lines;
- a new production dependency is needed;
- a generic filesystem deletion API, launcher-visible inventory/path/inode export, or broad recursive deletion is proposed;
- current Pi SDK behavior creates unbounded or unrecordable host files beneath `agentDir` or `sessionRoot`;
- cleanup uncertainty would report success or delete unknown/replaced content;
- telemetry would widen beyond metadata-only;
- raw model keys, OpenBao/API/egress/integration tokens, private keys, prompts, model outputs, tool outputs, source text, HTTP bodies, account IDs, raw provider IDs, raw provenance digests, inodes, or private paths would be persisted or reported;
- profile fallback, local-tool fallback, runc fallback, open-egress fallback, anonymous-auth fallback, hidden `sudo` mount, symlink/bind fallback, repo-path SSH fallback, or native macOS full-egress fallback is proposed; or
- AWS, cloud, deploy, release, production daemon, scheduler, or production authentication-service scope is requested.

## Reaffirmed issue #70 constraints

All ADR 0027 through ADR 0032 constraints remain binding. Issue #70 remains open until real insecure-container functional smoke/inventory and linux-kvm authoritative smoke/inventory evidence are accepted. This ADR does not authorize issue closure, worker-entry wiring, workflows, smoke evidence, cloud/AWS, release, deployment, production daemon, scheduler, production authentication service, dependency changes, profile fallback, tmpfs loosening, PID-only signaling, nonce persistence, API contract changes, or telemetry widening.

## Consequences

This ADR resolves the trusted composition stop gate by moving native Pi host-runtime cleanup authority to the production code that creates and understands those files. The launcher no longer needs to see or delete Pi runtime trees. Cleanup remains exact, opt-in, and fail-closed, while preserving native JSONL/history/export until final owned disposal.
