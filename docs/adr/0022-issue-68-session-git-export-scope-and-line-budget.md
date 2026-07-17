# ADR 0022: Issue #68 session, Git, and export scope and line budget

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Reviewed by: Delegated project lead
- Acceptance: Accepted under Nick Byrne's explicit delegation to continue autonomously and make project decisions without waiting, the same delegation basis used for ADRs 0020 and 0021.

## Context

Issue #68 implements the Stage 3 session state, Git observation/checkpoint, and raw export work described by `IMPLEMENTATION.md` section 25 and `DESIGN.md` sections 8, 14, and 15.

The current accepted baseline after issue #67 is `main` at `8a89daa`, with **14,495** production `src/**/*.ts` lines. ADR 0005 requires native Pi JSONL to remain the authoritative active transcript. ADR 0006 requires Git observations to be recorded as explicitly untrusted sandbox observations without claiming repository attestation. ADR 0008 and ADR 0020 constrain telemetry/export metadata: no prompt text, source excerpts, tool output, credentials, skill text, AGENTS content, arbitrary host paths, or private material outside their existing native transcript contexts.

Current implementation state relevant to issue #68:

- `src/api/server.ts` already exposes authenticated `GET /v1/entries` and `POST /v1/export` ports and marks export responses sensitive.
- `src/pi/session.ts` already uses Pi `SessionManager` under a trusted session root and exposes `sessionFile()` and canonical `skillMetadata()` handoff.
- Pi `SessionManager` preserves version 3 JSONL and writes synchronously when it writes, but does not expose a public durable fsync API and may defer early entries before the first assistant entry.
- SSH/SFTP and bash execution are already bounded behind `SshConnectionManager`; issue #68 Git commands must use fixed trusted commands/scripts over that boundary, not parse arbitrary model/user bash text.

## Decision

Approve issue #68 implementation only within the scope below.

### Line budget

Set a hard issue-specific cap of **17,200** production `src/**/*.ts` lines.

This cap is measured from the issue #67 baseline of **14,495** lines:

| Area | Estimated production lines |
|---|---:|
| Durable Pi JSONL flush and paged history | 330 |
| Trusted Git mapping sidecar and resolver | 360 |
| Bounded Git observation cadence over SSH | 300 |
| Non-pushed notes and optional hidden checkpoints | 340 |
| Deterministic local export directory and manifest | 460 |
| Authenticated API/lifecycle/shutdown integration | 250 |
| Benchmarks/evidence/applicability helpers | 170 |
| **Planned addition** | **2,210** |
| **Contingency** | **495** |
| **Total allowance from baseline** | **2,705** |
| **Cap** | **17,200** |

The contingency is **22.4%** over the planned addition. If implementation would exceed 17,200 lines, pause for another accepted ADR or explicit owner/lead review. Do not compress validation, cleanup, or fail-closed behavior to fit the cap.

### Native Pi JSONL and settled durability

Native Pi JSONL remains the sole authoritative transcript. Cogs must not create a second transcript or rewrite active Pi JSONL for history, export, mapping, or future sanitization.

For a normal settled prompt boundary, Cogs must fail closed rather than emit/acknowledge `run_settled` if Pi JSONL cannot be verified and durably flushed:

- the Pi session file must exist as a regular trusted-storage file when a normal completed turn requires durability;
- the file descriptor must be fsynced;
- the containing session directory must be fsynced;
- paging history must read from Pi JSONL after durable boundaries, not from a second transcript.

Implementation must first verify exactly what the pinned Pi `SessionManager` guarantees after `session.prompt()` resolves. If Pi has not yet created a file for a non-normal boundary, Cogs may report a bounded generic warning/status, but it must not fabricate JSONL entries.

### Git observation, mapping, notes, and checkpoints

All Git repository state is untrusted sandbox-reported data. Cogs authoritatively supplies only Pi entry ID, turn/boundary, and observation time.

Git observation/checkpoint/note failures are nonfatal warnings under ADR 0006 and must not fail an otherwise completed turn. However, trusted sidecar corruption or trusted sidecar write/fsync failure must never create or publish an `exact` claim. If a sidecar append cannot be made durably and consistently, the observation is dropped or downgraded to a warning, not emitted as exact mapping.

Records must remain compatible with the current `schemas/git-mapping-v1alpha1.json` shape. Do not add a required `source` field to individual mapping records in issue #68. File-wrapper or collection semantics may be defined in code or schema later without changing individual record compatibility.

Git lookup resolution is an internal tested port, not a new HTTP endpoint unless a later design/API decision adds one. Resolver behavior:

1. return an exact mapping if one exists;
2. otherwise return nearest mapped ancestor as `inferred-ancestor` when bounded Git ancestry checks succeed;
3. otherwise return an explicit pre-Cogs/out-of-scope response without fabricating exact mappings.

The first-turn pre-observation is held as pending and mapped only after the authoritative user entry exists. No Git observation may be attached to a non-existent or guessed Pi entry.

### Checkpoint options and limits

Checkpoint enable/disable, limits, timeout, and exclusions must be supplied through existing trusted constructor/composition options, not by expanding the launch schema. If implementation proves production wiring requires a launch-schema change, pause for separately reviewed schema/design approval.

Trusted exclusions must be validated as bounded canonical relative path or pattern values. They must not accept absolute paths, traversal, empty segments, control characters, backslashes, or any value that can inject arbitrary Git pathspec magic/options such as leading `-`, `:(...)`, or option-like/pathspec-control syntax.

Hidden checkpoints must:

- use fixed trusted scripts/commands and a temporary Git index;
- never modify `HEAD` or the user's index;
- use one total deadline for the complete checkpoint operation;
- preflight with strict NUL-delimited Git status output and SFTP `lstat` under the guest root;
- reject unsupported, malformed, over-limit, non-regular, escaping, symlink, device, or otherwise unsafe inputs;
- respect `.gitignore` and trusted exclusions only after those exclusions pass canonical relative path/pattern validation;
- enforce changed-file, per-file, total-size, output, and timeout bounds;
- tolerate residual unreachable Git objects only as documented untrusted workspace mutation after interrupted checkpoint attempts.

### Git notes

Cogs may attempt to append non-secret pointers under `refs/notes/cogs`. Notes content must be bounded and contain only non-secret mapping metadata such as session ID, entry ID, turn, confidence, and observation time. Cogs must never push notes, configure remotes, widen Git transport, or claim notes are authoritative.

### Export

Issue #68 implements deterministic local raw export directory generation only. No archive format, compression, tar/zip dependency, object-store upload, S3/MinIO client, cloud credential, share-link, or release/distribution behavior is approved.

The export directory format is:

```text
cogs-session-<session-id>/
  session.jsonl
  manifest.json
  git-map.json
  skills.json
  warnings.json
  transform-report.json
```

Attachments remain excluded by default and are not implemented in issue #68.

`manifest.json` must contain deterministic JSON, file SHA-256 hashes, byte counts, Pi/Cogs/schema version metadata, export mode `raw`, `attachments_included: false`, and skill metadata from `skillMetadata()` only. It must not contain skill markdown, AGENTS content, prompt/model/tool text outside native `session.jsonl`, source excerpts, credentials, arbitrary host paths, tool output, or private material.

The transform hook for issue #68 is a deterministic raw identity transform over a copied bundle with a report. Sanitization/anonymization remains future work and must not be claimed.

The existing authenticated JSON API may return a bounded sensitive local bundle descriptor for the daemon/platform. Export must not be exposed as a model-callable tool and must not stream large raw bundles through the small JSON API response.

## Implementation slice order

Implementation should proceed in reviewable slices:

1. **Durable JSONL/history**: verify Pi settled behavior, add file+directory fsync, and page history from JSONL.
2. **Git map sidecar/resolver**: append-only trusted sidecar, durable writes, exact/inferred/pre-Cogs internal resolver.
3. **Git observation cadence**: observe before turn, after completed tool boundaries, after settled flush, and before shutdown with bounded fixed SSH Git commands.
4. **Notes/checkpoints**: non-pushed notes, optional hidden checkpoint using temp index, strict preflights, limits, and warnings.
5. **Export directory/manifest**: deterministic local raw bundle, skills metadata, transform report, authenticated sensitive descriptor.
6. **Lifecycle/evidence**: graceful shutdown observation/export generation/cleanup, benchmarks, applicability matrix, and end-to-end evidence.

Every slice must report current production LOC and reaffirm the non-expansion boundaries below.

## Non-decisions and exclusions

This ADR does not approve:

- new or changed production dependencies;
- cloud work, AWS/EKS campaigns, object-store clients, S3/MinIO credentials, upload APIs, share links, or release/distribution claims;
- archive formats or compression in issue #68;
- restore implementation, chat fork/restore, workspace reset, branch truncation, or filesystem restoration;
- sanitization/anonymization claims;
- submodules, Git LFS restoration semantics, or multiple repository support;
- pushing notes, configuring remotes, or adding Git network transport behavior;
- parsing arbitrary model/user bash text;
- launch-schema expansion for checkpoint options without separate review;
- new public HTTP Git-lookup endpoint beyond `DESIGN.md` section 8;
- exposing export as a model-callable tool;
- weakening ADR 0005, ADR 0006, ADR 0008, or ADR 0020 constraints.

## Required evidence

Issue #68 must add deterministic tests/evidence for:

- pinned Pi JSONL compatibility and durable settled fsync ordering;
- paged history after SSE replay eviction without a second transcript;
- sidecar append/fsync, corruption handling, and no false exact claim;
- Git observation labels and first-turn pending observation behavior;
- notes attempted but never pushed/configured;
- checkpoint preflight limits, temp-index behavior, nonfatal warnings, disabled checkpoints, and residual unreachable object documentation;
- deterministic export directory/manifest/hashes/skills metadata/transform report;
- raw export authenticated API sensitive descriptor only;
- non-Git, Git-absent, corrupt repo, over-limit, timeout, and concurrent mutation applicability cases;
- small, large, and dirty repository benchmark rows.

## Consequences

Issue #68 can proceed with a measured cap and strict security language. Native Pi JSONL remains authoritative; Git records remain trusted records of untrusted observations; export remains local, raw, authenticated, and deterministic. No cloud, release, restore, sanitization, or dependency decision follows from this ADR.
