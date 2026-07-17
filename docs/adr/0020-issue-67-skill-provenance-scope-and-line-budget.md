# ADR 0020: Issue #67 skill provenance scope and line budget

## Header

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Reviewed by: delegated project lead
- Acceptance: Accepted by delegated project lead on 2026-07-17 under Nick Byrne’s explicit instruction: when a decision is required I let you make it based on what you think best.

## Context

Issue #67 is the Stage 3 S3-05 implementation for shared/private skills and bounded project context loading. It depends on the prior Cogs launch/session metadata and SFTP transfer behavior, but it is not an egress, cloud, release, or deployment feature.

The current clean `main` baseline is:

```sh
find src -name '*.ts' -print0 | xargs -0 wc -l | tail -1
# 11862 total
```

ADR 0001 requires Cogs to embed Pi with a closed custom `ResourceLoader`; ambient Pi package, extension, prompt, skill, settings, `.pi`, and `.agents` discovery remain disabled. ADR 0009 requires content-addressed skill artifacts whose trusted materializer rejects path traversal, absolute paths, links, devices, duplicate normalized paths, unsupported media and size/count violations; Pi prompt text must come from a verified trusted copy, the same verified artifact must be transferred to the guest, and the digest must be recorded. ADR 0008 keeps telemetry/export metadata metadata-only.

Issue #67's accepted plan selects a deterministic local artifact contract and explicitly avoids adding production dependencies, remote registries, object-store credentials, cloud resources, runtime guest credentials, release claims, or broad project-context discovery.

## Decision

Approve a bounded production line-count exception only for issue #67 skill provenance and project context loading.

Until issue #67 is closed, production TypeScript under `src/` may grow up to an absolute cap of **14,400** lines. This cap is measured from the accepted baseline of **11,862** lines and is independent of the closed issue #66 line-budget amendments. ADR 0015 through ADR 0019 were issue-specific secure-egress exceptions and must not be reused as a general Stage 3 budget.

The cap provides room for a readable implementation estimated at 1,800–2,100 production lines plus at least 20% contingency:

| Item | Production `src/` TypeScript lines |
|---|---:|
| Baseline before issue #67 | 11,862 |
| High readable estimate | 2,100 |
| 20% contingency on high estimate | 420 |
| Minimum cap from estimate | 14,382 |
| Accepted rounded cap | 14,400 |

This ADR authorizes only the components and constraints below.

## Canonical skill bundle

Issue #67 must not implement tar, gzip, zip, shell unpacking, remote unpacking, or dependency-backed archive handling.

Skills are represented by a strict canonical uncompressed JSON bundle with media type:

```text
application/vnd.cogs.skills.bundle.v1+json
```

The bundle contains sorted regular-file entries with canonical relative paths, canonical base64 content, explicit byte sizes, and per-file `sha256:<hex>` digests. The bundle digest is `sha256:<hex>` over the exact canonical JSON bytes.

The verifier must parse the bytes, validate strict shape and bounds, canonicalize/reserialize, require byte-for-byte equality with the input, and then verify all sizes and digests. This inherently rejects compression, links, devices, archive headers, duplicate or noncanonical paths, unsupported JSON shape, and noncanonical JSON encodings.

The implementation must enforce bounded archive bytes, decoded bytes, file count, path length, skill count, candidate skill markdown size, and prompt-append size. Exact bound constants may be selected in code review, but they must be finite and covered by tests.

Local source scanning for private snapshots and fixtures must use trusted injected source roots, not launch paths. It must scan with `O_NOFOLLOW` where supported plus `lstat`/`open`/`fstat` race bounds, and reject symlinks, non-regular files, devices, FIFOs, sockets, path escapes, duplicate normalized paths, oversized files, and unstable reads.

## Shared skills: local OCI Image Layout and manifest digest semantics

`LaunchConfig.skills.shared_revision` is a standard OCI artifact **manifest** digest, not a bundle/layer digest.

Issue #67 supports only a trusted local OCI Image Layout root injected by host configuration or tests. It does not support network registries, remote pulls, tag resolution, ref-name resolution, registry credentials, Docker credential helpers, guest runtime registry access, or cloud artifact distribution.

The local OCI layout verifier must:

- verify bounded `oci-layout` with a supported image layout version;
- verify bounded `index.json` is present and strictly shaped;
- require `index.json` to contain exactly one manifest descriptor whose digest equals the configured `shared_revision`;
- forbid index annotations and descriptor annotations;
- treat index descriptor presence as validation only, not tag or reference resolution;
- locate the manifest blob by digest under the local layout's `blobs/sha256/` tree;
- compute SHA-256 over exact manifest raw bytes and require equality to `shared_revision`;
- parse the manifest strictly with approved artifact/config/layer media types;
- require exactly one canonical JSON skills bundle layer descriptor;
- verify descriptor digest and size against the bundle blob;
- verify the bounded config descriptor/blob according to the approved empty/minimal config contract;
- verify the bundle bytes using the canonical JSON bundle verifier.

Safe metadata must record both the OCI manifest digest and bundle digest.

## Private skills: user-scoped startup snapshot

`LaunchConfig.skills.user_revision` is the canonical JSON bundle digest.

Private skills must be snapshotted from the current trusted local filesystem source for the validated launch `user_id` at session startup:

- derive the local user namespace as `sha256(userId)` rather than using raw `user_id` as a filesystem component;
- scan only trusted injected source roots for that namespace;
- build canonical JSON bundle bytes;
- compute the bundle digest;
- require equality with `skills.user_revision`;
- atomically retain the exact bundle bytes under a user-scoped content-addressed local store;
- deny cross-user resolve/fetch even if another user's store contains the same digest.

Empty skills must use a required deterministic empty artifact. Missing sources, missing store state, digest mismatch, or cross-user access is fatal required-provenance failure.

Object-store credentials, presigned capabilities, local store roots, private source roots, and private source paths must not enter the guest, Pi prompt, telemetry, or safe metadata.

## Strict Pi loading and prompt provenance

The implementation must keep Pi resource loading closed under ADR 0001.

For each verified bundle, Cogs must materialize files into a fresh trusted temporary directory, then use the pinned exported Pi `loadSkillsFromDir` API only on that verified directory. Discovery must support direct root `.md` files and recursive `SKILL.md` files consistently with the pinned Pi version.

Any candidate skill markdown with malformed, missing, or duplicate Pi metadata fails the whole required bundle. Pi diagnostics from `loadSkillsFromDir` must be exactly zero. The discovered skill set must exactly match the candidate skill markdown files. Duplicate skill names across shared and private bundles are fatal unless a later accepted decision specifies precedence.

Cogs must not rely on Pi lazily rereading trusted host paths for prompt content. Before the first model input, Cogs must append bounded full trusted `SKILL.md` text from the verified trusted copy to the Pi prompt, clearly marked as untrusted instructions and annotated with the authoritative scope, bundle/manifest digest, skill name, and normalized bundle path. These instructions may guide model behavior but cannot alter Cogs tools, auth, policy, telemetry, provenance, or launch/session configuration.

Cogs may return explicit Pi `Skill` descriptors for discovery/slash metadata, but descriptor paths must be remapped to fixed guest paths or synthetic safe paths, not trusted host temp paths. Guest mutation after startup cannot change already loaded prompt bytes or trusted provenance metadata.

Extensions, prompt templates, themes, packages, settings, ambient `.pi`/`.agents` discovery, and guest-discovered skills remain disabled.

## SFTP delivery and guest materialization

Issue #67 may add only the SFTP operations required for trusted internal materialization:

- bounded mkdir for fixed guest roots/directories;
- atomic regular-file writes using temp file, bounded write, fsync where available, close, and rename;
- exact canonical bundle copy to the guest;
- materialization of verified decoded bundle files under fixed guest roots `/shared/skills` and `/user/skills`;
- immediate reread of the guest bundle and digest verification before Pi session use.

No shell command, tar command, guest unpacker, remote registry command, or read-only mount claim is authorized. If the current runtime has no real read-only mount support, metadata/evidence must record that read-only enforcement is unsupported or false rather than claiming it.

## Project context: bounded nonfatal `AGENTS.md`

Project context is limited to bounded SFTP retrieval of `/workspace/AGENTS.md` for issue #67.

The content is untrusted instruction text. Missing file, oversized file, invalid UTF-8, permission denial, timeout, or read error is nonfatal and recorded as a safe diagnostic code. The initial scope is one file with finite byte bounds. It must be supplied to Pi through the closed loader's project context/agents-file path, not by enabling ambient discovery.

Loading ancestor files, multiple context names, guest project skills, `.pi`, `.agents`, package context, or settings-driven context discovery is outside issue #67.

## Startup ordering, lifecycle, and cleanup

Required skill provenance must be prepared before model API key resolution:

1. validate launch document;
2. verify shared OCI layout/manifest/bundle and private user snapshot/bundle;
3. materialize trusted temp copies and perform strict Pi skill discovery;
4. SFTP materialize fixed guest roots/files and verify copied bundle digest by reread;
5. load bounded `AGENTS.md` with nonfatal diagnostics;
6. only after required provenance succeeds, resolve the model API key in callback scope;
7. create the Pi session with explicit verified resources.

Required skill provenance failures are fatal before model secret scope and before Pi creation. Context failures are nonfatal safe diagnostics.

Trusted temp directories must be cleaned on every failure path and on session dispose. SFTP temp leftovers must be cleaned best-effort. The implementation should avoid background timers/workers; if any are introduced, they must join on dispose.

## Metadata handoff for issue #68

Issue #67 may produce safe in-memory or session-adjacent metadata for issue #68 export handoff, but issue #68 owns persistence/export inclusion.

Metadata may include stable digests, revision kinds, counts, byte sizes, fixed guest roots, safe status codes, `release_eligible: false`, `sftp_bundle_verified`, and honest read-only support status.

Metadata, telemetry, logs, and exports must not include skill text, `AGENTS.md` content, source excerpts, arbitrary host paths, trusted source/store roots, credentials, registry URLs with secrets/query/userinfo, object-store paths, SFTP file contents, prompts, model output, tool output, or private material.

## Evidence expectations

Issue #67 evidence is local functional provenance/integrity evidence only. It should include tests for:

- canonical JSON bundle determinism and hostile/noncanonical rejection;
- local source scanner path/type/race/size defenses;
- local OCI Image Layout verification including `oci-layout`, strict single-descriptor `index.json`, manifest raw-byte digest, media types, descriptor digest/size, and annotation rejection;
- private user snapshot digest matching, deterministic empty artifact, cross-user denial, and atomic user-scoped store retention;
- strict Pi `loadSkillsFromDir` behavior, zero diagnostics, direct root `.md` and recursive `SKILL.md`, duplicate/malformed metadata failures, closed loader, exact tool list, and eager trusted-copy prompt append;
- SFTP mkdir/materialization, exact bundle copy, reread digest verification, and guest mutation not changing trusted prompt bytes;
- bounded nonfatal `AGENTS.md` diagnostics;
- safe metadata content and forbidden-content absence;
- cleanup of trusted temp directories and local test stores;
- required provenance failure before model API key resolver callback.

KVM is not required unless the implementation changes existing composition or harness behavior that requires requalification. No AWS resources, cloud campaigns, release artifacts, or production distribution claims are authorized.

## Stop gates and non-expansion

Stop for a new ADR or explicit owner/lead review before any of the following:

- exceeding **14,400** production `src/` TypeScript lines for issue #67;
- adding or changing production dependencies;
- replacing the canonical JSON bundle with tar/zip/gzip/npm package archives or shell unpacking;
- implementing remote OCI registry access, tag/ref resolution, registry credentials, Docker credential helpers, object-store credentials, MinIO/S3 credential wiring, or guest registry/object-store capabilities;
- allowing launch documents or guest input to provide source/store roots or artifact paths;
- enabling ambient Pi discovery, extensions, packages, prompt templates, themes, settings-driven skills, `.pi`, `.agents`, or guest-loaded skill prompts;
- expanding project context beyond bounded `/workspace/AGENTS.md`;
- claiming read-only guest enforcement without actual runtime support and evidence;
- persisting/exporting metadata beyond the safe handoff owned by issue #68;
- making AWS, EKS, deployment, release, production-readiness, or artifact distribution claims.

## Consequences

Issue #67 can proceed with a deterministic, reviewable artifact and prompt-provenance implementation without compressing security-critical validation and cleanup paths. The accepted cap is issue-specific and does not alter prior egress budgets or future issue budgets.

Security claims remain bounded to local provenance/integrity evidence. Guest-visible skill files are convenience materialization only; authoritative prompt provenance is the verified trusted copy loaded before first input.
