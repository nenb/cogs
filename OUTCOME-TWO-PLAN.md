# Outcome 2 Plan: Exact Runtime Closure Without Another Monolithic Sandbox

## Objective

Outcome 2 is complete when we can prove:

> A trusted host-preparation process identifies, authenticates, opens, and seals the exact Python, gzip, zstd, loader, and shared-library closure required by qualification; rejects ambiguity or drift; emits deterministic canonical metadata; and leaves no descriptors, processes, files, or uncertain residue.

It does **not** require the zero-capability workload itself to rediscover the host through `/proc/map_files`.

## 1. Stop extending the current MR

1. Freeze the current branch and preserve its commits.
2. Preserve the successful Outcome 1 implementation and evidence.
3. Treat the later native-preflight work as research material.
4. Create a clean Outcome 2 branch from the reviewed Outcome 1 head.
5. Extract code only after deciding whether it belongs on the trusted or untrusted side.

No more corrective ADRs or CI patches go into the existing MR.

### Proposed PR structure

1. **Outcome 1 / atomic rootfs PR**
   - Rootfs and atomic candidate publication only.
2. **Runner capability report PR**
   - Non-authoritative probe and recorded facts only.
3. **Trusted runtime-closure PR**
   - Production closure implementation and portable tests.
4. **Native primitive qualification PR**
   - Small independent Linux tests.
5. **Outcome 2 integration/evidence PR**
   - Thin composition and final evidence.

## 2. Adopt the correct trust boundary

### Trusted preparation phase

The trusted host process may:

- Authenticate the exact checkout and executable paths.
- Read ELF objects.
- Inspect its own mappings through procfs.
- Resolve the exact loader and library closure.
- Open and retain authenticated descriptors.
- Copy executable bytes into sealed anonymous objects where required.
- Produce a canonical closure description.
- Construct read-only mounts and descriptor tables.

### Untrusted qualification phase

After preparation:

- Close all unneeded descriptors.
- Enter namespaces/chroot.
- Drop all capabilities.
- Enable `no_new_privs` and seccomp.
- Provide only fixed, sealed descriptors and canonical metadata.
- Prevent additional host-object discovery or acquisition.
- Run deterministic workloads.

The untrusted phase verifies the supplied closure but does not inspect unrestricted host procfs.

## 3. Five-agent parallel plan

The lead agent owns architecture, integration, and final review. Five subagents operate in independent worktrees with non-overlapping files.

### Wave 1: simultaneous investigation and decomposition

| Agent | Responsibility | Deliverable |
|---|---|---|
| 1 | Branch and MR decomposition | Exact keep/move/drop commit map for the current MR |
| 2 | Hosted-runner capability characterization | Metadata-only probe covering sudo, maps, namespaces, procfs, rlimits, KVM, and fd behavior |
| 3 | Runtime-closure production audit | Inventory of reusable closure code, defects, and trusted-boundary placement |
| 4 | Portable-test audit | Coverage matrix for ELF parsing, ambiguity, drift, cleanup, codecs, and recovery |
| 5 | Native-proof design | Minimal independent Linux primitives and required environment for each |

These agents do not modify the same files.

### Wave 1 gate

The lead integrates the reports into one architecture decision covering:

- Operations allowed before capability removal.
- Operations required afterward.
- Which GitHub-hosted facts are authoritative.
- Exact report schema.
- Exact cleanup obligations.
- Native jobs required.
- One realistic line budget.

Only one architecture ADR should be needed.

### Wave 2: parallel implementation

| Agent | File ownership | Work |
|---|---|---|
| 1 | Trusted launcher module | Exact-head authentication, privilege boundary, descriptor passing, and cleanup |
| 2 | Runtime-closure module | ELF closure, mapping validation, generation checks, sealing, and canonical report |
| 3 | Portable tests and fixtures | Parser, ambiguity, drift, crash, cleanup, and deterministic-output tests |
| 4 | Native proc/mapping probe | Trusted `map_files`, executable mapping, loader, and library identity |
| 5 | Native fd/process/tool probe | `close_range`, high fds, PDEATHSIG, gzip/zstd, rlimits, and residue |

### Rules

- Each agent works in a separate git worktree.
- Each owns explicit paths.
- No agent edits the integration workflow.
- Every handoff includes:
  - Commit or patch.
  - Changed files.
  - Tests run.
  - Facts proved.
  - Remaining uncertainty.
  - Security implications.
  - Measured line count.

### Wave 3: parallel review before integration

The five slots review different dimensions:

1. Trust-boundary review.
2. Descriptor and process lifecycle review.
3. Filesystem and cleanup review.
4. Parser, schema, and determinism review.
5. Native-environment and CI review.

The lead resolves findings and performs the integrated hostile review. Agents do not independently merge their work.

## 4. Capability probe first

Before finalizing native architecture, run one deliberately non-authoritative probe that records only fixed metadata.

### Probe fields

- Runner image/version.
- Kernel and architecture.
- Effective sudo policy relevant to descriptors.
- Soft and hard `RLIMIT_NOFILE`.
- `close_range` availability.
- `O_TMPFILE` availability.
- `O_PATH` behavior within and across mount namespaces.
- User, mount, and PID namespace support.
- UID/GID map behavior.
- Procfs ownership behavior.
- Self `map_files` access:
  - before namespace entry;
  - after user namespace entry;
  - before and after capability removal.
- Seccomp availability.
- KVM device availability and ioctl behavior.
- gzip/zstd exact identities.

### Probe constraints

- No secrets.
- No raw environment dump.
- No cloud access.
- No package installation.
- No acquisition.
- No evidence authority.
- No retry interpreted as success.

This replaces trial-and-error architecture changes.

## 5. Production runtime-closure design

### Inputs

Use a fixed table:

```text
python3-parser -> /usr/bin/python3
zstd           -> /usr/bin/zstd
gzip           -> /usr/bin/gzip
```

No PATH lookup is permitted.

### Per-object authentication

For every executable, loader, and library:

- Canonical compile-time path.
- `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`.
- Regular file.
- Root owned.
- Not group/world writable.
- Bounded size.
- Stable dev/inode/size/mtime/ctime before and after reading.
- Strict ELF parsing.
- Exact SONAME and `DT_NEEDED`.
- No ambiguous candidate libraries.
- No unresolved dependency.
- No duplicate role ambiguity.

### Running-mapping validation

A short-lived trusted helper:

1. Executes the exact pinned Python binary.
2. Captures its executable mappings while still on the trusted side.
3. Opens each mapping through procfs.
4. Authenticates the mapped bytes against the resolved closure.
5. Rejects unknown executable mappings.
6. Re-reads maps and fails on drift.
7. Terminates and is reaped exactly.

This proves the real mapped closure without requiring untrusted code to retain procfs privileges.

### Sealing

For gzip and zstd:

- Copy authenticated bytes into anonymous sealed objects.
- Require all relevant seals.
- Bind the sealed descriptor to the authenticated source generation.
- Never reopen by pathname after authentication.
- Close all source descriptors after settlement.

### Canonical report

Include only metadata:

- Tool role.
- Object role.
- Size.
- SHA-256.
- SONAME.
- Ordered dependencies.
- Closure digest.
- Mapping digest.
- Fixed schema version.

Require:

- Strict canonical JSON codec.
- Tracked schema.
- Byte-identical encoding across two executions.
- No paths beyond approved fixed host paths.
- No environment, command output, addresses, or identifiers.

## 6. Portable qualification

Run extensively in ordinary tests, not the native sandbox.

### Required tests

- Valid ELF closure.
- Missing loader.
- Missing library.
- Duplicate library candidate.
- SONAME mismatch.
- Unknown interpreter.
- Oversized object.
- Mutable object.
- Generation change during read.
- Mapping changed during capture.
- Unknown executable mapping.
- Closure byte bound.
- Object-count bound.
- Descriptor exhaustion.
- Partial initialization.
- Failure while sealing.
- Failure during cleanup.
- Double close.
- Canonical encoding stability.
- Schema rejection.
- No residual tracked descriptors or children.

Use synthetic fixtures for every failure path. Native jobs should not be responsible for testing parser branches.

## 7. Native qualification as small parallel jobs

Avoid one enormous native job.

### Job A: runtime mappings

Proves:

- Real ELF parsing on hosted Linux.
- Exact Python interpreter and loader closure.
- Self `map_files` access at the trusted boundary.
- Mapping stability.
- Exact cleanup.

### Job B: compression executables

Proves:

- Exact gzip and zstd binaries execute.
- Sealed executable descriptors work.
- Deterministic decompression.
- No PATH lookup.
- No network.
- No unexpected children or mappings.

### Job C: descriptor behavior

Proves:

- Soft descriptor limit is measured and normalized by trusted setup.
- High descriptor duplication.
- `close_range`.
- Exact inherited descriptor set.
- CLOEXEC behavior.
- No leaked descriptors.

### Job D: process lifecycle

Proves:

- PDEATHSIG before and after release.
- TERM/KILL/reap.
- PID/start-time identity.
- Process-group/session ownership.
- No process residue.

### Job E: sandbox boundary

Proves:

- Chroot and read-only binds.
- Exact user/PID/mount/network namespaces.
- Zero capability sets.
- `no_new_privs`.
- Seccomp socket/io_uring denial.
- No acquisition or writable checkout.

GitHub can execute these jobs concurrently after Quality passes.

## 8. Thin integration qualification

Only after Jobs A–E pass:

1. Trusted launcher resolves and seals the closure.
2. It validates the trusted helper's actual mappings.
3. It constructs the sandbox.
4. It passes fixed descriptors and canonical metadata.
5. The sandbox validates descriptors and executes one gzip and one zstd workload.
6. The parent enforces timeout and reap.
7. The parent validates:
   - exact marker;
   - exact closure digest;
   - no linked evidence;
   - no descriptors;
   - no children;
   - no checkout changes;
   - no namespace/mount residue.

The integration job composes already-qualified modules instead of duplicating their internal tests.

## 9. CI waiting-time parallelism

Whenever CI runs:

- Agent 1 monitors the run and extracts fixed diagnostics.
- Agent 2 inspects relevant upstream, kernel, or util-linux source.
- Agent 3 challenges the active hypothesis.
- Agent 4 runs portable and static regressions.
- Agent 5 prepares rollback and minimal next-change options.

Only the lead chooses and integrates one correction after the facts converge.

Do not push a speculative chain of five corrections.

## 10. Outcome 2 completion gate

Outcome 2 is complete. The evidence in Section 11 discharges every gate:

- [x] Trusted runtime closure succeeds twice with byte-identical reports.
- [x] Exact Python, gzip, zstd, loader, and library objects are accounted for.
- [x] Real mapped Python closure matches the resolved closure.
- [x] Unknown or ambiguous objects fail closed.
- [x] Sealed executables are generation-bound.
- [x] Portable hostile tests pass.
- [x] Native Jobs A–E pass on one exact clean head.
- [x] Thin integration qualification passes.
- [x] Descriptor, process, filesystem, mount, and checkout baselines are restored.
- [x] Exact-head hostile review signs off.
- [x] No Phase B, AWS, provider, OpenTofu, SSM, or deployment authority is consumed.

## 11. Completion evidence (2026-08-01 UTC)

### Exact authority and runs

- Correction PR: [#349](https://github.com/nenb/cogs/pull/349).
- Protected `main` commit: `c1186ade412403b26eb73e7b47c62951f8deaa8c`.
- Fast exact-head Job B: [run 30678667187](https://github.com/nenb/cogs/actions/runs/30678667187), passed.
- Full exact-head qualification: [run 30678688369](https://github.com/nenb/cogs/actions/runs/30678688369), passed.
- The full run's dispatch-authority, quality, image/SBOM, secret-scan, native C1, Jobs A–E, thin-integration, and final native-required jobs all passed on attempt 1.
- Every native report binds the protected `refs/heads/main` dispatch, checkout, head, workflow, and GitHub envelope to the exact commit above. The runner was `ubuntu-24.04` image `20260720.247.2`, `x86_64`, kernel `6.17.0-1020-azure`.

### Immutable report evidence

GitHub's artifact digest covers the uploaded archive; the report digest covers the downloaded canonical `report.json` bytes.

| Proof | Artifact ID | Artifact SHA-256 | Report SHA-256 |
| --- | ---: | --- | --- |
| Fast B | `8811409295` | `d6b6d69a27fc3aaef72e4e842e0ed3c498622793d97541aa323b1cf73403f1aa` | `3bb81880dda72bb2754c090ef3052134ad30f0657c0fd1160a4e29f8a648c156` |
| A | `8811481790` | `a6e6c971cd2652084222a628af8740afa7ecf34cba16131cb88e19c69d071260` | `d49525776c39ccbfa977ee6cc8c7f1d72e3fb51955ba81f758f5a01921a23eb1` |
| B | `8811480397` | `bd3dd2902ab605aed9b2d3f9938e8ac3aa9408673dfcfedc175b9d5d91182640` | `e2310254aaa9cf249ee2a865da9ba47d63e370f61a6195d5e02bf2b0bdbf0175` |
| C | `8811480173` | `839399323b806efee7976ff76504b8c8022cb3bbf44ba0c5e90050da5fb1f59f` | `5c7e8eb98de3fa0cff4a41ca861632a5ba9870998c0d642a6b72a115356d16a8` |
| D | `8811480415` | `f7d5251d579018de67dd58f8883c433bcdb4e22e773da4afb91c11b007c41cb4` | `2ab96c1ec5da54ffb7f5d297e78d86137b7bc681874f03da5f083ce8ffa9a338` |
| E | `8811480821` | `431322eff00cc2e1076393393f61050a35c5fe929a5bfbb78c49d53a4ce92bf4` | `d9f78a9249d4dce4ba87a9775c5804ae586cddefd2cf3d1122d0d56a201aacd3` |
| Integration | `8811485080` | `ebc6da9fbc370c00f6959be37bb9160365028f724240fed0c75d0f55a4098d85` | `70b224fe2a2ad64e038a2508f9a2b388f904cd3aff3ca484fa3adaec62557268` |

All seven downloaded reports were independently checked for canonical bytes, the production JSON schema, production semantic validation, exact source/workflow binding, passing checks, null failure diagnostics, and seven restored cleanup domains. Fast and full Job B have identical operation, metadata, and runner evidence.

### Closure and integration results

- Source-set SHA-256: `4f98c2e3a890ac651d2aa16f6ca94aefabc069957688ea3b2ed34bda58375eca`.
- Exact mapped Python closure SHA-256: `015e3f9a822e70662027b2e484e610b2be21047e1ea6f58a3eacb9f540e43c11`; Job A and Job B independently report the same six-object parser closure.
- Trusted runtime closure SHA-256: `709c89199cdeacf63056de079bcb0dd2810640e748a24d4a8c37553376447763`; Job B and integration agree.
- Gzip closure SHA-256: `aad6579cdbea6080e20b22731e25347a7bf51392a14321418ac6bc44a925b6ae`.
- Zstd closure SHA-256: `32c89ab4b4e06acd6341607d117610c89b74ba6118e508b16ec01ebae492d9a4`.
- Gzip executable/source/sealed SHA-256: `afea077ce127d4fa9ad410d3066ba2b54dea19c0b44f04adf56c72d5f7b7a9bb`.
- Zstd executable/source/sealed SHA-256: `7c5468b370f7c47eda07281e3437fafc568f95d10420051e3aa522709f9342c5`.
- Gzip and zstd produced the same fixed output SHA-256: `6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8`.
- The production integration operation made exactly two fresh preparations, closed the first, required canonical byte equality, and handed off only the second. Integration then passed closure preparation, exact handoff, both deterministic workloads, exact marker, no-linked-evidence, artifact re-download byte equality, and cleanup.

### Restoration, review, and authority boundary

- Jobs A–E and integration each report `true` for checkout, children, descriptors, limits, mounts, namespaces, and paths restoration.
- Job E passed zero capability sets, locked noroot, `no_new_privs`, exact namespaces, read-only checkout, socket/io_uring denial, no acquisition route, unchanged checkout, reap, mount restoration, and cleanup under seccomp policy SHA-256 `aacfce0e5eeb2fb79a1708b32f5383f89b381898ad7e6bd911905d87483b6bb2`.
- The exact correction diff received independent hostile review; the full portable hostile suite, AST/readability gates, schema semantics, dependency audit, image scans, and secret scan passed before and after merge.
- Only protected-default-branch GitHub qualification authority was consumed. No Phase B campaign, AWS/provider API, OpenTofu, SSM, deployment, or production authority was used.

Outcome 2 is complete for the exact commit and evidence above. Work stops at this boundary before any cloud or deployment activity.
