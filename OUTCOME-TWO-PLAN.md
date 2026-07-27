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

Outcome 2 is complete only when all are true:

- Trusted runtime closure succeeds twice with byte-identical reports.
- Exact Python, gzip, zstd, loader, and library objects are accounted for.
- Real mapped Python closure matches the resolved closure.
- Unknown or ambiguous objects fail closed.
- Sealed executables are generation-bound.
- Portable hostile tests pass.
- Native Jobs A–E pass on one exact clean head.
- Thin integration qualification passes.
- Descriptor, process, filesystem, mount, and checkout baselines are restored.
- Exact-head hostile review signs off.
- No Phase B, AWS, provider, OpenTofu, or deployment authority is consumed.

This strategy maximizes five-agent parallelism while keeping architecture decisions and final integration serialized and reviewable.
