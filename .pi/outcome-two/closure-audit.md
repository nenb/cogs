# Outcome 2 Wave 1 — Runtime-Closure Production Audit

**Agent:** Outcome 2 Wave 1 Agent 3  
**Audit date:** 2026-07-27  
**Research branch:** `research/outcome2-closure` at starting head `908041cf6473c10667a030c11c6798cb2338c5d4`  
**Audited candidate:** `feat/issue42-candidate-tar-remediation` at `d96b58ab55e932dda8b1cc007b7f88ad483f336e`  
**Outcome 2 plan:** `OUTCOME-TWO-PLAN.md` at the research head  
**Disposition:** research report only; no implementation is authorized or included.

## 1. Scope and authorities read

I read the complete project architecture/security authorities: `COGS.md`, `DESIGN.md`, `IMPLEMENTATION.md`, `SECURITY.md`, `SECRET-INJECTION.md`, `OUTCOME-TWO-PLAN.md`, and the accepted ADR corpus through ADR 0086 on the candidate branch. I also audited the relevant candidate production, schema, and companion-test code, especially:

- `deploy/aws-feasibility/remote/completion_kata_process.py`
- `deploy/aws-feasibility/remote/completion_runtime_closure.py`
- `deploy/aws-feasibility/remote/completion_fixtures.py`
- `deploy/aws-feasibility/remote/completion_kata_qualification.py`
- `deploy/aws-feasibility/remote/completion_kata_runtime.py`
- `scripts/run-stage2-phase-a-candidate.py`
- `schemas/stage2-phase-b-qualification-v1.json`
- their Python and TypeScript companions.

The governing security principle is consistent across those documents: repository and workload content are untrusted; operations that discover or acquire host objects must occur in a narrowly authenticated trusted host phase; after the boundary, checked/workload code receives only pre-authorized data and descriptors. Cleanup uncertainty is failure, not absence.

## 2. Executive conclusion

There is useful research code, but there is **no reusable trusted runtime-preparation module as a unit** on the candidate branch.

The strongest reusable pieces are the pure ELF parser and hostile fixtures from commit `07d592b3`, selected descriptor/mapping/sealing algorithms from `a7914db6`, and deterministic workload fixtures from `2582f8b3`. They must be extracted behind a new tracked trusted owner rather than imported through `completion_kata_process.py`.

The current implementation places approximately 988 gross new production lines of host closure, mapping, sealing, archive-child, recovery, and residue behavior into an already 843-line Kata process module. At candidate head that file is 1,829 lines. It mixes four authorities:

1. general command supervision;
2. host ELF discovery;
3. sealed decompressor execution;
4. durable archive-child recovery.

That is the monolith Outcome 2 is intended to avoid.

Two defects are architectural blockers:

- Python mapping validation uses the already-running, heavily imported process and explicitly accepts mappings outside the path-resolved closure (`_mapped_closure(..., require_expected=False)`). It therefore does not prove the resolved Python closure.
- gzip/zstd sealing reopens the executable by pathname after the original object was authenticated. The sealed bytes are hash-equal, but the seal is not bound to the authenticated source generation as required.

The native-preflight work also tried to prove trusted host discovery after chroot, capability removal, and procfs restriction. ADRs 0071–0086 document the resulting cascade of namespace/proc/descriptor corrections. Outcome 2 should not continue that architecture. Host procfs mapping discovery belongs before capability removal.

## 3. Exact trust-boundary placement

### 3.1 Trusted preparation phase

The following operations must run in one tracked trusted host process **before** chroot, the final user/PID/mount namespace transition, capability removal, seccomp, or loss of access to trusted procfs:

1. Authenticate the exact source revision/module bytes used for preparation. Invoke Python isolated (`-I -B`) with a fixed import root; do not import project/user modules by ambient path.
2. Resolve only the compile-time table, with no `PATH` lookup:
   - `python3-parser -> /usr/bin/python3`
   - `zstd -> /usr/bin/zstd`
   - `gzip -> /usr/bin/gzip`
3. Authenticate every fixed symlink/path component and open the final object with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`. Do not use `realpath()` as authority.
4. Check regular-file type, UID 0, no group/world write bit, fixed size bound, and stable `dev/inode/size/mtime/ctime` plus stable security metadata before and after the read.
5. Parse each ELF object from its held descriptor; resolve the exact loader and complete `DT_NEEDED` graph; reject ambiguity, unresolved names, SONAME conflict, duplicate role identity, forbidden dynamic search/audit tags, and bounds violations.
6. Start a short-lived helper from the exact pinned Python executable. Keep it blocked on a trusted gate before untrusted input or workload behavior. Through trusted `/proc/<pid>/maps` and `map_files`, open and hash every executable mapping, reject unknown executable mappings except explicitly enumerated kernel mappings, reread maps byte-for-byte, then terminate/reap the helper.
7. Execute gzip and zstd from sealed descriptors while their input pipes remain empty. Validate their actual loader/library mappings against the resolved closures before releasing any archive byte.
8. Copy gzip and zstd directly from the already-authenticated source descriptors into anonymous executable memfds. Verify complete readback, source generation stability, mode, and the exact seal set. Never reopen a source path.
9. Build and schema-validate one canonical metadata report and place it in a read-only sealed report memfd.
10. Close all source, procfs, map-files, helper, status, and temporary descriptors. Prove all helpers reaped and no preparation residue before settlement.

This phase is in the trusted computing base. Running a tracked file is not sufficient by itself: the launcher must authenticate the exact file/revision before importing it, use isolated Python, and exclude ambient import paths and environment authority.

### 3.2 Boundary transition

A single owner object performs an irreversible one-shot settlement:

- input: no caller-selected path, executable, command, library directory, report field, or fd number;
- output: only the fixed gzip descriptor, fixed zstd descriptor, sealed report descriptor, and a private owner token needed for cleanup;
- source/proc/map descriptors: all closed before output authority is issued;
- every output descriptor: `CLOEXEC` until the trusted launcher installs it into the fixed child fd table;
- any close, reap, seal, report-validation, or baseline uncertainty: no handoff.

The trusted launcher may then construct mounts/fd tables and enter the untrusted phase. The closure module itself must not also implement chroot, user mapping, seccomp, Kata, archive parsing, campaign reporting, or workload orchestration.

### 3.3 Untrusted qualification phase

After the transition, checked/workload code may:

- receive fixed descriptor numbers for sealed gzip, sealed zstd, and the sealed canonical report;
- `fstat`, hash, inspect seals, and compare those descriptors with report metadata;
- execute the supplied decompressor descriptors for deterministic fixed inputs;
- verify there are no extra inherited descriptors or children.

It must not:

- resolve `/usr/bin/*`, search `PATH`, inspect host library directories, or open another host object;
- use unrestricted host `/proc`, `/proc/<pid>/maps`, or `map_files` to discover closure state;
- reopen a reported path;
- modify or extend the report;
- acquire packages, archives, helpers, or libraries.

The untrusted phase verifies supplied authority. It does not create authority.

## 4. Reusable files, functions, and commits

### 4.1 Reuse by extraction and hardening

| Source / commit | Reusable material | Required changes before reuse |
|---|---|---|
| `completion_runtime_closure.py` from `07d592b3de3a5ae0bc1690cb3ee0cfd18489ac17` | `_span`, `_elf`, fixed-width ELF64 parsing, interpreter/SONAME/`DT_NEEDED` decoding, forbidden dynamic-tag checks; extensive synthetic hostile tests in `test/aws-stage2-completion-runtime-closure.py` | Move to a pure host-independent parser module; add explicit object/dependency count bounds; define treatment of every accepted dynamic tag; return typed parse results; do not retain the fixed 35-object rootfs assumptions in the reusable layer. |
| Same commit | `_regular`, `_library`, SONAME ambiguity and symlink/hardlink graph tests | Reuse only for immutable rootfs-plan closure. Host path resolution needs a different fd-relative implementation. |
| `completion_kata_process.py` additions from `a7914db60cd5ed3a76c081299ab1b79c56455b21` | Stable descriptor read pattern in `_host_read`; candidate enumeration idea in `_host_library`; map-files open/hash and maps-before/maps-after structure in `_mapped_closure` | Replace `realpath`; recheck all policy metadata; require exact resolved-vs-mapped equality for every tool; reject truncation; move into a tracked trusted module. |
| Same commit | `_sealed_memfd` write/readback/seal loop | Feed it the already-held source fd and generation; do not call `_read_exact_source` by path; require the complete executable seal profile and private generation binding. |
| Same commit | `_set_parent_death_signal`, pre-release gate, `execveat`, `close_range`, exact PID/SID/PGID/start-time observations, maps-before-input concept | Keep as small helper supervision primitives. Remove archive enumeration/report concerns and expose no generic argv/path surface. |
| `completion_kata_process.py` foundation from `910fdde882ca5ff91b0fad8c9daf8942a0f38182` | Bounded pipe drain, exact wait/reap, PID identity, error aggregation patterns | Extract narrow primitives only. The complete process owner includes unrelated Kata command authority and test-only issuers. |
| `completion_fixtures.py` from `2582f8b3602078e7cf3f9a8a96d9dc89af915fad` | Deterministic Git/package source and installed-tree models, canonical JSON-line and ustar fixture generation | Reuse unchanged for later portable workload qualification. It is not part of trusted host closure preparation and must not be imported there. |
| `stage2-phase-b-qualification-v1.json` from `a7914db6` | Closed object shape, SHA-256/SONAME bounds, fixed tool ordering, exactly-one executable/loader schema patterns | Use as a drafting source only. Create a separate closure schema; do not retain archive-discovery/Phase-B candidate coupling. |

### 4.2 Keep but do not generalize

`fixed_runtime_closure()` in `completion_runtime_closure.py` is useful for the accepted immutable Stage 2 rootfs. Its `_ROOTS`, source-set, exact 35-object, package-order, and rootfs-plan assumptions are correct domain restrictions there. Keep that function in its current domain; do not turn it into the host-preparation API.

`completion_fixtures.py` is also domain-correct deterministic data generation. It should remain separate from closure authentication, sealing, process ownership, and report generation.

### 4.3 Do not reuse as units

Do not transplant these units intact:

- `completion_kata_process.py`: mixed authority and excessive surface.
- `_RuntimeDiscoveryHost`: closure metadata is visible before a complete settled handoff; it does not enforce that both streams settled before close.
- `_FixedArchiveStream`: archive parsing, mapping validation, source streaming, callbacks, process recovery, and descriptor cleanup are coupled.
- `_sealed_bound`: it reopens the path and loses source-generation binding.
- `_mapped_closure(..., require_expected=False)`: it accepts unknown Python mappings.
- `schemas/stage2-phase-b-qualification-v1.json`: it is a candidate archive-discovery report, not the Outcome 2 contract.

### 4.4 Commit provenance summary

- `2582f8b3`: all 312 fixture production lines.
- `07d592b3`: all 276 rootfs closure production lines.
- `910fdde8`: initial 830-line process supervisor.
- `863fdb48`, `f299277e`, `82189eb6`, `7c4a77cc`: small supervisor/qualification corrections.
- `a7914db6`: 988 of the 1,829 final process-file lines and all 296 Phase B schema lines; this is the sole production host runtime-discovery implementation commit.
- Later candidate commits through `d96b58ab` changed the native workflow/test envelope and ADRs but did not repair or modularize the production closure code.

## 5. Defects and gaps

### P0 — boundary and authority

1. **Python does not compare actual mappings with the resolved closure.**  
   `completion_kata_process.py:1666` assigns `_mapped_closure(os.getpid(), self._closures[0], False)`. In the `False` branch, unknown executable mappings are accepted as libraries. This measures the already-running process, including extension modules imported by the runner, rather than a short-lived exact pinned Python helper. It cannot prove “actual mapped Python closure equals resolved closure.”

2. **Trusted discovery is not an enforceable module boundary.**  
   `_bind_runtime_discovery_host()` is a private function embedded in a Kata process module and can be called in any phase. Native-preflight attempted to execute it only after chroot/capability removal and then depended on privileged procfs behavior. The production runner happens to call it on the host, but the API does not encode or enforce that placement.

3. **Sealing is not source-generation-bound.**  
   `_sealed_bound()` at lines 1094–1099 constructs an artifact from `_HostBound` and calls `_sealed_memfd()`. `_sealed_memfd()` calls `_read_exact_source()`, which opens `artifact.logical_path` again. A replacement between the original authentication and this reopen can yield different generation authority. Hash equality prevents changed bytes from passing, but it does not satisfy “never reopen after authentication” or bind the sealed object to the authenticated source generation.

### P1 — authentication, mapping, sealing, and cleanup

4. **`realpath()` is raceable path authority.**  
   `_host_resolve()` canonicalizes by pathname and `_host_read()` later opens the result. Symlink and ancestor changes are not authenticated as one stable component chain. The fixed logical path itself is not proven to resolve to the held object before and after the read.

5. **Security metadata is checked only before reading.**  
   `_host_read()` rechecks `dev/inode/size/mtime/ctime`, but does not recheck type, owner, mode, or link/security policy after the read. A concurrent chmod/chown can change policy without changing the generation tuple used by the code.

6. **SONAME uniqueness is incompletely modeled.**  
   `_host_closure()` skips a pending dependency if any cached object advertises that SONAME, but it does not maintain an explicit one-SONAME-to-one-object identity map or reject root/loader/library role ambiguity. Final validation checks set satisfaction, not exact unique provider relationships.

7. **Mapping capture can silently truncate.**  
   `_mapped_closure()` performs one `os.read(..., 4 * 1024 * 1024)` for each maps snapshot and does not prove EOF. A maps file at the cap can be accepted without complete capture.

8. **Python mapping evidence is contaminated by runner imports.**  
   The audited module imports `ctypes`, hashing, compression, selectors, Kata modules, and repository code before inspecting `os.getpid()`. Even without the explicit `require_expected=False`, this is not the required minimal short-lived helper.

9. **Mapping digest is absent.**  
   `HostElfClosure` contains only `closure_sha256`. The report cannot distinguish resolved closure metadata from actual mapping evidence or bind two stable map snapshots.

10. **Seal contract is incomplete and private.**  
    The code requires WRITE/GROW/SHRINK/SEAL but has no explicit executable-seal profile/version, no report field, no source-generation binding, and no handoff-time revalidation. Availability/requirement of `MFD_EXEC` and `F_SEAL_EXEC` is not decided.

11. **Owner close does not require lifecycle completion.**  
    `_RuntimeDiscoveryHost.close()` closes descriptors without requiring both fixed streams to have settled. An active stream can be invalidated by owner close.

12. **Aborted-stream cleanup can hide uncertainty.**  
    `_FixedArchiveStream.close()` accumulates process/fd errors but does not raise them. It discards `_DISCOVERY_CHILDREN` after cleanup even when cleanup errors include a surviving or unreaped child. The outer runner’s durable recovery often catches this, but the reusable owner contract itself is unsafe.

13. **Module-global residue sets are not authority.**  
    `_DISCOVERY_FDS` and `_DISCOVERY_CHILDREN` are process-local bookkeeping. They are useful assertions but cannot establish crash recovery or a fresh-process descriptor baseline.

14. **No bounded preparation owner state machine.**  
    There is no explicit `NEW -> PREPARING -> READY -> HANDED_OFF -> CLOSED/POISONED` contract. Properties expose closure metadata while descriptors and child work remain live.

### P1 — report/schema

15. **The schema is for the wrong artifact.**  
    `stage2-phase-b-qualification-v1.json` requires runtime archives, archive layout facts, candidate blockers, and false production claims. Outcome 2 needs a small independently reusable trusted closure report.

16. **Required report metadata is missing.**  
    There is no mapping digest, seal profile, per-tool mapped/resolved binding, report digest, or global closure digest. Source-generation binding exists neither in private owner state nor report semantics.

17. **Object ordering is incidental.**  
    Objects sort lexically by role string, SONAME, and digest. This happens to be deterministic, but it is not a documented semantic order such as executable, loader, then SONAME-sorted libraries.

18. **Paths/generations and metadata are not cleanly separated.**  
    The public report correctly omits host paths and inode identifiers, but the implementation also omits a private authenticated-generation table. Outcome 2 needs private identity authority and public metadata, not one reduced model serving both purposes.

19. **Candidate report authority is coupled to archive success.**  
    Closure metadata can be emitted only inside a much larger runtime archive discovery report. It cannot be independently run twice and compared byte-for-byte as Outcome 2 requires.

### P2 — parser and coverage gaps

20. `_elf()` allows up to the dynamic-segment bound of dependencies and relies on later report validation for the 128-item limit. Reject the bound at parse/resolve time.
21. Unknown non-forbidden dynamic tags are accepted without an explicit supported-tag policy. The final parser contract should state whether it preserves, ignores, or rejects each tag class.
22. Portable tests cover many parser and ambiguity branches well, but the current closure-specific tests do not cover descriptor exhaustion, source chmod/chown during read, maps-file exact-cap truncation, duplicate SONAME provider roles, partial initialization of the final owner, handoff failure, double close after a poisoned close, or report-FD seal failure.
23. Fixture tests are strong but irrelevant to the trusted/untrusted closure boundary; importing fixture generation into preparation would only enlarge the TCB.

## 6. Proposed tracked trusted preparation module

### 6.1 Files

Create a narrow production boundary in tracked files (names proposed for Wave 2):

```text
deploy/aws-feasibility/remote/completion_elf.py
    Pure ELF64 parser and typed metadata only.

deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py
    Fixed host authentication, closure resolution, helper mappings,
    sealing, canonical report, handoff, and cleanup owner.

schemas/trusted-runtime-closure-v1alpha1.json
    Standalone canonical metadata contract.
```

`completion_kata_process.py` should consume the settled handoff through a narrow port; it should not own host discovery. `completion_runtime_closure.py` may use `completion_elf.py` while retaining its fixed rootfs-plan wrapper.

### 6.2 Public API

The production authority-bearing API should be intentionally small and fixed:

```python
FIXED_TOOL_TABLE = (
    ("python3-parser", "/usr/bin/python3"),
    ("zstd", "/usr/bin/zstd"),
    ("gzip", "/usr/bin/gzip"),
)

def prepare_fixed_runtime_closure() -> PreparedRuntimeClosure: ...

class PreparedRuntimeClosure:
    @property
    def canonical_report(self) -> bytes: ...

    def settle_fixed_handoff(self) -> RuntimeClosureHandoff: ...  # one shot
    def close(self) -> None: ...                                  # idempotent only after proved close
    def __enter__(self) -> "PreparedRuntimeClosure": ...
    def __exit__(self, ...): ...

@dataclass(frozen=True)
class RuntimeClosureHandoff:
    gzip_executable_fd: int
    zstd_executable_fd: int
    report_fd: int
```

No public production function accepts a path, tool name, search directory, argv, environment, library candidate, pid, report value, target fd, cleanup pathname, or retry selector. Test seams are injected only through an internal constructor unavailable from the zero-argument production entry.

`settle_fixed_handoff()` succeeds only from `READY`, returns once, transfers explicit fd ownership, and leaves the preparation owner with no source/proc/helper descriptors. The launcher installs those descriptors into one separately reviewed fixed fd map. A second settlement fails.

### 6.3 Internal typed model

Keep private identity and public metadata distinct:

```text
SourceGeneration
  dev, inode, size, mtime_ns, ctime_ns, mode, uid, gid

ElfMetadata
  soname, ordered_needed, interpreter, supported_dynamic_flags

AuthenticatedObject
  fixed_role, approved_logical_path, held_fd, generation, sha256, elf

ResolvedToolClosure
  tool, executable, loader, libraries, closure_digest

MappedToolClosure
  tool, canonical objects, mapping_digest, stable_maps_digest

SealedExecutable
  tool, fd, source_generation, size, sha256, exact_seals
```

None of `SourceGeneration`, held fd numbers, proc addresses, map text, or private paths enters the public JSON report.

## 7. Contracts

### 7.1 Authentication and closure contract

For each object:

- fixed approved logical path or fixed library-search root;
- component-by-component no-follow resolution with symlink-chain stability;
- final `O_RDONLY|O_NOFOLLOW|O_CLOEXEC` descriptor;
- regular, UID 0, no group/world write, size `1..134217728`;
- exact stable security metadata and `dev/inode/size/mtime/ctime` around complete read;
- exact SHA-256 and strict ELF parse;
- one loader, one provider per SONAME, every ordered `DT_NEEDED` satisfied, no ambiguity;
- maximum 128 objects per tool, 512 MiB per tool and aggregate bound fixed by the architecture decision.

No pathname is reopened after descriptor authentication.

### 7.2 Mapping contract

For each helper:

1. fork from the trusted owner and set `PDEATHSIG` before release;
2. execute the exact descriptor with empty fixed environment and no `PATH` lookup;
3. block before input/workload behavior;
4. capture complete maps to EOF under a fixed byte/line bound;
5. open every executable file mapping through `map_files`, hash and parse it, and match exactly one resolved object;
6. permit only explicitly named kernel synthetic executable mappings;
7. require exact executable/loader cardinality and closure-wide dependencies;
8. reread complete maps and require byte identity;
9. record canonical mapping metadata/digest without addresses or paths;
10. TERM/KILL if needed, reap exactly, and prove no session descendant.

Python uses a fresh minimal helper, never `os.getpid()` of the preparation runner.

### 7.3 Sealing contract

For gzip and zstd only:

- create anonymous executable memfd with `CLOEXEC` and sealing enabled;
- copy by `pread` from the held authenticated source fd;
- verify full source generation before and after copy;
- set fixed executable mode before the execute-seal transition;
- fsync, complete same-fd readback, size/SHA equality;
- require `F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL` and make an explicit ADR decision to require `F_SEAL_EXEC`/`MFD_EXEC` on the supported kernel rather than silently vary;
- verify exact seal bits at settlement and handoff;
- never name the memfd, expose `/proc/self/fd` as a reopening API, or reopen the source path;
- close the source only after the sealed descriptor and private generation binding settle.

### 7.4 Canonical report contract

Proposed top-level version: `cogs.trusted-runtime-closure/v1alpha1`.

```json
{
  "version": "cogs.trusted-runtime-closure/v1alpha1",
  "tools": [
    {
      "tool": "python3-parser",
      "objects": [
        {
          "role": "executable",
          "size": 1,
          "sha256": "...",
          "soname": null,
          "needed": []
        }
      ],
      "closure_sha256": "...",
      "mapping_sha256": "...",
      "sealed_executable": false
    }
  ],
  "closure_sha256": "..."
}
```

Required semantics:

- tools are exactly `[python3-parser, zstd, gzip]` in that order;
- objects are executable first, loader second, then libraries sorted by SONAME UTF-8 bytes and SHA-256;
- exactly one executable and loader per tool;
- every `needed` list preserves ELF order and has unique bounded SONAMEs;
- every dependency has exactly one provider in the same tool closure;
- per-tool digest hashes the canonical object array;
- mapping digest hashes the canonical mapped-object array after exact equality validation;
- top-level digest hashes the canonical tool array;
- gzip/zstd `sealed_executable` is true; Python is false;
- no descriptor number, address, raw map line, environment, command output, boot ID, PID, device/inode, timestamps, username, checkout path, arbitrary host path, or archive data;
- if logical paths are later deemed necessary, schema permits only the three fixed root paths and no library paths; omission is preferred;
- strict JSON: UTF-8, sorted keys, compact separators, no NaN, terminal LF, duplicate-key rejection, byte-identical re-encoding;
- report must pass both the tracked schema and the semantic codec twice before handoff;
- report itself is delivered in a sealed read-only memfd.

### 7.5 Cleanup contract

The owner has explicit states:

```text
NEW -> PREPARING -> READY -> HANDED_OFF -> CLOSED
                 \-> POISONED ---------> CLOSED only after proved recovery
```

Rules:

- every descriptor/process is registered before the next fallible operation;
- reverse cleanup always attempts all independently safe closures;
- helper cleanup uses exact PID/starttime/SID/PGID and executable identity, then bounded TERM, KILL, reap, and descendant absence;
- source/proc/map/report-temporary fds close before `READY`;
- sealed/report fds close on failure before handoff and transfer explicitly on handoff;
- close errors are aggregated with the primary failure; success followed by close uncertainty is failure;
- first successful `close()` makes later `close()` a no-op; a poisoned/uncertain close remains the same failure on repeat and cannot become success;
- no module-global set is cleanup authority;
- success proves the owner-local fd registry empty, helper registry empty, fixed fd baseline restored, and no named file/process residue;
- no broad kill, recursive delete, lazy cleanup, retry, or unknown-to-absent conversion.

The report is metadata, not cleanup evidence. Cleanup returns a typed local result or raises an aggregated cleanup exception; it does not rewrite a previously issued report.

## 8. Measured line inventory

All measurements below are physical lines from exact candidate head `d96b58ab55e932dda8b1cc007b7f88ad483f336e`, using `git show ... | wc -l` or the ADR 0039 frozen-count method.

### 8.1 Focused files

| Category | File | Lines |
|---|---|---:|
| Production | `completion_kata_process.py` | 1,829 |
| Production | `completion_runtime_closure.py` | 276 |
| Production | `completion_fixtures.py` | 312 |
| **Focused production subtotal** |  | **2,417** |
| Schema | `stage2-phase-b-qualification-v1.json` | 296 |
| Test | runtime-closure Python / TS | 351 / 36 |
| Test | Kata-process Python / TS | 573 / 86 |
| Test | fixtures Python / TS | 231 / 30 |
| **Focused test subtotal** |  | **1,307** |
| **Focused production + schema + tests** |  | **4,020** |

Nonblank measurements for the three focused production files are 1,654, 255, and 256 respectively. Their nonblank/non-comment measurements are 1,652, 254, and 256.

### 8.2 Embedded closure footprint

- `completion_kata_process.py` was 843 lines immediately before `a7914db6` and is 1,829 at candidate head.
- Candidate gross diff from exact Phase B baseline `84b30d30...` is `+988/-2` for that file.
- The contiguous host runtime-discovery region at lines 905–1829 is **925 physical lines**.
- Generic path-based source reading and memfd sealing at lines 348–402 adds another **55-line shared region**.
- The pure ELF/parser-plus-rootfs resolver file is **276 lines**; `_span` through `_library` occupies lines 68–229 (**162 physical span lines**) before the fixed rootfs wrapper.

This is why extraction, not extension of the 1,829-line process file, is the appropriate Wave 2 action.

### 8.3 Runtime-discovery slice and global Stage 2 count

Current candidate gross additions from the exact Phase B baseline across the six directly relevant counted surfaces are:

| Surface | Gross additions | Deletions |
|---|---:|---:|
| candidate runner | 509 | 4 |
| budget script | 16 | 3 |
| qualification | 394 | 1 |
| process | 988 | 2 |
| runtime | 798 | 9 |
| Phase B schema | 296 | 0 |
| **Total** | **3,001** | **19** |

(The ADR cap is based on gross additions and gives no deletion credit.)

Those six files currently total **7,300 physical lines**. The full ADR 0039 frozen counted set at candidate head measures:

- `deploy/aws-feasibility/**/*.{sh,py,tf}`: 20,571 lines across 41 files;
- frozen historical schema/validator/renderer set: 591 lines;
- fixed-source/candidate/budget plus Phase A v1/v2 and Phase B schemas: 6,651 lines;
- **frozen cumulative total: 27,813 physical lines**.

### 8.4 Realistic Wave 2 planning envelope

This is an estimate, not implementation authority:

| New/refactored production area | Estimated lines |
|---|---:|
| Pure typed ELF parser extracted from the measured 162-line span | 180–240 |
| Fixed path/component authentication and closure resolution | 220–320 |
| Short-lived helper and exact mapping validation | 240–340 |
| Descriptor-direct sealing and handoff | 120–180 |
| Owner state machine, canonical report, and cleanup | 260–380 |
| Standalone tracked schema | 160–230 |
| **Production + schema estimate** | **1,180–1,690** |

Portable tests/fixtures should be budgeted separately at roughly 1,000–1,500 readable lines. This is substantially smaller and more reviewable than extending the current 1,829-line process file and 7,300-line discovery slice.

## 9. Wave 2 handoff

1. Keep `completion_runtime_closure.py` and `completion_fixtures.py` in their existing fixed domains.
2. Extract the pure ELF parser with its hostile tests first.
3. Add the tracked trusted owner and standalone schema; do not wire it through the native zero-capability sandbox.
4. Qualify mapping access in a small trusted-side native job.
5. Qualify sealing/fd/process cleanup independently.
6. Only after both pass, let Kata/integration code consume the fixed settled handoff.
7. Do not preserve candidate branch ADR complexity merely because it exists; production closure code provenance is concentrated in `a7914db6` and can be decomposed cleanly.

The final Outcome 2 integration should contain no host discovery after the trusted-to-untrusted transition and no extension of `completion_kata_process.py` for closure preparation.
