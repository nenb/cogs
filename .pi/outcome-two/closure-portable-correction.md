# Outcome 2 closure portable correction matrix

- Design ID: `O2-TESTSFIX-DESIGN`
- Design source head: `2023e650e88767e0bd7574f0c302e780743eab5a`
- Exact implementation reviewed by the five reports: `64c055762e260b8fc2eed96741bdb30c89183f3c`
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- Governing authority: accepted ADR 0087 and `OUTCOME-TWO-PLAN.md`
- Disposition: correction design only. No production, schema, test, fixture, workflow, native, provider, cloud, or deployment implementation is authorized by this document.

## 1. Inputs and decision

This matrix incorporates all five closure reviews present at `2023e65`:

1. `.pi/outcome-two/closure-review-parser-auth.md`
2. `.pi/outcome-two/closure-review-mapping-cleanup.md`
3. `.pi/outcome-two/closure-review-launcher-schema.md`
4. `.pi/outcome-two/closure-review-portable-tests.md`
5. `.pi/outcome-two/closure-review-holistic.md`

Those reports all review the production/test implementation at `64c0557`; commits from `64c0557` through `2023e65` add review records, not closure implementation. The production blob identities remain:

| Surface | Git blob | SHA-256 |
| --- | --- | --- |
| `completion_elf.py` | `5e3ba497a5862eb039b4b3a984e877c3dc470c9f` | `21f794d9175b4daa6526cba0df477ad31ea9b5d870576c1ffbc1761e7d1e7c5e` |
| `completion_trusted_runtime_closure.py` | `508378c42810729b43c300aea58d3ae3f1eda292` | `b0c4b1c8f466582e3638020ee6451ce68cb01e16f4e7d2ac1bde84fac0d61436` |
| `completion_trusted_runtime_launcher.py` | `0b00f02e0f45b5fc4850c85df56dfd4c819e2d1d` | `72a72b46bbf5b3b9948fe6c145d002080f49d726d7fc87478294a103cff7d556` |
| `trusted-runtime-closure-v1.json` | `cdd8abf68df367b4839511d34e0ffd8c0de1201a` | `8a57f0fe87191dc8bc295d06112f25478b4739eea96262f64bc6e20e33905610` |

**Decision:** do not patch only the green test adapters. Portable correction starts after production exposes the real bootstrap, issuance, schema, lifecycle, recovery, and sandbox state machines through private syscall-level adapters. Tests then drive those exact production methods. Native Jobs A–E remain blocked until the corrected exact head has no unresolved P0–P3 finding.

A new ADR is mandatory before implementation. ADR 0087 gives zero gross-line headroom to the parser and closure owner, one line to the launcher, forbids new surfaces, and forbids compressed control flow. Several required corrections also change the effective bootstrap, handoff provenance, crash-owner, and T2 contracts. Unused aggregate or test headroom cannot be transferred.

## 2. Portable evidence rules

Every corrected case must satisfy all of these rules.

1. **Production method, not a test reimplementation.** A case names the production method it enters and the lowest adapter operation where the fault occurs. Patching `_resolve_tool`, `_spawn_helper`, `_stop_helper`, `_mapped_closure`, `_seal_source`, `_seal_report`, or `_run_fixed_tool` with a completed result is not evidence for that method.
2. **One intended predicate.** A semantic mutant has all dependent digests recomputed unless the digest itself is the target. The assertion checks the intended schema or semantic error, not merely “some exception.”
3. **Fixture truth.** Every manifest row is dispatched exactly once per declared oracle. The suite asserts `declared IDs == executed IDs`, uniqueness, no unknown fault token, and no positional slicing. A manually similar case does not make a dead manifest row live.
4. **Independent resource truth.** The adapter models kernel/resource state separately from owner registries. Empty fake dictionaries alone are not cleanup proof. Assertions compare fd, child/descendant, path, mount, namespace-handle, limit, and checkout baselines and require all registries empty.
5. **Register before effect.** The event transcript proves authority registration precedes the next fallible effect. After-effect faults leave ownership either proved closed/reaped or explicitly uncertain; an uncertain fd number is never retried.
6. **Primary plus cleanup.** The oracle checks the primary error and every independently safe cleanup error in stable order. A cleanup error must not replace the primary.
7. **No optimized assertions.** Each suite still rejects `-O`; security checks are executable control flow, not Python `assert` statements in production.
8. **Bounded and effect-minimal.** Portable adapters perform no sudo, namespace, mount, proc `map_files`, seccomp, KVM, compression-tool, network, container, provider, cloud, or workflow operation. Harmless subprocesses may be used only for the fixed outer-supervisor protocol and must be bounded and reaped.
9. **No authority promotion.** A portable pass proves only deterministic parser/codec/state-machine behavior against scripted operations. It does not prove Linux syscall availability, real source provenance, real `map_files`, executable memfd operation, T2 isolation, native cleanup, or Outcome 2 completion.

## 3. Required production seams before test correction

These are private seams, not new caller-selectable production arguments.

| Seam | Production owner/methods | Required behavior exposed to portable tests |
| --- | --- | --- |
| Source admission | fixed bootstrap before importing parser/closure/launcher; public `prepare_fixed_runtime_closure()` admission guard | Fixed `/usr/bin/python3 -I -B`, fixed empty environment, authenticated import root and schema bytes, parser/closure/launcher/bootstrap blob binding, no authority-bearing operation before admission, one-use admission token not supplied by caller data. |
| Filesystem authentication | `_resolve_once`, `_read_complete`, `_authenticate`, `_resolve_library`, `_resolve_tool` | Component and symlink observations; open/stat/read phase labels; held-generation state; no `PATH`/`realpath`; aggregate identity accounting. |
| Report validation | `_encode_report`, tracked-schema gate, independent `_decode_report`/semantic codec | Two genuinely separate validators and encoders; stable error codes; exact report bytes returned only after both agree. AJV is the portable reference for the tracked schema, not a production Node shellout. |
| Sealing and settlement | `_seal_source`, `_seal_report`, `PreparedRuntimeClosure.settle_fixed_handoff` | Every write/read/fsync/fcntl/open/close and transfer cut; descriptor state including `OPEN`, `CLOSED`, and `CLOSE_UNCERTAIN`; issuance record and generation snapshots. |
| Helper lifecycle | `_spawn_helper`, `_matching_child`, `_wait_child`, `_stop_helper`, `_prepare` failure cleanup | Independent child existence/reaped state, pidfd/start-time/SID/PGID/executable identity, descendants, gates, deadlines, registration and retained recovery authority. |
| Outer recovery | real fixed outer supervisor used by preparation and launcher | Worker/helper pre-registration protocol, parent-death cuts, fresh supervisor module state, exact identity/reap result, terminal uncertainty where proof is impossible. A new unrelated preparation is not recovery. |
| Launcher lifecycle | `_run_fixed_tool` through a private syscall adapter, then `launch_fixed_runtime_qualification` | Generic descriptor checks, report decode, issuance consume, executable/report byte binding, fixed-fd install, child identity, bounded I/O and wait, descendants, TERM/KILL/reap, exact cleanup. |
| T2 construction | production implementation behind `launch_fixed_sandbox_probe` | Construct fixed namespace/chroot/mount/capability/NNP/seccomp boundary and own cleanup. Returned booleans derive from observations; no prebuilt all-true result. Unsupported architecture fails before any architecture-specific syscall. |

The bootstrap and outer-supervisor shapes must be settled in the replacement ADR. Portable tests cannot compensate for an absent production owner.

## 4. Exhaustive correction matrix

### 4.1 Source admission, path authentication, and closure resolution

| ID | Production method/cut | Hostile or success case | Required oracle | Test owner |
| --- | --- | --- | --- | --- |
| SRC-01 | bootstrap before module import | Exact fixed Python, `-I`, `-B`, empty fixed environment, fixed authenticated root | Admission precedes the first import and first `_Ops` effect; exact argv/env transcript | launcher portable |
| SRC-02 | bootstrap blob set | Bootstrap, parser, closure, launcher, or schema blob missing, wrong mode, wrong digest, wrong revision, or duplicate tree row | Reject before import/effect with the exact missing/mismatch code | launcher portable |
| SRC-03 | bootstrap held reads | Replacement before open, during read, after read/before load, and current-path restoration after malicious loaded bytes | Held generation or loaded-byte mismatch rejects; restoring pathname cannot pass | launcher portable |
| SRC-04 | public constructor guard | Direct import and direct `prepare_fixed_runtime_closure()` without admitted bootstrap | Reject before `list_fds`, path open, helper, proc, memfd, or report operation | recovery portable |
| SRC-05 | import boundary | Ambient `sys.path`, `PYTHONPATH`, cwd shadow module, bytecode, and alternate module origin | None changes selected bytes; no ambient import succeeds | launcher portable |
| SRC-06 | source path walker | Symlink chain, absolute target, `..`, root escape, loop, >40 links, >256 components | `_resolve_once` rejects escapes/bounds and accepts only stable legal chains | runtime-closure portable |
| SRC-07 | source path walker | Ancestor/symlink/final component changes between `stat`, `open`, `fstat`, second resolution | Exact generation/transcript mismatch; all opened directories/finals closed once | runtime-closure portable |
| SRC-08 | static/runtime sentinel | Any `PATH` search, `realpath`, `Path.resolve`, caller path, environment path, or pathname reopen after authentication | Sentinel operation is unreachable in bootstrap/closure/launcher authority path | runtime-closure + launcher portable |
| AUTH-01 | `_authenticate` | Success and owner/mode/type/size boundaries | Exact bytes/ELF/generation returned; all source policy fields checked before and after read | runtime-closure portable |
| AUTH-02 | `_authenticate` | Short read and replacement before, during each chunk, after complete read, and on second resolution | Exact phase rejects; held fd and component fds close once | runtime-closure portable |
| AUTH-03 | `_resolve_library` | Same authenticated identity through two roots | Accepted once and duplicate held fd closed; not classified ambiguous | runtime-closure portable |
| AUTH-04 | `_resolve_library` | Same bytes/digest but distinct `(dev,inode)` providers | Reject ambiguous even when fingerprints match | runtime-closure portable |
| AUTH-05 | `_resolve_tool` | Missing loader/library, SONAME mismatch, role alias, duplicate provider, unresolved dependency, library with interpreter | Exact semantic code and reverse cleanup | runtime-closure portable |
| AUTH-06 | `_resolve_tool` | 128 accepted / 129 rejected objects; per-tool bytes at/beyond bound | Boundary values execute production loop, not patched completed closures | runtime-closure portable |
| AUTH-07 | `_prepare` aggregate | Three-tool deduplicated closure at 512 MiB and one byte over; same identity across tools; duplicate role identity across tools | Correct dedup sum; prohibited cross-tool role identity rejects explicitly | runtime-closure/recovery portable |
| AUTH-08 | `_Ops.list_fds`, `_prove_ready_baseline` | Enumeration fd occupies a transient low number; output fd reuse changes next enumeration number | Explicit directory fd is excluded; exact real algorithm reaches the modeled ready baseline | lifecycle portable |
| AUTH-09 | baseline methods | EMFILE/open/read/close/oversize at fd and child baseline capture | No transition to `PREPARING`/`READY`; primary plus cleanup retained | lifecycle/recovery portable |

### 4.2 ELF parser and mapped closure

The prior `test/aws-stage2-completion-runtime-closure.py` is adjacent evidence only. Its parser matrix must be ported or parameterized so every case calls `completion_elf.parse_elf64`.

| ID | Production method | Matrix | Required oracle | Test owner |
| --- | --- | --- | --- | --- |
| ELF-01 | `parse_elf64` | Every ELF identity/profile byte, header/table truncation and U64 overflow, program/section cardinality and overlap | Exact `ElfParseError`; no old-parser-only credit | runtime-closure portable |
| ELF-02 | `_parse_elf64` LOAD handling and `mapped()` | `p_align` 0/1, non-page congruence, page alias, rounded overlap, reversed segments, BSS/file-memory edge, remap ordering | Match the accepted fixed Linux x86-64 page profile; ambiguous loader-visible mapping rejects | runtime-closure portable |
| ELF-03 | dynamic parser | Duplicate singleton tags, duplicate `DT_NEEDED`, missing/multiple dynamic or interpreter, unknown/forbidden tags, `DT_FLAGS`/`DT_FLAGS_1` masks | Exact parser rejection/acceptance by declared profile | runtime-closure portable |
| ELF-04 | string parser | Missing/overflowed table, unterminated/empty/overlong/invalid names, slash/backslash/control/token names, duplicate/missing SONAME | Exact parser rejection | runtime-closure portable |
| MAP-01 | `_read_proc`, `_maps_snapshot` | Complete EOF, exact 4 MiB and 4,096-line boundaries, over-bound, missing LF, malformed rows/permissions/extents/UTF-8 | Bound and framing errors are distinct; fd closes once | mapped-closure portable |
| MAP-02 | `_mapped_closure` | Stable before/after and exact resolved set | Exact ordered `[role,sha256]` mapping digest | mapped-closure portable |
| MAP-03 | `_mapped_closure` | Changed maps, unknown synthetic/nonzero mapping, unopenable mapping, generation drift | Intended code plus all map/proc fds closed | mapped-closure portable |
| MAP-04 | `_mapped_closure` | Same fingerprint associated with two expected roles/identities | Reject ambiguity; never select by digest alone | mapped-closure portable |
| MAP-05 | `_mapped_closure` | Missing executable/loader/dependency and unknown expansion | Exact resolved/mapped equality rejection | mapped-closure portable |
| MAP-06 | `_mapped_closure` | 128/129 unique mapped objects and aggregate mapped-byte boundaries | Production cardinality/byte gate reached | mapped-closure portable |
| MAP-07 | `_read_proc` and per-map `finally` | Primary parse/read error plus close error; close-only error | `RuntimeClosureCleanupError(primary, close...)`, never replacement by close | mapped-closure portable |
| MAP-08 | helper child fd setup | Ambient inheritable/non-inheritable fds and every closed-stdio permutation | Reserve 0–2 first; child exact allowlist only; source fd cannot be clobbered | lifecycle portable |

### 4.3 Tracked schema, AJV, independent codec, and actual mutations

There must be three distinguishable oracles:

1. **AJV 2020 tracked-schema oracle:** `schemas/trusted-runtime-closure-v1.json` compiled by the repository's pinned AJV path and applied to the exact golden value and every structural mutant.
2. **Production tracked-schema gate:** an in-process, fixed, authenticated-schema validation path used by `_prepare`; it must not invoke Node, search `PATH`, or accept a caller schema. Its implementation requires replacement-ADR authority.
3. **Independent semantic codec:** strict UTF-8/JSON/canonical framing plus report semantics and digest recomputation, implemented independently of the schema gate. The launcher consumer is separately challenged against the same corpus.

Calling `_validate_report_bytes` twice is one oracle, not two. Merely inspecting schema source fields is not schema validation.

#### Mutation construction rules

- `recompute_all(hostile)` recomputes each objects digest, mapping digest, and top-level digest after a non-digest mutation.
- A digest-target mutation recomputes all other digests and changes only its target digest.
- Raw encoding mutants are created from otherwise valid canonical bytes and are not passed through a parser that normalizes them first.
- Each row declares `AJV: accept/reject/not-applicable`, `producer codec: accept/reject(code)`, and `launcher codec: accept/reject(code)`; the test checks all declared outcomes.
- Removing the intended production check must make that row fail even if another check remains. Stable error codes or typed failures are therefore required.

| Mutation group | Required cases | AJV expectation | Independent codec expectation |
| --- | --- | --- | --- |
| Golden/determinism | Golden; reversed input object-key enumeration; reversed library-root enumeration; two fresh encoders | accept | accept and emit byte-identical golden once, with one LF |
| Digest-only | top closure, each tool closure, each mapping digest | accept (format remains valid) | reject exact digest code |
| Tool semantics | tool reorder; wrong tool literal; Python/gzip/zstd seal profile and boolean independently changed | reject where prefix/const applies | reject exact order/seal code after dependent digest recompute |
| Object order/roles | loader/executable swap; library before loader; duplicate/missing role; library order; equal order key | schema may accept positional defects | reject exact role/order code after recompute |
| Dependencies/providers | duplicate needed; missing provider; duplicate provider; provider on wrong role; order change; >128 | reject duplicate/cardinality/name shapes; accept shape-valid missing provider | semantic codec independently rejects intended rule after recompute |
| Object identity | duplicate `(role,sha256)`; duplicate `(sha256,size)` policy case; cross-tool duplicate-role identity | schema accepts shape-valid forms | reject according to accepted identity rule |
| Names | slash, backslash, whitespace, control, `$ORIGIN`, empty, 256-byte SONAME/needed, invalid UTF-8 | reject represented invalid strings/patterns | independently reject exact name code |
| Numbers/types | size 0/max+1, bool-as-integer, float, NaN/Infinity, wrong list/object/null/string types | reject | strict parser/codec rejects independently |
| Shape/disclosure | every missing required key; unknown key at every object depth; path, environment, address, maps row, command output, PID/account/device/inode/time/run/archive/cleanup claim | reject | reject exact shape code |
| Encoding | duplicate key at each depth; leading/trailing whitespace; pretty JSON; missing/extra LF; invalid UTF-8; oversized; trailing bytes | not applicable to value-only AJV; strict fixture parser records rejection | producer and launcher reject exact framing/JSON/canonical code |
| Schema/codec divergence sentinels | `"bad name"`, overlong needed, positional role defect, shape-valid unresolved dependency | tracked expectations as above | no producer/schema/consumer divergence is accepted |

`test/outcome-two-runtime-report-portable.py` must not use stale digests to claim semantic coverage. `scripts/validate-schemas.ts` must validate the canonical golden and the structural mutation corpus with AJV, not an unrelated digest-placeholder sample alone. Structural validity is not semantic validity: AJV acceptance of a shape-valid bad digest or missing provider is expected and must not be reported as schema failure.

### 4.4 Executable/report sealing and settlement cuts

| ID | Production method/cut | Required cases | Required oracle | Test owner |
| --- | --- | --- | --- | --- |
| SEAL-X-01 | `_seal_source` | Existing success and every declared source-seal fault | Preserve direct held-source use and exact executable seals | sealing portable |
| SEAL-X-02 | `_seal_source` close after effect | Destination close reports failure after the descriptor is actually released and number is reused | Mark uncertain; do not close that number again; unrelated replacement remains open | sealing/lifecycle portable |
| SEAL-R-01 | `_seal_report` | memfd, every partial/zero/error write, chmod, fsync, readback short/error/mismatch | Reject exact stage; close each certainly owned descriptor once | sealing portable |
| SEAL-R-02 | `_seal_report` | `F_ADD_SEALS`, each missing required data seal, `F_GET_SEALS` error | Exact data profile or fail | sealing portable |
| SEAL-R-03 | `_seal_report` | read-only `/proc/self/fd` reopen EMFILE, wrong identity, wrong access mode, wrong seals | Reject and restore descriptor baseline | sealing portable |
| SEAL-R-04 | `_seal_report` writable close | close-before-effect, close-after-effect, fd number reuse | Never retry an uncertain writable fd; preserve read fd only on proved transfer | sealing/lifecycle portable |
| REPORT-01 | `_prepare` publication | candidate mutation, schema-gate reject, codec reject, first/second encoding mismatch | No report fd or `READY`; exact cleanup | report/recovery portable |
| HAND-01 | `settle_fixed_handoff` | checkpoint before revalidate; gzip/zstd/report `F_GET_SEALS` error and missing bits | Owner remains `READY` with all outputs, then closes exactly | recovery portable |
| HAND-02 | settlement report read | short, extra, changed bytes, read error | No transfer; owner remains authoritative | recovery portable |
| HAND-03 | `_prove_ready_baseline` | fd/child mismatch and baseline read errors | No transfer; no false `HANDED_OFF` | recovery/lifecycle portable |
| HAND-04 | transfer | before-transfer cut and a cut before each ownership removal/state publish | Either all three remain owner-owned or all three are issued; no partial ownership | recovery portable |
| HAND-05 | one-shot | second settlement, settlement after close/poison, canonical report outside `READY` | Exact state error, no fd effect | recovery portable |
| HAND-06 | `close()` | `cleanup.before`, each close, baseline, and `cleanup.after` | `CLOSED` only after the last fallible step; after-error repeats the same poison, never success | recovery portable |

The current `cleanup.after` fixture oracle is forbidden: it publishes `CLOSED`, raises, then accepts a no-op close. The corrected oracle requires the final fallible checkpoint before publishing `CLOSED`, or requires `POISONED` with the identical repeated error.

### 4.5 Handoff forgery, descriptor substitution, and consumer binding

Generic regular-file shape and seals are not provenance. The replacement production design must combine one-shot issuer admission with byte binding.

| ID | Production method | Attack | Required oracle | Test owner |
| --- | --- | --- | --- | --- |
| ISSUE-01 | handoff constructor/consumer | Public dataclass construction with three plausible fds | Rejected as never issued before any exec | launcher portable |
| ISSUE-02 | handoff consumer | `SimpleNamespace`, subclass, copied fields, object reconstructed from a legitimate handoff | Rejected as never issued; Python type/module strings are not authority | launcher portable |
| ISSUE-03 | issuance consume | Legitimate object consumed twice or concurrently | Exactly one consumer wins; all later attempts reject without closing foreign/reused fds | launcher/recovery portable |
| FD-01 | post-issuance revalidation | Close/reuse gzip, zstd, or report fd with same number | Issued generation mismatch; no execution; owner/launcher closes only proved-owned descriptors | launcher portable |
| FD-02 | descriptor-role binding | Swap gzip/zstd, duplicate one fd, use report as executable, or executable as report | Distinct-role and report binding reject | launcher portable |
| FD-03 | executable/report binding | Correct seals but changed size/hash/ELF bytes; fixed-output attacker executable; self-consistent forged report | Issuance rejects forged report; consumer complete-read hash/size/role comparison rejects substitution before exec | launcher portable |
| FD-04 | generation during inspection | Descriptor metadata or bytes drift during bounded read | Reject exact generation change | launcher portable |
| FD-05 | report binding | Valid report unrelated to issued executable generations | Reject before fixed-fd duplication or child creation | launcher portable |
| FD-06 | close uncertainty | Consumer close succeeds-but-reports-error and number is reused | Do not retry; terminal cleanup uncertainty; replacement remains open | launcher/lifecycle portable |

An issuer registry or hidden token is only meaningful against callers that have not already compromised admitted T1 code. The design must not claim resistance to malicious code already executing inside the trusted Python process. Source admission is what excludes that code. If a robust one-shot issuance binding cannot be implemented while retaining ADR 0087's three-field public dataclass, the replacement ADR must change the API rather than call the type unforgeable.

### 4.6 Real production lifecycle adapter and crash recovery

The corrected lifecycle suites must enter production orchestration and fault only syscall/process operations. They may not fabricate `_ToolOutcome`, `MappedToolClosure`, `SealedExecutable`, or an all-true sandbox result at the boundary being claimed.

| ID | Production method/cut | Required matrix | Required oracle | Test owner |
| --- | --- | --- | --- | --- |
| LIFE-01 | `_spawn_helper` | every pipe/open/fork/pidfd/status/proc/identity operation; partial initialization after each acquired resource | Child authority registered before release; every certain fd closes; child state independently reaped | lifecycle portable |
| LIFE-02 | child setup | PDEATHSIG failure, parent change before/after release, `setsid`, dup, status write, exec failure, ambient fd, closed stdio | Fixed failure record, exact allowlist, no unbounded wait | lifecycle portable |
| LIFE-03 | `_matching_child` | start time/SID/PGID/executable/descendant mismatch and each observation error/close error | No signal on mismatch; terminal uncertainty where absence cannot be proved | lifecycle portable |
| LIFE-04 | `_stop_helper` | TERM error/timeout, identity change before KILL, KILL error/timeout, wait/reap error | KILL only after repeated full identity match; pidfd retained until reap or recovery transfer | lifecycle portable |
| LIFE-05 | `_prepare` failure owner | `_stop_helper` failure with child still live independent of pidfd registry | Second independently safe recovery attempt or transfer to outer owner; no return claiming no child | lifecycle/recovery portable |
| LIFE-06 | `_run_fixed_tool` | pipe/fork/dup/close-range/exec/status/input/output/select and output-bound faults | Production method executes each branch; exact descriptor cleanup | launcher portable |
| LIFE-07 | `_run_fixed_tool` wait | child closes stdout/status then remains alive; wait identity drift; wait timeout; descendant appears | Deadline still applies after EOF; exact TERM/KILL/reap and no descendant | launcher portable |
| LIFE-08 | baseline ledger | unexpected fd, child, file, mount, namespace handle, limit change, checkout change | Result cannot be constructed; all independently safe reverse actions attempted | lifecycle/launcher portable |
| CRASH-01 | outer supervisor | preparation worker crashes at every state/preparation/publication/handoff cut | Supervisor, not worker, survives; anonymous fds close by death; exact registered children recovered/reaped | recovery portable |
| CRASH-02 | parent death | helper exists before/after registration and before/after release | PDEATHSIG is requested but not treated as reap proof; supervisor observes exact terminal state | recovery portable |
| CRASH-03 | identity uncertainty | start time/SID/PGID/executable mismatch, lost pidfd, unreadable identity, unknown descendant | Do not signal foreign identity; return terminal uncertainty, never “recovered” | recovery portable |
| CRASH-04 | fresh state | supervisor imports production module independently and receives only fixed protocol records/retained authority | No worker module-global set or retry supplies recovery facts | recovery portable |
| CRASH-05 | recovery cleanup | TERM/KILL/reap/close/protocol corruption/timeout plus primary crash | Aggregate exact failures; no success or new preparation masks them | recovery portable |

A valid crash test kills only the inner worker. `os._exit(73)` of the entire case followed by `fresh("success")` is deleted as a recovery oracle. A subsequent preparation may remain a separate module-state-independence test, but its name and claim must say exactly that.

### 4.7 Actual T2 adapter, sandbox facts, and no-overclaim results

| ID | Production method | Required case | Required oracle | Test owner |
| --- | --- | --- | --- | --- |
| T2-01 | `launch_fixed_runtime_qualification` | Success transcript | Source/issuance/report/fd validation all precede child creation; T2 precedes input release | launcher portable |
| T2-02 | fixed sandbox construction | every namespace/chroot/mount/group/capability/securebits/NNP/seccomp transition cut | Reverse exact owned resources; irreversible uncertainty prevents result | launcher portable |
| T2-03 | capability facts | effective/permitted/inheritable/bounding/ambient sets individually nonzero | Exact set rejects; no aggregate `capabilities_zero=true` from only three sets | launcher portable |
| T2-04 | namespace/mount facts | wrong/missing user, PID, mount, network namespace; PID not 1 where required; checkout writable/changed; mount foreign/replaced | Corresponding result false/reject; never hard-coded true | launcher portable |
| T2-05 | syscall facts | socket, io_uring, namespace creation, seccomp replacement each allowed/wrong errno/unobserved | Each named check must be observed; unobserved is not pass | launcher portable |
| T2-06 | architecture | non-Linux/non-x86-64 for every hard-coded syscall path | Fail before loading libc or invoking a syscall number | launcher portable |
| T2-07 | cleanup facts | fd range beyond 8192, child/descendant, path/mount/ns/checkout residue | Complete baseline comparison; booleans derive from observations only | launcher portable |

Portable T2 cases prove stage ordering and fail-closed logic. They do not prove that real Linux creates the boundary; that remains native Job E after the portable/review gate.

## 5. Dead and misleading fixture ledger

### 5.1 Selector-dead rows

| Fixture | Dead rows at `64c0557` | Cause | Required correction |
| --- | --- | --- | --- |
| `closure/cases.json` | `object-bound`, `byte-bound` | `cases[:10]` excludes both; `FsOps` implements neither fault token | Iterate all rows by ID; implement production-call builders for 129 objects and deduplicated three-tool aggregate bytes. |
| `maps/cases.json` | all ten `hostile` rows are selector-dead | The suite loads only `objects`; it never iterates `hostile` | Dispatch all ten rows and assert exact declared/executed equality. Existing handwritten analogues may be called by the dispatcher, not counted separately. |
| `lifecycle/faults.json` | all five `cleanup` rows are selector-dead | `MATRIX["cleanup"]` is never consumed | Dispatch every row to a production lifecycle/registry case and assert its exact cleanup transcript. |

Within the selector-dead maps rows, `ambiguous-fingerprint` and `mapping-object-bound` are also behavior-dead; the other eight have handwritten analogues but no fixture-truth binding. Within lifecycle cleanup, `unexpected-owned-child` and an intentional `double-close` production case are behavior-dead; primary-plus-close, fd reuse, and duplicate registration have handwritten analogues.

### 5.2 Executed names with dead or false intended predicates

| Fixture row | Problem | Required correction |
| --- | --- | --- |
| `closure/cases.json:same-inode-alias` | It hardcodes inode `103` without binding that value to the existing alpha provider and is expected to reject. It proves neither allowed aliasing nor distinct ambiguity. | Derive alias identity from the existing provider; require success and one logical provider. Keep `duplicate-library-candidate` distinct and rejecting. |
| `sealing/faults.json:destination-close` | `SealOps.fchmod()` raises for `destination-close`, so the later close-failure branch is unreachable. | Separate `fchmod` and `close-after-effect` tokens; record kernel state independently and assert no retry after reuse. |
| `recovery/cases.json:cleanup.after` | The fault occurs after `_state=CLOSED`; the test then accepts a successful no-op close. | Move the final fallible cut before `CLOSED`, or require poison/repeated identical failure. Never accept closed-after-error uncertainty. |
| report semantic rows `tool-order`, `object-order`, `duplicate-needed`, `missing-provider`, `seal-profile`, `sealed-executable` | Stale dependent digests can reject before the named semantic predicate. | Recompute all dependent digests, assert exact intended error, and run AJV plus producer and launcher codec expectations. |
| launcher `success_steps`/`fault_steps` | Rows execute only coarse scripted methods; `run_tool` returns a fabricated `_ToolOutcome` and sandbox success is prebuilt. | Retain high-level order checks only as orchestration tests; add syscall-level manifests that drive production `_run_fixed_tool`, issuance binding, and sandbox construction. Do not describe coarse rows as boundary qualification. |

### 5.3 Live fixture data that remains useful

- All ten ELF byte fixtures are read by at least one current direct parser/resolver path. They remain bounded data, but the hostile parser contract must be expanded beyond them.
- Stable and changed maps text files are read; the stable before/after blobs are intentionally byte-identical.
- The canonical JSONL golden is read by report and launcher tests; it becomes the common AJV/producer/consumer positive sample.
- All report mutation names and all recovery cut names are currently iterated. Their deficient predicates are corrected as above rather than called selector-dead.
- All source-sealing fault names are iterated, subject to the shadowed `destination-close` correction.
- Launcher step names are iterated, but only at the coarse orchestration level described above.

### 5.4 Fixture-truth format

Every JSON manifest must have a fixed version, unique case IDs, a closed allowlist of keys, production method, fault operation, expected code, and expected cleanup domains. Each suite records an `executed` multiset and ends with an equality check against the manifest IDs. Unknown additions, deletions, duplicate IDs, renamed tokens, unimplemented operations, and accidental extra executions fail the suite.

Binary ELF fixtures remain data-only and are bound by byte length plus SHA-256 in the test manifest or test constants. Tests must not regenerate them through host compilers or ELF tools.

## 6. File ownership after replacement-ADR authorization

| Existing surface | Correction responsibility | Current risk |
| --- | --- | --- |
| `test/outcome-two-runtime-closure-portable.py` | Full new parser contract; path/symlink/replacement transcript; alias/ambiguity; exact per-tool and aggregate bounds | Current 55-line headroom is insufficient for the required matrix. |
| `test/outcome-two-mapped-closure-portable.py` | Manifest-driven all-map rows; ambiguous/object bounds; proc/map primary-plus-close | Current 71-line headroom is not implementation authority for unplanned compression. |
| `test/outcome-two-sealing-portable.py` | Source and report seal matrices; real after-effect close uncertainty | Current 54-line headroom likely cannot hold the report matrix readably. |
| `test/outcome-two-lifecycle-portable.py` | Syscall-level helper/launcher lifecycle, real independent resource ledger, all cleanup fixture rows | Only 24 lines remain; revised high is mandatory. |
| `test/outcome-two-recovery-portable.py` | Production outer supervisor; worker-only crash; settlement/publication/state cuts; poison semantics | Only 41 lines remain; revised high is mandatory. |
| `test/outcome-two-runtime-report-portable.py` | Actual recomputed mutants; production schema gate and codec oracles; common corpus | AJV itself belongs in TypeScript; Python remains codec/fresh-encoder owner. |
| `test/outcome-two-trusted-launcher-portable.py` | Bootstrap admission, issuance/forgery/substitution, syscall-level tool lifecycle, T2 construction/facts | Coarse `_ScriptedLauncherAdapter` success is retained only for narrow orchestration. |
| `test/outcome-two-portable.test.ts` | Bounded suite wrapper plus AJV tracked-schema corpus validation | It must not synthesize production semantics or invoke native effects. |
| `scripts/validate-schemas.ts` | Register exact golden and structural mutation corpus under AJV | Current unrelated placeholder sample is insufficient. |
| `test/fixtures/outcome-two/**` | Manifest truth, report-seal/handoff/lifecycle/bootstrap cases, parser mutations | New files or changed aggregate authority require the replacement ADR. |

Do not move missing production behavior into tests, fixtures, schema, workflow YAML, or generated data to avoid production line highs.

## 7. Exact current accounting

ADR 0087 counts gross physical additions from `bec0a19...`; highs are per-surface and non-transferable. The exact `2023e65` implementation count is:

| Surface | Actual | High | Headroom |
| --- | ---: | ---: | ---: |
| `completion_elf.py` | 240 | 240 | 0 |
| `completion_trusted_runtime_closure.py` | 1,220 | 1,220 | 0 |
| `completion_trusted_runtime_launcher.py` | 599 | 600 | 1 |
| `trusted-runtime-closure-v1.json` | 122 | 230 | 108 |
| `validate-schemas.ts` Outcome 2 gross addition | 19 | 30 | 11 |
| runtime-closure portable | 195 | 250 | 55 |
| mapped-closure portable | 169 | 240 | 71 |
| sealing portable | 156 | 210 | 54 |
| lifecycle portable | 266 | 290 | 24 |
| recovery portable | 249 | 290 | 41 |
| runtime-report portable | 149 | 230 | 81 |
| trusted-launcher portable | 149 | 280 | 131 |
| TypeScript wrapper | 48 | 120 | 72 |
| fixture aggregate under accepted `wc -l`/LF convention | 231 | 500 | 269 |
| **Trusted/portable subtotal** | **3,812** | **4,730** | **918** |

Fixture reconciliation is exact:

- ordinary text fixtures contain 223 LF-terminated lines;
- the ELF files contain 8 LF bytes counted by `wc -l`;
- accepted fixture aggregate: `223 + 8 = 231`;
- Git text numstat reports 224 additions because the 7-byte `malformed-magic.elf` is treated as one non-LF text record;
- Git classifies the other nine ELF fixtures as binary; eight contain one LF byte and `truncated.elf` contains none.

Thus the review values `231`, `224 plus nine binary fixtures`, and `3,805 text additions` describe different counting views. The ADR's accepted physical/LF accounting result is **231 fixture lines and 3,812 subtotal**. The parser review's `241` fixture / `3,822` subtotal is not reproducible from the exact head under that convention and must not be used.

Future accounting must report both:

1. per-surface gross additions from `bec0a19...`, with binary fixtures explicitly disclosed; and
2. current physical/LF counts using the accepted fixture convention.

Deletion, rename, movement, generated content, compressed one-line control flow, and unused headroom provide no credit. No projected correction total is asserted here because no authorized correction diff exists. The replacement ADR must assign readable per-file and aggregate highs before any implementation; after implementation, exact counts replace estimates.

The accounting-predecessor `git diff --check` also remains red because of retained trailing whitespace in `.pi/outcome-two/capability-rereview-{driver,schema}.md`. That is a separately disclosed P3 accounting check issue; it is not silently attributed to closure production or fixed by altering accepted review meaning.

## 8. Required execution order and gates

1. Adopt a replacement ADR authorizing readable highs and any changed/bootstrap/supervisor/issuance surfaces or API.
2. Implement pre-effect source admission and make direct unauthenticated preparation inert.
3. Implement issuer-bound, byte-bound handoff consumption and exact fd uncertainty rules.
4. Implement tracked-schema production validation, AJV corpus validation, and independent producer/consumer codecs.
5. Correct helper and launcher lifecycle owners plus the real outer crash supervisor.
6. Implement actual T2 construction; remove hard-coded success facts.
7. Convert every fixture manifest to exact dispatch and close all dead/wrong rows.
8. Run the portable suites only after the production methods exist; record exact per-case method/error/cleanup coverage.
9. Run locked schema, type, lint, format, test, accounting, and diff checks. A pre-existing unrelated failure is disclosed, not converted into pass.
10. Obtain a new exact-head hostile review with no unresolved P0–P3.
11. Only then begin independent native Jobs A–E. Portable tests do not fill native evidence, and native jobs do not fill this matrix.

## 9. Completion and claim language

The portable correction is complete only when:

- every matrix ID has a production method, adapter operation, fixture ID, intended error/success code, and cleanup-domain assertion;
- every declared fixture row executes exactly as declared and no behavior-dead row remains;
- the exact golden and actual recomputed mutants are checked by AJV, the production tracked-schema gate, the producer codec, and the launcher codec as applicable;
- report sealing and handoff cuts prove atomic ownership and no retry after uncertain close;
- direct source bootstrap bypass, forged handoffs, role swaps, and fd close/reuse substitutions fail before execution;
- helper and launcher process faults drive real production state machines, with child truth independent of fd registries;
- crash cases recover the crashed worker through the production outer supervisor, or return explicit terminal uncertainty;
- sandbox result fields derive from observed production transitions and baselines rather than fabricated booleans;
- exact current and gross accounting is within newly accepted per-file and aggregate highs; and
- a new hostile review signs off the exact head.

Permitted claim after a green portable gate:

> The exact production parser, report validators, and scripted syscall-level ownership state machines reject the enumerated bounded portable faults and restore the modeled baselines.

Forbidden claims until applicable native and integration evidence exists:

- exact host source provenance was established;
- Linux `map_files`, memfd executable seals, pidfd/PDEATHSIG, namespace, mount, capability, seccomp, or `close_range` behavior was qualified;
- a real T2 sandbox was cleaned;
- Jobs A–E or thin integration passed;
- Outcome 2, AWS, provider, OpenTofu, deployment, production, release, or issue closure is authorized.

This is a stop-and-correct matrix, not sign-off.
