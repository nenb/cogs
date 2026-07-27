# ADR 0088: Correct the first trusted-closure implementation review before native qualification

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Architecture predecessor: ADR 0087.
- Exact implementation reviewed: `64c055762e260b8fc2eed96741bdb30c89183f3c`.
- Exact five-report review head: `2023e650e88767e0bd7574f0c302e780743eab5a`.
- Accounting predecessor remains: `bec0a19b0b984f88ab9c2effc5059f3737915caa`.
- Supersedes: ADR 0087 only where this ADR changes trusted bootstrap admission, handoff issuance/consumption, final execution-generation binding, T2 construction and unavailable semantics, recovery/lifecycle details, hostile portable obligations, and numeric highs. ADR 0087's fixed tool table, report disclosure boundary, capability-probe separation, native A–E split, thin-integration order, cloud boundaries, and all non-conflicting rules remain accepted.

## Context

ADR 0087 replaced post-drop host discovery with tracked trusted preparation before capability removal. The first implementation added a pure ELF parser, descriptor-relative host resolution, fresh helper mapping checks, descriptor-direct gzip/zstd sealing, a canonical report and schema, a one-shot owner, a launcher, and seven portable suites.

Five independent hostile reviews were committed at the exact review head:

- `.pi/outcome-two/closure-review-parser-auth.md`;
- `.pi/outcome-two/closure-review-mapping-cleanup.md`;
- `.pi/outcome-two/closure-review-launcher-schema.md`;
- `.pi/outcome-two/closure-review-portable-tests.md`; and
- `.pi/outcome-two/closure-review-holistic.md`.

All five reviewed the same exact implementation head. No production implementation changed between that head and the report head. The reviews agree that useful unit-level mechanisms exist but the accepted T0/T1/T2 composition does not. In particular:

- parser and closure code import and acquire authority before source admission;
- a caller can construct or substitute a handoff and make the launcher execute bytes unrelated to the report;
- the later dynamic-loader and library mappings are not bound to the generations authenticated during preparation;
- the launcher executes in the ambient host and the sandbox probe reports facts it did not construct or prove;
- no outer owner recovers a crashed authority-bearing worker;
- real descriptor enumeration prevents the owner reaching `READY` on Linux;
- helper and launcher cleanup do not own exact descendants or bounded reaping;
- report production repeats one codec instead of independently applying the tracked schema;
- close uncertainty can retry a reused descriptor number;
- ELF load-segment reasoning is byte-span rather than Linux-page granular; and
- portable adapters replace several security mechanisms with preassembled success instead of driving production operations.

Native Jobs A–E cannot repair these defects. Running them now would qualify the wrong production boundary or move missing security behavior into test/workflow code. The correction must remain on the existing three production modules, schema/registration, seven portable suites, wrapper, and fixture tree before any native implementation or execution.

## Decision

### 1. Gate and scope

The exact reviewed implementation is **not ready** for handoff, native Jobs A–E, or thin integration. All controlling P0–P3 dispositions below are mandatory. A fresh exact-head hostile review must report no unresolved P0–P3 finding before native implementation may begin.

This ADR authorizes only later source corrections on the exact existing trusted/portable surfaces and the revised gross-line highs below. It adds no fourth production module, dependency, generated security program, workflow behavior, native surface, command-line policy input, fallback, or authority selector. Test seams remain private and unreachable from every production entry.

### 2. Exact P0 fixes

#### P0-1 — Admit the complete loaded T1 implementation before import or effect

The current post-preparation check is removed as security authority. The accepted order is:

1. T0 admits the exact launcher bootstrap bytes before Python executes them. Self-authentication is not claimed; the trust root is the separately reviewed exact-head envelope.
2. The bootstrap starts fixed `/usr/bin/python3 -I -B` with an empty fixed environment, reserved stdin/stdout/stderr, no bytecode, no ambient `sys.path`, and no caller-selected path, revision, module, argument, or environment value.
3. Before importing or executing parser/closure code, the bootstrap descriptor-relatively opens and authenticates the fixed import root and the exact launcher, parser, closure, and tracked-schema blobs against one exact reviewed commit. It retains the authenticated generations while loading.
4. Parser and closure modules are compiled/executed from the bytes completely read from those held authenticated descriptors. A later pathname read, `Path.resolve()`, `realpath()`, ambient import, restored file, or Git worktree lookup cannot stand in for the loaded generation.
5. Only that admitted worker may call the production closure constructor. A direct ambient import or missing/invalid bootstrap capability fails before host-object discovery, procfs access, helper creation, sealing, report construction, or sandbox work.

The fixed bootstrap and outer supervisor live in `completion_trusted_runtime_launcher.py`; authenticated parser/closure admission enforcement lives in the existing parser/closure modules. Native workflow YAML or a test driver may invoke the fixed route but may not implement or replace it.

#### P0-2 — Make handoff issuer-bound and bind executable descriptors to the report

`RuntimeClosureHandoff` is no longer authority merely because an object has three integer attributes or a tracked Python type name. Direct construction, copied attributes, object mutation, replay, and fd close/reuse substitution must fail.

The closure worker is a distinct issuer. Settlement creates a one-shot kernel-backed issuer endpoint and an issuance transcript over the exact report bytes, gzip/zstd sealed-object identities, complete bytes, sizes, SHA-256 values, seal profiles, private source generations, and the fixed closure-generation table. The launcher consumes descriptors atomically from that live issuer endpoint. A Python token, module name, private attribute, or process-local random value alone is not an unforgeable boundary.

Before any exec, and again after installation at the fixed descriptor numbers, the launcher must:

- completely read gzip, zstd, and report from the consumed descriptors under their bounds;
- require exact regular-file/mode/access/CLOEXEC and seal state;
- independently decode the report;
- compare each executable's complete size and SHA-256 to the matching report executable record and issuer transcript;
- compare the report bytes and digest to the issuer transcript; and
- prove that closing/reusing any original fd number cannot substitute the consumed kernel object.

Settlement and consumption form one ownership-preserving transaction. The issuer cannot settle twice, the launcher cannot consume twice, and failure or uncertainty consumes/closes all still-owned authority without making a handoff reusable.

#### P0-3 — Construct real T2 and bind the final mapped generations

The production launcher, not Job E, workflow YAML, or an external caller, owns the fixed T2 construction. It must build a private read-only root from direct copies of the still-held authenticated executable, loader, and library descriptors. Every copied object is completely read back and privately bound to its source generation and report digest before source authority closes.

The fixed child then enters the accepted user, PID, mount, and network namespaces; becomes PID 1 where required; enters the fixed chroot; receives only the exact fixed fd/data set; clears supplementary groups and effective, permitted, inheritable, bounding, and ambient capabilities; locks securebits `noroot`; sets `no_new_privs`; and installs the fixed seccomp policy denying socket acquisition, io_uring, namespace/mount changes, seccomp replacement, and every other forbidden acquisition route. No host checkout or host library tree is available in the qualification root.

After `execveat` has loaded gzip or zstd but before input release, the trusted outer owner captures complete stable mappings through trusted procfs, opens every executable mapping through `map_files`, and requires exact equality with the materialized generation table and report. This final check binds the actual interpreter and `DT_NEEDED` providers used by qualification, not merely an earlier helper run. Unknown, changed, host-reopened, expanded, or unopenable mappings are terminal.

There is no ambient-host execution fallback. On a non-Linux/non-x86-64 host, or when any required user-namespace, mount, chroot, PID-1, capability, securebits, NNP, seccomp, proc-owner, mapping, or cleanup primitive is unavailable, the launcher returns/raises a typed fail-closed unavailable outcome after proved cleanup. It emits no qualification success and no all-true placeholder fields.

`launch_fixed_sandbox_probe()` must construct and own this fixed boundary and report only measurements it actually made. It may not inspect the caller and infer construction, hard-code restoration booleans, inspect fds only through 8,192, or claim checkout, namespace, capability, mount, acquisition, descendant, or cleanup facts it did not prove.

### 3. Exact P1 fixes

#### P1-1 — Add the real outer recovery owner

The launcher is the fixed outer supervisor for one authority-bearing worker. Before the worker's next fallible effect, it transmits and the outer owner registers the exact pending descriptor, child, namespace, mount, and named-state authority. Anonymous descriptors close on worker death, but that fact alone is not recovery evidence.

Parent-death cuts must use a real worker and real child relationship. The outer owner retains pidfd/start-time/session/process-group/executable identities and exact namespace/mount authority, revalidates them, terminates and reaps the worker and every owned descendant under fixed deadlines, removes only exact owned state, restores all baselines, and returns terminal uncertainty when any recovery fact cannot be proved. A fresh unrelated successful preparation is a retry, not recovery.

#### P1-2 — Own exact child and descendant lifecycle

Every helper, tool child, namespace init, and descendant is registered immediately at creation, before status/exec/proc inspection. Startup failure may not use an unbounded raw-PID kill/wait route. Each owner uses pidfd plus PID start time, expected executable identity, owned session and process group, and an exact descendant baseline. It becomes a subreaper or uses the final PID namespace where needed to reap all descendants.

Before TERM and again before KILL, identity is revalidated. TERM, KILL, and reap have fixed monotonic deadlines, including after stdout/status EOF. A pidfd is not discarded while a child may remain live. Unexpected descendants are identified, terminated only through retained owned authority, and reaped; direct `waitpid` success is not descendant cleanup. Primary and all cleanup failures are preserved.

The fresh helper reserves fds 0–2 before acquiring sources and closes every inherited descriptor except its exact gate/status/executable allowlist with the fixed descriptor primitive. Ambient caller descriptors, closed-stdio permutations, and fd reuse cannot add authority.

#### P1-3 — Correct descriptor enumeration and complete-fd proof

Every production baseline opens `/proc/self/fd` explicitly, enumerates through that directory descriptor, excludes that exact enumeration fd, bounds names/count, and closes it with aggregated-error semantics. It never includes a transient pathname-`listdir` fd and never scans only a numeric prefix. Portable Linux production-adapter coverage must prove the real implementation can reach `READY`, compare `baseline | outputs`, and restore the baseline.

#### P1-4 — Treat close uncertainty as permanent uncertainty

After any close error, the descriptor number is retired as uncertain and is never closed again. In particular `_seal_report` may not close the writable fd and then pass the same number to generic cleanup. Before-effect and after-effect close faults, concurrent fd reuse, primary-plus-close failure, map/proc close failure, report reopen failure, and handoff/launcher close failure must all preserve the primary error and poison the owner.

`CLOSED` is published only after every fallible completion step succeeds. A `cleanup.after` cut cannot produce `CLOSED`, and repeated `close()` after uncertainty raises the same stored failure forever. A successful proved close alone makes later close a no-op.

#### P1-5 — Apply the tracked schema independently of semantic codecs

Production authenticates and applies `schemas/trusted-runtime-closure-v1.json` to the exact candidate bytes. That schema-validation implementation is independent of the producer semantic codec and the launcher consumer codec. Calling one decoder twice is forbidden.

The producer and consumer each reject duplicate keys, floats/constants, noncanonical UTF-8/framing, schema divergence, SONAME character/length violations, `needed` overflow, role/order/provider errors, digest errors, and prohibited metadata. Two separately decoded values are independently re-encoded and must be byte-identical to the candidate and each other. Portable tests compile the tracked schema against the exact golden and every structural mutant and recompute unaffected digests so each intended semantic branch is challenged independently.

#### P1-6 — Drive full hostile production adapters

Every security-sensitive production operation—bootstrap source admission, component walking, fd enumeration, report sealing/reopen, issuer transfer, descriptor hashing/binding, helper/tool lifecycle, close-range, namespace/mount/root construction, capabilities, securebits, NNP, seccomp, final maps, cleanup, and outer recovery—must be behind a private production adapter whose system implementation is used by the public route.

Portable suites script those primitive operations and before/after-effect cuts while driving the real production state machines. They may not replace `_run_fixed_tool`, sandbox construction, recovery, source authentication, or descriptor binding with preassembled success objects or booleans. The production adapter is fail-closed, inaccessible through public arguments, and performs no real privileged/native effect in portable tests.

### 4. Exact P2 fixes

1. **Page-granular ELF:** `completion_elf.py` models the fixed Linux x86-64 4,096-byte load-page profile. It requires page and `p_align` congruence, deterministic ordered `PT_LOAD` behavior, page-rounded file/memory extents, BSS boundaries, and unique file-backed resolution; it rejects `p_align=0/1`, page aliases, rounded overlap, reversed/remapped segments, ambiguous last-page bytes, and interpreter/dynamic metadata not wholly in one uniquely file-backed load. The complete prior hostile parser matrix is ported to `parse_elf64`, including new page-alias/rounded-overlap/BSS cases.
2. **Component and closure hostility:** drive symlink chains, absolute/relative targets, `..`, loops, root escape, ancestor/final replacement, stat/open/read/second-resolution drift, before/during/after short read, chmod/chown, no-`PATH`, no-`realpath`, same-identity aliases, distinct-provider ambiguity, global cross-tool role identity, per-tool bounds, and the deduplicated three-tool aggregate.
3. **Map/report/fixture truth:** execute every declared fixture exactly once or reject an unimplemented fixture at test startup. Cover ambiguous fingerprints, 129 unique mappings, exact map bounds, report-seal partial I/O/fsync/readback/seals/reopen/close, handoff revalidation/transfer cuts, and recomputed semantic/schema mutants. Slicing `hostile[:10]`, loading but not iterating manifests, and unused cleanup rows are forbidden.
4. **Cleanup error composition and residue:** proc/maps/map-files/source/report close paths preserve the active primary and aggregate every independently safe cleanup failure. Portable models derive, rather than prefill, restoration of descriptors, children/descendants, files, mounts, namespace handles, limits, private roots, and checkout/no-checkout state.
5. **Architecture gates:** every hard-coded Linux x86-64 syscall path rejects unsupported platform/architecture before invoking a number. Native jobs later gate the same exact architecture and primitive; portable success does not imply availability.
6. **Readable control flow:** undo cap-driven multi-operation lines and compressed exception branches. One physical line may not hide multiple fallible security effects or cleanup decisions. Gross highs give no license to move behavior into tests, schema, fixtures, or workflow YAML.
7. **Truthful result shape:** qualification and sandbox result fields are set only from observed checks. Unavailable, failed, unobserved, and cleanup-uncertain values remain distinct; none can be converted to `true`, `pass`, or absence.

### 5. Exact P3 disposition

The only standalone P3 was seven trailing-whitespace lines in retained capability rereview records, predating the closure implementation range. Those records are historical review evidence, not production, and their meaning will not be rewritten. This ADR explicitly dispositions that predecessor-wide `diff --check` noise: implementation acceptance requires a clean exact correction-range diff and no new whitespace defect, while the retained historical lines do not block closure correction. Any later whitespace-only normalization must be a separately disclosed evidence-preserving documentation change and supplies no line credit.

### 6. Corrected ownership sequence

The accepted production sequence is now:

```text
T0 exact launcher admission
  -> fixed isolated bootstrap and authenticated byte loading
  -> outer supervisor starts/registers issuer worker
  -> T1 resolve/authenticate/map/copy/report
  -> issuer-bound one-shot transfer
  -> launcher verifies report + executable bytes + private generations
  -> launcher materializes exact read-only root
  -> T2 namespaces/chroot/capabilities/NNP/seccomp
  -> exec blocked on fixed input
  -> trusted final mapped-generation equality
  -> release one gzip or zstd input
  -> exact descendant/mount/fd cleanup and baseline proof
  -> qualification result
```

No report or result is published before cleanup appropriate to that stage. The public three-descriptor data boundary remains the only authority visible to T2; private issuer and generation state remains in T1 and never enters report metadata. Source descriptors may remain in the issuer only until the launcher has directly materialized and authenticated the exact T2 root; they are then closed before input release. This narrow change supersedes ADR 0087's earlier assumption that three descriptors alone could preserve dynamic-loader generation authority.

### 7. Portable completion gate

Before native work, portable qualification must prove at least:

- pre-import bootstrap rejects wrong launcher/parser/closure/schema bytes, replaced loaded generations, ambient imports/environment, non-fixed Python, and missing bootstrap capability before any authority-bearing event;
- forged/replayed/copied handoffs, wrong issuer, fd close/reuse, descriptor/report mismatch, wrong role, changed seals, and transfer cuts fail before exec;
- exact root materialization and final maps bind every executable/loader/library byte and generation, and any host reopen or closure expansion fails;
- real production-adapter T2 construction sequences all namespace/root/capability/NNP/seccomp operations and reports unavailable without claims when any primitive is denied;
- outer recovery owns a real crashed worker and child, and terminal uncertainty is distinct from fresh retry;
- helper/tool/process-group/descendant creation, identity drift, EOF hang, TERM/KILL/reap, inherited fds, closed stdio, pidfd loss, and cleanup faults are bounded and residue-free or terminally uncertain;
- production fd enumeration excludes only its exact directory fd and reaches/restores `READY` under Linux behavior;
- every close site's before/after-effect and fd-reuse behavior is one-shot and poison-stable;
- tracked schema, producer semantics, and consumer semantics independently accept the golden and reject isolated hostile mutations; and
- the page-granular ELF and complete fixture matrices are live, exhaustive, deterministic, and optimization-safe.

Portable tests invoke no real sudo, namespace, mount, chroot, seccomp, `map_files`, compression tool, network, provider, cloud, or workflow. Native A–E later prove only real kernel/runner primitives after this gate is clean.

## Revised measured readable highs

All highs continue to count gross added physical lines from exact predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`. Deletion, rename, generated-file, binary, compression, and code-movement credit remain forbidden. Blank/comment lines count. Highs are non-transferable and require ordinary readable formatting.

### Trusted closure, launcher, schema, and portable qualification

| Exact file/surface | Hard high |
| --- | ---: |
| `deploy/aws-feasibility/remote/completion_elf.py` | 320 |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py` | 1,700 |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py` | 1,300 |
| `schemas/trusted-runtime-closure-v1.json` | 260 |
| `scripts/validate-schemas.ts` Outcome 2 registration only | 30 |
| `test/outcome-two-runtime-closure-portable.py` | 350 |
| `test/outcome-two-mapped-closure-portable.py` | 300 |
| `test/outcome-two-sealing-portable.py` | 300 |
| `test/outcome-two-lifecycle-portable.py` | 400 |
| `test/outcome-two-recovery-portable.py` | 400 |
| `test/outcome-two-runtime-report-portable.py` | 300 |
| `test/outcome-two-trusted-launcher-portable.py` | 500 |
| `test/outcome-two-portable.test.ts` | 150 |
| `test/fixtures/outcome-two/**` aggregate | 700 |
| **Trusted/portable subtotal and hard high** | **7,010** |

### Native qualification and integration — unchanged

| Exact file | Hard high |
| --- | ---: |
| `.github/workflows/ci.yml` gross Outcome 2 addition | 180 |
| `schemas/native-qualification-report-v1alpha1.json` | 150 |
| `scripts/native-qualification/common.py` | 220 |
| `scripts/native-qualification/job-a-runtime-mappings.py` | 160 |
| `scripts/native-qualification/job-b-compression.py` | 180 |
| `scripts/native-qualification/job-c-descriptors.py` | 140 |
| `scripts/native-qualification/job-d-process-lifecycle.py` | 180 |
| `scripts/native-qualification/job-e-sandbox.py` | 240 |
| `scripts/native-qualification/thin-integration.py` | 170 |
| `test/native-qualification-common.test.ts` | 120 |
| `test/native-qualification-a.test.ts` | 70 |
| `test/native-qualification-b.test.ts` | 70 |
| `test/native-qualification-c.test.ts` | 60 |
| `test/native-qualification-d.test.ts` | 70 |
| `test/native-qualification-e.test.ts` | 100 |
| `test/native-qualification-integration.test.ts` | 90 |
| **Native subtotal and hard high** | **2,200** |

The listed trusted/portable and unchanged native highs total **9,210**. The Outcome 2 production, portable, native, and integration aggregate hard high is **9,300 gross physical lines**. The remaining **90-line aggregate margin** is not transferable to a listed file and authorizes no unlisted file. The separate non-authoritative capability-probe high remains **2,830** and supplies no credit to this work.

Stop and adopt a new ADR before crossing any file, subtree, subtotal, or aggregate high; adding a production/portable/native surface or dependency; changing the fixed tool/report disclosure contract; weakening fail-closed behavior; or moving security behavior into workflow YAML, generated data, fixtures, or tests.

## Integration order and authority

1. Correct only the existing trusted/portable surfaces under this ADR.
2. Obtain fresh independent bootstrap/trust-boundary, issuer/descriptor, lifecycle/recovery, parser/schema/determinism, sandbox, and holistic exact-head reviews.
3. Resolve every P0–P3 finding before native implementation.
4. Only under later separate execution authority, implement and qualify native Jobs A–E in parallel.
5. Only after same-head A–E success, run thin integration on a sixth fresh runner.

This ADR and its documentation commit grant **no authority for any run**: no test command, production invocation, capability observation, native job, workflow, sudo, namespace, mount, KVM, provider, cloud, AWS, deployment, or integration execution. No production or test implementation is changed by this ADR. Every existing AWS, cloud, provider, OpenTofu, deployment, campaign, production, release, and issue-closure stop remains in force.

## Consequences

The first implementation remains useful research rather than trusted handoff authority. The correction makes the trust admission precede imports, makes descriptor authority issuer-bound and byte-bound, carries authenticated generations through actual execution, and assigns T2 and recovery to production owners instead of tests or workflow code.

The larger highs reflect measured review findings and readable ownership, not a relaxation of scope. Unsupported T2 is an explicit fail-closed unavailable state, never a weaker sandbox or a successful qualification claim. Native evidence remains blocked until the corrected production path and its complete hostile adapters receive clean exact-head review.
