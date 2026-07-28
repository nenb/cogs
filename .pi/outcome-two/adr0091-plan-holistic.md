# ADR 0091 holistic correction plan — exact production ownership before native qualification

- **Status:** planning record only; not an accepted ADR and not implementation or execution authority
- **Plan synthesis head:** `4eb9da3d2c98dd4a59e1e59817d34643bfba0d46`
- **Implementation reviewed by the five final reports:** `ea6e74fe709e02061e13be78922da13a8cf6f748`
- **Gross-line accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Inputs:** ADRs 0087, 0088, 0089, and 0090; `native-final-review-common.md`, `native-final-review-ab.md`, `native-final-review-cd.md`, `native-final-review-ei.md`, and `native-final-review-holistic.md`
- **Current disposition:** **BLOCKED**

This document synthesizes the five final reviews into one measured correction plan. It changes no production, test, workflow, schema, native, provider, or cloud implementation. No test, native selector, workflow, sudo, namespace, mount, seccomp, `map_files`, compression qualification, provider, cloud, or AWS operation was run while producing it.

## 1. Controlling outcome and boundaries

A future ADR 0091 may authorize only the closed source correction and portable/static verification described here. It must retain these boundaries:

1. **No native execution from ADR 0091.** `--workflow-bound`, Jobs A–E, thin integration, workflow dispatch/rerun, sudo, real namespace/mount/seccomp/`map_files`, and real compression qualification remain forbidden.
2. **Fresh clean reviews precede any native authority.** After correction and ordinary non-native portable/static gates, five fresh exact-head reviews—common/workflow/schema, A/B, C/D, E/integration, and holistic—must each have no unresolved P0, P1, P2, or P3 finding.
3. **A later accepted execution ADR is mandatory.** Even five clean reviews do not themselves authorize a native run. A later decision must name the exact clean head, workflow blob, source blobs, run/event eligibility, attempt 1, and stop conditions.
4. **AWS remains a separate mandatory boundary.** Neither this plan, ADR 0091, a portable pass, clean reviews, nor a later native result grants AWS, provider, OpenTofu, deployment, campaign, production, release, or issue-closure authority. Any AWS action requires its own later accepted decision under the existing AWS controls.
5. **No new implementation surface.** Correction is confined to the exact files in section 8. No dependency, action, service, generated security program, selector, fallback, retry, native job, or report disclosure outside the amended closed schema is allowed.
6. **No cap evasion.** Security behavior stays in production owners, not YAML, generated data, fixtures, or token-only tests. Gross physical lines are counted from `bec0a19`; deletion, rename, binary, compression, or movement supplies no transferable credit.

## 2. Conflict resolutions

The reports agree on the blockers but sometimes prescribe apparently different API or ownership shapes. ADR 0091 should resolve them as follows.

### 2.1 Keep private source admission; do not restore a forgeable ambient public API

ADR 0087 originally named ambient public closure/launcher functions. ADRs 0088–0090 superseded that handoff where direct Python construction or import could forge authority. The correction must **not** make an ambient import authoritative again.

“Call the production owner” means entering the real closure/launcher state machine inside the exact held-byte, issuer-bound bootstrap. It does not mean exposing private methods or accepting a duck-typed handoff. The admitted synthetic package has fixed internal operations for:

- `A`: production Python closure and mapping observation;
- `B`: production gzip/zstd closure, sealing, execution, and fixed output observation;
- `C`: the exact production fd enumerator and `close_range` primitive;
- `D`: the exact production process owner;
- `E`: a sandbox-only production probe; and
- `integration`: the complete ordinary fixed runtime qualification.

The operation is bound to the exact admitted driver identity and a closed result version before effects. There is no general caller-selected mechanism, path, policy, argv, fd, or command. Direct private calls, ambient imports, copied claims, operation/result substitution, and replay fail before effects.

### 2.2 Fixed internal operations are not substitute coordinators

The current mapping coordinator manually composes closure-private calls, while C/D duplicate mechanisms. Both forms are removed.

- A is a terminal observation emitted by the actual `PreparedRuntimeClosure` state machine after its real fixed-Python resolution/helper/maps/cleanup transitions. It does not add an outer user or mount namespace.
- C reaches the same production bounded `getdents64` enumerator and `close_range` operation used by closure cleanup.
- D reaches the same launcher process-owner registry, pidfd identity, descendant census, TERM/KILL, and reap state machine used by production.
- E reaches a sandbox-only launcher transaction that performs no ELF parsing, closure discovery, gzip, or zstd work.
- Integration reaches the ordinary complete runtime transaction and owns no bootstrap, pipe, unshare, root, mount, or process implementation.

A fixed profile may narrow which production transaction is observed; it may not reimplement that transaction.

### 2.3 Preserve source admission across sudo without executing checkout pathnames

The current E path executes runner-writable checkout pathnames as root and then rejects the runner-owned checkout. The corrected route admits and retains exact launcher bytes before sudo. The fixed noninteractive sudo command starts only `/usr/bin/python3 -I -B` with an empty environment and feeds a closed, bounded, exact held-byte root capsule; root opens or executes no checkout pathname and receives no checkout descriptor as trust authority.

The root capsule is a transport for already admitted bytes, not a caller-generated policy. Its manifest, framing, cardinality, profile, and byte digests are fixed and independently checked before the first root effect. E can select only the sandbox probe. Root never changes checkout ownership, treats runner ownership as root provenance, or makes the checkout visible to T2.

The unprivileged A/B/integration routes likewise execute held admitted launcher bytes rather than reopening a launcher pathname after the outer source read.

### 2.4 One common baseline owner, one report custodian

Common code, not six drivers, captures the common pre-effect baseline and derives all seven cleanup values. It uses the exact bounded production `getdents64` enumeration pattern, exact direct-child/owned-descendant observations, mount and namespace identities, limits, checkout state, `/tmp/cogs-o2-runtime-v1`, and the real per-job report directory.

Report publication uses a preregistered surviving custodian before the first named effect. The custodian retains parent-directory, private-directory, staged-file, and published-file generation authority across upload. A worker/driver crash is recovered by that surviving owner. Cleanup after either upload success or failure asks that same owner to compare each retained descriptor generation with its current name immediately before unlink. A mismatch, replacement, lost custodian, or close uncertainty preserves foreign state and fails; it never deletes to manufacture a restored-looking baseline.

The report publication lease is separate from the already-restored native/common baseline. It is retired only after upload and exact post-upload cleanup.

### 2.5 Planned identity transitions are registered, not mistaken for drift

D preregisters immutable identity (pidfd, PID/start time, executable) plus the expected `setsid` transition before release. It does not require pre-`setsid` session/group values to equal post-`setsid` values. The child reaches a second gate after the transition; the owner verifies exact `(session, process_group) == (pid, pid)` before case effects.

A leader transfers each still-blocked descendant's creator-held pidfd with one exact `SCM_RIGHTS` and credentials record plus complete identity. The outer owner validates packet/cardinality/credentials/identity, registers authority, and only then acknowledges release. Reopening pidfds from raw PIDs is not transfer. Stable recursive census, adoption, spawn-after, identity drift, lost authority, TERM/KILL, siginfo, and reap are all owned by the production process state machine.

### 2.6 Native metadata is truthful and independently recomputable

- B publishes the observed six-bit mask `63`, not `15`.
- Both gzip and zstd output digests must equal `6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8`, the SHA-256 of `b"cogs-runtime-qualification-v1\n"`; equality to each other is insufficient.
- A object size is `1..134217728`; executable then loader then sorted libraries are exact; `needed` is ordered and unique; every needed SONAME has one provider.
- A includes a closed, bounded metadata-only mapped role/digest sequence so common can recompute `mapping_sha256`; it recomputes per-tool closure and top-level closure summaries from artifact rows. No path, address, PID, fd, map line, device/inode, or source generation is disclosed.
- Schema, common semantics, and producer checks remain independent.

## 3. Corrected architecture and ownership sequence

```text
workflow exact-head gate (non-native)
  -> fixed admitted driver + common bytes
  -> common captures one exact common baseline
  -> held-byte bootstrap authenticates launcher/parser/closure/schema generations
  -> fixed job-bound production operation
       A: real closure owner mapping observation
       B: real closure + launcher compression observation
       C: real production fd/close_range primitive
       D: real production process owner
       E: held-byte sudo capsule -> real sandbox-only launcher
       integration: real complete closure + launcher transaction
  -> production owner boundedly settles all process/fd/root/mount authority
  -> common independently reobserves every baseline and derives cleanup
  -> report custodian stages, validates, publishes, and retains generation fds
  -> fixed upload step
  -> same custodian identity-checks/unlinks and proves report-path restoration
  -> aggregate job result
```

No operation can return an ordinary runtime result from another profile. The ordinary result remains the exact frozen versioned field set; A–E profile observations have separate closed types and cannot add private fields to it.

## 4. Acceptance-test catalog

All tests below are portable/static and must make real native effects unreachable.

| ID | Mandatory acceptance | Primary exact test surfaces |
| --- | --- | --- |
| `AT91-BOOT-01` | Drive the real held-byte bootstrap for all six fixed operations; reject ambient import, pathname re-exec, wrong driver/profile, replay, cross-profile output, and mutation before effects. | `test/outcome-two-trusted-launcher-portable.py`, `test/outcome-two-portable.test.ts`, six focused native tests |
| `AT91-A-01` | Real production closure owner resolves an executable, loader, libraries, ordered dependencies, stable maps, and cleanup. Remove A's unshare/mount route and all completed closure mocks. Branch-removal sentinels prove the owner calls are live. | `test/outcome-two-runtime-closure-portable.py`, `test/outcome-two-mapped-closure-portable.py`, `test/native-qualification-a.test.ts` |
| `AT91-A-META-01` | Six-job golden corpus plus A mutations for role/order, 134217728 bound, duplicate/unprovided `needed`, object identity, mapped sequence, and independently recomputed mapping/per-tool/top-level digests. | `test/native-qualification-common.test.ts`, `scripts/validate-schemas.ts`, `test/native-qualification-a.test.ts` |
| `AT91-B-01` | Require observed seal mask 63 and both exact marker digests; reject mask 15, equal-wrong outputs, source/sealed/mapping drift, and cross-tool row substitution. | `test/native-qualification-b.test.ts`, `test/native-qualification-common.test.ts`, `test/outcome-two-trusted-launcher-portable.py` |
| `AT91-FD-01` | Through the real production adapter, bounded `getdents64` excludes exactly its directory fd and never a transient duplicate; C invokes real `close_range`; every open/dup/close/reuse/limit cut derives a result and restoration observation. | `test/outcome-two-runtime-closure-portable.py`, `test/outcome-two-lifecycle-portable.py`, `test/native-qualification-c.test.ts` |
| `AT91-PROC-01` | Drive preregistration, expected `setsid`, second gate, exact `SCM_RIGHTS`/credentials pidfd transfer, malformed transfer, descendant census/adoption/spawn-after, identity drift, PDEATH before/after release, TERM/KILL/siginfo/reap, pidfd loss, and subreaper restoration. | `test/outcome-two-lifecycle-portable.py`, `test/outcome-two-recovery-portable.py`, `test/native-qualification-d.test.ts` |
| `AT91-OUTER-01` | At every pipe/open/fork/pidfd/write/read/close cut, each returned fd is leased before the next effect and each blocked child is registered before release; primary and aggregate cleanup errors are preserved under one monotonic deadline. | `test/outcome-two-lifecycle-portable.py`, `test/outcome-two-recovery-portable.py`, A/B/E/integration focused tests |
| `AT91-BASE-01` | Common captures and reobserves source, exact fds, children/descendants, mountinfo, four namespaces, limits, checkout, actual `/tmp/cogs-o2-runtime-v1`, and actual report directory. Every cleanup boolean is observation-derived; prefilled claims and wrong `.json`/`/run` names reject. | `test/native-qualification-common.test.ts` and all six focused job tests |
| `AT91-REPORT-01` | Real custodian transaction covers short/zero/interrupted write/read, fsync/fstat, before/after close, fd reuse, reopen, canonical/schema/semantic drift, collision, no-replace publication, directory fsync, staged unlink, worker crash, upload failure, post-upload unlink, replacement, custodian loss, and cleanup aggregation. A mismatch is preserved, never deleted. | `test/native-qualification-common.test.ts`, `test/outcome-two-recovery-portable.py` |
| `AT91-SCHEMA-01` | All six production `_validate` goldens pass. Isolated source/envelope/job/check/order/result/failure/cleanup and job-specific metadata mutants reject in schema and independent semantics. | `scripts/validate-schemas.ts`, `test/native-qualification-common.test.ts` |
| `AT91-E-01` | Compose runner-owned checkout with the held-byte sudo capsule; prove root executes no checkout pathname/fd, sandbox probe reaches the real sandbox-only owner, and no closure/compression operation is reachable. Drive every production boundary observation and rollback cut. | `test/outcome-two-trusted-launcher-portable.py`, `test/native-qualification-e.test.ts` |
| `AT91-I-01` | Integration calls the same real complete owner, owns no admission/unshare/pipe/process/root/mount implementation, accepts only the exact ordinary result, and rejects each missing/extra/renamed/false/wrongly typed field. | `test/outcome-two-trusted-launcher-portable.py`, `test/native-qualification-integration.test.ts` |
| `AT91-MODE-01` | Exercise fd-3/fixed transport through production bootstrap for every operation; an A/B/E result cannot be accepted as ordinary runtime output or another job's evidence. | `test/outcome-two-trusted-launcher-portable.py`, all six focused native tests |
| `AT91-WF-01` | Parse workflow and dispatch: exact `--workflow-bound`, same-repository attempt 1, failed fork/push/malformed/attempt-2 eligibility, all failed/cancelled/skipped conclusions fail final result, exact upload then custodian cleanup. No native function is called. | `test/native-qualification-common.test.ts`, six focused native tests |
| `AT91-NOSUB-01` | Static/branch-removal sentinels forbid `os.listdir` fd baselines, A private-method composition, C raw local close-range, D local parallel supervisor, E pathname root exec/full-runtime mode, integration bootstrap duplication, and completed-result mocks. | all changed portable/focused tests |
| `AT91-READABLE-01` | AST/static review rejects packed multi-effect lines and verifies each fallible effect has an immediately visible lease/registration transition. | Python portable suites and fresh human reviews |

A green token/regex test is not acceptance. Each fault case must identify the production method, primitive cut, intended typed failure, cleanup domains, and a branch-removal sentinel; declared, selected, consumed, and oracle-proved case sets must be equal.

## 5. Every final-review finding mapped to architecture and acceptance

Repeated findings remain listed so none is silently collapsed.

| Final report finding | Architectural disposition | Acceptance IDs |
| --- | --- | --- |
| A/B `P1-1`: B rewrites mask 63 to 15 | Publish and schema-fix exact mask 63; common checks observed row without transformation. | `AT91-B-01`, `AT91-SCHEMA-01` |
| A/B `P1-2`: A/B launch leaks fds/children | Replace driver launchers with the shared admitted production owner; lease every pipe result and preregister blocked children. | `AT91-OUTER-01`, `AT91-BASE-01` |
| A/B `P1-3`: common deletes replacement | Retained report custodian unlinks only fd-identical owned generations and preserves mismatches. | `AT91-REPORT-01` |
| A/B `P1-4`: A is not mapping-only and uses fabricated owner | Remove A namespace/mount work; add the real closure-owner A observation; prohibit completed mocks. | `AT91-A-01`, `AT91-NOSUB-01` |
| A/B `P2-1`: equal wrong B output passes | Bind both rows to the fixed marker SHA-256. | `AT91-B-01` |
| A/B `P2-2`: modes are structural-only | Drive each fixed profile through the real authenticated bootstrap and reject cross-mode substitution. | `AT91-BOOT-01`, `AT91-MODE-01` |
| C/D `P1-1`: D's `setsid` contradicts preregistered identity | Register expected transition, verify at a second gate, retain immutable pidfd/start/exe identity. | `AT91-PROC-01` |
| C/D `P1-2`: no descendant pidfd transfer/census | Exact credentialed `SCM_RIGHTS` transfer before ack plus stable recursive census/adoption ownership. | `AT91-PROC-01` |
| C/D `P1-3`: duplicate-library fd enumeration | Use exact bounded production `getdents64` enumerator everywhere. | `AT91-FD-01`, `AT91-BASE-01` |
| C/D `P1-4`: C/D qualify substitutes and tests replace mechanisms | Route C/D through actual closure/launcher production owners and primitive-level faults. | `AT91-FD-01`, `AT91-PROC-01`, `AT91-NOSUB-01` |
| C/D `P1-5`: close uncertainty and exact-name cleanup | One-shot fd leases plus retained identity-bound report custodian; never reopen onto retired uncertain numbers. | `AT91-REPORT-01`, `AT91-OUTER-01` |
| C/D `P2-1`: cleanup `paths` observes unused sibling | Common observes actual production and report roots and derives the value. | `AT91-BASE-01` |
| Common `P1` recovery/generation authority | Custodian exists before named effects, recovers worker/staging cuts, and retains generations across upload. | `AT91-REPORT-01` |
| Common `P1` cleanup observations are caller supplied | Common captures all baselines and accepts typed job observations, never caller cleanup booleans. | `AT91-BASE-01` |
| Common `P1` A/B semantic falsehood | Exact B facts; exact A order/bounds/providers and recomputed summaries. | `AT91-A-META-01`, `AT91-B-01`, `AT91-SCHEMA-01` |
| Common `P1` mandatory gate is token coverage | Replace token-only checks with real production state machines and complete fault corpora. | `AT91-REPORT-01`, `AT91-WF-01`, `AT91-NOSUB-01` |
| E/I `P1-1`: mutable pathname before admission and root-owner mismatch | Execute retained bytes; use fixed held-byte sudo capsule; root never opens the checkout. | `AT91-BOOT-01`, `AT91-E-01` |
| E/I `P1-2`: E selects full integration and integration duplicates bootstrap | Fixed sandbox-only production operation; integration delegates entirely to ordinary owner. | `AT91-E-01`, `AT91-I-01`, `AT91-MODE-01` |
| E/I `P1-3`: outer owners leak and observe `/run` not `/tmp` | Production owner handles preregistered transport/reap; common observes exact `/tmp` root. | `AT91-OUTER-01`, `AT91-BASE-01` |
| E/I `P1-4`: common cleanup pathname-based | Retained descriptor-generation comparison immediately before unlink. | `AT91-REPORT-01` |
| E/I `P2-1`: hostile report/wrapper cuts absent | Complete custodian and wrapper fault matrices through production adapters. | `AT91-REPORT-01`, `AT91-E-01`, `AT91-I-01` |
| Holistic `P1-1`: E unreachable and not independent | Held-byte sudo capsule and fixed sandbox-only production owner. | `AT91-E-01` |
| Holistic `P1-2`: A/C/D substitute coordinators | Fixed operations on actual closure/launcher owners; remove replicas. | `AT91-A-01`, `AT91-FD-01`, `AT91-PROC-01`, `AT91-NOSUB-01` |
| Holistic `P1-3`: A/B reports untruthful | Recompute A summaries and require exact B seals/output. | `AT91-A-META-01`, `AT91-B-01` |
| Holistic `P1-4`: cleanup/publication is not one exact transaction | One common baseline owner and retained report custodian with exact paths and generations. | `AT91-BASE-01`, `AT91-REPORT-01` |
| Holistic `P2-1`: tests validate substitutions | Cross-file production composition and branch-removal tests replace completed observations. | `AT91-BOOT-01` through `AT91-NOSUB-01` |

No final report identified a P0 or standalone P3. Fresh reviewers may do so; ADR 0091 must require their resolution rather than treating this table as exhaustive authority.

## 6. Parallel implementation ownership (maximum five workers)

File ownership is exclusive. Shared API contracts are frozen in a short design checkpoint before wrapper work; workers do not edit another worker's files.

| Worker | Exclusive exact files | Deliverable/dependency |
| --- | --- | --- |
| **W1 — admitted production owners** | `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py`; `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py`; `test/outcome-two-runtime-closure-portable.py`; `test/outcome-two-mapped-closure-portable.py`; `test/outcome-two-lifecycle-portable.py`; `test/outcome-two-recovery-portable.py`; `test/outcome-two-trusted-launcher-portable.py`; `test/outcome-two-portable.test.ts`; `test/fixtures/outcome-two/**` | Freeze closed A–E/integration result protocols first; implement real production operations, source/sudo capsule, process/fd owners, and portable adapters. |
| **W2 — common/report/schema/workflow** | `.github/workflows/ci.yml`; `schemas/native-qualification-report-v1alpha1.json`; `scripts/native-qualification/common.py`; `scripts/validate-schemas.ts`; `test/native-qualification-common.test.ts` | One baseline owner, report custodian, exact A/B semantics, six-job schema corpus, and static workflow final gate. Starts after W1 protocol freeze; can proceed in parallel with W3–W5. |
| **W3 — A/B callers** | `scripts/native-qualification/job-a-runtime-mappings.py`; `scripts/native-qualification/job-b-compression.py`; `test/native-qualification-a.test.ts`; `test/native-qualification-b.test.ts` | Thin fixed-operation callers, exact A/B facts, no private lifecycle or namespace substitute. |
| **W4 — C/D callers** | `scripts/native-qualification/job-c-descriptors.py`; `scripts/native-qualification/job-d-process-lifecycle.py`; `test/native-qualification-c.test.ts`; `test/native-qualification-d.test.ts` | Thin actual-primitive callers and focused cross-file registration/status tests; no local supervisor/enumerator. |
| **W5 — E/integration callers** | `scripts/native-qualification/job-e-sandbox.py`; `scripts/native-qualification/thin-integration.py`; `test/native-qualification-e.test.ts`; `test/native-qualification-integration.test.ts` | Held-byte sudo client, sandbox-only E, ordinary thin integration, and exact result decoders. |

### Integration order

1. W1 publishes types/protocols only after its portable state-machine tests are coherent.
2. W2–W5 work in parallel against that freeze.
3. W1 reviews call-site composition but does not edit W2–W5 files; each owner makes required changes.
4. One integration owner runs only ordinary non-native static/portable commands after all changes merge. No native selector may be used.
5. Line accounting and correction-range `diff --check` run before fresh reviews.

## 7. Non-native verification and review gate

Permitted only under a future accepted correction ADR:

- Python AST/compile and the Outcome Two portable Python suites using scripted adapters;
- TypeScript typecheck, schema validation, and focused tests after locked dependency provisioning under existing project policy;
- static workflow parsing, source/selector scans, branch-removal sentinels, gross-line accounting, `git diff --check`, and repository integrity checks.

Forbidden during correction and review:

- every `--workflow-bound` invocation;
- any real sudo, namespace, mount, seccomp, `map_files`, `close_range`, pidfd/process qualification, compression executable, native workflow, or integration execution;
- provider, network acquisition, cloud, AWS, OpenTofu, deployment, or campaign operation.

The review candidate must be one exact clean head. The five fresh reports must all name that head and independently cover:

1. common/report/schema/workflow;
2. A/B and fixed operation authenticity;
3. C/D descriptor/process ownership;
4. E/integration source/sandbox composition; and
5. holistic cross-file authority, line accounting, and boundaries.

Any unresolved P0–P3 restarts correction and review. Only after all five are clean may a separate execution ADR be proposed.

## 8. Measured gross-line highs

### 8.1 Counting method and measured basis

`git diff --numstat bec0a19..4eb9da3` gives **7,892** current trusted/portable text additions and **3,811** current native additions. The native value agrees with all five final reviews. Existing binary ELF fixtures provide no line credit.

The raised spans are based on the concrete missing transitions, not speculative features:

- closure: one production observation protocol shared by A/C and removal of direct-private composition;
- launcher: fixed operation binding, held-byte/root capsule, sandbox-only route, exact process transition/pidfd transfer ownership;
- trusted portable suites: before/after primitive cuts and branch-removal coverage for those real owners;
- common/schema: common baselines, a surviving publication custodian, generation leases, A digest/provider semantics, and six discriminated production goldens;
- focused native companions: cross-file composition and mutation coverage instead of completed booleans.

Hard highs retain roughly 10–20% readable contingency over the measured correction spans. They are ceilings, not targets. Unused allowance is non-transferable. Obsolete code should be deleted for architecture clarity, but deletion does not fund another file or subtotal.

### 8.2 Trusted/portable exact surfaces

| Exact surface | Reviewed gross | ADR 0090 high | Proposed ADR 0091 high | Justification |
| --- | ---: | ---: | ---: | --- |
| `deploy/aws-feasibility/remote/completion_elf.py` | 306 | 320 | **320** | Frozen; no final-review parser finding. |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py` | 2,098 | 2,100 | **2,350** | Real A observation and shared exact fd/close-range production operation; delete mapping substitutes. |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py` | 1,897 | 1,900 | **2,600** | Fixed operation binding, held-byte/root capsule, sandbox-only route, process transition/pidfd transfer, and exact outer ownership. |
| `schemas/trusted-runtime-closure-v1.json` | 134 | 260 | **260** | Frozen report contract. |
| `scripts/validate-schemas.ts` Outcome Two addition | 27 | 30 | **140** | Six native goldens and isolated structural/semantic mutation registration without generated fixtures. |
| `test/outcome-two-runtime-closure-portable.py` | 350 | 350 | **450** | Drive real A/C closure owner operations and fd cuts. |
| `test/outcome-two-mapped-closure-portable.py` | 257 | 300 | **400** | Real loader/provider/mapping composition and summary inputs. |
| `test/outcome-two-sealing-portable.py` | 269 | 300 | **300** | Frozen; production sealing matrix already belongs here and no new duplicate matrix is planned. |
| `test/outcome-two-lifecycle-portable.py` | 550 | 550 | **720** | Planned session transition, transfer, registration, deadline, and close cuts. |
| `test/outcome-two-recovery-portable.py` | 319 | 550 | **600** | Real owner crash/recovery and report-worker/custodian interaction cuts. |
| `test/outcome-two-runtime-report-portable.py` | 399 | 400 | **400** | Frozen trusted-report contract; native report mutations stay native. |
| `test/outcome-two-trusted-launcher-portable.py` | 790 | 800 | **1,150** | All six authenticated operations, root capsule, E-only route, ordinary-result separation, and cross-profile rejection. |
| `test/outcome-two-portable.test.ts` | 167 | 170 | **200** | Wrapper registration and branch-removal/static gate additions only. |
| `test/fixtures/outcome-two/**` aggregate | 329 text | 900 | **900** | Existing accepted ceiling is sufficient for closed primitive fault manifests; no generated/binary credit. |
| **Trusted/portable subtotal and hard high** | **7,892** | **8,930** | **10,790** | Binding. |

### 8.3 Native qualification/integration exact surfaces

| Exact file | Reviewed gross | ADR 0090 high | Proposed ADR 0091 high | Justification |
| --- | ---: | ---: | ---: | --- |
| `.github/workflows/ci.yml` Outcome Two addition | 250 | 300 | **300** | Wiring remains thin; only custodian cleanup/final-result wiring may change. |
| `schemas/native-qualification-report-v1alpha1.json` | 293 | 300 | **420** | Exact mask 63; closed mapped role/digest sequence; A order/provider/bounds; six strict branches. |
| `scripts/native-qualification/common.py` | 400 | 400 | **750** | One exact baseline owner, one-shot fd leases, retained report custodian, recovery, and independent semantic recomputation. |
| `scripts/native-qualification/job-a-runtime-mappings.py` | 300 | 300 | **330** | Thin real-owner client; room only for closed observation validation and aggregate error handling. |
| `scripts/native-qualification/job-b-compression.py` | 341 | 350 | **380** | Exact observed seals/output plus thin admitted-owner client. |
| `scripts/native-qualification/job-c-descriptors.py` | 250 | 250 | **280** | Thin real primitive client; local enumerator/close-range implementation is deleted. |
| `scripts/native-qualification/job-d-process-lifecycle.py` | 350 | 350 | **400** | Thin production process-owner client and exact typed outcome validation; local supervisor is deleted. |
| `scripts/native-qualification/job-e-sandbox.py` | 449 | 450 | **500** | Held-byte fixed sudo capsule client and sandbox-only result validation; no production T2 duplication. |
| `scripts/native-qualification/thin-integration.py` | 350 | 350 | **400** | Exact ordinary-owner call/result validation; duplicate bootstrap/process code is deleted. |
| `test/native-qualification-common.test.ts` | 197 | 200 | **500** | Full publication/custodian matrix, exact baselines, six goldens, semantics, and workflow conclusions. |
| `test/native-qualification-a.test.ts` | 98 | 120 | **180** | Real-owner composition, A metadata digest/provider mutations, no namespace/substitute route. |
| `test/native-qualification-b.test.ts` | 111 | 120 | **190** | Exact 63/output/source/sealed/mapping and operation substitution mutations. |
| `test/native-qualification-c.test.ts` | 91 | 120 | **220** | Real production primitive and open/dup/register/close/reuse/limit cuts. |
| `test/native-qualification-d.test.ts` | 112 | 150 | **280** | Transition, credentialed pidfd transfer, census, signals/siginfo/reap, and failure cuts. |
| `test/native-qualification-e.test.ts` | 112 | 180 | **230** | Runner-owner/root-capsule composition, sandbox-only reachability, and rollback cuts. |
| `test/native-qualification-integration.test.ts` | 107 | 150 | **220** | No-parallel-bootstrap sentinel and exhaustive exact ordinary-result mutations. |
| **Individual-file ceiling sum** | **3,811** | **4,090** | **5,580** | Not simultaneously consumable. |
| **Native subtotal hard high** | **3,811** | **4,000** | **5,400** | Binding; at least 180 lines of individual ceilings must remain unused. |

### 8.4 Aggregate highs

- Trusted/portable binding subtotal: **10,790**.
- Native binding subtotal: **5,400**.
- Binding listed total: **16,190**.
- Outcome Two production/portable/native/integration aggregate hard high: **16,250** gross physical lines from `bec0a19`.
- The remaining **60-line aggregate margin** is non-transferable and authorizes no unlisted file.
- The separate capability-probe hard high remains **2,830** and supplies no credit to this work.

Stop and adopt another measured ADR before crossing a file high, either subtotal, or the aggregate; modifying a frozen surface; adding/renaming a surface; changing report disclosure beyond the fixed mapped role/digest sequence; or changing source trust, job split, cleanup domains, execution contract, or cloud boundary.

## 9. Definition of correction complete

Correction is complete only when all of the following are true at one exact clean head:

- every row in section 5 is closed by its acceptance IDs;
- no production path executes a checkout pathname after held-byte admission;
- A/C/D enter real production owners, E enters only sandbox probe, and integration owns no parallel mechanism;
- B publishes mask 63 and the exact marker digest;
- A summaries are independently recomputable from closed metadata;
- common alone derives seven cleanup observations from exact baselines;
- report cleanup retains generation authority across upload and preserves foreign/replaced state;
- all portable/static gates pass without a native selector or real native primitive;
- exact gross additions remain within every proposed high and subtotal;
- correction-range whitespace and repository integrity checks pass; and
- five fresh exact-head hostile reviews report no unresolved P0–P3.

That state is only eligibility to request a separate native-execution ADR. It is not native, artifact, AWS, production, release, or issue-closure authority.
