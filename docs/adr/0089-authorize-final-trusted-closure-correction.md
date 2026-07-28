# ADR 0089: Authorize the final measured trusted-closure correction

- Status: Accepted
- Date: 2026-07-28
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-28 under Nick Byrne's standing authorization to complete all non-AWS work.
- Architecture predecessors: ADR 0088 and, where non-conflicting, ADR 0087.
- Exact second implementation reviewed: `d845cb13111cc3077141d84a3796537bd125dd0b`.
- Exact five-report second-rereview head: `4d329b677be9b409767532f235c18ab1270be61f`.
- Exact correction-gate head: `d111eac246a42f186ff5072c0bb99ce589ca3b5c`.
- Accounting predecessor remains: `bec0a19b0b984f88ab9c2effc5059f3737915caa`.
- Supersedes: ADR 0088 only where this ADR clarifies the execution contract, narrows absence claims, specifies the final correction, and raises measured readable highs. ADR 0088's non-conflicting trust, disclosure, cleanup, review, native-order, and operational boundaries remain accepted.

## Context

The first ADR 0088 correction materially improved held-source authentication, ELF page modeling, descriptor-relative closure resolution, complete-object sealing, private `SCM_RIGHTS` issuance, report binding, explicit descriptor enumeration, and closure-local lease behavior. Five independent second hostile rereviews nevertheless found that the composition was still not acceptable:

- ambient Python could forge the private source-admission claim, while the exact held-byte loader could not import its fixed standard-library dependencies and the Python identity check compared incompatible path spellings;
- sealed execution objects remained `O_RDWR`, issuer credential/cardinality/generation checks were incomplete, and the producer called one semantic decoder twice;
- the launcher sampled maps without an exec-complete barrier and asserted T2 facts from operation labels rather than observations;
- user/group-map ordering, final seccomp policy, root rollback, process registration, descendant ownership, descriptor enumeration, close uncertainty, and typed unavailability were incomplete;
- portable launcher and recovery tests drove parallel transcript players rather than the production state machines; and
- multiple fixture IDs executed without reaching their named production predicate.

The exact gate `.pi/outcome-two/closure-second-correction-gate.md` maps every second-rereview finding to a mandatory acceptance test and establishes that ADR 0088's four-line closure and launcher margins cannot hold a readable correction. It also identifies a genuine architecture issue: classic BPF is stateless, so it cannot consume an `execveat` allow rule. A seccomp user-notification broker would add a new protocol, kernel primitive, listener lifecycle, and race analysis merely to preserve an unnecessarily broad claim.

This ADR chooses the smaller measurable contract. The setup child remains trusted through its one fixed exec attempt. Successful exec atomically consumes its only executable-authority descriptor through `CLOEXEC`. Before untrusted input is released, the outer owner proves that the resulting T2 has no executable-authority descriptor, no proc mount, and no executable materialized mount. Later execution is prevented by the conjunction of the fixed syscall policy and authority absence, not by a fictional stateful cBPF counter.

This is the final pre-native closure correction, not authority for another speculative design cycle. The accepted implementation work is the closed set below, on the existing files only.

## Decision

### 1. Gate, scope, and evidence layers

The reviewed head is **not ready** for native Jobs A–E or thin integration. Correct only the existing parser, closure, launcher, schema/registration, seven Python portable suites, TypeScript wrapper, and Outcome Two fixture tree under this ADR. Delete obsolete compatibility and transcript-player routes rather than preserving them as apparent boundary coverage.

The correction must keep three evidence layers distinct:

1. **Portable/model evidence** proves that the real production state machine requests typed primitive observations and cannot publish a fact from an absent, failed, mismatched, or cleanup-uncertain observation.
2. **Production transaction evidence** consists of successful primitive returns plus exact readbacks bound to the transaction. An operation name, intended effect, or prefilled boolean is not an observation.
3. **Native applicability evidence** may be established only later by same-head Jobs A–E under separate execution authority. A portable pass does not claim that a Linux kernel supplied a namespace, mount, seccomp, proc, `map_files`, pidfd, or cleanup result.

A fresh exact-head hostile review must report no unresolved P0–P3 finding before native implementation may begin. Native execution cannot repair a portable or production defect.

### 2. Final execution contract

The accepted contract does **not** use seccomp user notification, a post-loader trampoline, or a stateful cBPF claim.

The pre-exec child is fixed, single-threaded, source-admitted trusted code until its exec transition. It receives exactly one authenticated, sealed, read-only, `CLOEXEC` executable descriptor for the selected gzip or zstd object. It receives no second executable descriptor. Its production state machine may issue exactly one `execveat` call, using only that registered descriptor and the fixed accepted flags. If the call returns or fails, the child reports the typed setup failure and exits; it never retries. If the call succeeds, kernel `CLOEXEC` handling consumes that descriptor during the image transition.

The fixed x86-64 seccomp program must check architecture before syscall numbers. It denies `execve` and every enumerated socket, io_uring, namespace/process creation, mount/root mutation, capability/acquisition, filter-replacement, executable-object creation, and authority-duplication route required by the accepted policy. It may admit only the fixed pre-exec `execveat` shape needed for the one trusted transition. Classic BPF is not described as counting calls or binding a later numeric fd to the consumed object.

After clean exec readiness and before input, the surviving trusted outer owner must:

1. under a fixed deadline, observe the complete post-exec fd table and two complete stable mapping snapshots at the exact expected non-executable fd set and materialized-generation/report set; the executable and status descriptors are absent and the loader has completed its required mappings;
2. transition every materialized-root mount to read-only `noexec` and reread the exact final mount state;
3. establish that the T2 root contains no proc mount and exposes no host checkout or host executable path;
4. re-enumerate the complete exact fd table, capture two complete stable final mapping snapshots through trusted outer procfs, open every executable mapping through trusted `map_files`, and require that fd and mapping state remain exactly equal after the mount transition; and
5. only then release the first input byte.

The final untrusted T2 therefore has no executable-authority descriptor, no proc, and only read-only `noexec` materialized-root mounts. `execve` is seccomp-denied. A later `execveat` has no eligible executable object: the sole sealed execution descriptor was consumed, the exact fd table contains no replacement, executable-object creation and authority-duplication routes are denied, and every reachable materialized object is on a `noexec` mount. Unexpected success or an eligible object is terminal.

This contract does not claim that stateless cBPF makes `execveat` one-shot. Exactly one attempt is a property of the authenticated trusted pre-exec state machine; post-exec safety is a measured policy-and-authority conjunction.

### 3. Exec readiness, final state, and truthful claims

A registered `CLOEXEC` status channel is the exec-ready barrier. The child writes one bounded typed setup error on every pre-exec failure or returned `execveat`. The writer is not explicitly closed on a success path; clean EOF is valid only when successful exec consumed it. Timeout, bytes, malformed status, partial setup, early close, identity drift, or missing EOF fails with the input gate unopened.

No map read, post-exec qualification, or input write may occur before clean EOF. After EOF, bounded exact fd/map readiness must precede the final noexec transition; exact mount readback and a second exact fd/two-snapshot map check then establish the final state. Final map equality and report-generation equality precede input. Portable tests must independently mutate each barrier observation and prove that no later stage opens.

Every qualification fact starts as `UNOBSERVED`. The production observed-fact builder may publish success only from the complete conjunction of independent typed observations for:

- user, PID, mount, and network namespace object identities and ownership relations;
- PID 1 metadata;
- the exact post-exec descriptor table;
- effective, permitted, inheritable, bounding, and ambient capability sets;
- supplementary groups, securebits, NNP, seccomp installation, mode, exact program digest, and required denial outcomes;
- singular final UID/GID maps;
- the final no-proc, read-only/noexec mount and pathname state;
- two stable final mappings and exact object generations;
- owned children, descendants, namespace handles, roots, mounts, paths, checkout, limits, and cleanup baselines.

An unobserved value is not `true`. Successful seccomp installation, `PR_GET_SECCOMP == 2`, the exact installed-program bytes/digest, and observed syscall denials are separate facts. Wrong errno and unexpected success are failures. Literal all-true construction and operation-label evidence are removed.

`no_acquisition_route` is scoped to this conjunction: every route in the accepted exhaustively enumerated x86-64 policy table is observed denied or removed, and the final descriptor/path/mount authority inventory contains no eligible executable object. It is not a universal statement about future syscalls, kernel defects, or a stateful cBPF program. Likewise, `namespaces_released` means all exact owned processes and namespace descriptors were reaped/closed and the observed initial baselines restored; it does not claim that no foreign host reference exists.

### 4. Source admission and fixed bootstrap

Admission is enforced by source exclusion plus live kernel topology, not by a Python-name secret and not against arbitrary malicious code already admitted into T1.

The isolated T0 bootstrap must authenticate and retain the exact launcher, parser, closure, schema, and fixed standard-library loader before any architecture, fd, proc, source, helper, or sandbox effect. The held-byte synthetic package may import the complete fixed transitive standard-library set, including `platform`, while checkout and tracked-module search remain disabled. Any tracked or checkout import outside the exact admitted set is terminal.

Only the exact synthetic package instance connected to the live one-shot bootstrap/issuer endpoint and expected worker PID may enter the production constructor. Ambient public and private/test aliases, duck-typed or copied claims, wrong package, wrong issuer, wrong PID, and replay reject before effects. Pure Python object identity, underscores, stack inspection, module names, and process-local random values are not independently called unforgeable.

The fixed Python check compares kernel object identity for `/proc/self/exe` with the descriptor-relatively admitted `/usr/bin/python3` object. A versioned symlink target is accepted only when it is the same object; same-spelling replacement or an alternate Python object rejects.

### 5. Issuance, report, and generation binding

Every sealed gzip/zstd executable, loader, and library object is reopened after sealing through a distinct `O_RDONLY | O_CLOEXEC` reference. The writable memfd reference is retired through its lease exactly once. The issuer rejects any wrong access mode before transfer.

The one-shot `SOCK_SEQPACKET` issuance protocol requires exactly one credentials record and one rights record, exact PID/UID/GID, exact descriptor count, no unknown ancillary data, no truncation, one packet, acknowledgement, then EOF with no second packet. Split, duplicate, extra, missing, replayed, or conflicting records fail and consume the transaction.

Generation bindings are unique and exactly equal to every gzip/zstd `(tool_index, object_index)` report row. Aliases are accepted only when they name one identical authenticated object. Missing, duplicate, extra, conflicting, or unreferenced rows or descriptors reject.

The tracked schema gate, producer semantic codec/re-encoder, and launcher semantic codec/re-encoder are three genuinely distinct implementations. The exact production schema gate is part of the hostile corpus. Calling one decoder twice is not independence. Golden and recomputed isolated mutants must pass through all three paths with an implementation-identity sentinel.

### 6. User boundary, root transaction, and lifecycle ownership

Capture parent UID/GID before `CLONE_NEWUSER`. Clear supplementary groups before writing `setgroups=deny`; never call `setgroups` after deny. Write and reread exact singular UID/GID maps. Overflow identities observed after unshare can never become parent-map values.

Root and mount preparation is write-ahead. Register the exact parent-relative root intent before creation and each mount intent before mount. Preserve exact parent and mount-namespace authority across faults before and after create, copy, readback, remount, and assignment. Cleanup removes only exact owned state. Replacement, foreign state, identity mismatch, or inability to observe cleanup is terminal uncertainty.

Every worker, helper, namespace owner, PID-1 child, and descendant is created behind a release gate. Creation returns a pidfd before child effects. The surviving outer owner registers PID, start time, session, process group, executable identity, release gate, pending descriptors, roots, mounts, and namespace authority before release. Authority is retained until exact reap or explicitly transferred to the surviving owner.

One shared process owner performs a stable recursive descendant census, retains pidfds, revalidates identity before TERM and KILL, uses fixed monotonic TERM/KILL/reap deadlines, acts only through retained owned authority, operates as subreaper or equivalent where required, and reaps adopted descendants. Blocking `waitpid(..., 0)`, raw-PID signaling, ignored lost-reap ownership, and pidfd discard after uncertainty are forbidden. EOF-live, PID reuse, identity drift, unexpected descendants, spawn-after-registration faults, and lost reap ownership are terminally handled or remain explicit uncertainty.

Every descriptor in closure and launcher code is an `OWNED -> CLOSED | TRANSFERRED | CLOSE_UNCERTAIN` lease. Before- and after-effect close faults are attempted once; an uncertain or reused number is never touched. Bundle loops retire each lease before the next close. Primary and all independently safe cleanup errors remain ordered, and a poisoned owner repeats the same terminal failure.

Every fd snapshot explicitly opens `/proc/self/fd`, parses bounded `getdents64` records through that exact fd, excludes exactly the enumerator fd, and closes it through a lease. A transient or duplicate library descriptor cannot enter the snapshot. Success proves `baseline | owned_outputs`; cleanup restores the baseline.

Proc stat, children, maps, and sandbox control records require the requested identity, one bounded complete record, strict lexical fields and integer bounds, exact version/shape/sequence/cardinality, and no trailing bytes. One-byte mutants must reach the intended parser error.

`RuntimeLauncherUnavailable` preserves the exact unavailable primitive through namespace owner, tool owner, and bootstrap and may be returned only after observed cleanup. Cleanup uncertainty is a distinct terminal error. Generic exit 1/125, success placeholders, or unavailable-with-unproved-cleanup are forbidden.

### 7. Actual production primitive adapters and hostile acceptance

Replace `_drive_fixed_bootstrap_with_adapter_for_tests`, `_drive_fixed_issuer_with_adapter_for_tests`, `_drive_fixed_t2_with_adapter_for_tests`, `_drive_fixed_outer_recovery_with_adapter_for_tests`, `_T2_SEQUENCE`, and obsolete compatibility routes with private primitive adapters entered by the real production state machines. `_SystemOps` and the portable model implement the same protocol.

Portable tests may fault a primitive before or after its effect. They may not replace source authentication, issuance, root construction, process ownership, exec, final maps, result construction, cleanup, or recovery with a completed result, claim set, attack-name loop, or harmless empty worker. In particular:

- bootstrap cases are consumed by real authenticate/load operations;
- issuer cases drive real `_WorkerIssuer`, `sendmsg`, `recvmsg`, `_consume_issuance`, descriptor reads, acknowledgement, and EOF;
- T2 cases drive real root, namespace-owner, boundary, exec-ready, exact-fd, noexec/proc, final-map, input, stop, and observed-result state machines; and
- recovery cases crash the real authority-bearing inner worker at every write-ahead cut while a surviving outer owner retains and recovers its worker/helper/root/mount/namespace transaction without retrying preparation.

The gate catalog `AT-ADM-01` through `AT-READABLE-01` in `.pi/outcome-two/closure-second-correction-gate.md` is incorporated as mandatory acceptance criteria, except that `AT-EXEC-ONCE-01` is resolved by section 2 of this ADR: it proves the trusted child's one fixed attempt, clean successful-exec EOF, consumed executable fd, exact post-exec table, final noexec/no-proc state, `execve` denial, and no eligible object for later `execveat`; it does not require a stateful filter or syscall-notification broker.

All seven Python suites and the fixture tree use closed manifests with unique ID, production method, primitive fault, exact intended typed code, cleanup domains, and a branch-removal sentinel for the named predicate. Declared, selected, consumed, and oracle-proved sets must be equal. `same-inode`, `ambiguous-fingerprint`, `mapping-object-bound`, `double-close`, `unexpected-owned-child`, `spawn-after`, and `cleanup-after-poison` must reach their named production branches. The mapping bound uses 129 unique authenticated identities; fingerprint ambiguity uses two valid distinct expected identities. Accepting any exception is forbidden.

Readable control flow is an acceptance property. Remove packed field declarations, multi-effect lines, duplicate compatibility paths, and transcript players. One physical line cannot hide multiple fallible security effects or cleanup decisions. Static accounting and a fresh human hostile review are both required.

### 8. Corrected final sequence

```text
T0 exact source and fixed-Python admission
  -> surviving outer owner preregisters the real worker transaction
  -> T1 exact closure preparation and read-only one-shot issuance
  -> launcher verifies descriptors, report, schema, and generations
  -> write-ahead private-root and namespace construction
  -> pre-exec UID/GID capture; groups/maps/capabilities/NNP/seccomp
  -> release one trusted single-threaded child with one sealed CLOEXEC exec fd
  -> exactly one fixed execveat attempt
  -> clean CLOEXEC status EOF on successful exec
  -> exact post-exec non-executable fd table and stable loader-complete maps
  -> final read-only noexec mounts and no proc
  -> exact final fd table and two stable generation/report-equal maps
  -> release first gzip or zstd input byte
  -> bounded exact descendant/mount/fd/root cleanup and baseline proof
  -> observed qualification result
```

No report or result is published before the cleanup appropriate to its stage. Failure never selects a fallback, retries preparation, relaxes T2, or turns uncertainty into absence.

## Revised measured readable highs

All highs count gross added physical lines from exact predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`. Deletion, rename, generated-file, binary, compression, and code-movement credit remain forbidden. Blank and comment lines count. Highs are non-transferable and require ordinary readable formatting.

### Trusted closure and portable qualification

| Exact file/surface | Hard high |
| --- | ---: |
| `deploy/aws-feasibility/remote/completion_elf.py` | 320 |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py` | 2,100 |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py` | 1,900 |
| `schemas/trusted-runtime-closure-v1.json` | 260 |
| `scripts/validate-schemas.ts` Outcome 2 registration only | 30 |
| `test/outcome-two-runtime-closure-portable.py` | 350 |
| `test/outcome-two-mapped-closure-portable.py` | 300 |
| `test/outcome-two-sealing-portable.py` | 300 |
| `test/outcome-two-lifecycle-portable.py` | 550 |
| `test/outcome-two-recovery-portable.py` | 550 |
| `test/outcome-two-runtime-report-portable.py` | 400 |
| `test/outcome-two-trusted-launcher-portable.py` | 800 |
| `test/outcome-two-portable.test.ts` | 170 |
| `test/fixtures/outcome-two/**` aggregate | 900 |
| **Trusted/portable subtotal and hard high** | **8,930** |

The parser, schema, schema-registration, runtime-closure, mapped-closure, and sealing highs are unchanged from ADR 0088. The raised closure, launcher, lifecycle, recovery, report, launcher-test, wrapper, and fixture highs are the measured readable allowance for the closed correction above, not speculative feature room.

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

The listed trusted/portable and native highs total **11,130**. The Outcome 2 production, portable, native, and integration aggregate hard high is **11,200 gross physical lines**. The remaining 70-line aggregate margin is not transferable to any listed file and authorizes no unlisted surface. The separate non-authoritative capability-probe high remains 2,830 and supplies no credit.

Stop and adopt a new ADR before crossing any file, subtree, subtotal, or aggregate high; adding or renaming an implementation surface; adding a dependency or generated security program; changing the fixed tools, report disclosure, execution contract, authority model, cleanup rule, native job, or integration scenario; weakening fail-closed behavior; or moving security behavior into workflow YAML, schema, fixtures, or tests.

## Authority and consequences

This ADR authorizes one final correction on the exact existing implementation surfaces. It authorizes no new implementation file, dependency, workflow behavior, native surface, command-line selector, fallback, or run. The ADR documentation file and index entry record this decision; they do not expand implementation scope.

No test command, production invocation, capability observation, native job, workflow, sudo, namespace, mount, seccomp, `map_files`, compression-tool qualification, provider, cloud, AWS, deployment, or thin-integration execution is authorized by this commit. Existing AWS, cloud, provider, OpenTofu, campaign, production, release, and issue-closure stops remain in force.

The consequence is a narrower and provable execution boundary: exactly one trusted setup attempt consumes one authenticated execution descriptor, while the untrusted phase begins only after measured descriptor, mount, proc, map, policy, and authority closure. This avoids a speculative stateful seccomp protocol and makes every final claim traceable to an observed fact and a surviving exact owner.
