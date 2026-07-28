# Native Jobs C/D final exact-head signoff review

## Verdict

**BLOCKED** — exact implementation head `ea6e74fe709e02061e13be78922da13a8cf6f748` has unresolved P1/P2 findings. It is not ready for native execution, artifact reliance, release, or signoff under ADRs 0087–0090.

## Scope and method

- Reviewed exact `HEAD` and requested implementation head: `ea6e74fe709e02061e13be78922da13a8cf6f748` (identical).
- Read ADRs 0087, 0088, 0089, and 0090 in full; inspected Jobs C/D, their focused tests, common report ownership, the discriminated schema, workflow admission/upload/cleanup/final gate, and the production close-range/process-owner implementations.
- Static/portable only. No `--workflow-bound` selector, native syscall qualification, sudo, namespace, mount, seccomp, `map_files`, compression qualification, cloud, provider, or AWS route was invoked.
- Portable C/D companions passed 6/6 via Node's TypeScript stripping. Python AST/bytecode compilation, schema JSON parsing, correction-range `git diff --check`, and cap accounting passed. `node_modules` is absent, so the AJV/common wrapper and full project suite were not run. A Darwin-only attempt of the common happy-path transaction stopped before creation because `/tmp` plus `O_NOFOLLOW` is not portable; that result is not treated as Linux evidence.
- Gross native additions from accounting predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa` are `3811/4000`. Relevant exact highs are met but not exceeded: common `400/400`, C `250/250`, D `350/350`, C test `91/120`, D test `112/150`, workflow `250/300`, schema `293/300`.

## Findings

### P1-1 — Job D invalidates its own registered identity and cannot complete any case

`SystemOps._register()` records start time, process group, and session before release (`scripts/native-qualification/job-d-process-lifecycle.py:100-114`). Both the PDEATH parent and tree leader are registered while blocked, then released, and call `setsid()` (`:142-178`, `:198-229`). Their process-group and session values therefore necessarily change after registration.

The code nevertheless compares the stale pre-release values to `(pid, pid)` (`:178`, `:229`) and later requires the complete current identity to equal the stale tuple before wait, TERM, and KILL (`:112-117`, `:235-243`). Thus `ownership` is false and `_exact()` rejects the intended process transition. `pdeath_case()` cannot reach its exact parent reap, and `terminate_tree()` cannot reach TERM/KILL. Job D cannot produce a passing native result even on an otherwise applicable Linux runner.

The focused test misses this because its `Scripted` object returns preassembled `ownership=True` and `revalidated=True`; it never drives `_register()`, `setsid()`, or `_exact()` (`test/native-qualification-d.test.ts:22-40`).

### P1-2 — D does not transfer or preregister descendant pidfd authority as specified

The registered leader opens each descendant pidfd, but sends only an eight-byte raw PID over an inherited pipe (`job-d-process-lifecycle.py:164-177`, `:214-228`). The outer owner then calls `pidfd_open()` again. There is no `SCM_RIGHTS`, credential/cardinality check, creator-bound identity record, or ownership-preserving pidfd transfer. The creator's pidfd is not transferred to the surviving subreaper.

This does not satisfy ADR 0090 section 7's requirement that the leader report a still-blocked descendant's complete identity **and pidfd authority** before acknowledgement/release. It also leaves failure ownership split between an inner `_abort_child()` and an outer registry. Adoption proof is only one instantaneous `pid in _children()` membership test (`:190`, `:245`), not the required stable recursive census/retained authority for unexpected or adopted descendants.

The static test checks only source ordering around raw PID registration/release and contains no `SCM_RIGHTS`, pidfd-transfer, malformed-transfer, spawn-after, lost-owner, or census fault case (`test/native-qualification-d.test.ts:66-111`).

### P1-3 — C/D's supposedly exact fd baseline uses the forbidden duplicate-library enumeration path

Both `_fds()` implementations explicitly open `/proc/self/fd` and then call `os.listdir(directory)` (`job-c-descriptors.py:22-33`; `job-d-process-lifecycle.py:24-35`). CPython implements fd-based `listdir` by duplicating the supplied fd for `fdopendir`. That transient duplicate is live while `/proc/self/fd` is read, is included in the returned names, and is closed before the subsequent Python loop calls `fstat()` on every listed number. The code excludes only the original `directory` number, so the duplicate can produce `EBADF`; independently, this is not bounded `getdents64` through the exact enumerator as mandated by ADRs 0089/0090.

Consequently the initial/final descriptor baseline can fail before either job runs and cannot establish exact cleanup. The focused tests merely regex-match `open`, exclusion of the original fd, and `fstat`; they do not execute or model the enumeration implementation (`native-qualification-{c,d}.test.ts:84,109`). The accepted production adapter already has an exact `getdents64` primitive, but C/D do not use it.

### P1-4 — C/D do not qualify the admitted production primitives, and their “fault cuts” replace the mechanisms

Job C calls a driver-local raw syscall wrapper for `close_range` (`job-c-descriptors.py:13-21,123-126,159-166`) instead of the production close-range adapter in `completion_trusted_runtime_closure.py`. Job D implements a second local process registry/supervisor rather than driving the admitted production `_ProcessOwner`/lifecycle operations in `completion_trusted_runtime_launcher.py`. C cleanup also sends `SIGKILL` through the pidfd without revalidating the registered start-time/session/group/executable identity (`job-c-descriptors.py:136-143,167-184`).

The portable companions inject faults only above the security mechanisms: C replaces normalization, descriptor construction, inheritance, close-range, and restoration with completed method returns; D replaces each entire PDEATH/tree transaction with completed booleans (`test/native-qualification-c.test.ts:22-39`; `test/native-qualification-d.test.ts:22-40`). No before/after-effect cut reaches fork registration, pidfd acquisition/transfer, release writes, descriptor reuse, identity drift, EOF, TERM, KILL, waitid, reap, subreaper restoration, or cleanup aggregation. These tests therefore cannot establish ADR 0090 section 9's real-state-machine and branch-removal acceptance obligations, and their green result does not qualify production behavior.

### P1-5 — The common report owner violates permanent close uncertainty and exact-name cleanup

`finalize_report()` retires fd variables before each fallible close (`scripts/native-qualification/common.py:322-341`). If a close reports uncertainty, its exception path reopens parent/report directories (`:343-355`), allowing the kernel to reuse a retired uncertain number and later close it. This is precisely the fd-reuse route ADRs 0088–0090 forbid. There is no lease state or fault adapter to distinguish before-/after-effect close cuts.

`_remove_owned()` unconditionally unlinks both fixed names without proving either current name still denotes the retained generation (`:252-281`). `cleanup_report()` records a validation/replacement failure but calls `_remove_owned()` anyway (`:368-391`), so a replaced or unprovable object is deleted rather than preserved as terminal uncertainty. The common test covers only one happy transaction and source-token presence; it has none of ADR 0090's required close-before/after, fd-reuse, publication-replacement, staged-unlink, post-upload-unlink, or upload-failure fault matrix (`test/native-qualification-common.test.ts:157-176`).

This blocks trust in C/D artifact restoration even though the workflow correctly makes each upload/cleanup step part of the job result and the final `always()` gate requires all eight dependency results to be `success` (`.github/workflows/ci.yml:288-330,402-413`).

### P2-1 — The reported `paths` cleanup fact observes the wrong name

C and D derive `cleanup.paths` from absence of `/tmp/cogs-native-qualification-{C,D}.json` (`job-c-descriptors.py:50-61`; `job-d-process-lifecycle.py:42-53`). The actual common-owned report baseline is the directory `/tmp/cogs-native-qualification-{C,D}` and final `report.json` beneath it (`common.py:237-239`; workflow `:290-330`). The `.json` sibling is never used, so equality of that boolean is not evidence for the named path cleanup domain.

`WorkflowContext` separately rejects a pre-existing real report directory, and publication has its own later lifecycle, but that does not make the C/D cleanup value truthful. ADR 0090 requires common capture/recomparison of the exact private/report path baseline and forbids representing an unobserved/non-applicable domain as success. The scripted tests prefill all seven cleanup fields `true`, reproducing rather than detecting this overclaim.

## Disposition

- **P0:** none found.
- **P1:** five unresolved findings.
- **P2:** one unresolved finding.
- **P3:** none found.
- Positive static observations: the literal workflow ABI, explicit eligibility failure, A–E sibling topology, integration dependency, final required result, schema job/check discrimination, C fixed descriptor numbers/limit intent, D `waitid` siginfo comparisons, and numeric highs are present.

## Required before rereview

1. Correct D's preregistered identity model so the planned session/group transition is registered without making later exact revalidation self-contradictory.
2. Transfer each blocked descendant's creator-held pidfd and complete identity to the surviving owner through an exact `SCM_RIGHTS` protocol before acknowledgement/release; add stable adopted/descendant census and failure ownership.
3. Use the exact production `getdents64`, close-range, and lifecycle owners or an admitted production adapter surface authorized by a controlling ADR; do not qualify driver-local substitutes.
4. Add primitive-level portable before/after cuts for C/D registration, release, pidfd transfer/loss, identity drift, TERM/KILL/siginfo/reap deadlines, subreaper/adoption, descriptor close/reuse, and all restoration paths.
5. Give common report fds one-shot lease states, never reopen onto retired uncertain numbers, and unlink only the exact retained staged/published generation. Exercise the full report publication/upload-cleanup fault matrix.
6. Capture and recompare the actual common path/report baseline and derive every cleanup field from that exact observation.
7. Because common, C, and D are already at their ADR 0090 per-file highs, delete enough obsolete substitute code or adopt a new measured ADR before exceeding any high. Then rerun portable/static gates and obtain a new clean exact-head review before any native execution.

**SIGNOFF: BLOCKED**
