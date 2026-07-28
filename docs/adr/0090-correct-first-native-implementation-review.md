# ADR 0090: Correct the first native-qualification implementation review

- Status: Accepted
- Date: 2026-07-28
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-28 under Nick Byrne's standing authorization to complete all non-AWS work.
- Architecture predecessors: ADR 0089 and, where non-conflicting, ADRs 0088 and 0087.
- Exact first native implementation reviewed: `6d7d86401d96dfc9971fd9a4e0f784d0169cda62`.
- Exact five-report native review head: `3eaaccafc5733a2ebbc26e538fef5b0d2844f530`.
- Accounting predecessor remains: `bec0a19b0b984f88ab9c2effc5059f3737915caa`.
- Supersedes: ADR 0089 only where this ADR corrects native workflow admission/final gating, the common report transaction, A–E/integration ownership, native report semantics, cleanup evidence, portable acceptance, and native numeric highs. ADR 0089's trusted execution contract, trusted/portable highs, source-admission boundary, report disclosure boundary, and all non-conflicting authority and cloud prohibitions remain accepted.

## Context

The first native implementation added a common workflow context and report encoder, one tracked report schema, five parallel native drivers, thin integration, focused portable companions, exact-head workflow declarations, and fixed artifact uploads. It stayed within ADR 0089's then-current native highs and no native selector was executed during review.

Five committed hostile reports reviewed the same exact implementation head:

- `.pi/outcome-two/nreview-common.md`;
- `.pi/outcome-two/nreview-ab.md`;
- `.pi/outcome-two/nreview-cd.md`;
- `.pi/outcome-two/nreview-ei.md`; and
- `.pi/outcome-two/nreview-hol.md`.

The reports classify some defects at different severities, but agree that the exact head is blocked. In particular:

- workflow YAML invokes `--workflow-bound`, while A accepts `--native-fixed` and C/D accept `--native`; C/D also bypass the common artifact API;
- job-level event/attempt conditions turn an ineligible event or later attempt into skipped checks rather than an explicit failed required gate;
- common report production exposes the final upload pathname before write, fsync, identity, close, reopen, and independent validation have succeeded;
- the schema permits the wrong job's checks, contradictory pass/cleanup/failure states, duplicate logical check IDs, and generic metadata that omits A/B authority facts;
- A, B, E, and integration assert cleanup domains from constants instead of exact before/after observations, and the uploaded report pathname is not removed and rechecked;
- A, E, and integration call private or duplicated mechanisms instead of the admitted production owners, while B passes a runner-owned checkout to a bootstrap contract that requires an authority shape the workflow cannot provide and selects a state root the unprivileged runner cannot create;
- C/D fork effectful children before exact owner registration, use incomplete descriptor enumeration, and can block or strand children on failure;
- D does not prove the exact `SIGKILL`/`waitid` outcomes represented by its lifecycle claims;
- E duplicates namespace, root, mount, and teardown construction rather than qualifying production T2; and
- integration accepts any collection of 35 true booleans instead of one exact versioned production result.

A skipped job, a disposable runner, an operation label, a prefilled boolean, a private helper call, and a schema-valid contradiction are not native qualification evidence. Native execution cannot correct any of these source defects. The correction must make the workflow ABI, production ownership, cleanup transaction, publication transaction, and artifact contract exact before a later ADR can authorize one native observation.

## Decision

### 1. Gate and closed implementation scope

The reviewed head is **not ready** for native Jobs A–E, thin integration, artifact reliance, or issue closure. This ADR authorizes source correction and portable/static verification only. A fresh exact-head hostile review must report no unresolved P0–P3 finding before a later ADR may authorize native execution.

Correction is limited to the existing files listed in the trusted and native high tables below. No implementation file may be added, renamed, generated, or moved to evade accounting. No dependency, package, action, service, cache, secret, command-selected policy, fallback, retry, AWS surface, or additional native job is authorized. Existing private production adapters may be corrected, but they remain inaccessible through public arguments and portable tests perform no native effect.

The five native jobs remain independent fresh-runner siblings after Quality. Integration remains a sixth fresh-runner job after A–E and downloads no A–E artifact. Workflow YAML remains wiring only; admission, validation, report publication, baseline capture, process ownership, and cleanup behavior live in tracked code.

### 2. One workflow-bound ABI and an explicit required result

All six tracked drivers have exactly one workflow entry selector: literal `--workflow-bound`. A, B, C, D, E, and integration must enter `WorkflowContext.from_environ(expected_job, __file__)`, the common baseline/report API, and the exact job implementation through that selector. `--native-fixed`, `--native`, ad-hoc stdout reports, alternate report paths, and private workflow-equivalent selectors are removed or unreachable from production entry.

A portable cross-file test parses the workflow declarations and driver dispatch without executing a native primitive. It requires each YAML invocation to select `--workflow-bound`, each driver to accept that selector, each job identity/artifact path to agree with the common API, and every incompatible selector to fail before effects.

Eligibility is an always-evaluated non-native workflow gate. It succeeds only for a same-repository `pull_request` at `github.run_attempt == 1` with the exact event fields required for source admission. A fork pull request, push, missing/malformed field, or any later attempt explicitly fails eligibility; it is never represented as skipped or neutral success. A–E do not execute native code when eligibility fails.

One final required native-qualification result runs under `always()` and fails unless all of the following are true in the same run and attempt:

1. eligibility concluded `success`;
2. Quality concluded `success`;
3. A–E each concluded `success`;
4. integration concluded `success`;
5. all six exact report uploads concluded `success`; and
6. all six post-upload report cleanup checks concluded `success`.

A failed, cancelled, or skipped dependency is failure at this final required result. Branch protection must require that final result, not an individual conditionally skipped native job. Static workflow tests cover attempt 2, fork PR, push, malformed event data, failed/cancelled/skipped dependencies, and successful same-repository attempt 1. This changes gate semantics only; it grants no run authority.

### 3. Common atomic report transaction

`common.py` owns one report transaction shared by all six jobs. A driver may supply typed observations; it may not choose a report pathname, bypass validation, or write an artifact itself.

The fixed transaction is:

1. construct the exact job-discriminated value and canonical bytes in memory only after the job's applicable native-resource cleanup baselines have been rechecked;
2. independently apply the tracked JSON Schema and the common semantic validator to that value;
3. open a staged file with no-follow, exclusive-create, close-on-exec semantics beneath one private mode-0700 report directory held by exact directory authority;
4. completely write under the report bound, fsync the file, compare its exact regular-file identity, size, mode, owner, link count, and generation, then close it exactly once;
5. reopen the staged object read-only through the retained directory authority, compare the generation, completely read it, require byte-for-byte canonical equality, independently apply schema and semantic validation again, and close it exactly once;
6. atomically publish that validated generation to the absent fixed upload name using a no-replace operation, fsync the containing directory, reopen the published name, and require the same generation and bytes; and
7. expose the fixed path only after every preceding write, fsync, close, reopen, schema, semantic, canonical, and identity check succeeded.

Short/zero/interrupted writes, fsync/fstat/close uncertainty, reopen/read failure, generation drift, schema or semantic rejection, canonical mismatch, publication collision, directory-fsync failure, or staged cleanup uncertainty is terminal. Before publication, every failure attempts exact staged cleanup and proves the final name absent. It can never leave a final pass-authority pathname. No uncertain descriptor number or pathname identity is retried or reused.

After the fixed upload step, the common owner performs identity-bound unlink of the exact published generation, fsyncs the directory, removes its exact private directory, and proves restoration of the report-path baseline. That cleanup runs after both successful and failed upload. Upload or cleanup failure makes the job and final required result fail; a retained report is not accepted as evidence. YAML may invoke only the fixed common cleanup entry and carry its fixed status, never implement file identity or unlink policy.

Portable fault injection covers short and interrupted writes, fsync, fstat, close-before/after-effect, fd reuse, reopen, short read, schema/semantic divergence, canonical drift, publish collision, no-replace publication, directory fsync, staged unlink, post-upload unlink, replacement, and upload-failure cleanup. Every cut proves either one exact validated publication followed by baseline restoration or no final path and a terminal failure.

### 4. Discriminated schema and independent semantic validation

`schemas/native-qualification-report-v1alpha1.json` is a closed discriminated union for `A`, `B`, `C`, `D`, `E`, and `integration`. Each branch fixes:

- its job and workflow job ID;
- exact check-array cardinality, order, IDs, and outcomes;
- its allowed metadata record variants, cardinalities, roles, sizes, and digest fields;
- the complete seven-key cleanup object; and
- pass or fail result state.

A pass branch requires every fixed check outcome and every cleanup value to be `pass`/`true`, with both `failure_phase` and `diagnostics_sha256` null. A fail branch retains the same exact check inventory, requires at least one failed check or false cleanup value, and requires both a bounded non-null failure phase and a non-null diagnostics digest. Duplicate logical IDs, extra/missing/reordered checks, generic substitution, an all-success fail, an all-success pass with failure data, and any cleanup/result contradiction reject.

Job A metadata binds each authenticated object role, size, SHA-256, SONAME where applicable, ordered `DT_NEEDED`, closure digest, and mapping digest. Job B metadata binds each source and sealed digest/size, exact seal mask, execution-mapping digest, and deterministic output digest. C/D/E metadata is limited to its fixed categorical or digest evidence and cannot expose descriptors, PIDs, start times, namespace IDs, mounts, paths, or raw syscall records. Integration fixes the exact production-result version and exact ordered field set and rejects every missing, renamed, substituted, extra, wrongly typed, or false field before deriving its report.

The common semantic validator is independent of both the producer codec and JSON Schema. It checks relationships JSON Schema cannot express, including checkout SHA equals admitted head SHA, attempt equals 1, repository/event relationships, workflow/job/driver identity, exact metadata identity uniqueness, and result/check/cleanup coupling. Production applies the tracked schema and semantic validator to the reopened staged bytes; the general schema-validation suite registers one valid sample per job and isolated hostile mutants. Calling the producer decoder twice is not independent validation.

### 5. Exact common and job cleanup baselines

Before the first job effect, common code captures exact source HEAD and porcelain/config state, an explicitly enumerated descriptor baseline, direct-child and owned-descendant state, mountinfo digest, user/PID/mount/network namespace identities, soft/hard `RLIMIT_NOFILE`, private path absence/identity, and the report-path baseline. Descriptor enumeration explicitly opens `/proc/self/fd`, parses and bounds entries through that exact descriptor, excludes only the enumerator descriptor, validates live entries, and closes through a one-shot lease.

Each job also captures the exact applicable owner registries and mechanism-specific state before mutation. After cleanup it rereads every common domain, including domains the job did not mutate. Each cleanup boolean is derived only from its named before/after observation. `dict.fromkeys(..., True)`, blanket success updates, operation labels, and “not applicable” represented as an unobserved success are forbidden. Failure reports preserve the individually observed cleanup values; unknown or uncertain is false and prevents pass.

Every descriptor, child, descendant, root, mount, namespace handle, path, and limit change is write-ahead registered before release or the next fallible effect. Cleanup uses one monotonic deadline, exact retained authority, identity revalidation, TERM then KILL only where required, bounded nonblocking reap, reverse-order descriptor and mount/path cleanup, original-limit restoration, and aggregate primary-plus-cleanup errors. Raw PID signaling, blocking `waitpid(..., 0)`, broad process scans as authority, lazy/force/recursive unmount, `rm -rf`, and runner disposal as proof remain forbidden.

A pass report is constructed only after the native transaction has restored all native/common baselines. The staged/published report itself is a separate fixed publication lease and must subsequently restore the report-path baseline under section 3 before the final required workflow result can pass.

### 6. Jobs A and B use admitted production owners

Job A no longer composes `_resolve_tool`, `_spawn_helper`, `_mapped_closure`, or `_stop_helper` as a test-owned lifecycle. It calls the actual admitted production closure owner through the fixed held-byte bootstrap. That owner authenticates the exact Python generation, performs production ELF closure and stable trusted `map_files` binding, owns the blocked helper and cleanup, and returns only the typed observations needed by A. A independently checks the fixed Job A result and outer common baselines; it does not recreate closure or helper ownership.

Job B no longer starts an ambient production module against an ordinary runner-owned checkout and impossible `/run` state-root precondition. The fixed bootstrap admits exact launcher/parser/closure/schema bytes and their generations before import, then calls the actual production launcher owner. A runner-owned checkout pathname or UID is never asserted to be trusted-root ownership and is never passed as final sandbox authority.

The admitted production route uses held exact-head source authority and an authenticated private runner-owned preparation root whose ownership is valid in the production user/mount transaction. The private root is selected by fixed production policy, opened and generation-bound before mutation, preregistered with the surviving production owner, never exposed to T2, and exactly removed. This does not weaken root/source admission, add sudo to B, accept an ambient import, trust caller-supplied source claims, or permit a caller-selected path. Missing user-namespace/root/private-state support is a typed fail-closed native failure, not a fallback.

B invokes the production closure/sealing/launcher transaction and independently requires the exact gzip/zstd source and sealed generations, seals, actual execution mappings, fixed `execveat` transition, deterministic outputs, policy denials, process cleanup, and outer common baselines. It does not duplicate production source admission, root construction, sealing, execution, or supervision.

### 7. Jobs C and D preregister and prove real mechanisms

C and D remain narrow native primitive jobs; they do not replace their mechanisms with portable models or completed observations.

Every C child is held behind a release gate. The owner obtains and registers PID, pidfd, start time, expected executable identity, session/process-group identity, release/status descriptors, and the original limit/fd state before release. If pidfd acquisition or registration fails, the gated child has performed no assigned effect and is boundedly reaped through retained creation authority. Reap is attempted regardless of readiness/status failure. C invokes the genuine production `close_range` primitive and proves exact soft-limit normalization, fds 198 and 4,096, CLOEXEC/inheritance, close-range behavior, child outcome, original-limit restoration, and exact fd/child baselines.

Every D leader and descendant is likewise created blocked. The outer owner registers the leader first; the registered leader reports a still-blocked descendant's complete identity and pidfd authority; the outer owner registers and acknowledges it before either process may perform the case. Spawn/handshake/status failure cannot leave an unregistered effectful process.

D uses the real production lifecycle primitives and separately observes each case. It checks exact parent status, `waitid` siginfo, `CLD_KILLED` and `SIGKILL` where parent-death killing is claimed, normal exits where required, pidfd/start-time revalidation, session/group ownership, TERM deadline, KILL escalation, adopted-descendant census, exact reap, restored subreaper state, and all common baselines. One death, reap, or blanket boolean cannot stand for another mechanism.

Portable tests drive scripted before/after-effect cuts through these real state machines, while the real syscall modes remain unreachable in portable runs. Branch-removal sentinels prove the registration gates, exact outcome checks, and cleanup paths are live.

### 8. Job E and thin integration use the admitted launcher owner

Job E invokes only the fixed admitted production sandbox-probe/launcher entry. Production code owns private-root creation, namespace ownership, mount setup/readback, UID/GID maps, capabilities, securebits, NNP, exact seccomp program, exec readiness, final fd/maps/noexec/no-proc checks, input release, process/descendant ownership, rollback, and observed-result construction. E deletes its duplicate `_root_setup`, private `_enter_boundary` composition, unbounded subprocess/pipe/wait ownership, and literal policy-label digest. Its report derives the policy digest and every sandbox check from the exact observed production result plus outer common baselines. E remains the only A–E job allowed the already accepted fixed noninteractive sudo envelope; sudo does not perform or replace production T2 ownership.

Thin integration invokes the same admitted production closure and launcher owners through the fixed bootstrap. It owns no parallel admission, unshare, pipe, process, root, mount, or cleanup implementation. It accepts exactly one versioned production result with the closed ordered field set specified by the schema/semantic contract. Counting booleans, accepting unknown fields, or substituting an unrelated true field for a required observation is forbidden.

The integration scenario remains thin: one fixed gzip input and one fixed zstd input, exact marker and output digests, exact handoff and source binding, no linked A–E evidence, and exact outer cleanup. All descriptors and children are preregistered before release/write; every write/read/status/close/reap path is bounded and aggregated by the production owner. Integration does not repeat A–E matrices or download their artifacts.

### 9. Portable acceptance and rereview

Without invoking a native selector, portable/static tests must prove at least:

- literal workflow selectors and all six common API/report paths agree;
- invalid event/attempt and every failed/skipped/cancelled dependency make the final required result fail while native code remains unexecuted;
- report staging, fsync/close/reopen, independent schema and semantic validation, no-replace publication, upload cleanup, and path-baseline restoration survive the complete fault matrix;
- all six discriminated golden reports pass and isolated job/check/order/result/failure/cleanup/metadata/source-envelope mutations reject;
- every cleanup value comes from an exact observation and every common baseline is captured and restored;
- A/B/E/integration call admitted production entries and cannot reach private substitute owners or impossible ambient-checkout admission;
- C/D register blocked children and descendants before effects, use genuine mechanism entry points, prove exact status/signal outcomes, and boundedly reap at every fault cut;
- E's facts and policy digest come only from the production observed-result builder; and
- integration rejects each missing, extra, renamed, false, or wrongly typed production field.

After ordinary portable/static gates, obtain fresh independent common/workflow, A/B, C/D, E/integration, schema/cleanup, and holistic exact-head hostile reviews. Resolve every P0–P3 finding before seeking separate native execution authority.

## Revised measured readable highs

All highs count gross added physical lines from exact predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`. Deletion, rename, generated-file, binary, compression, and code-movement credit remain forbidden. Blank and comment lines count. Highs are non-transferable and require ordinary readable formatting; one physical line may not hide multiple fallible security effects or cleanup decisions.

### Trusted closure and portable qualification — unchanged from ADR 0089

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

No trusted/portable high increases. Corrections needed to expose the actual admitted production owners must delete obsolete compatibility/substitute routes and remain within these accepted ceilings. Native allowance supplies no trusted-file credit.

### Native qualification and integration — raised

| Exact file | Hard high |
| --- | ---: |
| `.github/workflows/ci.yml` gross Outcome 2 addition | 300 |
| `schemas/native-qualification-report-v1alpha1.json` | 300 |
| `scripts/native-qualification/common.py` | 400 |
| `scripts/native-qualification/job-a-runtime-mappings.py` | 300 |
| `scripts/native-qualification/job-b-compression.py` | 350 |
| `scripts/native-qualification/job-c-descriptors.py` | 250 |
| `scripts/native-qualification/job-d-process-lifecycle.py` | 350 |
| `scripts/native-qualification/job-e-sandbox.py` | 450 |
| `scripts/native-qualification/thin-integration.py` | 350 |
| `test/native-qualification-common.test.ts` | 200 |
| `test/native-qualification-a.test.ts` | 120 |
| `test/native-qualification-b.test.ts` | 120 |
| `test/native-qualification-c.test.ts` | 120 |
| `test/native-qualification-d.test.ts` | 150 |
| `test/native-qualification-e.test.ts` | 180 |
| `test/native-qualification-integration.test.ts` | 150 |
| **Native subtotal and hard high** | **4,000** |

The individual native file ceilings sum to 4,090, but the independently binding native subtotal hard high is **4,000**. Therefore at least 90 lines of individual-file ceiling must remain unused; those 90 lines are not margin, are not transferable, and authorize no simultaneous consumption of every per-file high.

The binding listed trusted/portable and native subtotals total **12,930**. The Outcome 2 production, portable, native, and integration aggregate hard high is **13,000 gross physical lines**. The remaining 70-line aggregate margin is not transferable to a listed file and authorizes no unlisted surface. The separate non-authoritative capability-probe high remains 2,830 and supplies no credit.

Stop and adopt a new ADR before crossing any file, subtree, native subtotal, or aggregate high; adding or renaming an implementation surface; adding a dependency; changing the fixed jobs/integration scenario, source trust, report disclosure, execution contract, cleanup domains, or authority model; weakening fail-closed behavior; or moving security behavior into YAML, schema, fixtures, generated data, or tests.

## Authority and consequences

This ADR authorizes only the closed existing-surface correction and its portable/static verification. It grants **no native execution authority**: no `--workflow-bound` driver invocation, native A–E job, integration run, workflow dispatch/retry, sudo, namespace, mount, seccomp, `map_files`, compression qualification, or hosted capability observation may be performed under this decision. A later accepted ADR must identify a clean reviewed head and separately authorize any native attempt.

It grants no AWS, cloud, provider, OpenTofu, deployment, campaign, production, release, or issue-closure authority. Every existing AWS and mandatory-stop boundary remains in force. No AWS action may be inferred from a portable pass, review, workflow edit, or future native result.

The consequence is one fail-closed workflow ABI and required result, one independently validated atomic report transaction, exact cleanup evidence, real preregistered C/D mechanisms, and native callers that qualify admitted production owners rather than substitutes. The first native implementation remains non-authoritative review input until the complete correction receives clean exact-head hostile review.
