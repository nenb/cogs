# ADR 0048: Reduce Stage 2 rootfs qualification replay cost without weakening recovery

- Status: Accepted
- Date: 2026-07-25
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead under Nick Byrne's standing instruction to continue bounded local qualification and stop before AWS. This decision authorizes only the security-preserving rootfs performance work, the minimal ADR 0047 evidence correction, one test-portability correction, one subsequent non-authoritative Phase A candidate, and the cap change below. It retains the Phase B, staged, step-5, trigger/permission, campaign, and cloud gates.

## Context

ADR 0047 authorized one measured Phase A candidate after raising the local rootfs work and recovery limits. It required a stop after that candidate and did not authorize repeated timeout tuning, production qualification, or campaign use. ADR 0045 retains staged work through steps 2–4 and requires a stop before the step-5 seven-cycle controller.

Phase A run `30159926371` executed source revision `a8873f59f03e3d08c4f2e67d279929caca2cf737` (`a8873f5`). Its exact sanitized `cogs.stage2-phase-a-candidate/v1` report records:

- authority `candidate`, `qualified: false`, and candidate duration **1,524,279 ms**;
- first build `failed`, with `work_outcome: deadline` and total elapsed **1,503,114 ms**;
- second build `blocked` and never started;
- one recorded recovery attempt ending `over-bound` after **600,237 ms**;
- blockers `rootfs-first-build-deadline`, `observe-uncertainty`, `cleanup-uncertainty`, and `residue-uncertainty`;
- diagnostics `rootfs-recovery-exhausted` and `rootfs-baseline-not-restored`;
- no rootfs result and no host-tool, runtime, network, SSH, or coordinator authority; and
- `claims.network`, `claims.runtime`, `claims.ssh`, and `claims.coordinator_invoked` all false.

Render, validation, export, upload, and export cleanup completing did not promote the candidate. Rootfs state remained or could not be proven absent, and the runner correctly reported the baseline as unrestored; the sanitized artifact does not expose enough identity data to claim which exact state survived. Runner disposal is not cleanup proof. Run `30159926371` is therefore a **failed candidate**, not qualification evidence.

### Performance diagnosis

The fixed rootfs plan contains exactly **4,353 entries**: 538 directories, 3,477 regular files, 337 symlinks, and one hardlink. The accepted writer is doing avoidable superlinear work around that fixed graph:

1. every ledger append reconstructs and validates the complete record prefix, making successful append validation quadratic in the number of records;
2. every parent snapshot repeatedly lists the parent and obtains full identities for every existing sibling even though `LedgerParent` consumes the held parent generation and sorted child names; and
3. cleanup reparses the growing ledger, walks the shrinking tree, and reconciles the complete graph after nearly every durable record.

A successful build is expected to produce about 26,139 ledger records before ordinary cleanup and about 39,213 after cleanup. Static inspection of those repeated global operations and the intentionally large durability-barrier count provides a code-supported diagnosis consistent with the bounded failure. The candidate contains no syscall or structural-counter trace and therefore does not establish which cost dominated. It does not show that a build was near completion and is not evidence for another timeout-only increase.

Two reviewed replans disagreed on forward group commit. Batching could reduce `fsync` count, but it changes the accepted crash boundary: creating more than one name before each extant name's exact observed identity is durable can leave names that exact recovery must preserve as uncertain. Even a narrower observed/settled batching design would add a multi-pending ledger state and new crash semantics for uncertain benefit. This decision chooses only the optimizations that leave the scalar durable transaction model unchanged.

### Test portability observation

The portable Phase A test currently assumes that adding a regular file must change a directory's `st_size` or `st_nlink`. Directory size is filesystem-dependent and a regular child does not have to change the parent's link count. Failure of that assertion is a **test-portability defect only**. It is not evidence of a production identity, cleanup, or durability defect.

The assertion may be corrected in excluded test code so the test checks the intended cleanup/replacement behavior portably. That correction must not change production identity fields, generation checks, ownership semantics, or cleanup behavior and creates no counted-line credit.

### Frozen count and remaining plan

The ADR 0039 physical-line method, retained-file accounting, exclusions, and anti-evasion rule remain binding. At revision `a8873f5`, the conservatively measured cumulative count is **20,562 physical lines**:

| Frozen counted set | Lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` | 16,908 |
| Frozen historical schema/validator/renderer files named by ADR 0039 | 591 |
| `scripts/prepare-stage2-fixed-source.py` | 1,049 |
| `scripts/run-stage2-phase-a-candidate.py` | 1,673 |
| `scripts/stage2-phase-a-budget.py` | 73 |
| `schemas/stage2-phase-a-candidate-v1.json` | 268 |
| **Measured cumulative total** | **20,562** |

The rootfs and evidence-correction estimate is re-derived for this no-batching design by exact existing module surface:

| Authorized correction | Exact production surface | Counted estimate |
| --- | --- | ---: |
| D1 incremental automaton and O(1) active append history | `completion_rootfs_ledger.py`, `completion_rootfs_builder.py` | 220–330 |
| D2 stable parent-name snapshots and exact delta semantics | `completion_rootfs_fs.py`, `completion_rootfs_builder.py`, `completion_rootfs_ledger.py` | 160–240 |
| D3 poisoned scalar cleanup session and local proofs | `completion_rootfs_builder.py`, `completion_rootfs_ledger.py` | 280–400 |
| Structural counters and bounded reporting | Existing rootfs modules, Phase A runner/schema | 60–90 |
| Minimal ADR 0047 evidence correction | Existing Phase A runner/schema/budget files | 120–180 |
| **Rootfs plus evidence correction** |  | **840–1,240** |

The workflow wiring and excluded tests are mandatory but remain excluded by the frozen count method; they create no cap credit. The evidence allocation counts the runner, schema, and budget implementation conservatively. No batching codec, paired commit, or fsync deduplication is included.

The revised named remaining high estimate, with no deletion credit, is:

| Remaining named work | High |
| --- | ---: |
| Security-preserving rootfs and ADR 0047 evidence correction above | 1,240 |
| Separately gated Phase B committed-attestation qualification from the exact Phase B replan | 3,270 |
| Newer conservative steps 3–4 closure, candidate, qualification, and workload plan | 1,900 |
| Retained steps 5–7 controller, evidence, and readiness highs | 2,060 |
| **Total remaining high** | **8,470** |
| **Projected cumulative** | **29,032** |

The 1,900 step-3/4 high is the newer conservative remaining-work figure used by this decision rather than the older 1,580 high in the Phase B replan. The 2,060 step-5/7 high is the retained 780 controller, 980 evidence, and 300 readiness highs. The prior 25,500-line hard cap cannot contain the revised projection. Every later-slice figure is accounting only; including it does not authorize that slice or remove any stage gate.

## Decision

Authorize only D1 incremental ledger validation, D2 stable parent-name snapshots, D3 one full entry reconciliation per cleanup pass with scalar per-name transactions, the structural counters below, and the minimal ADR 0047 evidence correction. These changes supersede ADR 0040 only on the frequency of complete in-memory legal-record replay, active history representation, full sibling identity inspection for parent snapshots, and whole-ledger/whole-tree reconciliation inside cleanup loops. They do not supersede ADR 0040's canonical ledger, exact ownership, write-ahead, durability, identity, writer/walker, hardlink, publication, or uncertainty semantics.

### D1: incremental legal-record validation

Refactor the existing legal-record validator into one equivalent incremental state transition:

- every fresh owner, reopen, or recovery starts by parsing and validating the complete canonical ledger from byte zero;
- the resulting immutable in-memory legal state remains bound to the exact held ledger inode, offset, and settled hash;
- active record history uses an O(1) append representation and must not perform `active.records + (record,)`, tuple reconstruction, or any equivalent prefix copy; a complete ordered view may be materialized only at a full authority boundary that already requires replay;
- append validates exactly the proposed next record against that state, writes the same one canonical record, performs the same ledger `fsync`, and advances durable in-memory state only after the existing write, sync, identity, and close checks succeed; and
- complete parse/replay remains mandatory on every fresh open, before lease or publication authority, before operation retirement/final zero authority, and at other existing independent authority boundaries.

For every legal and hostile history, incremental advance and full replay must produce equivalent state or the same rejection. In-memory state is never persisted as authority, trusted across reopen, or used to repair a malformed or uncertain ledger tail.

D1 changes no record body, hash-chain rule, sequence, offset, record limit, canonical bytes, append count, `fsync` boundary, rollback rule, or failure classification.

### D2: exact stable parent-name snapshots

Replace full sibling identity scans only where the ledger contract consumes names rather than sibling identities. The bounded helper must preserve these two distinct comparisons:

- **Within one snapshot:** the complete held parent generation must remain exactly equal before, between, and after repeated stable sorted byte-name listings, and every listing must contain the same exact byte names. Any inode, mount, mode, owner, nlink, size, mtime, ctime, or name drift rejects the snapshot.
- **Across the intended mutation:** preserve current `_parent_delta` semantics. Pre/post parents must have the same exact key, mode, UID, and GID and the names must have exactly the intended one-name addition or removal. Nlink, size, mtime, and ctime may change as legitimate consequences of the mutation; arbitrary drift may not. The complete post generation becomes the exact expected generation for the next action.

The helper must also capture the exact child identity for the one name actually created, linked, removed, or revalidated. It retains component-relative no-follow traversal, complete held-operation-root-to-parent validation, byte-preserving name checks, mount/device policy, replacement resistance, deadline checks, and fail-closed handling of unstable or ABA observations under the existing privileged-mutator exclusion. It must not stat/open every unaffected sibling merely to populate information absent from `LedgerParent`.

Use this helper only at parent-name snapshot call sites. Fresh-open, recovery, postwalk, retirement, and final complete walkers continue opening and identifying every child. Differential tests must cover directory create/remove nlink changes, regular-child directory-size behavior on multiple filesystems, timestamp changes, parent inode replacement, mode/owner drift, same-name replacement, and unstable/ABA observations, and must match current `_parent_delta` acceptance and rejection.

D2 does not authorize pathname fallback, reduced child identity, inferred ownership, relaxed hardlink checks, a second walker, a parent cache with stale authority, or omission of final complete walks.

### D3: one full entry reconciliation per cleanup pass

A fresh cleanup or recovery pass begins with one complete fresh-open ledger parse, full operation walk, and exact graph reconciliation. That proven state initializes an in-memory cleanup session. Full checks before operation removal, before ledger unlink, and at final baseline/zero authority remain separate mandatory lifecycle boundaries; “one” does not remove them.

For every scalar name, the session must complete this local proof before touching another name:

1. Revalidate the complete held operation-root-to-parent chain, exact operation-root generation, exact held parent and expected `LedgerParent` names/generation, exact child generation, ledger inode/hash/offset and legal phase, and hardlink target generation/count where applicable.
2. Append and `fsync` the existing separate intent record. At that durable boundary update the exact ledger inode/hash/offset binding and legal phase together to intent-durable, while retaining the proven pre-mutation filesystem model.
3. Perform only the exact authorized unlink/rmdir, revalidate the complete held operation-root-to-parent chain, and obtain a stable post-parent snapshot. Prove the exact one-name delta, exact child absence, and exact hardlink target/count transition where applicable; complete every existing object/target and parent durability barrier and readback.
4. Append and `fsync` the separate observed record. Update the operation-root generation, affected `LedgerParent`, owned-child/absence state, hardlink target generation, ledger inode/hash/offset binding, and legal phase together to the exact **observed-durable** state.
5. Append and `fsync` the separate settled record, then update those bound fields together to the exact **settled-durable** state. Observed and settled are distinct states and must never be collapsed, paired, buffered, or acknowledged by one sync.

Any exception, failure, deadline, cancellation, rollback, failed or uncertain append, `fsync`, readback, identity/generation check, durability proof, or close immediately **poisons and discards** the cleanup session. No next name may be touched, even if an observed record appears durable or rollback appears successful. Recovery must fresh-open the fixed authority and perform a complete replay, walk, and reconciliation before any further mutation. No in-memory session state survives a return, interruption, reopen, or uncertainty.

The per-name loop must not reparse the entire ledger, rewalk the entire operation, or reconcile the whole graph after every append. “Per cleanup pass” never means adopting a name by containment, plan membership, deterministic bytes, or apparent absence. Unknown, replaced, malformed, contradictory, partially observed, over-bound, or timed-out state remains preserved.

### No batching or timeout increase

This decision explicitly does **not** authorize group commit or batching. In particular, it authorizes no:

- multi-name intent, observed, settled, or pending record;
- buffered or paired ledger commit that removes an existing record-level `fsync`;
- creation of a next name before the prior extant name's exact identity is durably recoverable;
- per-parent namespace durability aggregation;
- batching of metadata, hardlink, cleanup, lease, publication, or retirement transitions; or
- configurable batch size or alternate transaction version.

Any future batching proposal requires a separate accepted ADR with an exact crash/power-loss model and evidence that every extant name remains tied to durable exact identity. This decision also does not authorize fsync deduplication.

All ADR 0047 timing values and layering remain unchanged:

- one shared **900-second** `BUILD_SECONDS`/`MATERIALIZE_SECONDS` deadline per build;
- **600 seconds** maximum for one inline cleanup or exact recovery pass;
- **2,400 seconds** for the local two-build outer envelope;
- **3,300 seconds** for Phase A observation;
- the unchanged **90-minute** workflow guard, 600-second setup boundary, `anchor + 3900` observe boundary, 1,500-second `always()` reserve, and final 300-second mandatory-work reserve.

The two 900-second enforcement points are not additive. Although ADR 0047 permits at most two conditional passes, the current runner/schema implement one; the next candidate retains **exactly one** recovery attempt of at most 600 seconds. This decision does not authorize a second attempt or its schema/runner wiring. There is no 1,200/3,000 increase, retry, rerun substitution, fallback, or erosion of cleanup/reporting reserve.

## Minimal ADR 0047 evidence correction

Before the next candidate, authorize and count only the schema/runner/budget changes and narrow existing-workflow wiring needed to satisfy retained ADR 0047 evidence requirements.

The candidate schema and runner must always emit the fixed rootfs phases `first-build-work`, `first-inline-cleanup`, `second-build-work`, `second-inline-cleanup`, `recovery-attempt-1`, `equality`, `pin`, `post-verification`, and `settlement`. Every phase has exactly one status from `success`, `failure`, `blocked`, or `not-reached`, a bounded categorical outcome, and `elapsed_ms`:

- `success` and `failure` mean the phase was attempted and carry its measured monotonic elapsed time;
- `blocked` means a failed or uncertain prerequisite prohibited the phase and has zero elapsed time;
- `not-reached` means the enclosing bounded observer ended before the phase could be selected and has zero elapsed time; and
- a null rootfs result, early return, deadline, or exception may not omit a phase row.

First- and second-build work and their inline cleanup are separate phases; pooled build time is insufficient. Work failure distinguishes deadline from other bounded categories. Recovery remains exactly one separately timed attempt. Equality, pin, post-verification, and settlement remain explicit even when blocked or not reached. These fields are diagnostic candidate evidence only and cannot issue a permit.

The existing workflow may be changed only to enforce this order at the end:

1. render, validate, and export the metadata-only candidate report;
2. upload that report under the existing bounded artifact policy;
3. perform exact export cleanup through the existing exact-owner route;
4. run a new **independent read-only post-export-cleanup residue step** covering rootfs baseline, exact cache, candidate assets, state, and exported-report absence; and
5. enforce export-cleanup and final-residue outcomes in the job result.

The final residue step performs no cleanup and cannot convert uncertainty to absence. The uploaded report remains `authority: candidate`, `qualified: false`, and non-authoritative; neither workflow success nor the added step promotes or rewrites it. No second workflow, trigger change, permission increase, dispatch/push/schedule route, retry, or cloud path is authorized.

## Structural counters and non-linearity boundary

Production/test instrumentation and the candidate's bounded metadata must count, per fixed rootfs phase:

- record-reference copies caused by active-history append;
- total byte names returned across all directory listings;
- parent snapshots;
- complete legal-record folds;
- complete filesystem walks; and
- incrementally advanced ledger records.

Active append must copy no existing record prefix and must remain O(1) with respect to active history length. Tests must set fixed structural ceilings showing that complete folds and walks occur only at the authorized fresh-open/pass/final boundaries, never per record or per name. Parent snapshots and total listed names must be reported separately because repeated complete name listings can remain superlinear in high-fanout directories. These counters are bounded non-sensitive integers and expose no paths, names, ledger bytes, host identities, or commands.

D1–D3 remove the diagnosed full-prefix replay, unaffected-sibling identity scans, and per-record whole-tree reconciliation. They do **not** claim end-to-end linear runtime. No linearity or deadline-margin claim may be made until the counters and candidate timings demonstrate it.

## Next Phase A candidate

After D1–D3, the evidence correction, structural counters, and portable test correction receive portable and hostile review, authorize exactly **one** subsequent non-authoritative Phase A candidate using the narrowly amended ADR 0046 pull-request-only workflow on the exact reviewed clean head.

Before that candidate:

1. portable tests must pass without filesystem-specific directory-size assumptions;
2. incremental/full ledger differential tests must cover every legal and hostile transition and O(1) active-history append without prefix copying;
3. parent-name tests must cover high fanout, replacement, concurrent name drift, unstable/ABA listing, within-snapshot full-generation equality, `_parent_delta` pre/post semantics, and exact one-name deltas;
4. cleanup fault tests must interrupt around every scalar intent, mutation, durability barrier, observed append, settled append, readback, and close and prove immediate session poisoning followed by fresh replay/walk/reconciliation;
5. structural counters must meet the reviewed fixed ceilings for record copies, listed names, parent snapshots, full folds, and complete walks;
6. the fixed 4,353-entry graph and committed manifest/ustar pins must remain unchanged;
7. every required evidence phase and the independent post-export-cleanup residue step must be structurally present and enforced; and
8. the frozen count and revised remaining high must remain below the hard cap.

The candidate may make only bounded metadata-only observations allowed by ADRs 0046–0048. It may not tune a bound, broaden the workflow, dispatch itself, retry, add a second recovery attempt, feed Phase B automatically, or become qualification authority. First-build uncertainty still blocks the second build. Exact cleanup, exact export cleanup, and the independent final read-only residue step must all pass for a successful candidate observation.

Stop after that one candidate for explicit measurement and replan. Phase B still requires separately reviewed committed attestations and independent reproduction at a later exact clean revision; this ADR's estimate does not authorize Phase B implementation or execution.

## Cumulative cap

Amend only ADR 0045's numeric cumulative Stage 2 limits:

- preferred cumulative target: **29,500 physical lines**;
- hard cumulative cap: **31,500 physical lines**.

From the measured 20,562 baseline, these leave 8,938 preferred lines and 10,938 hard-cap lines. The preferred target is **468 lines** above the 29,032 projected cumulative high. The hard cap leaves a **2,468-line** margin above that projection.

The margin is reserved for readable review-driven corrections within already accepted scope. It grants no later slice, module, transaction mechanism, qualification claim, workflow change beyond the minimal evidence wiring above, or execution authority. Every earlier 24,000 preferred-target and 25,500 hard-cap reference and numeric stop threshold in ADRs 0045–0047 is superseded by 29,500 and 31,500. The frozen counted set, physical-line method, retained-file accounting, exclusions, anti-evasion rule, and no-deletion-credit method remain unchanged.

After each counted production slice, report the complete frozen count and revise every remaining named range. Stop before further counted implementation whenever `actual frozen count + revised remaining high >= 31,500`, or whenever implementation itself would reach 31,500.

## Retained gates and non-authority

Every non-numeric requirement and stop gate in ADRs 0038–0047 remains binding. In particular:

- step 2 must establish its complete rootfs and authoritative local lifecycle gates before step 3;
- step 3 must pass before step 4, and step 4 must pass before arrival at step 5;
- **stop before step 5**; the seven-cycle controller remains unauthorized regardless of unused line cap;
- the immutable 16 rootfs artifacts, exact ten packages, direct one-writer/one-walker route, root policy, complete postwalk, deterministic two-build equality, pins, retained lease, canonical mounts, fixed runtime/network/SSH contracts, and exact teardown remain unchanged;
- no second writer/walker, external or staged extractor, host tar, package change, source drift, rootfs pin drift, alternate path, mount relocation, tmpfs rootfs, special filesystem, fallback, force/lazy/recursive cleanup, broad deletion, or unknown-to-absent conversion is authorized; and
- Phase A remains candidate-only and cannot satisfy Phase B, runtime, campaign, evidence-publication, issue-closure, release, or production gates.

No AWS credential, CLI, account lookup, provider, OpenTofu plan/inventory/apply, SSM action, workflow dispatch, deployment, resource creation, cloud cleanup, or campaign activity is authorized. This documentation-only task performs no network, workflow, cloud, or production action.

## Consequences

The next rootfs correction removes the diagnosed full-ledger replay per append, unaffected-sibling identity opens, tuple-prefix copying, and whole-tree reconciliation per cleanup record without changing the accepted scalar durability boundary. Repeated complete name listings and required fresh/final authority checks remain and are measured rather than described as fully linear.

A successful next candidate would still be only bounded performance, phase, cleanup, and residue evidence for another review. A failed, missing-phase, late, or uncertain candidate stops again. The larger cap permits readable accounting for the accepted roadmap but does not authorize Phase B, steps 3–7, step 5, a campaign, or any cloud action.
