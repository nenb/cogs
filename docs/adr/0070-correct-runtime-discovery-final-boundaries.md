# ADR 0070: Correct runtime-discovery final boundaries

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Amendment scope: Amend four ADR 0069 non-transferable Phase B per-file gross-addition maxima; authorize only the existing `scripts/stage2-phase-a-budget.py` plus the existing candidate workflow's fixed literal profile wiring to set the exact runtime-discovery internal schedule below; and clarify the independent responsibilities of the Phase B JSON schema and strict production canonical codec. The absolute Phase B high remains 3,310, the outer workflow timeout remains 5,400 seconds, and every non-conflicting ADR 0065–0069 requirement remains binding.

## Context

The corrected hostile integrated rereview is recorded in `/tmp/runtime-final-rereview.md`. It reviewed the working tree from exact baseline `84b30d30b3307f1c5222dd9e50dfa755cdee673a`, not a clean exact final head. It found no P0, but kept the `phase-b-runtime-discovery` event gate and the sole local actual-size evidence gate closed. P1-01 was statically corrected; P1-02 through P1-06, P2-01, and P3-01 were not all closed, and the rereview identified concrete remaining P1 defects in anonymous-inode qualification and export readability, outer-owner authentication, failed archive-child settlement, the post-loader/pre-input closure handshake, PAX/GNU semantics, schema/codec testing, and enforcement of the final internal deadline.

The rereview measured these gross additions against the same exact baseline:

| Counted file/surface | Current gross additions | ADR 0069 high | Position |
| --- | ---: | ---: | --- |
| `scripts/run-stage2-phase-a-candidate.py` | 445 | 450 | 5 remaining |
| `completion_kata_qualification.py` | 357 | 450 | 93 remaining |
| `completion_kata_process.py` | **850** | **850** | at high |
| `completion_kata_runtime.py` | 424 | 800 | 376 remaining |
| Phase B schema | 299 | 300 | 1 remaining |
| Other counted Phase B files | 0 | retained individual highs | unchanged |
| **Absolute Phase B aggregate** | **2,375** | **3,310** | **935 remaining** |

The aggregate remains sufficient, but process is at its high, the schema has one line, and the runner has five lines. The exact remaining ownership, settlement, schema, schedule, authentic-test, and readability corrections cannot be presented soundly by compression within those stale individual maxima.

ADR 0069 also required a final internal boundary no later than +5,280 seconds but permitted earlier boundaries merely to be narrowed as necessary. The implementation retained upload and cleanup boundaries after +5,280, so the final check could fail only after those mutations. The schedule must instead be concrete and enforce each operation before the final boundary.

Finally, ADR 0069 described schema-codec equivalence too broadly. JSON Schema can independently express and enforce the report's structural domain, but it cannot recompute discovered digests and sums or prove closure-wide and cross-field semantic relationships. Treating `schemaAccepts(value) && codecAccepts(value) == false` as the only hostile assertion hid that distinction: the assertion passed when the schema incorrectly admitted a structural hostile, and it also mislabeled intentional semantic layering as inequivalence.

## Decision

### Exact runtime-discovery schedule

Authorize one route-isolated schedule in the existing `scripts/stage2-phase-a-budget.py`. The existing candidate workflow must set literal `COGS_STAGE2_BUDGET_PROFILE=phase-b-runtime-discovery` before its first budget call. The budget script must accept only that exact value or absence; absence preserves the complete legacy `BOUNDARIES` mapping byte-for-byte for the consumed rootfs workflow and every other existing caller, while the exact profile selects the mapping below. Any unknown, empty, duplicated, caller-derived, or mismatched profile fails closed. No event, label, input, API result, or environment outside the reviewed literal workflow wiring may select it. Measured from the existing monotonic anchor, its complete internal boundaries are:

| Boundary | Absolute offset |
| --- | ---: |
| source | +600 seconds |
| observe | +3,900 seconds |
| cleanup | +4,980 seconds |
| residue | +5,040 seconds |
| render | +5,080 seconds |
| validate | +5,120 seconds |
| export | +5,160 seconds |
| upload | +5,170 seconds |
| export-cleanup | +5,260 seconds |
| post-residue | +5,275 seconds |
| final | +5,280 seconds |
| outer workflow timeout | +5,400 seconds |

The post-residue operation may start only after export-cleanup and must complete by +5,275; there is no separately later start boundary. The final guard must run no later than +5,280, leaving at least 120 seconds for platform completion. A phase must check its own boundary before beginning and fail closed if late; a later final failure cannot legitimize an upload, export cleanup, or other mutation started after that operation's boundary.

This is the only stage/deadline amendment. It does not change the source or observe values, the legacy mapping, the 5,400-second outer timeout, the non-borrowing rule, any lifecycle-discovery, authoritative, workload, rootfs, or other stage boundary, or any timeout, kill reserve, retry, recovery count, event, or attempt rule. The workflow receives only the fixed literal profile binding; it gains no selector or general schedule authority.

### Independent schema and codec enforcement

Supersede only ADR 0069 P1-06's requirement that the JSON schema and production codec accept exactly the same domain. Replace it with layered, independently tested enforcement:

1. The Phase B JSON schema must independently reject every invalid bound representable in the existing JSON Schema design. This includes the complete required/additional-property structure; exact constants and role values; JSON scalar types without bool/integer coercion; string, numeric, and array bounds; required role and executable/loader cardinalities; and every representable fixed-position, array-order, and structural-order constraint.
2. The strict production canonical codec must enforce that structural contract and additionally enforce the semantic domain that schema cannot derive: discovered and recomputed digests; per-closure, per-type, per-link, and aggregate sums; canonical encoding and canonical discovered ordering; closure-wide `DT_NEEDED` satisfaction; blocker/check derivation; and every cross-field arithmetic or consistency relationship used before qualification.
3. The exact report must pass the real schema validator and the strict production canonical codec before upload. Rejection or uncertainty in either blocks export/upload and enters the retained cleanup path.

Tests must exercise the real validators independently. Every structural hostile must have a direct assertion that the schema rejects it. Every structurally valid semantic hostile—including wrong digest, wrong total or aggregate sum, unresolved `DT_NEEDED`, invalid discovered order, and inconsistent cross-field arithmetic—must have a direct assertion that the strict codec rejects it. Valid canonical reports must pass both. A test that asserts only that the conjunction of schema and codec acceptance is false is prohibited: it neither proves independent schema rejection of structural hostiles nor independent codec rejection of semantic hostiles.

This clarification does not broaden the upload shape, weaken the canonical codec, permit a schema-representable constraint to be deferred to the codec, or permit a semantic constraint to be omitted because JSON Schema cannot express it. Both layers remain mandatory before upload.

### Per-file highs

Replace only the process, runner, budget-script, and schema maxima. The complete Phase B maxima become:

| Counted file/surface | ADR 0069 high | Revised high |
| --- | ---: | ---: |
| `scripts/run-stage2-phase-a-candidate.py` | 450 | **520** |
| `scripts/stage2-phase-a-budget.py` | 0 | **30** |
| `completion_kata_qualification.py` | 450 | **450** |
| Phase B schema | 300 | **340** |
| `completion_kata_actions.py` | 40 | **40** |
| `completion_kata_operation.py` | 400 | **400** |
| `completion_kata_process.py` | 850 | **1,000** |
| `completion_kata_inputs.py` | 260 | **260** |
| `completion_kata_network.py` | 280 | **280** |
| `completion_kata_runtime.py` | 800 | **800** |
| `completion_kata_ssh.py` | 90 | **90** |
| `completion_kata_coordinator.py` | 500 | **500** |
| `run-stage2-completion-remote.sh` | 20 | **20** |
| **Absolute Phase B high** | **3,310** | **3,310** |

Against the rereviewed tree, the revised room is 75 lines in the runner, 30 in the route-isolated budget script, 93 in qualification, 150 in process, 376 in runtime, and 41 in the schema. Those individual margins are not additive authority. Only 935 aggregate lines remain across all counted Phase B surfaces, and the unchanged 3,310 aggregate is always binding.

Gross additions remain measured against exact baseline `84b30d30b3307f1c5222dd9e50dfa755cdee673a`. Deletion, replacement, rename, movement, generated code, test/workflow placement, excluded-surface placement, or presentation compression creates no credit. Unused room in one file cannot fund another file, surface, or behavior. The highs are maxima, not targets; stop and replan before crossing any individual high or the aggregate.

## Exact P1 corrections remain required

This ADR does not waive or itself resolve any concrete P1 finding in `/tmp/runtime-final-rereview.md`. The correction must retain P1-01's statically corrected exhaustive cross-head marker guard and complete all of the following before signoff:

- **Anonymous input and upload-readable export:** the production descriptor pin must explicitly accept the verified anonymous `O_TMPFILE` route with link count zero while preserving its anonymity and exact identity; it must not weaken the linked-file rule for other descriptors. The root-owned mode-0400 discovery report must not be handed directly to the non-root upload action. Validation/export must create a separate, identity-bound, runner-readable upload object, and retained cleanup must remove exactly that owned export.
- **Authenticated outer ownership:** creation must reject a pre-existing fixed owner name, and recovery must authenticate the exact owner rather than trust self-described state from `/var/tmp`. It must require and revalidate the protected creator/owner identity, root ownership, mode 0600, link count one, exact inode and digest chain, and every retained source/parent baseline. Unauthenticated, forged, foreign, replaced, or uncertain state must fail closed without signaling or deletion. Authentic initialization, publication, export, and cleanup crash cuts must be tested.
- **Non-terminal failed settlement:** `runtime-stream-settled` may suppress durable recovery only after the exact child has been reaped, the archive operation succeeded, all mandatory descriptors settled, and exact leader and descendant absence is proved. Timeout, error, unreaped child, or remaining descendant must remain durably recoverable. A fresh cleanup process must recover from the durable SID/PGID and exact-PID records and prove process residue without relying on process-local sets.
- **Post-loader, pre-input closure binding:** successful kernel `exec` or CLOEXEC status-pipe closure alone is not readiness. Each Python/gzip/zstd path must provide an authenticated post-loader/pre-read handshake, or an equivalent proof, while archive input remains blocked. The actual mapped loader/library closure must be descriptor-opened, hashed, and rechecked before any archive byte can be consumed; later executable mapping, partial mapping, or handshake uncertainty blocks discovery.
- **Strict PAX/GNU semantics:** global PAX `g` headers and every other unsupported or unknown extension semantic must be rejected, not counted as ordinary unsupported members. GNU long-link `K` must be rejected when inapplicable to the following member, including a non-link member. Retain all ADR 0069 suffix, fixed-field NUL, duplicate/conflicting/unknown local-PAX, genuine long-name, and exact-role requirements.
- **Layered schema/codec proof:** implement and test the independent schema and strict codec responsibilities above. Structural hostiles must be rejected by schema itself and semantic hostiles by the codec itself; the prior false conjunction is not evidence.
- **Effective final boundary:** the exact schedule above must prevent upload and cleanup mutations from starting after their own boundaries and must complete post-residue and final checks by +5,275 and +5,280 respectively.

These requirements are concrete additions to, not substitutes for, every non-conflicting P1-01 through P1-06 condition retained by ADR 0069. A summary-level or source-text assertion that does not exercise the production primitive is insufficient.

## Evidence, checks, and exact review

P2-01 and P3-01 remain open until proved otherwise. Required tests must use production primitives and include the authentic ownership/report/export crash cuts, failed-settlement later-process recovery, post-loader/pre-input gzip/zstd paths on native Linux amd64, strict PAX/GNU cases, independent schema and codec hostiles, the exact schedule, and ordinary readable security transitions. The schema must be tracked.

ADR 0069's sole local exact-size execution is not renewed or replaced. It remains ineligible until the implementation is locally complete, generated/fault tests pass, native-Linux checks are established, and its unconsumed state is proved. Uncertainty about prior consumption is a stop. This ADR authorizes no local evidence retry or substitute.

Before any `phase-b-runtime-discovery` event, run all checks required by ADRs 0065–0069, including formatting, type checking, schema validation, Python and TypeScript Kata companions, native Linux process coverage, authentic crash cases, `git diff --check`, and the full local check suite. Record the clean predecessor, exact final 40-hex head, physical lines, gross additions for every counted file, the complete Phase B aggregate, applicable peak RSS and phase timings, and every test outcome.

Obtain a new independent hostile review of the exact baseline-to-final-head range. It must explicitly verify every concrete P1 correction above, P2-01, P3-01, the schema/codec split, the exact schedule, all retained ADR 0065–0069 boundaries, and every count, with no unresolved P0–P3 finding. Any code, workflow, test, schema, or documentation change after review invalidates signoff. Until then, the runtime-discovery event gate remains closed.

## Retained boundaries and consequences

The absolute Phase B high remains 3,310. The conservative projection remains:

`26,074 no-deletion reserve + 3,310 Phase B + 1,900 steps 3–4 + 2,060 future = 33,344 < 34,000`.

The 656-line hard-cap margin grants no implementation allowance. The 32,000 preferred target remains exceeded and documented, and the 34,000 hard cap is unchanged.

Except for the route-isolated schedule/profile binding, schema/codec responsibility clarification, and four individual highs above, this ADR changes no implementation file set, production behavior, owner model, archive policy, report shape, stage order, deadline, timeout, non-borrowing reserve, event count, event-consumption rule, trigger, permission, token boundary, attempt count, retry, rerun, fallback, recovery count, production permit, workload authority, step-5 stop, release authority, issue-closure authority, cloud boundary, or AWS authority.

Acceptance authorizes no label, ready transition, event, run, acquisition, upload, KVM/rootfs/lifecycle action, production use, workload, campaign, deployment, cloud action, or AWS action. It creates no retry or replacement authority. The consequence is only enough non-transferable room for the already-required corrections, one exact enforceable runtime-discovery schedule under the unchanged outer timeout, and truthful layered validation before upload. This proposed documentation-only ADR creates no implementation or operational authority until accepted.
