# ADR 0069: Reallocate runtime-discovery correction highs

- Status: Proposed
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Amendment scope: Amend four non-transferable ADR 0068 Phase B per-file gross-addition maxima: `scripts/run-stage2-phase-a-candidate.py` from 240 to 450, `completion_kata_qualification.py` from 320 to 450, `completion_kata_process.py` from 600 to 850, and the Phase B schema from 220 to 300. Also authorize exactly one bounded local pre-event actual-size evidence execution and move only the final internal software boundary from 5,400 to at most 5,280 seconds while retaining the 5,400-second outer timeout. `completion_kata_runtime.py` remains 800, every other per-file high and the absolute Phase B high of 3,310 remain unchanged. Every non-conflicting ADR 0065–0068 requirement remains binding.

## Context

The hostile integrated review of the ADR 0068 runtime-discovery implementation is recorded in `/tmp/runtime-discovery-review.md`. It kept the `phase-b-runtime-discovery` event gate closed with exact findings P1-01 through P1-06, P2-01, and P3-01. The review was of an uncommitted working tree, not an exact final 40-hex head, and is neither an implementation signoff nor event authority.

Against exact baseline `84b30d30b3307f1c5222dd9e50dfa755cdee673a`, the review measured these gross additions:

| Counted file/surface | Current gross additions | ADR 0068 high | Position |
| --- | ---: | ---: | --- |
| `scripts/run-stage2-phase-a-candidate.py` | **240** | **240** | at high |
| `completion_kata_qualification.py` | **320** | **320** | at high |
| `completion_kata_process.py` | 591 | 600 | 9 remaining |
| `completion_kata_runtime.py` | 391 | 800 | 409 remaining |
| Phase B schema | **220** | **220** | at high |
| **Absolute Phase B aggregate** | **1,762** | **3,310** | **1,548 remaining** |

The aggregate has ample room, but three files are at their non-transferable maxima and the process owner has only nine lines remaining. Correcting durable ownership, process supervision, schema equivalence, authentic tests, and readability by deleting or compressing the rejected code would conflict with the review. Runtime itself retains enough room and needs no revised maximum.

The counted defect is a per-file distribution defect, not evidence that the accepted aggregate or global cap is insufficient. The same review independently proves two pre-event execution-boundary defects: ADR 0068 supplies no authority to run its mandatory exact 1.55 GB evidence before the event, and the final 5,400-second software boundary equals the outer timeout rather than leaving platform completion margin. This ADR corrects only those two boundaries; it does not add a hosted event, retry, outer-timeout increase, workflow authority, cloud authority, or AWS authority.

## Decision

If accepted, replace only the four per-file maxima identified below. The complete Phase B maxima become:

| Counted file/surface | ADR 0068 high | Revised high |
| --- | ---: | ---: |
| `scripts/run-stage2-phase-a-candidate.py` | 240 | **450** |
| `completion_kata_qualification.py` | 320 | **450** |
| Phase B schema | 220 | **300** |
| `completion_kata_actions.py` | 40 | **40** |
| `completion_kata_operation.py` | 400 | **400** |
| `completion_kata_process.py` | 600 | **850** |
| `completion_kata_inputs.py` | 260 | **260** |
| `completion_kata_network.py` | 280 | **280** |
| `completion_kata_runtime.py` | 800 | **800** |
| `completion_kata_ssh.py` | 90 | **90** |
| `completion_kata_coordinator.py` | 500 | **500** |
| `run-stage2-completion-remote.sh` | 20 | **20** |
| **Absolute Phase B high** | **3,310** | **3,310** |

Against the measured tree, the revised individual room is 210 lines in the runner, 130 in qualification, 259 in process, 409 in runtime, and 80 in the schema. These margins are not additive authority. Only 1,548 aggregate Phase B lines remain across every counted surface, and the 3,310 aggregate remains binding even though the sum of independent file ceilings is larger.

Gross additions remain measured against exact baseline `84b30d30b3307f1c5222dd9e50dfa755cdee673a`. Deletion, replacement, rename, movement, generated code, test or workflow placement, excluded-surface placement, or presentation compression creates no credit. Unused room in one file cannot fund another file, another surface, or another behavior. The highs are maxima, not targets; stop and replan before crossing any per-file maximum or the unchanged aggregate.

## Exact correction obligations

This numeric amendment does not waive, narrow, or itself resolve any review finding. P1-01 through P1-06, P2-01, and P3-01 must be corrected in full. The following requirements preserve, and do not replace, the exact review text.

### P1-01: one cross-head marker gate

The earliest-run guard must enforce one consumed gate for the literal stage marker across heads. It must exhaustively inspect the relevant workflow runs without making the current `head_sha` a visibility boundary, recognize an earlier exact `phase-b-runtime-discovery` marker run even when that run has another head, and fail the current run before mutation. A new head cannot hide or renew a consumed marker.

The guard must retain all existing exact repository, workflow, PR, same-repository head/base, labeled-event, literal-marker, reviewed-head, attempt-1, token-isolation, exhaustive-pagination, malformed-response, and fail-closed checks. It may emit no run listing or token material. This is a correction enforcing ADR 0068's existing singular gate, not authority for a new gate or event.

### P1-02: durable file, state, and export ownership

A recoverable durable outer owner must exist before creation of the runtime state tree, journal, anchor, or other owned state. Every later mutation must be recoverable from durable identity-bound state; intent alone must never authorize adoption or deletion of an existing object.

Runtime downloads must use anonymous `O_TMPFILE` inodes. No named partial download is permitted. The implementation must retain and validate the anonymous inode identity through size and SHA-256 verification and publish only by the existing exact final-cache transaction. Unsupported anonymous-inode semantics, uncertain publication, or loss of identity is a stop, not permission to fall back to a named partial.

Evidence and export creation, cleanup, and crash recovery must likewise derive destructive authority from identities durably captured before the relevant mutation. Cleanup must never infer ownership from an intended pathname, root ownership, mode, size bound, or a digest first observed during recovery. Every initialization, write, publication, export, close, and cleanup cut must either recover the exact owned object or fail closed without deleting foreign state.

### P1-03: complete archive-child ownership

The archive-child intent must be durable before `fork`. The child must remain behind a parent-owned gate until the parent has durably recorded and revalidated the exact child identity needed for recovery.

Every archive child must set `PR_SET_PDEATHSIG` before exec, verify by handshake that the expected parent remained alive across that setup, and exit without consuming archive input when the handshake or parent identity fails. Parent death after release must not leave a decompressor or helper running.

Normal and later-process recovery must causally capture and revalidate descendants, scan for reparented descendants that retain the owned lineage/PGID/SID identities, narrowly TERM and bounded-KILL only exact owned processes, reap children when possible, and prove leader and descendant absence. Leader disappearance alone is not cleanup success, and process-local sets cannot substitute for durable later-process recovery.

### P1-04: bind the closure that actually executes

Executable closure claims must bind the loader and libraries actually mapped by the running executable, not objects previously read through raceable host pathnames. While the child remains blocked and before any archive input is supplied, inspect the actual `/proc/<pid>/maps` bindings, open and hash the mapped loader and libraries through identity-preserving descriptors, and require exact agreement with the reported executable/loader/library closure.

Apply the same actual-mapping rule to Python and every gzip/zstd helper involved in discovery. A missing, changed, extra, unresolved, or unopenable executable mapping is a blocker. Pathname revalidation after execution cannot replace pre-input binding to the actual maps, and no archive byte may be consumed before the closure succeeds.

### P1-05: strict tar grammar and exact roles

The production parser and its tests must enforce one explicit canonical tar grammar:

- after the two required end blocks, accept only the explicitly permitted count of complete 512-byte zero blocks and reject every non-block-aligned suffix, including a lone zero byte;
- validate each fixed-width field completely, including all bytes after the first NUL, and reject hidden non-padding suffix bytes rather than truncating them;
- use an explicit PAX/GNU extension policy, reject malformed, duplicate, conflicting, unsupported, or unknown PAX keys and extension semantics, and exercise genuine long-name records; and
- define exact asset-specific role rules, require each selected role member itself to be the required type, and reject generic suffix matches, link-mediated role substitution, ambiguity, absence, and extras.

Canonical member facts and digests must distinguish every accepted layout. Unknown layout or metadata remains a blocker and cannot be silently normalized away.

### P1-06: schema-codec equivalence

The JSON schema and production qualification codec must accept and reject the same report domain. In particular, both must require file-valued roles, the exact asset-specific roles, exactly one executable and one loader where required, closure-wide `DT_NEEDED` satisfaction, canonical object order and digest semantics, and every other cross-field invariant used by production qualification.

Independent differential tests must send the same valid and invalid values through the real schema validator and production codec and prove equivalent outcomes. A constraint that cannot be represented and independently enforced by the existing schema/codec design is a stop and replan; accepting a broader upload shape and relying on a later loader to reject it is not sufficient.

### P2-01: authentic crash, Linux, and actual-size evidence

Focused tests must execute production primitives rather than source matching, mocks, or encoded facsimiles. At minimum they must cover:

- every durable-state initialization, anonymous download, publication, evidence, export, close-fault, cleanup, and report-ordering crash cut;
- pre-intent/post-fork rejection, post-release parent death, `PR_SET_PDEATHSIG`, parent handshake, helper creation, reparenting, descendant discovery, later-process recovery, narrow signaling, reaping, and independent process/descriptor residue on native Linux amd64 for the real gzip and zstd paths;
- malformed suffix, fixed-field NUL, PAX/GNU long-name, unknown-key, role ambiguity/type, canonicalization, and truncation cases through the production tar parser;
- schema/codec differential equivalence through the real validators; and
- the actual pinned 1,547,940,938-byte archive acquisition/hash/stream path, with measured peak RSS and elapsed phase times proving that the retained 90-minute outer timeout and non-borrowing cleanup/reporting reserve are sufficient.

The actual-size test must not weaken a pin, add a retry, increase the outer timeout, consume a hosted discovery event, or substitute a synthetic smaller object. If authentic evidence cannot fit the retained bounds, stop and replan.

Authorize exactly one local pre-event evidence execution after the implementation is locally complete and its generated/fault tests pass. It may use one Linux/amd64 Docker process on the local workstation and outbound HTTPS only to the two exact public origin URLs already pinned by ADR 0068 plus each origin's existing production-enforced single redirect to `release-assets.githubusercontent.com` under the unchanged strict target-host, `/github-production-release-asset/` path, query, framing, and redirect-count rules. It must acquire each archive at most once, require the exact fixed size and SHA-256 before parsing, execute only the fixed runtime-discovery no-argument production owner, and write only bounded metadata, peak-RSS, and phase-timing results beneath a fresh private local temporary directory. It may install nothing on the host, use no credential or secret, contact no other origin or target host, access no KVM/rootfs/lifecycle path, upload nothing, and must delete every downloaded byte, partial, container, volume, and temporary object before success. Failure, interruption, pin mismatch, cleanup uncertainty, or residue consumes this one local evidence execution and is a mandatory stop; there is no retry or substitute. This local execution is non-authoritative and is not any of ADR 0068's six hosted gates.

### P3-01: ordinary readable security code

Ownership, mutation, proof construction, close handling, recovery, signaling, and residue checks must be ordinary readable transitions. Do not use semicolon chaining, one-line loops or conditionals, multi-action statements, compressed compound proofs, or helper indirection whose purpose is to evade a high. Tests and review must be able to identify the durable-before-mutation and report-after-cleanup ordering directly.

## Checks, measurement, and exact review

Before any `phase-b-runtime-discovery` event, run all ADR 0065–0068 checks applicable to runtime discovery, including formatting, type checking, schema validation, Python and TypeScript Kata companions, native Linux process coverage, the authentic crash cases above, `git diff --check`, and the full local check suite. Then perform the sole local actual-size execution authorized above. A hosted event is not a test substitute.

Keep the 5,400-second outer workflow timeout unchanged. Move the final internal software boundary to no later than `+5,280` seconds from the monotonic anchor, leaving at least 120 seconds for platform step completion. Earlier non-borrowing acquisition, observation, cleanup, validation, export, upload, and residue allocations may only be narrowed as necessary to fit that boundary; they cannot be lengthened or borrow from cleanup/reporting reserve.

Record the clean predecessor, exact final 40-hex head, physical lines, gross additions for every counted file, the complete Phase B aggregate, peak RSS, phase timings, and all applicable test outcomes. The schema must be tracked. Obtain a new independent hostile review of the exact baseline-to-final-head range. It must explicitly verify P1-01 through P1-06, P2-01, and P3-01, the retained ADR 0065–0068 boundaries, and every count, with no unresolved P0–P3 finding. Any code, workflow, test, schema, or documentation change after review invalidates signoff.

Until that clean exact review exists, the runtime-discovery event gate remains closed. Acceptance provides only the four revised per-file highs, the sole bounded local evidence execution, and the narrower final internal boundary stated above; none opens, renews, replaces, or consumes a hosted event.

## Retained boundaries and consequences

The absolute Phase B high remains 3,310. The conservative global projection remains:

`26,074 no-deletion reserve + 3,310 Phase B + 1,900 steps 3–4 + 2,060 future = 33,344 < 34,000`.

The 656-line hard-cap headroom grants no implementation allowance. The 32,000 preferred target remains exceeded and documented, and the 34,000 hard cap is unchanged.

Except for the singular fixed local evidence execution and narrower final internal boundary above, this amendment changes no production behavior, archive policy authority, owner model, implementation-file set, stage order, event count, event-consumption rule, trigger, permissions, token boundary, attempt count, retry or fallback rule, outer timeout, report shape authority, production permit, workload authority, step-5 stop, deployment authority, cloud boundary, or AWS authority. It authorizes no new module, workflow, schema, contract, command surface, grant, hosted event, rerun, relabel, KVM action, lifecycle, metadata upload, production use, campaign, cloud action, or AWS action.

The consequence is enough non-transferable room to present the already-mandatory runtime-discovery corrections readably, one bounded way to obtain the exact pre-event size/RSS/timing evidence, and an enforceable 120-second platform margin, while the unchanged aggregate and all mandatory stops continue to bind. This proposed documentation-only ADR creates no implementation or operational authority until accepted.
