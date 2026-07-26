# ADR 0057: Authorize atomic unnamed candidate-tar remediation

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing bounded-local delegation, after corrected independent hostile review reported no P0–P3 findings.
- Acceptance record: [GitHub pull request #226](https://github.com/nenb/cogs/pull/226).
- Scope: One exact-base correction, local portable/static and six-fault qualification, one clean final exact-head review, and one hosted authentic two-build execution.

## Context

ADRs 0038–0056 retain the fixed Stage 2 inputs, direct one-writer/one-walker rootfs route, scalar durable ownership, exact cleanup, candidate/Phase B distinction, staged order, stop before step 5, and all production and cloud prohibitions.

ADR 0050's final Phase A authority was consumed by run `30199795587`, attempt 1, at exact source `8caab23bb4277121a77d80dc043b3c2c43b07ced` (`8caab23`). It remains a failed non-authoritative candidate with no rootfs result and no runtime, network, SSH, coordinator, Phase B, campaign, production, or cloud authority. Exact recovery failed closed and the rootfs baseline remained present; runner disposal is not cleanup proof.

The bounded diagnosis in `/tmp/candidate-30199795587-diagnosis.md` localized postwork to the candidate manifest/tar tail. Its counters strongly corroborate that location, but do not prove that canonical writing began, completed, or changed the tar generation. Exact source separately exposes both a named writable-tar transaction window and a call to `completion_rootfs_materializer._metadata` missing required `node_chain`; the latter necessarily raises `TypeError` if reached. The exact first runtime exception and exact reconciliation predicate remain unknown.

At exact source, `_build_once_unmasked` creates and settles an empty named `.cogs-rootfs-candidate-v1.tar`, reopens it writable, emits canonical bytes, and only then attempts a metadata transaction. Failure after mutation can therefore leave a named generation not represented by durable authority. Accepted-output publication already uses qualified Linux `O_TMPFILE` and `linkat(AT_EMPTY_PATH)`, but its journal, parent, names, inode-version authority, recovery, and terminal meaning belong to a different authority domain.

The consumed run cannot be retried or renamed. A correction and any further hosted execution require this decision.

## Decision

If accepted, authorize the following single consolidated correction and qualification path only.

### Exact branch, baseline, and stacked pull request

Create same-repository head branch `feat/issue42-candidate-tar-remediation` directly from frozen feature ref `feat/issue42-deterministic-rootfs`. The **first remediation commit's parent** must be exactly:

`8caab23bb4277121a77d80dc043b3c2c43b07ced`

Open one new **draft stacked pull request** with base ref exactly `feat/issue42-deterministic-rootfs`. Its base SHA must be `8caab23bb4277121a77d80dc043b3c2c43b07ced` at creation, every review, the `ready_for_review` event, and the hosted run. Do not move or modify the frozen base branch. Review and count scope is exactly `8caab23bb4277121a77d80dc043b3c2c43b07ced..H`, where `H` is the final full 40-hex remediation head recorded by the clean final signoff.

The relevant pre-remediation production, tests, pins, source preparation, budget code, and candidate workflow must initially be blob-identical to `8caab23`. Unrelated drift, a different first parent, base ref, or base SHA is a stop. PR #212 is historical: do not push to it, reopen it, synchronize it, relabel it, rerun it, or use its checks as remediation evidence. The `security` label remains absent and the existing Phase A workflow is not selected.

### Unnamed candidate-tar transaction

Replace only the named-empty-tar tail in `completion_rootfs_build._build_once_unmasked` with one fixed project-owned transaction:

1. After complete materialization, postwalk, and manifest construction, open one anonymous regular inode using Linux `O_TMPFILE | O_RDWR | O_CLOEXEC` relative to the held operation-directory fd. Prove exact mount-ID and device equality with that directory. No caller, path, environment, or configuration selects its directory or final name; the fd is not duplicated, inherited, delegated, or retained beyond the locked transaction.
2. The existing canonical ustar emitter remains the sole tar-byte writer and writes directly to that fd. There is no empty named tar, path reopen, second canonicalizer, host tar, memfd, copied tar, temporary-directory file, accepted-output staging, alternate filesystem, or fallback.
3. While `nlink == 0`, set UID 0, GID 0, mode `0600`, and `SOURCE_DATE_EPOCH` mtime through the fd; require empty xattrs/ACLs; fsync; and obtain stable observations. Everywhere in this ADR, exact full generation means only mount ID, device, inode, kind, mode, UID, GID, link count, size, mtime, and ctime. It excludes atime and accepted-publication directory inode-version authority.
4. Before naming, require canonical manifest equality, 4,353 entries, size 136,905,728, streaming SHA-256 `47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3`, complete bounded same-fd readback from offset zero, matching readback size/digest, stable full generation, and successful seek/sync accounting. Unverified bytes receive no naming authority.
5. Append, fsync, and exact-readback the fixed `candidate-tar-intent` described below. Revalidate that the fixed name is absent and the operation parent still equals the recorded pre-parent, then perform exactly one `linkat(AT_EMPTY_PATH)` to fixed `.cogs-rootfs-candidate-v1.tar`. There is no replace, unlink/retry, rename fallback, or second naming attempt.
6. Reopen the fixed name no-follow. Prove exact mount/device/inode continuity, the exact zero-to-one link transition, exact size/digest, and exactly one added parent name. Complete inode and parent durability, append/fsync/read back `candidate-tar-observed`, then append/fsync/read back `candidate-tar-settled`. Close all anonymous and named descriptors with exact error aggregation.
7. Only the settled tar may enter `BuildCandidate`, two-build comparison, pin checking, or ordinary exact-owned scalar cleanup. Accepted publication may later consume already verified bytes only through its separately gated transaction; it cannot regenerate this tar or lend publication authority to it.

The immutable manifest may retain its existing ordinary create transaction. Delete the empty-tar `_create_ledger_entry`, `_writable_file`, named metadata route, `_candidate_record`, and missing-`node_chain` call; do not repair that dead route.

### Exact ledger exception and four-record contract

This ADR supersedes ADR 0040 **only** for an existing fixed candidate-tar name reached from the exact pre-bound anonymous inode in a durable `candidate-tar-intent`. ADR 0040's rule that every other intent with an existing name but no durable observed identity is uncertain and preserved remains unchanged.

The existing `completion_rootfs_ledger.py` is the sole record codec/parser, legal automaton, graph fold, and reconciler. It adds exactly these record types and bodies; every object has no additional keys:

| Record | Exact body |
| --- | --- |
| `candidate-tar-intent` | `token`, fixed `path`, exact pre-link `parent`, exact `anonymous` full generation with `nlink == 0`, verified `size`, verified `sha256` |
| `candidate-tar-abort` | exactly the intent body; its fresh absent-name parent observation must equal the recorded full `parent` |
| `candidate-tar-observed` | `token`, fixed `path`, exact post-link `parent`, exact intent-bound `anonymous`, exact `linked` full generation with `nlink == 1`, verified `size`, verified `sha256` |
| `candidate-tar-settled` | exactly the preceding observed body |

`path` is always `.cogs-rootfs-candidate-v1.tar`; `size` is 136,905,728 for the fixed full build and must equal both generations' size; `sha256` is the verified byte digest. The anonymous-to-linked transition requires identical mount ID, device, inode, kind, mode, UID, GID, size, and mtime, `nlink` exactly 0→1, and permits only the link-caused ctime change. The intent pre-parent to observed post-parent transition records both full snapshots and requires the same parent key/kind/mode/UID/GID/link count plus exactly the one fixed added name; only directory size, mtime, and ctime may differ as part of that single link transition.

The only legal automaton edges are:

```text
active --candidate-tar-intent--> candidate-tar-intent
candidate-tar-intent --candidate-tar-abort--> active
candidate-tar-intent --candidate-tar-observed--> candidate-tar-observed
candidate-tar-observed --candidate-tar-settled--> active
```

The intent is legal only from `active`, with no pending transition, before lease, for the fixed absent direct child, with the body's pre-parent exactly equal to `operation_parent`. Abort changes neither `operation_parent` nor `owned`. Observed records the exact link transition but does not yet change either. Settlement atomically changes legal state by setting `operation_parent` to the observed post-parent and adding exactly `owned[path] = linked`; no other parent or owned entry changes.

Fresh reconciliation is exact:

- intent + absent fixed name + operation parent exactly equal to the recorded pre-parent permits only durable `candidate-tar-abort`, then ordinary cleanup;
- intent + exact fixed name/key, exact 0→1 generation, exact digest/size, and exact one-name post-parent permits durability/readback and `candidate-tar-observed`;
- observed + the same exact name, generations, digest/size, post-parent, ledger binding, and durability permits `candidate-tar-settled`;
- settled is ordinary `active` state with exactly the linked generation in `owned`; and
- every other absence, name, inode, generation, parent, digest, size, ledger, mount, link-count, or phase state is preserve/no-mutation uncertainty.

`completion_rootfs_builder.py` remains the sole fresh recovery and cleanup authority and performs those abort/advance actions by consuming ledger reconciliation results. Settled removal uses its existing scalar remove transaction. Any new `completion_rootfs_candidate.py` is only a fixed straight-line forward coordinator over existing canonical, filesystem, ledger, and builder capabilities. It may not parse records, define legality or ownership, reconcile, recover, clean up, walk, canonicalize, expose caller-selected production behavior, or create an alternate model.

Before durable intent, forward error handling only aggregates closure of the nlink-zero fd. At or after intent, it closes held fds and fails into the existing fresh builder recovery route; it does not reconcile inline. Cleanup deadlines, poisoning, complete replay/walk/reconciliation, recovery-attempt limits, and primary/cleanup/close aggregation remain unchanged. No broad deletion, timeout increase, retry, second naming attempt, second recovery route, or unknown-to-absent conversion is authorized.

### Authority-neutral primitive extraction

Move from `completion_rootfs_publish.py` to `completion_rootfs_fs.py` only the strict low-level operations for opening an `O_TMPFILE` under a held directory, observing its mount/full generation, closing it, and one `linkat(AT_EMPTY_PATH)`. Preserve exact platform, flags, fdinfo, no-follow, errno, and close behavior. Publication calls those primitives without semantic change.

No transaction abstraction, record, parser, journal, parent authority, recovery result, name, pin, inode-version authority, or terminal state is shared. If those syscall contracts are not exactly shareable, stop and replan rather than copy, generalize, or add fallback behavior.

### Exactly six local real-fd fault boundaries

Run exactly this bounded matrix against a small immutable synthetic graph through the production transaction and real Linux descriptors/names. Every case proves the seam was reached, exact error aggregation, complete fresh ledger replay/walk/reconciliation by builder, authorized removal, preservation of mismatch, baseline restoration when authorized, and no qualification-owned descriptor or temporary-state residue.

| Boundary | Exact cut | Required result |
| --- | --- | --- |
| F1 | anonymous open, before first canonical write | close/discard nlink-zero inode; no name; ordinary cleanup |
| F2 | inject exception/cancellation **after a positive partial byte count and before emission completes** | same as F1; partial bytes never receive naming authority |
| F3 | complete emission, before metadata/fsync/readback verification completes | same as F1; complete-looking unverified bytes remain unnamed |
| F4 | durable intent readback, before `linkat` | exact absence and unchanged pre-parent permit intent abort only |
| F5 | sole `linkat` returns, before durable observed readback | exact pre-bound inode transition may advance observed/settled and then ordinary removal; mismatch is preserved |
| F6 | durable observed readback, before durable settled readback | exact state may settle and then use ordinary scalar removal; mismatch is preserved |

Ordinary positive short writes that loop to successful completion remain separate normal writer coverage, not a seventh fault state. Cuts around a row may prove that row but do not authorize more transaction states or an open-ended campaign. Modeled inode authority, dictionary mutation, unused labels, pathname-only checks, and repeated use of one common exception path are not evidence. Equal-full-generation privileged ABA remains outside the inherited privileged-mutator exclusion.

### Local gates, final review, and cache boundary

Local work is limited to formatter/static/schema/full-repository and portable rootfs/ledger/materializer/publication tests plus the six real-fd synthetic Linux/Docker faults. Existing accepted-publication tests must retain their anonymous-generation, uncertain-link, transaction-recovery, no-replace, and inventory meaning. Docker remains functional-only.

No local acquisition is authorized. A test may read and verify a retained private exact-artifact cache only if it is already present; absence must skip that optional read-only cache check, not fetch or synthesize artifacts. No local route may run or substitute the authentic exact-16-artifact complete two-build regression. Source, fixed 16-artifact contract, ten-package order, graph, manifest/ustar pins, runtime pins, bounds, and historical candidate bytes remain unchanged.

Local review and correction may iterate normally. After all corrections and exact count remeasurement, one independent hostile **final signoff** must review exact `8caab23bb4277121a77d80dc043b3c2c43b07ced..H` and report no unresolved P0–P3. It must record full `H` and cover transaction legality, fd/inode continuity, the narrow ADR 0040 exception, parser/automaton/reconciler authority, builder-only recovery, cleanup, primitive-domain separation, six faults, workflow gates, readability, and counts. Any correction after that signoff invalidates it and requires another clean final signoff of the new exact head. Passing tests, self-review, an earlier iterative review, or hosted results cannot substitute for this one clean exact-head signoff.

### One hosted authentic execution

After clean final signoff, freeze draft PR head at exact `H`, then perform its single draft-to-ready transition. The new workflow's sole trigger is:

```yaml
pull_request:
  branches: [feat/issue42-deterministic-rootfs]
  types: [ready_for_review]
```

It has one GitHub-hosted `ubuntu-24.04` job, no job container, read-only contents permission, persisted credentials disabled, and `timeout-minutes: 90`. `concurrency.cancel-in-progress: false` prevents only concurrency cancellation. An authorized actor or the platform can still cancel the run; cancellation consumes this authority and grants nothing.

Before work, fail closed unless all gates hold exactly: same-repository head; `github.event_name == pull_request`; `github.event.action == ready_for_review`; PR draft state is false; base ref `feat/issue42-deterministic-rootfs`; base SHA `8caab23bb4277121a77d80dc043b3c2c43b07ced`; absent `security` label; event PR head SHA equal to recorded reviewed `H`; checked-out `HEAD` equal to both values; and `github.run_attempt == 1`. The pre-event operator must verify those same fields and that no prior matching run exists. A label, synchronize, reopen, push, schedule, dispatch, second ready transition, rerun, or another SHA is not authorized.

Establish a monotonic anchor before checkout and enforce this exact 5,400-second allocation:

1. checkout, metadata/head gates, fixed-source preparation, one-use hardened acquisition, and post-verification finish by `anchor + 600`;
2. the authentic invocation ends by `anchor + 3900`, retaining the 3,300-second observation ceiling; within it the complete two-build route retains `OUTER_SECONDS == 2400`, each build shares its existing 900-second build/materialization deadline, and first-build failure blocks build two;
3. `anchor + 3900` through `anchor + 4500` is available for at most the one already-authorized fresh exact recovery pass, only if one was not already consumed inline;
4. `anchor + 4500` through `anchor + 5100` is reserved for exact qualification-temporary/cache cleanup and independent read-only observation of their pre-run baselines; and
5. `anchor + 5100` through `anchor + 5400` is reserved for final close/error accounting and fail-closed job termination.

Early completion does not extend a later boundary; a late phase cannot borrow from a reserve. Timeout, guard failure, actor/platform cancellation, or inability to finish final observation grants nothing.

This single hosted invocation is the only authentic exact-input regression. It uses the existing hardened route to acquire only the authorized 16 public rootfs artifacts, independently reloads/verifies them for each build, constructs two fresh plans and tokens, materializes/postwalks all 4,353 entries twice, uses distinct anonymous candidate inodes and operation state, and requires:

- manifest size 1,049,443 and SHA-256 `8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691`;
- ustar size 136,905,728 and SHA-256 `47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3` from streaming generation and complete same-fd readback;
- byte-identical manifests and tars without shared candidate inode or operation state;
- exact cleanup of build one before build two and exact cleanup of build two; and
- an unchanged exact cache snapshot before exact cache cleanup, then an independent final read-only proof of the fixed sentinel/lock rootfs baseline, the pre-run cache baseline (absence on the fresh one-use route), no qualification-owned temporary state, and closure of descriptors created by the driver/workflow.

It emits no candidate report and performs no export creation or export-residue check. It does not rerun the six local faults, acquire runtime assets, invoke KVM/Kata, network/SSH/coordinator stages, or publish accepted/campaign evidence.

Authority is consumed when the first run for that one `ready_for_review` event and exact `H` is created, whether it runs, skips, succeeds, fails, times out, is cancelled, or remains uncertain. Missing or duplicate matching runs, metadata mismatch, any attempt above 1, cleanup uncertainty, or residue grants nothing and requires stop/replan; do not choose a favorable run. Record PR number, base ref/SHA, `H`, event/action, labels, run ID, attempt, outcome, two-build result, cleanup, and final observation. Every hosted outcome, including success, ends in an immediate mandatory stop. Success grants no Phase B, later stage, production, or cloud authority.

### Measured patch plan and unchanged cumulative caps

At exact source `8caab23`, the counted files total 24,535 physical lines, the inherited no-deletion reserve is 25,634, and retained later named high is 7,230. The following estimates were measured from exact-source function spans, not from a module-sized abstraction: publication's `_observe_anonymous` is 9 lines, `_close_anonymous` 9, `_prepare_anonymous` 27, and `_link_anonymous` 11; build's removable `_writable_file` and `_candidate_record` are 26 and 15, and `_build_once_unmasked` is 91; ledger's `_validate_body`, `LedgerLegalState`, `_replay_graph`, `_advance_history`, `_matching_transition`, and `_reconcile_ledger` are 107, 56, 59, 148, 28, and 228; builder's `_require_cleanup_model`, `_session_append`, `_cleanup_owned`, and `_recover_locked` are 58, 20, 17, and 60.

Gross additions are measured against exact `8caab23`; deletions create no credit. The low is the measured straight patch and the high includes readable branch-local assertions/error aggregation, not alternate machinery.

| File / exact function-level patch | Low | High |
| --- | ---: | ---: |
| `completion_rootfs_fs.py`: extracted anonymous open (16–22), observe (8–12), close (7–10), link (9–13) | 40 | 57 |
| `completion_rootfs_publish.py`: adapt `_prepare_anonymous` and `_publish_unmasked` to filesystem primitives; delete local duplicates | 6 | 12 |
| `completion_rootfs_ledger.py`: constants/contracts (8–12), `_validate_body` (18–26), `LedgerLegalState` (8–12), `_replay_graph` (4–7), `_advance_history` (28–40), `_matching_transition` (12–18), `_reconcile_ledger` (40–58), `LedgerState` status validation (4–8) | 122 | 181 |
| `completion_rootfs_builder.py`: candidate body/capability (12–18), `_require_cleanup_model` (8–14), `_session_append` (3–6), intent recovery/abort (20–30), observed recovery/settle (25–38), cleanup/recovery dispatch (4–8) | 72 | 114 |
| new `completion_rootfs_candidate.py`: fixed result/contracts (10–16), anonymous verification/emission (38–55), straight-line publish/close aggregation (75–105) | 123 | 176 |
| `completion_rootfs_build.py`: import and one fixed coordinator call/result binding in `_build_once_unmasked`; delete the two helpers and named mutation tail | 12 | 25 |
| **Counted production total** | **375** | **565** |

Per-file absolute maxima are 60, 12, 185, 120, 180, and 25 respectively, with a **565-line total maximum**; unused file allowance cannot fund another file or increase the total. No other counted production file is authorized. In particular canonical, materializer, Phase A runner/schema, pins, package/runtime contracts, and accepted evidence are unchanged. Needing another writer, parser, recovery path, generic transaction, canonical change, or file is a stop/replan condition.

The corresponding excluded qualification plan is also measured and split by responsibility:

| File / function-level test patch | Low | High/max |
| --- | ---: | ---: |
| new `test/aws-stage2-completion-rootfs-candidate.py`: synthetic real-fd fixture/seams (80–110), six-state matrix and mismatch assertions (90–120), hosted-only fixed production invocation/result checks (75–100), bounded CLI/close reporting (25–35) | 270 | 365 / **370** |
| new `test/aws-stage2-completion-rootfs-candidate.test.ts`: one fail-closed portable/static wrapper and mode/child checks | 18 | 28 / **30** |
| new `.github/workflows/stage2-rootfs-full-build-qualification.yml`: event/permission/gate policy (30–40), budget/acquisition/invocation (25–35), final cleanup/observation/result handling (20–30) | 75 | 105 / **110** |
| **Excluded total** | **363** | **498 / 510** |

Excluded surfaces contain no production transaction, parser, recovery, cleanup, ownership, canonicalization, or fixed-input replacement. Stop rather than compress before a file maximum, changing another test/workflow, or requiring another invocation/report surface. Ordinary readable formatting is mandatory.

The accepted preferred **32,000** and hard **34,000** cumulative limits remain unchanged. The conservative maximum is:

`25,634 + 565 + 7,230 = 33,429`

This is 571 lines below the hard cap. Stop if a file/total high would be crossed or if exact-head remeasurement gives `current no-deletion reserve + revised remaining high >= 34,000`; do not raise the cap or consume later-stage allowance to fit this correction.

## Retained exclusions and consequences

Every non-conflicting requirement of ADRs 0038–0056 remains binding. This decision authorizes no package/pin/fixture refresh, second writer/walker, alternate storage, accepted-output redesign, runtime asset, KVM/Kata, network, SSH, coordinator, Phase B, step 3 or 4 execution, step-5 controller, campaign, production use, release, or issue closure.

There is no AWS credential, CLI, account lookup, provider, OpenTofu action, SSM action, deployment, resource creation, cloud cleanup, or other AWS action. Stop before step 5 regardless of hosted success or unused margin.

This documentation-only proposal creates no branch, commit, pull request, label/event, implementation, test, review, acquisition, network operation, hosted run, candidate, cloud resource, or AWS action.
