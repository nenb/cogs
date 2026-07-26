# ADR 0062: Raise the hosted driver cap for signal-safe failure handling

- Status: Proposed
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Amendment scope: This ADR amends only ADR 0061's absolute gross-addition maximum for `test/aws-stage2-completion-rootfs-candidate.py`, from 570 to 1,100, and the corresponding excluded three-file total maximum, from 710 to 1,250. It authorizes only the narrow signal-safe hosted-driver correction and committed portable coverage below. Every other ADR 0057–0061 requirement remains binding.

## Context

Fresh final hostile review rejected exact head `bc4d3673ef13538e5af987badcc027c572aa9e70`. The review found that the hosted candidate driver still had asynchronous gaps in acquisition authority, bootstrap lifecycle transfer, and production-seam installation. It also found incomplete close aggregation and no portable tests for the required failure paths. That head is not ADR 0057's required clean final signoff and cannot be used for the reviewed-head variable or the `ready_for_review` event.

The current `_open_private_chain` wrapper receives control only after the complete `.state/completion-v1/artifacts/cache` chain exists, and acquisition provides no per-file completion callback. Any of those four directories can be created by acquisition. Reconstructing authority after failure cannot close those gaps: a pending `SIGALRM` can arrive after any directory mutation but before its authority is recorded, during sentinel creation, between publication mutations, after a file completes but before a later scan records it, or while that scan is in progress. The all-or-nothing snapshot also loses cleanup authority for earlier completed files when later state is incomplete.

The driver has corresponding bootstrap and seam gaps. A signal can arrive between a `bootstrap_started` assertion and actual mutation, between completed bootstrap mutation and lifecycle capture, or while the two production seams are only partly installed. Those windows can request recovery without mutation, lose exact post-bootstrap authority, leave a stale seam, or count recovery twice.

The correction must remain qualification-only. The safe route is a temporary proxy and hooks installed only on the imported `completion_artifact_acquisition` module, together with narrow `SIGALRM`-masked handoffs in the candidate driver. Production acquisition, verification, rootfs, workflow, TypeScript, mode, command, event, deadline, and recovery semantics do not change.

The candidate Python file is currently 564 gross lines against its 570-line maximum. The excluded three-file aggregate is 702 against 710. The measured plan's own responsibility ranges derive an ordinary-readable final estimate of **919–1,064** candidate lines: low `564 + 45 + 175 + 65 + 180 - 110 = 919`; high `564 + 60 + 215 + 85 + 220 - 80 = 1,064`. This is an honest plan-derived estimate, not a completed implementation measurement; it deliberately applies the stated removal range rather than assuming unmeasured overlap. It cannot fit the current limits without unreadable compression or omission of required portable failure coverage. Deletions do not create budget credit.

## Decision

If accepted, authorize a correction in exactly one implementation file:

- `test/aws-stage2-completion-rootfs-candidate.py`

The following files may be read but must not be modified under this ADR:

- `deploy/aws-feasibility/remote/completion_artifact_acquisition.py`
- `deploy/aws-feasibility/remote/verify-completion-artifacts.py`
- `scripts/run-stage2-phase-a-candidate.py`

No production rootfs source, acquisition or verifier source, workflow, TypeScript file, report, export, or other file may change. The existing default invocation must run the new portable failure suite. Existing `--linux-synthetic` and `--hosted-exact` meanings remain unchanged. No command, mode, branch of execution, retry, recovery pass, report, or candidate state is added.

### Narrow deadline-aware critical sections

Use one small authority-handoff primitive throughout the correction. It must:

1. block only `SIGALRM` with `signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})` and preserve the exact prior mask;
2. reject nested entry;
3. run only a small local filesystem mutation and its in-memory authority update, a local lifecycle mutation tail and its snapshot transfer, or a module-seam install or restore and its ownership update;
4. restore the exact prior mask on every path;
5. immediately after the unmask attempt read `time.monotonic_ns()` and reject `now >= active_absolute_deadline`, even when unmasking itself delivered or raised; and
6. retain callback, mask-restoration, alarm-delivery, and deadline failures in the common ordered error aggregate rather than replacing one with another.

The primitive must not re-anchor, reset, borrow from, or extend a timer or deadline. Network requests, response reads, artifact streaming and writes, large reads, source-bundle verification, full-file hashing, builds, and authentic recovery remain unmasked and interruptible. Only directory or file creation, link or unlink, final small `stat` and authority decisions, bootstrap's small mutation tail, and seam assignment may be masked. In particular, masking network work, large reads, hashing, builds, or recovery is forbidden.

### Incremental module-local acquisition authority

Create in-memory cache authority before acquisition starts. Before the first acquisition mutation, capture an exact no-follow, fd-relative baseline from the fixed source base through `.state`, `completion-v1`, `artifacts`, and `cache`. For every reachable preexisting component, record its directory identity, UID, mode, and exact retained inventory; once a component is absent, record it and all unreachable descendants as absent. A preexisting exact directory and its baseline entries are retained state, never run-owned state.

The authority records a separate lifecycle for each of the four directories: `preexisting-retained`, or `baseline-absent` followed only by `created-by-this-run` and, after valid cleanup, `removed-by-this-run`. It also records sentinel identity and fixed-byte verification state; every acquisition-created inode, exact owned aliases, and incomplete, provisional, or complete state; and each completed artifact's contract name, identity, size, mode, and SHA-256. No preexisting directory, name, or inode may be adopted as owned merely because it matches an expected pathname or contract.

Temporarily replace only the imported acquisition module's `os` binding with a delegating proxy. The proxy may specialize:

- each expected `.state`, `completion-v1`, `artifacts`, and `cache` `mkdir`: verify the exact parent and baseline state, perform the real mutation, open and capture the new directory identity, and mark that exact component `created-by-this-run`, all in one critical section before signal delivery resumes;
- sentinel or contract `.partial` `open` with `O_CREAT | O_EXCL`, recording the returned inode from `fstat` before signal delivery resumes;
- `.partial`-to-contract `link`, atomically transferring authority to the two exact aliases;
- owned-alias `unlink`, atomically recording the alias transition; and
- `close`, attempting the real close and retaining any failure while allowing every later close attempt.

A failed `mkdir` records no creation. An expected preexisting directory must continue to match its retained baseline identity when acquisition opens it; it is never changed to run-owned. All other `mkdir` calls, attributes, constants, reads, and ordinary opens delegate to the real `os` module without masking. The correction must never mutate the process-wide `os` module or globally monkeypatch `os.mkdir`, `os.open`, `os.link`, `os.unlink`, `os.close`, or any equivalent operation.

Temporarily replace only the acquisition module's `_stable_read` with a same-signature implementation retaining its existing checks. Descriptor reads and SHA-256 work remain unmasked. Its final small stable `stat`, identity/size/digest decision, and authority completion record form one short handoff, so a signal can observe either an exactly owned provisional inode or an already recorded complete file, never an unrecorded completed file. Sentinel completion must additionally verify its fixed bytes in that handoff.

Temporarily wrap `_LiveResponse.close` so response and connection closes are independently attempted and all failures enter the common collector. Install the authority and all acquisition hooks before calling acquisition while the inherited absolute `+600` guard is active. Restore `_LiveResponse.close`, `_stable_read`, and the module-local `os` binding independently on every exit, using the same narrow seam handoff.

### Exact ownership and fail-closed cleanup

Cleanup consumes only incrementally recorded authority. It may not rescan to manufacture ownership, adopt an unrecorded name or inode, infer ownership from pathname shape, or perform broad or best-effort deletion. In particular, it may remove a directory only when the authority lifecycle proves that exact identity was created by this run; every `preexisting-retained` directory and baseline entry must remain present and unchanged.

Before the first deletion, open and validate the fixed base, all reachable `.state/completion-v1/artifacts/cache` components, and every recorded name fd-relatively with no-follow behavior. Validate the complete baseline-plus-owned inventory, all four directory identities and lifecycle states, alias-to-inode bindings, regular-file/UID/link policy, and exact mode, size, and digest of completed sentinel and artifacts. Full reads and digests remain unmasked. Empty cache state, sentinel in progress, a partial in progress, linked provisional state, one complete artifact followed by failure, and a fully complete inventory are cleanable only when each exact recorded lifecycle is valid.

Any unrecorded name, replacement, identity mismatch, digest mismatch, alias mismatch, baseline change, or uncertain lifecycle must fail before mutation and preserve the complete tree. After successful whole-inventory prevalidation, remove only exact run-owned file aliases. Then revalidate the candidate directories' exact identities and emptiness and remove only directories proven `created-by-this-run`, in strict reverse creation order: `cache`, `artifacts`, `completion-v1`, `.state`. Stop reverse removal at retained state as dictated by the lifecycle; never remove a retained preexisting directory. Each unlink, `rmdir`, and authority transition is a short handoff with the exact parent and child identities checked. Every held descriptor close, unlink, `rmdir`, deadline failure, and final observation must be attempted where possible and retained in order.

### Gap-free bootstrap and production seams

Delete the `bootstrap_started` approximation. Temporarily wrap `fs._verify_source_bundle`; run the real, potentially expensive verification unmasked. Only after it succeeds, while rootfs is still proven absent, enter the held critical section before returning to `builder._bootstrap_unmasked`. Keep the small rootfs directory/sentinel/lock mutation tail, bootstrap descriptor closes, `runner._snapshot_rootfs_lifecycle`, and assignment of exact lifecycle authority in that handoff. Assert that the verification handoff occurs exactly once, begins with absent `ROOTFS_STATE`, and follows no rootfs mutation. Restore the verification hook before unmasking and fail closed if production call order changes.

Treat `fs._link_anonymous` and `builder._recover_fixed` as one seam set. Capture both originals first; install both wrappers in one handoff and mark ownership only after both assignments succeed. If installation fails, attempt both rollbacks and retain every error. Put the build `try/finally` outside installation so every post-install path restores both originals independently in one handoff before any external recovery decision.

Count recovery only on entry to `counted_recovery`. The external route may temporarily install that same counted wrapper around `runner._recover_rootfs`; it may not pre-count recovery. Builds and authentic recovery remain unmasked. Require zero or one recovery during execution and exactly one authentic recovery when an injected post-bootstrap failure requires it. No second recovery, changed recovery authority, stale-seam recovery, or broadened deletion is authorized.

### Complete error aggregation

Use one ordered collector with the primary error first and every secondary failure retained. Independently attempt response and connection close; acquisition writer and complete directory-chain close; cleanup file, `.state`, `completion-v1`, `artifacts`, `cache`, and fixed-base close; acquisition-hook restoration; bootstrap verification-hook restoration; both production-seam restorations; timer cancellation; prior `SIGALRM` handler restoration; and final cache, rootfs, temporary-state, and descriptor observations.

When `completion_rootfs_fs` is available, fold all retained errors into nested `fs.RootfsFsError` values without loss. Before it is available, use a `BaseExceptionGroup`. A close, restore, deadline, cleanup, or observation failure must not replace the primary or prevent another independent close, restore, cleanup, or observation attempt.

## Portable acceptance tests

Commit the portable tests in the same candidate Python file and run them through its existing default mode. They must use tempfiles, tiny contract rows, in-memory responses, the real acquisition behavior under an isolated import, and only narrow fake hosted collaborators where fixed paths require them. They perform no network operation and require no root.

Coverage must include:

1. guard, deadline, authority, and hooks active before the first fake request or filesystem mutation;
2. body failure after sentinel or partial creation, preserving the primary while attempting all closes/restores and leaving no owned residue or descriptor;
3. row one completed and recorded before row two fails, followed by exact cleanup of both owned states;
4. exact baseline and authority lifecycle for each of `.state`, `completion-v1`, `artifacts`, and `cache`, including every valid preexisting-prefix/fresh-suffix chain: preserve each preexisting exact directory and baseline entry, and clean each directory proven created by this run in reverse order; also cover empty root, sentinel in progress, partial in progress, linked provisional, one-complete-plus-one-failed, and fully complete inventory;
5. mismatch preservation before any cleanup mutation when a recorded completed file is replaced or altered;
6. aggregation of one primary, at least two independent close failures, and at least two independent restoration failures, with every attempt occurring once and every exception discoverable; and
7. one authentic recovery after bootstrap lifecycle transfer, with authentic seams restored, the lifecycle baseline restored, and no stale-wrapper recursion.

A table-driven pending-alarm test must use fresh process state and a fresh temporary tree for each boundary. Raise `SIGALRM` while blocked and verify delivery after the authority handoff for `.state` creation, `completion-v1` creation, `artifacts` creation, `cache` creation, sentinel creation, sentinel completion, partial creation, publication link, partial unlink, artifact completion, bootstrap lifecycle transfer, production-seam installation, and production-seam restoration. Every one of the four directory rows must prove the just-created identity is run-owned before delivery, cleanup removes only the run-created suffix in reverse order after prevalidation and emptiness checks, and any preexisting prefix remains identity- and inventory-exact. Each row must also prove authority, cleanup, seam restoration, descriptor equality, and monotonic timeout. Repeat each boundary with an injected monotonic clock crossing the absolute deadline without a signal; the immediate post-unmask check must reject it. Keep payloads small enough for the existing default TypeScript launcher's 30-second limit.

No new test command or mode is authorized. The inherited validation remains:

```text
python3 -I test/aws-stage2-completion-rootfs-candidate.py
python3 -I test/aws-stage2-completion-rootfs-candidate.py --linux-synthetic
node --test test/aws-stage2-completion-rootfs-*.test.ts
git diff --check 8caab23bb4277121a77d80dc043b3c2c43b07ced..HEAD
```

The authentic hosted exact command may run only in its already approved environment and only after the inherited clean review and event gates. This ADR does not itself authorize that execution.

## Revised excluded maxima

Gross additions remain measured against exact baseline `8caab23bb4277121a77d80dc043b3c2c43b07ced`; deletions receive no credit and allowances are non-transferable.

| Excluded file | Absolute maximum gross additions |
| --- | ---: |
| `test/aws-stage2-completion-rootfs-candidate.py` | **1,100** |
| `test/aws-stage2-completion-rootfs-candidate.test.ts` | **30** |
| `.github/workflows/stage2-rootfs-full-build-qualification.yml` | **110** |
| **Excluded three-file total** | **1,250** |

Only the candidate Python maximum changes from 570 to 1,100, and only the excluded aggregate changes from 710 to 1,250. The TypeScript maximum remains 30 and the workflow maximum remains 110. The three per-file maxima reserve `1,100 + 30 + 110 = 1,240`, ten lines below the 1,250 aggregate maximum; that difference is not a transferable per-file allowance. No production per-file or aggregate maximum, production gross or net count, counted physical-line reserve, preferred or hard cumulative cap, companion cap, or later-stage allowance changes.

The plan-derived candidate estimate is **919–1,064** lines. At its 1,064-line high, the 1,100 candidate maximum leaves **36** lines of file headroom. Using the current 30-line TypeScript and 108-line workflow contributions gives `1,064 + 30 + 108 = 1,202`, leaving **48** lines beneath the 1,250 aggregate maximum. These are planning margins, not completed measurements, deletion credit, compression credit, transferable allowance, or authority for additional behavior. Keep the implementation ordinarily formatted and readable. Stop and replan before crossing either revised maximum, modifying another file, moving logic elsewhere, compressing required checks to manufacture margin, or needing any behavior outside this decision.

## Retained review, execution, and stop boundaries

The rejected exact head receives no signoff. After this bounded correction and exact remeasurement, the complete new exact head requires the inherited clean independent hostile review of the exact base-to-head range with no unresolved P0–P3 finding. Any later correction invalidates that signoff.

Every non-conflicting ADR 0057–0061 requirement remains binding, including exactly one `ready_for_review` event, exactly one hosted run at attempt 1, the same event and workflow gates, the same exact 5,400-second allocation and all absolute phase boundaries, the same one authentic recovery maximum, the same two builds and exact artifacts, and the mandatory stop after every hosted outcome. This ADR creates no additional review, event, attempt, run, retry, recovery, candidate, report, mode, command, deadline, timeout, stage, campaign, production, release, issue-closure, cloud, or AWS authority.

In particular, it authorizes no network acquisition during documentation or portable validation; no credential, AWS CLI, account, provider, OpenTofu, SSM, deployment, resource, cloud-cleanup, or other AWS action; and no Phase B, later-stage, step-5, campaign, production, or release action.

## Consequences

The excluded driver can close each asynchronous local-authority gap without masking expensive or remote work. Every acquisition-created name, including each of the four possible directory creations, gains exact incremental authority before alarm delivery resumes; completed files remain cleanable after later failure; retained preexisting directories are never removed; mismatches preserve the complete tree; bootstrap absence transfers directly to an exact lifecycle snapshot; production seams are jointly owned and restored before recovery; and all close and restore failures remain visible. The cost is 530 additional candidate-file lines and 540 additional excluded-total lines of maximum capacity.

This documentation-only proposal remains uncommitted and creates no implementation, test change, workflow change, command, review, branch, commit, pull request, label, event, acquisition, network operation, hosted run, candidate, report, cloud resource, or AWS action.
