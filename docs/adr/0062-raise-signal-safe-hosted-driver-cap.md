# ADR 0062: Use a parent/child supervisor for hosted qualification

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing bounded-local delegation, after independent hostile review and focused confirmation reported no unresolved P0–P3 findings.
- Acceptance record: [GitHub pull request #233](https://github.com/nenb/cogs/pull/233).
- Review state: The prior signal-mask/module-proxy version of ADR 0062 was unmerged and unaccepted and supplies no signoff or authority for this decision.
- Amendment scope: This ADR amends ADR 0061's accepted absolute gross-addition maximum for `test/aws-stage2-completion-rootfs-candidate.py` from 570 to 1,100 and the corresponding excluded three-file total from 710 to 1,250. Every non-conflicting ADR 0057–0061 requirement remains binding.

## Context

The unmerged and unaccepted prior ADR 0062 design attempted to make asynchronous Python exceptions safe by masking `SIGALRM` around mutations, proxying the acquisition module's `os` binding, and temporarily replacing module functions. That approach made safety depend on identifying every mutation boundary, restoring several process-local seams, and proving that no alarm could split a filesystem mutation from an in-memory authority update. It also encouraged exhaustive instruction-boundary testing instead of testing the small number of durable states that matter.

That design is abandoned. It must not be implemented, treated as reviewed, or used as authority for signal masks, module proxies, monkeypatching, or lifecycle hooks.

The hosted route still needs to enforce the inherited absolute acquisition and invocation ceilings while authentic acquisition, bootstrap, recovery, and two-build code can mutate qualification cache and rootfs state. A synchronous in-process Python timeout cannot safely interrupt that mutator. The replacement puts process-deadline ownership and post-mortem cleanup in a non-mutating parent and runs the authentic mutating route in one disposable trusted child. Filesystem cleanup authority then derives from state established before `fork`, the identity of that sole child, a fixed name contract, and exact observations after the child has terminated—not from an asynchronous callback or reconstructed ownership.

The replacement remains qualification-only. No production source, production API, verifier, acquisition implementation, rootfs implementation, TypeScript wrapper, workflow, report, export, or command changes.

## Decision

If accepted, implement one parent/child hosted qualification supervisor inside the existing `--hosted-exact` route of:

- `test/aws-stage2-completion-rootfs-candidate.py`

The file's existing default portable route must contain the supervisor tests described below. Existing default, `--linux-synthetic`, and `--hosted-exact` meanings remain unchanged. No new mode, command, network route, workflow path, or implementation file is authorized.

### 1. Parent preflight and fd-bound setup

The original qualification process is the parent. Before `fork`, it must:

1. validate the inherited monotonic anchor and derive the unchanged absolute `anchor + 600`, `+3900`, `+4500`, `+5100`, and `+5400` boundaries once, without resetting, borrowing, or extending any boundary;
2. independently validate the inherited exact source/head inputs, fixed source locations, acquisition approval, and ambient-environment restrictions before importing or invoking the mutating route;
3. validate the fixed artifact base and rootfs baseline with no-follow, fd-relative observations, rejecting a symlink, wrong owner, wrong type, unexpected inventory, changed source, or inconsistent environment before mutation;
4. walk the fixed `.state/completion-v1/artifacts/cache` chain from a held base directory fd, recording the exact reachable preexisting prefix, including each directory's device/inode identity, UID, mode, link count, and retained inventory;
5. require the reachable prefix to end no later than `completion-v1`, so `artifacts` and `cache` are always absent and become fresh parent-created private directories; after the first absent component, require every descendant to be absent, then create the complete missing suffix in order using only fd-relative, exclusive, no-follow operations with private fixed permissions;
6. open and retain an fd and exact identity for every resulting directory, and prove each newly created directory—including `artifacts` and `cache`—was empty before it could be inherited by the child; and
7. capture the exact pre-fork cache, rootfs `ROOTFS_STATE`, qualification-temporary-state, and process-fd baselines.

There are exactly three valid preexisting-prefix cases: fixed base only, fixed base plus `.state`, and fixed base plus `.state/completion-v1`. This is exhaustive because the inherited pre-setup `ARTIFACT_ROOT` (`.state/completion-v1/artifacts`) baseline **MUST be absent**, and therefore no inherited `artifacts` or `cache` directory is valid. A preexisting valid prefix remains retained state and is never adopted as run-owned, even when its names and metadata happen to match the fixed contract. Preexisting `artifacts` or `cache` is a stop, not reusable storage. Every directory in the created suffix—including `artifacts` and `cache` in all three valid cases—is parent-created state and is removable only after its exact identity and emptiness are revalidated. Setup may not create another cache, staging tree, alternate filesystem, copied artifact set, candidate state, or storage fallback.

The parent checks the active absolute deadline immediately before and immediately after every bounded local setup syscall and filesystem observation. Expiry before a call prevents the call; expiry after a call records failure and prevents the next setup operation or phase. These checks do not pretend to interrupt a stuck kernel call. The unchanged outer GNU `timeout` remains the final process-group guard if the parent, child, or kernel fails to make progress.

### 2. Exactly one trusted mutating child

After successful setup, the parent creates one close-on-exec pipe and forks exactly once. There is one fixed child PID and one child-to-parent pipe writer. There is no replacement child, helper child, retry child, second attempt, child pool, or additional mutating process.

The child closes the parent pipe end, uses the inherited fixed source and private chain, and directly invokes the authentic existing verifier, hardened acquisition, bootstrap, and complete two-build route. Build one must succeed and settle cleanly before build two starts. Both builds retain the inherited fresh plans, tokens, operation state, anonymous candidate inodes, exact artifact reloads, equality checks, and fixed pins. Production functions and modules are called as they exist; the child may not replace, wrap, proxy, or patch them.

The child sends only bounded fixed-size protocol frames over the one pipe. The protocol has a fixed version, a closed enum of phase/result codes, a monotonically increasing ordinal, a fixed maximum frame count, and no caller-selected path, name, exception text, or unbounded payload. It reports only the fixed acquisition-complete, bootstrap/build progress, terminal result, and portable-test cut states needed by this ADR. An inline-recovery counter is obtained only from the authentic existing recovery seam and increments only on entry to authentic inline recovery, never from phase progress or inferred rootfs state; the exact terminal frame reports that count as the closed value zero or one. Duplicate, out-of-order, malformed, oversized, truncated, excess, or post-terminal data, an invalid recovery count, or a missing or duplicate terminal frame is failure and grants no cleanup or recovery authority. A frame is an observation of the sole child, never filesystem ownership proof; the parent always verifies the filesystem independently.

The child installs no `SIGALRM` handler, receives no asynchronous Python exception, and does not convert TERM into a Python cleanup path. On parent-directed termination it exits by normal process signal semantics. Synchronous errors from authentic code are reported only as a fixed result code where possible and then terminate the child; arbitrary exception serialization, candidate state, or report generation is forbidden.

### 3. Parent-owned process deadlines

Only the parent enforces the hosted process ceilings. It uses monotonic time, nonblocking pipe reads, `poll`, and `waitpid(..., WNOHANG)` against the original absolute boundaries:

- the required acquisition-complete frame must be fully received and validated by `anchor + 600`; and
- the sole child must have completed the authentic invocation by `anchor + 3900`.

Each ceiling reserves a fixed bounded termination lead inside that same absolute boundary. If the required frame or child exit has not occurred by the lead point, or if protocol/process validation fails, the parent sends TERM to the exact recorded child PID, polls and performs nonblocking waits for only the fixed grace, then sends KILL if needed. It never moves TERM/KILL or reap time into a later phase to give work more time. Early completion creates no credit. A phase may not borrow from recovery, cleanup, or final-observation reserves.

The parent drains only complete bounded frames and correlates the complete bounded stream, exact terminal frame, EOF, and `waitpid` status. Only that fully validated terminal frame and bounded pipe record can supply durable child-side evidence of the authentic inline-recovery count. It does not begin recovery, cache cleanup, temporary-state cleanup, or final observation until a terminal wait proves the exact child is reaped. If terminal wait cannot be established, mutator absence is uncertain: the parent performs no filesystem cleanup or recovery, reports failure through process status only, and leaves the outer GNU timeout as the final guard. Once terminal wait succeeds, that sole child mutator no longer exists and no child can retain or resume mutation.

This process supervision replaces Python alarms; it does not change any production-internal deadline. `OUTER_SECONDS == 2400`, each existing 900-second build/materialization deadline, and every inherited `+600`, `+3900`, `+4500`, `+5100`, and `+5400` boundary remain exact and non-borrowing.

### 4. Exact post-mortem authority and cache cleanup

The parent may derive cleanup authority only from all of the following together:

- the exact empty identities of directories the parent created before `fork`;
- the recorded sole child PID and proof that it was the only process given the private chain;
- successful terminal `waitpid` for that exact child;
- the fixed sentinel name and bytes;
- exactly the 16 cache names in the verified fixed contract and each name's mechanically fixed `.<contract-name>.partial` alias; and
- complete fd-relative, no-follow validation immediately before any deletion.

No frame alone grants deletion authority. Apart from the already bound structural suffix directories, the accepted file inventory contains no name other than the fixed sentinel, the 16 complete contract names, and their 16 fixed partial aliases: `artifacts` may contain only the sentinel and fixed `cache` directory, and `cache` may contain only those contract names and aliases. For each observed object, the parent validates parent identity, device/inode identity, regular-file or directory type, effective UID, exact permitted mode, link count, and size. It performs stable bounded reads and requires the fixed sentinel bytes. Every complete contract name must have its exact contract size and SHA-256 digest. A partial may be accepted only in the fixed lifecycle state indicated by its observed metadata: an incomplete private partial has one link, private mode, and size no greater than its contract bound; a complete pre-publication partial has exact size, mode, and digest; and linked partial/final aliases must have equal device/inode identity, an exact two-link count, exact size/mode, and the contract digest. A settled final has one link and the exact size/mode/digest.

Validation is whole-inventory and stable: observations before and after reads must agree. An unknown name, symlink, non-regular object, unexpected hard link, wrong UID/mode/size, changed identity, digest mismatch, alias inequality, directory replacement, retained-prefix change, protocol ambiguity, or any other mismatch fails before cleanup mutation and preserves the tree. The parent may not rescan to manufacture provenance, infer ownership from a plausible pathname, or delete best-effort around uncertainty.

After complete prevalidation, the parent removes only validated fixed child-provenance aliases and sentinel entries, using fd-relative no-follow operations and fixed alias order. It then revalidates every held directory identity and emptiness and removes only the exact parent-created suffix directories, in reverse order: `cache`, `artifacts`, `completion-v1`, `.state`, stopping at the first retained preexisting component. The complete preexisting prefix and its retained inventory remain identity-exact.

The parent checks the active absolute deadline immediately before and after every bounded cleanup syscall, stable read chunk, digest step, sync, close, and observation. Once a check expires, it performs no further mutation and never enters the next phase. Failure and unclosed-resource observations remain aggregated for terminal status, but deadline expiry grants no broader cleanup. Local checks are cooperative bounds around bounded syscalls; the outer GNU timeout remains the final guard for an unreturning syscall.

### 5. Rootfs recovery and final observations

A child phase frame does not authorize rootfs recovery. After terminal wait, the parent may invoke at most one authentic existing rootfs recovery only when both independent conditions hold: the complete bounded pipe record contains exactly one valid terminal frame whose authentic-seam inline-recovery count is zero, and an exact no-follow post-reap observation of the inherited `ROOTFS_STATE` satisfies the existing recovery-needed predicate. Mere bootstrap mutation is insufficient. A missing, truncated, malformed, excess, or otherwise uncertain frame or pipe record, an absent or invalid count, a nonzero count, absence, a pre-bootstrap death, a mismatch, an unrecognized rootfs state, or uncertain identity grants no parent recovery. Protocol uncertainty requires preservation without filesystem mutation and fail-closed status. Recovery is never speculative and is never retried.

The existing recovery implementation and authority remain unchanged. If authorized, it runs only in the inherited `anchor + 3900` through `anchor + 4500` recovery interval. The parent performs exact qualification cache/rootfs/temporary cleanup plus the independent read-only cache, rootfs sentinel/lock, qualification-temporary-state, and process-fd observations only in the `+4500` through `+5100` interval. That interval independently proves the retained pre-run prefix and baselines, absence of authorized run-created residue, and closure of supervisor-created descriptors. The `+5100` through `+5400` interval is reserved only for final close, error aggregation, deterministic status accounting, and fail-closed termination; no recovery, cleanup, or cache/rootfs/temporary/fd observation starts there. A late, failed, mismatched, or uncertain phase cannot enter the next interval and cannot borrow time.

After final waits, recovery, cleanup, descriptor closure, and observations, no mutator remains. Any primary child error, protocol error, termination result, recovery error, cleanup error, close error, deadline error, or final-observation error remains visible in deterministic parent-side terminal aggregation; none can create a report or candidate state.

### 6. Explicitly forbidden alternatives

This ADR authorizes none of the following:

- `pthread_sigmask`, `SIGALRM` masking, Python alarm handlers, or any asynchronous Python exception in the mutating child;
- a module-local or global `os` proxy, rebinding an imported module, wrapping acquisition internals, replacing `_stable_read` or `_LiveResponse.close`, global monkeypatching, or production seam installation;
- a second artifact store, shadow cache, staging cache, copied artifact tree, alternate rootfs, memfd substitute, or fallback storage;
- candidate state, a candidate report, accepted/campaign report, export, export-residue path, or new result surface;
- a second child, helper mutator, retry, rerun, recovery retry, extra hosted run, extra attempt, extra ready event, or another workflow execution path; or
- production, workflow, TypeScript, verifier, acquisition, bootstrap, rootfs, transaction, ledger, parser, reconciliation, publication, cleanup, canonicalization, pin, package, fixture, network, or command changes.

## Portable acceptance tests

The abandoned pending-alarm and every-bytecode matrices are deleted from the plan. The existing default invocation must run a table-driven portable supervisor suite using fresh temporary directories, tiny fixed contract rows, real local fds, one pipe, one trusted child per row, and no network or root privilege.

Use exactly these six meaningful child-death boundary kinds plus one success kind; instantiate that seven-row table for every valid preexisting-prefix/fresh-suffix case described below:

| Row | Exact durable cut |
| --- | --- |
| writing | after a positive partial write while the object remains private |
| pre-flush | after complete emission and before the first required durability flush completes |
| pre-publication | after exact byte verification while the object is still private and before durable publication intent |
| publication intent | after durable intent and before the sole publication link is known complete |
| post-publication | after the fixed name is linked and before durable observed/settled completion |
| post-settlement | after durable settlement and before ordinary child completion/cleanup |
| success | complete acquisition/bootstrap/two-build protocol and clean terminal exit |

Instantiate the seven-row table for exactly the following three valid inherited-prefix cases. In the matrix, **created** means parent-created before fork, exact identity revalidated after child reap, and removed with the fresh suffix in reverse order; **retained** means its inherited identity and inventory are revalidated exactly and remain unchanged.

| Valid inherited prefix | `.state` lifecycle | `completion-v1` lifecycle | `artifacts` / `ARTIFACT_ROOT` lifecycle | `cache` lifecycle |
| --- | --- | --- | --- | --- |
| fixed base only | created | created | **always created** | **always created** |
| fixed base + `.state` | retained | created | **always created** | **always created** |
| fixed base + `.state/completion-v1` | retained | retained | **always created** | **always created** |

For every matrix row, prove the stated lifecycle for all four named directories, exact identity revalidation, reverse removal of the complete created suffix, and identity- and inventory-exact retention of the complete inherited prefix. These are the only valid cases because the inherited pre-setup `ARTIFACT_ROOT` / `artifacts` baseline must be absent; preexisting `artifacts` or `cache` is invalid setup and is never adopted or authorized.

Separately add one portable negative-baseline case, parameterized for a preexisting `artifacts` directory and a preexisting `artifacts/cache` chain. In each fixture, prove setup rejects the baseline before fork and before any supervisor filesystem mutation, the authentic mutating route is never invoked, and every inherited identity and inventory remains exact. This is one setup-rejection case, not part of the seven-row table, not a seventh child-death or fault boundary, and grants no cleanup, reuse, or adoption authority for preexisting `artifacts` or `cache`.

Across the six death boundary kinds, prove that the parent observes each fixed frame/cut, terminates or reaps the exact sole child, never cleans while it may still run, permits authentic recovery only when the exact terminal frame reports authentic-seam inline recovery count zero and the independent post-reap `ROOTFS_STATE` observation proves recovery needed, validates every accepted fixed name and alias, preserves an injected unknown or mismatched object before mutation, removes only authorized fixed child-provenance entries in cleanable rows, restores the rootfs/cache/temp baselines where authorized, closes supervisor fds, and respects monotonic phase ceilings. Within the same table, and without another child-death boundary, prove that a terminal count of one forbids parent recovery and that an absent, truncated, malformed, or uncertain terminal frame or pipe record preserves state and fails closed. The success kind proves the clean terminal path, cleanup plus independent observations in `+4500..+5100`, and only final close/error/status accounting in `+5100..+5400`, without forced death.

These are lifecycle-boundary tests, not instruction-boundary tests. Do not add alarm-delivery permutations, every-bytecode injection, repeated offsets around a cut, random fault campaigns, or a seventh child-death state. Existing production transaction tests and the inherited F1–F6 meaning remain unchanged; this table tests supervisor behavior and supplies no new production fault seam.

No new test command or mode is authorized. The inherited local validation remains:

```text
python3 -I test/aws-stage2-completion-rootfs-candidate.py
python3 -I test/aws-stage2-completion-rootfs-candidate.py --linux-synthetic
node --test test/aws-stage2-completion-rootfs-*.test.ts
git diff --check 8caab23bb4277121a77d80dc043b3c2c43b07ced..HEAD
```

Default and synthetic validation perform no acquisition or other network operation. The authentic `--hosted-exact` route may run only in its already approved hosted environment after the inherited exact-head review and event gates; this proposed rewrite grants no execution by itself.

## Proposed revised excluded maxima

Gross additions remain measured against exact baseline `8caab23bb4277121a77d80dc043b3c2c43b07ced`; deletions receive no credit and allowances are non-transferable.

| Excluded file | Absolute maximum gross additions |
| --- | ---: |
| `test/aws-stage2-completion-rootfs-candidate.py` | **1,100** |
| `test/aws-stage2-completion-rootfs-candidate.test.ts` | **30** |
| `.github/workflows/stage2-rootfs-full-build-qualification.yml` | **110** |
| **Excluded three-file total** | **1,250** |

This ADR newly proposes raising ADR 0061's accepted candidate maximum from 570 to 1,100 and excluded aggregate maximum from 710 to 1,250. The proposed arithmetic is `1,100 + 30 + 110 = 1,240`, leaving ten aggregate lines unallocated; those ten lines are not a transferable per-file allowance. The accepted TypeScript maximum remains 30 and the accepted workflow maximum remains 110. No production per-file or aggregate maximum, counted physical-line reserve, preferred 32,000 cap, hard 34,000 cap, companion cap, or later-stage allowance changes.

Keep the implementation ordinarily formatted and readable. Stop and replan before crossing either proposed maximum, modifying another file, moving logic elsewhere, compressing required checks to manufacture margin, or needing behavior outside this decision.

## Review, execution, and stop boundaries

The prior ADR 0062 version was unmerged and unaccepted; its review history does not approve this new proposal. The complete corrected exact head requires a fresh independent hostile review of the inherited exact base-to-head range with no unresolved P0–P3 finding. Any later correction invalidates that signoff.

Every non-conflicting ADR 0057–0061 requirement remains binding, including exactly one `ready_for_review` event, exactly one hosted run at attempt 1, the existing event and workflow gates, the exact 5,400-second allocation, exact 16-artifact contract, two builds, at most one authentic recovery, independent final observations, and the mandatory stop after every hosted outcome. The existing workflow, outer GNU timeout, one job, permissions, trigger, source gates, and run accounting remain unchanged.

This ADR creates no additional implementation file, review event, ready transition, run, attempt, retry, recovery, candidate, report, export, mode, command, timeout, stage, campaign, production, release, or issue-closure authority. In particular, it authorizes no network acquisition during documentation or portable validation; no credential, AWS CLI, account, provider, OpenTofu, SSM, deployment, resource, cloud cleanup, or other AWS action; and no Phase B, later-stage, step-5, campaign, production, cloud, or release action.

## Consequences

The mutating Python code no longer needs to survive an asynchronous exception. The parent enforces process ceilings, proves the sole child has terminated, and derives narrow post-mortem authority from private empty directories, fixed provenance, fixed names, and exact filesystem observations. Unknown or changed state is preserved. The tradeoff is one fork and a small fixed protocol in the excluded hosted driver, while production and all operational authority remain unchanged.

This documentation-only proposal remains uncommitted and creates no implementation, test change, workflow change, command, review, branch, commit, pull request, label, event, acquisition, network operation, hosted run, candidate, report, export, cloud resource, or AWS action.
