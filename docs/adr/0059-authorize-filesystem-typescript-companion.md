# ADR 0059: Authorize the filesystem TypeScript companion

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing bounded-local delegation, after corrected independent review reported no P0–P3 findings.
- Acceptance record: [GitHub pull request #229](https://github.com/nenb/cogs/pull/229).
- Amendment scope: This ADR amends only ADR 0058's omitted companion scope for exactly `test/aws-stage2-completion-rootfs-fs.test.ts`. Every other ADR 0057–0058 scope, test, execution, review, budget, cap, stage, and stop boundary remains binding.

## Context

ADR 0057 moves the strict anonymous-inode primitives into `completion_rootfs_fs.py` and permits exactly one `O_TMPFILE | O_RDWR | O_CLOEXEC` open in `fs._open_anonymous`. ADR 0058 authorizes the five existing Python companions needed to describe that architecture, including replacement of the Python filesystem test's stale global `O_RDWR` prohibition with strict scoped assertions. ADR 0058 nevertheless expressly permits no TypeScript companion change.

The existing TypeScript wrapper independently reads `completion_rootfs_fs.py` after its unchanged Python child succeeds. Its source policy still globally rejects every `O_RDWR` token. The file is unchanged from exact baseline `8caab23bb4277121a77d80dc043b3c2c43b07ced` (`8caab23`), so it rejects ADR 0057's sole required anonymous open even when the ADR 0058 Python companion passes.

The current complete rootfs result is **16/17**: exactly `test/aws-stage2-completion-rootfs-fs.test.ts` fails on that stale global prohibition. Inspection of the remaining wrappers found no other stale wrapper assertion. This result does not accept the remediation, substitute for ADR 0057's qualification or final review, or authorize another execution; it only identifies the remaining companion-scope omission.

## Decision

If accepted, authorize a static-assertion-only update in exactly:

- `test/aws-stage2-completion-rootfs-fs.test.ts`.

No other file is authorized.

### Replace only the stale global prohibition

Remove `O_RDWR` only from the wrapper's existing global forbidden-token expression. Replace that obsolete blanket prohibition with strict source assertions proving all of the following:

- `completion_rootfs_fs.py` contains exactly one `O_RDWR` token;
- that token is scoped inside the sole `fs._open_anonymous` definition;
- the scoped flags expression is exactly `os.O_TMPFILE | os.O_RDWR | _O_CLOEXEC` and retains its exact numeric flag check;
- the corresponding open is exactly the anonymous `os.open(b".", flags, mode, dir_fd=directory.operation_fd.number)` relative to the held operation-directory descriptor; and
- no second `O_RDWR` use, named writable open, fallback, or generalized write route is accepted.

The assertions must isolate the `_open_anonymous` body rather than merely matching the three flag names anywhere in the module. They may not broadly allow `O_RDWR`, lower a count, accept reordered or additional flags, accept a caller-selected path or directory, or replace an absence assertion with an unconstrained presence check.

### Retain every unrelated source and wrapper constraint

The existing bans on `O_CREAT`, `O_EXCL`, `O_TRUNC`, `O_WRONLY`, named create/truncate/write, `rmtree`, `os.walk`, globbing, subprocesses, sockets, Boto, and Terraform remain. The existing `os` mutation-call ban, including `write` and `pwrite`, remains unchanged. The positive checks for `O_PATH`, fd and symlink xattrs, surrogate escaping, and `PRIVILEGED_MUTATOR_EXCLUSION` remain unchanged, as do the bans on a main entry point, argument parsing, argv, and environment-selected behavior.

The wrapper's test name, Python child path and arguments, working directory, bytecode setting, timeout, status check, success-output check, source path, and all unrelated assertions remain unchanged. This amendment does not authorize weakening the Python companion or using the TypeScript wrapper to test transaction, ledger, recovery, cleanup, publication, or candidate semantics.

## Measured gross-addition plan

Gross added physical lines are measured against exact baseline `8caab23bb4277121a77d80dc043b3c2c43b07ced`; deletions create no credit. At that baseline the exact wrapper is 36 physical lines and is blob-identical in the inspected remediation worktree. The estimate is measured from its stale four-line forbidden-token block: 4–6 lines to isolate and uniquely count the anonymous body and 4–8 lines for the exact flags/open assertions and retained forbidden-token expression.

| Exact companion / purpose | Gross low | Gross high/max |
| --- | ---: | ---: |
| `test/aws-stage2-completion-rootfs-fs.test.ts`: replace only the stale global `O_RDWR` ban with strict scoped static assertions | 8 | **14** |
| **Exact one-file total** | **8** | **14** |

The 14-line file and total maximum is absolute and non-transferable. Stop and replan before crossing it, changing another file, weakening an unrelated assertion, or compressing the assertions to fit. These are excluded companion-test lines and create no deletion credit, counted-set credit, cap headroom, production allowance, or later-stage allowance. ADR 0057's production and qualification highs and the accepted 32,000 preferred and 34,000 hard cumulative caps remain unchanged.

## Existing gates only

This amendment adds or changes no test command, child process, wrapper selection, package script, workflow step, job, trigger, event, mode, timeout, invocation, acquisition, qualification route, or hosted run. The amended static assertions may be evaluated only through already-authorized existing routes. The current 16/17 observation grants no rerun or additional execution authority.

ADR 0057's one clean independent final exact-head signoff must include this exact wrapper change, its gross count, the sole scoped anonymous-open proof, and retention of every unrelated source constraint. This inclusion is part of the same existing signoff and does not authorize another review or execution.

## Retained scope and stops

This amendment changes no Python file, production file, workflow, command, execution authority, schema, report, fixture, pin, dependency, lockfile, source preparation, budget, cap, stage, timeout, transaction, ledger contract, recovery behavior, cleanup behavior, publication behavior, candidate contract, or evidence contract.

Every exact-base/head, branch, stacked-PR, final-review, six-fault, authentic exact-16 two-build, one-ready-event, run-attempt, mandatory-stop, Phase B, later-stage, step-5, campaign, production, release, issue-closure, cloud, and AWS boundary retained by ADRs 0057–0058 remains unchanged. No implementation defect may be fixed under this companion-only authority.

This documentation-only proposal creates no implementation, test change, command, test execution, review, branch, commit, pull request, workflow, event, acquisition, network operation, hosted run, candidate, report, cloud resource, or AWS action.

## Consequences

The existing TypeScript wrapper can enforce the same narrow anonymous-open architecture as the amended Python filesystem companion without preserving a contradictory global `O_RDWR` ban. Named mutation and every unrelated source restriction remain fail-closed, and no implementation, execution, cap, or stage authority expands.
