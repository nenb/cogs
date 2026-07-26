# ADR 0058: Authorize atomic-candidate Python test companions

- Status: Proposed
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Amendment scope: This single combined amendment changes only ADR 0057's omitted companion-test file scope. It permits necessary ordinary-readable updates in exactly five existing Python tests. Every production, qualification, review, execution, budget, stage, and stop boundary of ADR 0057 remains binding.

## Context

Accepted ADR 0057 authorizes a narrow exact-base remediation of the candidate-tar tail at `8caab23bb4277121a77d80dc043b3c2c43b07ced` (`8caab23`). Its production plan moves authority-neutral anonymous-inode primitives into `completion_rootfs_fs.py`, removes the named writable-tar route from `completion_rootfs_build.py`, adds four candidate-tar ledger records and builder recovery states, and adapts accepted publication to call the filesystem primitives. ADR 0057 also requires existing portable rootfs, ledger, builder, and publication tests to pass and retain their meaning.

ADR 0057 nevertheless names only a new candidate qualification test, its TypeScript wrapper, and its hosted workflow in the excluded qualification patch plan. It expressly says to stop before changing another test. It therefore omitted authority for the ordinary existing Python companions that necessarily describe the changed architecture.

The remediation worktree remains unchanged in those five tests relative to `8caab23`. The retained production-test log `/tmp/adr0057-production-tests.log` reports 12 of 16 wrappers passing and exactly four failures:

1. `test/aws-stage2-completion-rootfs-fs.py` still globally forbids `O_RDWR`, although ADR 0057 places the one strict `O_TMPFILE | O_RDWR | O_CLOEXEC` open primitive in the filesystem module.
2. `test/aws-stage2-completion-rootfs-ledger.py` requires its exercised record types to equal `RECORD_TYPES`, but supplies no authentic chains for `candidate-tar-intent`, `candidate-tar-abort`, `candidate-tar-observed`, or `candidate-tar-settled`.
3. `test/aws-stage2-completion-rootfs-builder.py` still requires the deleted named writable-file helper and its old close path in `completion_rootfs_build.py`.
4. `test/aws-stage2-completion-rootfs-publication.py` still expects the anonymous fdinfo constant and open/observe/link helpers to be locally owned by the publication module rather than the filesystem module.

That log exercised only the canonical wrapper's portable mode. The retained real mode in `test/aws-stage2-completion-rootfs-canonical.py` has two latent companion omissions: its fixed-workspace source tuple does not copy the new `completion_rootfs_candidate.py` imported unconditionally by `completion_rootfs_build.py`, and its accepted-publication uncertain-link fault still patches the deleted `publication._link_anonymous` rather than `fs._link_anonymous`. The real mode is also reused by the retained lease real harness, so the four immediate failures do not establish that only the immediately failing files are sufficient.

These are companion omissions, not evidence that the production remediation is accepted or correct. Merely deleting the failing assertions would also be insufficient: the four new durable record types, their two legal paths, preserve-on-mismatch reconciliation, and builder-only recovery must enter the existing hostile matrices through production codecs and parsers.

The corrected independent review of proposed ADR 0057 retained at `/tmp/adr0057-review2.md` accepted the narrow production design and specifically required exact parser/automaton/reconciler authority, builder-only recovery, primitive-domain separation, retained publication meaning, readability, and exact gross counts. This amendment supplies only the missing existing-test authority needed to preserve those requirements.

## Decision

If accepted, authorize one combined companion amendment in exactly these existing files:

- `test/aws-stage2-completion-rootfs-fs.py`;
- `test/aws-stage2-completion-rootfs-ledger.py`;
- `test/aws-stage2-completion-rootfs-builder.py`;
- `test/aws-stage2-completion-rootfs-publication.py`; and
- `test/aws-stage2-completion-rootfs-canonical.py`.

No other test file is authorized. In particular, this amendment permits no TypeScript companion change, new test file, new wrapper, new command, or new execution route.

### Replace stale architecture assertions; do not weaken them

The filesystem test must replace only the obsolete global `O_RDWR` prohibition. It must continue to forbid named create/truncate/write fallbacks and unrelated mutation machinery, while proving that the exact anonymous fdinfo flag tuple and the sole scoped `O_TMPFILE | O_RDWR | O_CLOEXEC` open belong to the strict filesystem primitive. It must not turn the filesystem module into a general writer, transaction owner, parser, reconciler, recovery route, cleanup owner, or publication authority.

The builder test must replace the obsolete `_writable_file`/old close-path assertion with assertions for the fixed candidate coordinator call and the absence of the deleted named-empty-tar, writable reopen, `_candidate_record`, and materializer metadata route. Its existing assertions for one parser/reconciler entrance, poisoning, scalar cleanup, complete walk, chain revalidation, fixed `recover-owned` CLI, time bounds, retained build, equality, and pins must remain.

The publication test must point its anonymous fdinfo, observe, close, and link expectations and mocks at the filesystem primitives, and must assert that publication calls those primitives without retaining local duplicates. It must preserve all accepted-publication transaction parsing, anonymous-generation, exact inode continuity, uncertain-link, no-replace, inode-version, recovery, inventory, ext4, pin, and closure meaning. Moving the low-level syscall assertions cannot move publication's journal, parent/name, inode-version, recovery, or terminal authority into the filesystem test.

The canonical test may change solely to add `completion_rootfs_candidate.py` to the fixed real-workspace source tuple and to patch and restore `fs._link_anonymous`, instead of the deleted `publication._link_anonymous`, for its retained accepted-publication uncertain-link fault. The fault's link-then-fail behavior and recovery meaning, every other copied source, and all portable, real, Docker, native, and lease-harness behavior remain unchanged. This adds no fault, mode, invocation, source-preparation mechanism, or publication authority.

A stale assertion may be replaced only by a stricter assertion describing ADR 0057's exact architecture. Do not broadly remove a forbidden-token set, lower a count, replace a behavioral check with source presence, or weaken an unrelated assertion merely to make the changed source pass.

### Authentic four-record codec and malformed coverage

The ledger test must add ordinary-readable fixtures for exactly the closed bodies of:

- `candidate-tar-intent`;
- `candidate-tar-abort`;
- `candidate-tar-observed`; and
- `candidate-tar-settled`.

The positive fixtures must enter as encoded ledger bytes and be accepted by the production `_parse_ledger` and `_parse_ledger_history` routes. They must populate the existing complete record-type, phase, positive-edge, forbidden-edge, independent-reference, status, and reconciliation-emission matrices rather than special-case those completeness assertions away.

The same production parsers must reject authentic raw-record mutations covering each of the four record types. At minimum the combined malformed matrix must prove:

- missing and additional body keys and the fixed-path requirement;
- exact token, size, digest, mode, UID, GID, kind, and `nlink` requirements;
- anonymous-to-linked mount/device/inode and unchanged-field continuity, exact `0 -> 1` link count, and permitted ctime-only generation transition;
- exact intent/abort body equality;
- exact observed/settled body equality;
- exact one-name parent transition and rejection of parent key, mode, UID, GID, link-count, unrelated-name, or regressive size/mtime/ctime drift; and
- rejection of all candidate record types from every illegal phase or edge, including after lease.

Malformed JSON bodies must reach the production raw parser. Direct calls to `_validate_body`, acceptance or rejection only by `LedgerProposal.create`, a test-only parser, or only the test's reference automaton are not substitutes. Test helpers may repair record-envelope offsets and hashes solely to deliver a body or edge mutation to the production parser; they may not normalize the mutated body or duplicate production legality.

### Exact transitions, reconciliation, and builder-only recovery

Through parser-produced histories and the production reconciler, the existing ledger test must cover both complete legal paths:

```text
active -> candidate-tar-intent -> candidate-tar-abort -> active
active -> candidate-tar-intent -> candidate-tar-observed -> candidate-tar-settled -> active
```

It must prove all of the following without directly fabricating `LedgerLegalState` or `LedgerState` results:

- intent plus exact absence and unchanged pre-parent is `candidate-tar-abortable`;
- intent plus the exact pre-bound linked generation, exact digest/size observation, and exact one-name post-parent is `candidate-tar-observeable`;
- observed plus those same bindings is `candidate-tar-settleable`;
- abort changes neither `operation_parent` nor `owned`;
- observed alone changes neither `operation_parent` nor `owned`;
- settlement changes only the operation parent and adds only the fixed linked candidate generation to `owned`; and
- every mismatched absence, name, generation, digest, size, parent, operation, ledger, phase, or observation is `preserve` with no cleanup authority.

The builder companion must exercise its candidate recovery dispatch using histories produced from encoded bytes by the production ledger parser and outcomes produced by the production reconciler. It must cover the absent-intent abort route, exact-linked intent advance through observed and settled, observed-only settlement, subsequent ordinary scalar removal, and preserve/no-mutation behavior for a representative mismatch. It must prove that durable candidate records are appended through the existing bounded append/readback capability, candidate recovery remains poisoned and builder-owned, and no inline coordinator reconciliation, second parser, second recovery path, broad deletion, or unknown-to-absent conversion is introduced.

A test may use bounded fakes for unrelated descriptor mechanics in this existing portable companion, but it may not mock or replace the production record-body validator, codec, parser, legal fold, reconciler, or recovery dispatcher whose behavior it claims. ADR 0057's separate six-case real-fd matrix remains authoritative for F1–F6 and must not be copied, expanded, or replaced here.

### Preserve unrelated tests and ordinary readability

Every assertion, fixture, mutation, invocation mode, skip rule, timeout, cleanup check, pin, and functional/native meaning unrelated to the four failures, the two canonical companion repairs, and candidate-record coverage remains unchanged. Existing malformed and legal matrices are supplemented, not narrowed. Existing accepted-publication tests retain their original authority domain. Existing Docker and native modes remain exactly as authorized by prior ADRs.

New fixtures and mutation tables must use ordinary readable Python: named helpers and records, reviewable nested bodies, and one semantically coherent assertion or compact group per line. Do not compress complete records, mutation matrices, or recovery cases onto long physical lines to fit the high. The highs below are maxima, not targets.

## Measured gross-addition plan

All measurements use raw gross added physical lines against exact baseline `8caab23bb4277121a77d80dc043b3c2c43b07ced`; deletions create no credit. At that baseline the five files are respectively 475, 1,533, 981, 553, and 596 physical lines and are blob-identical in the inspected remediation worktree. The estimates were measured against the affected baseline spans: filesystem `pure_tests`; ledger `codec_and_reconcile_tests`, `reference_matching`, `reference_validate`, `incremental_validation_tests`, `status_matrix_tests`, and `reconcile_emission_tests`; builder `portable_tests` and its existing recovery fixture; publication's initial anonymous-primitive block and terminal architecture assertions; and canonical's fixed-workspace source tuple and retained accepted-publication uncertain-link fault.

| Existing Python test / exact companion purpose | Gross low | Gross high/max |
| --- | ---: | ---: |
| `test/aws-stage2-completion-rootfs-fs.py`: moved fdinfo constant checks (3–5), scoped anonymous-open and retained no-fallback architecture assertions (7–11) | 10 | **16** |
| `test/aws-stage2-completion-rootfs-ledger.py`: readable candidate bodies/raw mutation support (28–42), four-record malformed parser matrix (44–65), legal/forbidden transition and reference coverage (38–56), reconciliation/status/preserve coverage (28–42) | 138 | **205** |
| `test/aws-stage2-completion-rootfs-builder.py`: stale build assertions (8–14), parser-produced candidate recovery fixture (22–34), abort/advance/settle/removal/preserve dispatch assertions (40–62) | 70 | **110** |
| `test/aws-stage2-completion-rootfs-publication.py`: filesystem-owned primitive mock adaptation (7–12), retained publication-domain/source assertions (6–10) | 13 | **22** |
| `test/aws-stage2-completion-rootfs-canonical.py`: fixed-workspace candidate-module copy (1–2), filesystem-owned retained uncertain-link seam (3–4) | 4 | **6** |
| **Exact five-file excluded total** | **235** | **359** |

Each file high and the 359-line total are absolute and non-transferable. Stop and replan before crossing either, changing another file, adding an execution surface, or compressing ordinary presentation to fit. Exact-head remeasurement must use `git diff --numstat 8caab23 --` for these five files and count gross additions only.

These are excluded companion-test lines. They do not change ADR 0057's 375–565 production plan, its six production files, its 565 production maximum, its excluded new-candidate/workflow plan, or the accepted 32,000 preferred and 34,000 hard cumulative caps. They create no deletion credit, counted-set credit, cap headroom, allowance transfer, production funding, or later-stage credit.

## Existing gates only

The five amended Python files may run only inside the local and hosted test routes already authorized by ADR 0057. This amendment adds no TypeScript wrapper, workflow step, job, trigger, dispatch, label event, rerun, test command, Docker/native mode, hosted invocation, acquisition, or execution authority. It does not add a seventh fault, a second authentic full-input regression, or a second hosted run.

ADR 0057's one clean independent final signoff must include these exact five-file changes, their gross counts, retained unrelated meaning, authentic production-parser coverage, builder-only recovery, and absence of source weakening. This is part of the same exact-head signoff, not authority for another review or execution. Any later correction still invalidates that signoff exactly as ADR 0057 specifies.

## Retained scope and stops

This amendment changes no production file, TypeScript file, workflow, schema, report, pin, package, fixture, dependency, lockfile, source preparation, budget, timeout, acquisition route, candidate transaction, ledger contract, recovery implementation, cleanup implementation, publication implementation, or hosted evidence contract. It grants no authority to fix a production defect discovered while writing the companions; such a defect remains a stop/replan condition under ADR 0057.

Every exact branch/base/head, stacked-PR, first-parent, final-review, one-ready-event, run-attempt, timeout, cache, six-fault, authentic exact-16 two-build, mandatory-stop, Phase B, later-stage, step-5, campaign, production, release, issue-closure, cloud, and AWS boundary of ADR 0057 remains unchanged. No scope or authority is expanded beyond the five necessary existing Python companions.

This documentation-only proposal creates no implementation, test change, test execution, review, branch, commit, pull request, workflow, event, acquisition, network operation, hosted run, candidate, report, cloud resource, or AWS action.

## Consequences

The existing Python suites can describe ADR 0057's moved primitive ownership and deleted named-writer architecture while authentically exercising all four durable records, their only legal transitions, preserve-on-mismatch reconciliation, and builder-only recovery. All unrelated test meaning and every ADR 0057 production, execution, cap, and stage boundary remain intact.
