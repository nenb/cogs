# ADR 0055: Move native C1 to a fresh post-quality job and harden its invoker

- Status: Proposed
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Amendment scope: If accepted, this ADR amends ADR 0052's placement and job identity for workflow-bound native C1, ADR 0053's invoker correction and invocation scope, and ADR 0054's companion-test file, invocation, assertion, and line scope only as specified below. ADR 0051–0052's native observation requirements are clarified by the exact permission split below; every other non-conflicting requirement of ADRs 0050–0054 remains binding.

## Context

GitHub Actions run `30194550977`, attempt 1, exercised exact source head `1b13404d948368b5f421b4df0f5b837dd446ff03` (`1b13404`) on hosted Ubuntu 24.04. Its existing quality gates passed, but native C1 failed before sudo because the unprivileged parent attempted to stat `/proc/1/ns/pid` and received `PermissionError`. The run issued no native qualification and consumed no candidate.

The first independent hostile review, retained as `/tmp/native-permfix-review.md`, confirmed that splitting observations between unprivileged parent-self and privileged child-self/PID1 fixes that host `/proc` permission problem. It nevertheless found one P1: the sudo invoker child and native-test child were not launched with Python isolated mode, and the parent accepted only selected fields rather than the exact complete privileged record. An untracked import shadow could therefore forge a passing partial record.

The corrected attempt was independently reviewed in `/tmp/native-permfix-review2.md`. It added `-I` and complete-record validation, but also added pre/post pathname checks and synthetic pathname-attack tests. That review found the checks did not bind the bytes Python consumed: an earlier quality step could leave a process that transiently exchanged an ancestor directory between check and use. The attempt grew the invoker by 426 gross additions while its generated repositories, toy scripts, and persistent self-modification test did not exercise the authentic authority route.

The assessment retained as `/tmp/native-reorder-assessment.md` concluded that strict early execution on a fresh GitHub-hosted workspace closes that active-attacker premise under an explicit runner trust boundary. Its safest structure is a separate fresh job that waits for `quality`, checks out and verifies the exact head, and then immediately invokes native C1 before setup or other checked-out code. That structure preserves quality-first qualification without treating an earlier C1 log line as final authority. It is not authorized by ADR 0052, which places C1 at the end of `quality`, or ADR 0054, which does not permit the required companion invocation and ordering changes.

## Decision

If accepted, replace the trailing native C1 step in `quality` with exactly one dedicated `native-c1` job and authorize only the bounded invoker and existing companion-test corrections below.

### Fresh post-quality `native-c1` job

The job identifier and authority-bearing expected job identity are exactly `native-c1`. The job must:

1. declare `needs: quality` without `always()` or another condition that permits execution after quality failure, cancellation, or skip;
2. run only on exact first attempt `github.run_attempt == 1` for a `pull_request` whose `pull_request.head.repo.full_name` exactly equals `github.repository`; reruns, fork pull requests, and every push or other event must skip it;
3. declare exactly `runs-on: ubuntu-24.04`, no job container, no service, no matrix, and no namespace or container wrapper;
4. use the existing pinned `actions/checkout` revision to check out exactly `pull_request.head.sha`, with `persist-credentials: false`;
5. run the fixed workflow-shell exact-head verification immediately after checkout and fail closed unless the event head repository equals `github.repository`, the head SHA is canonical lowercase 40-hex, and `/usr/bin/git rev-parse --verify HEAD` equals that SHA; and
6. invoke `/usr/bin/python3 -I test/aws-stage2-completion-rootfs-builder-native.py --workflow-bound` as the immediately following and final job step, directly from the ordinary unprivileged runner account.

No setup action, package installation or lifecycle, repository script, sourced repository shell, test, build, generated executable, or other checked-out project code may run between checkout and C1 or before C1 in this job. Checkout, the fixed verification shell, and the direct C1 invocation are the complete step list. The invoker and the native route it deliberately starts are the first checked-out code executed in the fresh workspace.

A passing `native-c1` job is authoritative only on run attempt 1, when its required `quality` job completed successfully in that same workflow run and attempt. A rerun attempt or failed, cancelled, or skipped `quality` job prevents qualification. A passing `quality` job without a passing `native-c1` job also provides no native C1 qualification.

The existing same-repository exact-head behavior and all ordinary steps in `quality` remain unchanged except that its trailing C1 step is removed. The new job must use the same run and event metadata domains as ADRs 0052–0053, but the fixed job declaration, `GITHUB_JOB` observation, expected metadata, and emitted record must all name `native-c1`, never `quality`.

This authority relies explicitly on a fresh, trusted GitHub-hosted Ubuntu 24.04 VM/workspace, the GitHub runner, and the pinned checkout action completing synchronously without leaving an adversarial process. Source continuity also relies on no repository-controlled process executing before the gate and on the gate starting no concurrent repository-mutating process before consuming its sources. This is an ordering-and-runner-trust argument, not a general pathname-execution binding.

The pinned checkout action may receive only GitHub's automatic token limited to read-only `contents`, and must use `persist-credentials: false`. No token or secret may be exposed to C1 or any later step. The job and C1 invocation must otherwise reference or receive no secret, persist no credential, create or upload no artifact, and request no write permission. No other permission, token use by C1, cache, artifact action, output publication, or secret context is authorized. The existing 15-minute workflow timeout boundary may be retained for the dedicated job but may not be increased.

### Exact parent, privileged-child, and PID1 observations

The unprivileged workflow parent must collect only its own process evidence. It must not read PID1 namespaces, root, mountinfo, or cgroup data. Its local record must contain its exact self observations for PID, mount, user, and cgroup namespace identities; kernel; NSpid depth; root identity and root mount; cgroup2 mount identity; and the retained bounded marker and changed-root/container-rootfs checks it can perform without PID1 access.

Only the EUID-0 sudo child may collect both its own process observations and mandatory PID1 namespace, root, root-mount, and applicable cgroup observations. The child must independently recollect workflow/source observations and fail closed on any unavailable, malformed, duplicate, extra, or mismatched field.

Validation must require exact parent and child dictionaries and prove, without fallback:

- observation-only classification and the exact record version;
- exact non-empty kernel equality;
- exact shape and validity of all PID, mount, user, and cgroup namespace identities;
- parent-self equality with privileged-child-self for every shared field;
- privileged-child-self equality with PID1 for every required namespace;
- parent/child equality for NSpid depth, root identity, complete root-mount identity, and cgroup2 identity;
- privileged-child-self/PID1 equality for root identity and the complete root mount; and
- retention of mount ID, parent ID, device, root, mount point, options, filesystem type, hashed source, and super options, including rejection of changed roots and known container filesystems.

Missing PID1 evidence, permission denial, apparent marker or cgroup absence, local-manual output, or a partial comparison is failure, never authority.

### Isolated launches and exact full-record validation

Every Python invocation in the authorized workflow, invoker, and companion-test routes must use isolated mode `-I`. This includes the workflow parent, the sudo invoker child, the native-test child, the companion's native-invoker portable invocation, its local-manual invocation, and its existing portable builder-test invocation. The privileged child's exact sudo command readback and provenance must include and validate the isolated invocation.

The unprivileged parent must parse and validate the exact complete privileged record before printing it. Exact validation must reject missing or extra fields and require:

- exact top-level classification and `workflow-bound-native-c1` context;
- the complete execution envelope, source record, and runner-environment readback from the parent's expected observations;
- the exact complete local record containing parent-self and privileged-child-self/PID1 observations;
- complete sudo caller identity and provenance, including UID, GID, account, exact isolated command, and parent/child equality claim; and
- the exact native-test result, source SHA, classification, and ordered observation labels.

Nested records must also have their exact required shapes. Duplicate JSON names, malformed values, a substituted runner or source value, a partial sudo record, a fabricated local pair, a missing PID1 record, a changed native result, or any additional field fails closed. Selected-field `.get()` checks are not complete-record authority.

Portable negative coverage must remain compact and table-driven. Starting from one complete valid fixture, it must pass authentic malformed complete-record variants through the same parser and validator used by the parent and cover representative missing, extra, duplicate, malformed, context, workflow/source/runner, sudo, parent/child/PID1, and native-result failures. These are record-validation tests only; they must not claim GitHub-hosted authority or pathname continuity.

Do not add or retain `file_binding`, pre/post pathname identity or hash checks, generated Git repositories or child scripts, import-shadow marker scripts, source self-modification tests, reversible pathname-exchange simulations, or similar machinery presented as binding executed code to a pathname. Existing exact Git-head and source-byte comparisons remain required observations. Their continuity is supplied by the fresh-job ordering and trust boundary, not by misleading check/use/check claims.

### Exact file and gross-line bounds

Implementation authority is limited to these three files, measured as gross raw added physical lines against exact implementation baseline `1b13404d948368b5f421b4df0f5b837dd446ff03`. Deletions create no credit, and unused allowance in one file cannot fund another:

| Authorized file | Authorized purpose | Maximum gross raw additions |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Remove trailing quality C1 and add the exact fresh `native-c1` job | 45 |
| `test/aws-stage2-completion-rootfs-builder-native.py` | Permission split, isolated children, exact full-record validation, and compact malformed-record coverage | 260 |
| `test/aws-stage2-completion-rootfs-builder.test.ts` | Assert the dedicated-job boundary and use `-I` for every existing Python invocation | 55 |
| **Total** |  | **360** |

These are maximum highs, not targets. The final implementation must report each exact gross measurement and remain materially below the rejected 426-addition invoker design by omitting its pathname-binding and toy-harness machinery. Stop and replan before exceeding any per-file high or the 360-line total, changing another workflow/test file, or needing another implementation surface.

No production file, native builder test, schema, documentation other than this decision, dependency, lockfile, generated file, candidate workflow, or companion file is authorized to change. The existing companion test must retain every non-conflicting source-domain, synthetic-envelope, sudo, observation-only, local-manual, and fail-closed assertion.

## Candidate and retained stops

This decision adds, selects, consumes, replaces, labels, or reruns no candidate. ADR 0050's sole operationally selected non-authoritative candidate remains unconsumed. The `security` label must remain absent throughout implementation, ordinary CI, native qualification, remeasurement, and review. The dedicated job is native C1 regression authority only for its own exact source, workflow run, and attempt; it is not KVM, Phase A, candidate, later-stage, campaign, or production authority.

Every retained C1–C4 and R1 gate, exact-source and exact-head requirement, separate ADR 0053 synthetic-envelope observation, run-attempt and duplicate-run rule, formatter and hostile-review gate, counted production high, candidate-freeze and one-label-event rule, timeout, retry, rerun, Phase B, later-stage, step-5, campaign, production, issue-closure, cloud, AWS, and mandatory-stop boundary from ADRs 0038–0054 remains unchanged. No fallback is authorized from failed quality, failed or ambiguous native evidence, unavailable PID1 observations, source mismatch, exceeded line high, or unresolved review.

No AWS credential, CLI, account lookup, provider, OpenTofu operation, SSM action, deployment, resource creation, cloud cleanup, network qualification, Docker, or KVM action is authorized. This proposed documentation-only decision performs no code, workflow, test execution, dependency, lockfile, network, candidate, campaign, production, cloud, or AWS action.

## Consequences

If accepted, native C1 runs only after successful quality but on a separate fresh Ubuntu 24.04 workspace where it is the first checked-out code executed after exact-head verification. That removes the prior same-runner process premise without pretending mutable pathname observations bind execution.

The permission split accommodates hosted `/proc` restrictions while retaining mandatory privileged PID1 evidence. Isolated Python launches and exact complete-record validation close the import-shadow and partial-record spoof routes. The cost is one narrowly bounded read-only CI job and compact companion coverage; every candidate, security-label, AWS, production, and later-stage stop remains in force.
