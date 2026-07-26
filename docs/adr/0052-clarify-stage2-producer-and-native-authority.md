# ADR 0052: Clarify Stage 2 producer states and native qualification authority

- Status: Proposed
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Acceptance authority: Nick Byrne, or the delegated project lead acting under Nick Byrne's standing bounded-local delegation.
- Amendment scope: If accepted, this ADR amends only ADR 0051's C3 producer semantics, C1 native-qualification authority (including the one narrow existing-CI workflow change specified below), and counted-line highs. Every non-conflicting ADR 0050 and ADR 0051 requirement remains binding.

## Context

The final clean-signoff review of the ADR 0050/0051 C2/C3 implementation, retained as `/tmp/adr0051-c2c3-signoff.md`, remains blocked. It found three P1 issues:

- After durable `cache-owned`, authentic bootstrap, token, lifecycle, or other pre-phase failures can leave every rootfs phase `not-reached` while runtime is correctly `blocked`. The schema and canonicalizer reject parts of that producer state space.
- Cache ownership and runtime publication effects can complete before fallible timing bookkeeping. A later timing failure can currently rewrite the completed effect as stage `failure`.
- The ordinary format gate is red. Mechanically formatting the current schema would also exceed ADR 0051's schema high, so compressed unformatted causality is not an acceptable remedy.

The final C1/R1 review retained as `/tmp/adr0051-c1r1-finalreview.md` also found that a process-local script cannot prove that its visible PID 1 is the GitHub runner host init. A sufficiently privileged nested container can reproduce the script's namespace-local positive observations. Host qualification therefore needs authority external to the tested process namespace.

That review's separate R1 close-order and authentic fault-matrix findings are not waived by this decision. They remain implementation defects to close under ADR 0051 before candidate freeze.

The implementation still has one unconsumed non-authoritative candidate from ADR 0050. No review finding justifies consuming it before all retained gates are green.

## Decision

If accepted, authorize only the following clarifications and revised highs.

### C3 authentic pre-phase producer states

The live v2 schema and canonicalizer must accept the authentic state produced after durable cache success when a resolved rootfs setup or pre-phase failure prevents entry into the first rootfs phase:

- `artifact_cache.status` is `success` with its valid measured elapsed time and `checks.artifact_cache` is `pass`;
- `first_build_setup` is the exact trusted boundary reached by the producer;
- every rootfs phase is `not-reached` with zero elapsed time;
- `runtime_assets.status` is `blocked`, its elapsed time is zero, the runtime-assets array is empty, and `checks.runtime_assets` is `blocked`.

The applicable trusted setup values include:

- `rootfs-bootstrap` for failures after durable `cache-owned` and before bootstrap and lifecycle ownership complete;
- `operation-establishment` for token generation or validation, repeated fixed-input validation, or operation-establishment failure before first-phase entry; and
- `materializer-dispatch` for a resolved failure after exact operation ownership but before materialization enters the first rootfs phase.

A resolved setup failure is sufficient causal authority for runtime `blocked`; a fabricated rootfs-phase `failure` is neither required nor permitted. Runtime `not-reached` remains invalid after that prerequisite failure has resolved. Once materialization has entered a rootfs phase, the existing phase-progress and settlement rules remain unchanged.

Producer-driven tests must reach every real failure boundary from durable `cache-owned` through first-phase entry and assert the exact produced setup, phase, cache, and runtime state. Schema and canonicalizer tests must accept each authentic state and continue to reject adjacent impossible states, including runtime `not-reached` after a resolved prerequisite failure.

### Completed stage effects and timing failure

A completed stage effect is irreversible evidence about that stage. In particular:

- cache success is fixed when all existing ADR 0050 cache-success requirements, including durable exact `cache-owned` readback, have completed; and
- runtime-assets success is fixed when all required runtime download, verification, and publication effects have completed.

The implementation must bind that semantic completion before fallible elapsed-time or instrumentation bookkeeping. A later timing or instrumentation failure must not rewrite the stage to `failure`, `attempting`, or any other false outcome.

Because a canonical stage row requires a valid measured `elapsed_ms`, such a post-effect timing failure makes that row unavailable. Its summary may only become `unknown`; no elapsed value or stage status may be fabricated. The required `stage_evidence` object must then fail the final canonical/schema gate, and no report may be exported. This fail-closed no-export result preserves the completed effect without making an unsupported wire claim.

The same rule applies at both cache and runtime success boundaries. Tests must exercise the real effect-before-bookkeeping seams end to end and prove both that success is never rewritten as failure and that an unavailable row cannot validate or export.

### Ordinary formatting and readability

All ordinary repository checks, including the repository's ordinary formatter check, must pass at the reviewed head. Every changed schema, production file, and test must use the ordinary formatter output; changing or bypassing formatter configuration is not authorized.

Causal schema definitions and tests must remain ordinarily readable after formatting. Dense manual compaction, formatter-resistant layout, duplicated opaque branches, or other line-count evasion is forbidden. The additional schema allowance below exists so the closed causal graph can be factored and reviewed in ordinary formatted form.

### C1 native authority is workflow-bound

ADR 0051's script observations remain required but are not standalone host authority. The script is observations-only: it must never claim `native-host` authority, and reviewers must not infer that authority from its visible `/proc`, namespace, cgroup, root, mount, marker, or sudo observations. A local manual invocation, Docker invocation, or script-emitted classification cannot satisfy C1.

C1 native qualification authority is instead the reviewed composite of:

1. a reviewed, tracked GitHub Actions workflow job whose source-head workflow declaration is exactly `runs-on: ubuntu-24.04` and has no job `container`;
2. a direct invocation of the tracked native C1 gate in that job, without an intervening container or namespace wrapper;
3. durable external execution-envelope metadata identifying the repository, workflow and job, event and action, run ID, run attempt, synthetic pull-request merge SHA, workflow ref/SHA, base SHA, and pull-request number; and
4. one exact source revision shared by the same-repository pull-request head, explicit checkout, reviewed implementation head, workflow blob, invoker, native test, and native test's recorded source SHA, together with the invoker's bounded sudo provenance, parent/child equality, kernel, namespace, root-mount, filesystem, descriptor, recovery, counter, and exact-baseline observations required by ADR 0051.

The synthetic pull-request merge SHA is a distinct trusted execution/control envelope and is expected not to equal the source revision. It must be recorded from `github.sha`, equal the event's `pull_request.merge_commit_sha`, and be a canonical 40-hex SHA. It is never described as the tested source revision. The source identities named in item 4 must all equal `pull_request.head.sha`. The workflow file bytes used from the pull-request source head must hash to the exact reviewed workflow blob; review must bind that blob and the external execution envelope through the exact repository, workflow/job, event/action, pull-request number, run ID, and run attempt. Missing, malformed, collapsed, or inconsistent envelope/source metadata, a different run attempt, a job-level container, indirect container execution, or incomplete script observations fails closed. Unit-test or locally supplied envelope values remain observations-only. Each real run attempt is a distinct observation and cannot be represented as another.

This external workflow authority resolves the host-init ambiguity identified by native review; it does not weaken the script's positive observations or exact recovery comparison. An ordinary portable path by itself still does not count.

To make that authority reachable, authorize exactly one narrow change to the existing `.github/workflows/ci.yml` `quality` job:

- Only for a `pull_request` whose `pull_request.head.repo.full_name` exactly equals `github.repository`, checkout must select the exact `pull_request.head.sha`; `persist-credentials` must remain `false`. Fork-pull-request checkout and the existing `main` push path and behavior must remain unchanged.
- The checkout-verification and C1 steps must be gated to that same-repository pull-request condition and skipped for every other event. Before any checked-out pull-request code executes, the fixed verification step must fail closed unless the event head repository equals `github.repository`, the event head SHA is a valid exact SHA, and `git rev-parse HEAD` equals that SHA.
- After the existing tests and quality checks have passed, the fixed C1 step must invoke the tracked native gate directly from the ordinary unprivileged runner account. The tracked invoker's own bounded `sudo` transition remains the only privilege transition; the workflow must not invoke the gate through `sudo`, a container, a namespace wrapper, or a portable-test wrapper.
- That step must supply fixed expected metadata declarations for repository, workflow file and `quality` job, event and action, run ID, run attempt, synthetic execution-envelope SHA, workflow ref/SHA, base SHA, pull-request number, pull-request head repository and SHA, checked-out SHA, and reviewed workflow-blob digest. Values bound to the event or run must come directly from their corresponding trusted GitHub Actions contexts, while workflow identity, job identity, expected event, and reviewed blob digest are fixed reviewed values. The gate must compare each envelope field to its matching envelope observation and each source field to the one source revision; it must never compare or substitute the synthetic merge SHA as the source SHA. Any missing, malformed, unequal, collapsed, or locally fabricated value fails closed.
- The C1 invocation must receive no secret, request no token or write permission, and create or upload no C1 artifact; only the bounded job log and GitHub's run/event metadata are review records. No new artifact behavior is authorized. The job remains `runs-on: ubuntu-24.04`, has no job container, and remains under read-only `contents` permissions.

This route is non-candidate C1 regression authority only. It is never KVM, Phase A, candidate selection or consumption, or authority for any later-stage gate. The `security` label must remain absent. No other workflow file or job may change, and no workflow trigger, permission, runner label, job container, timeout, existing main-push behavior, candidate workflow, artifact behavior, or security-label policy change is authorized.

### Revised exact-baseline highs

Raw additions remain measured against exact baseline `0017ac2ec441301a252363b2b9ee90db65fda41e` under ADR 0050's frozen counted set, no-deletion-credit rule, exclusions, and anti-evasion rule. Replace only ADR 0051's per-surface and total highs with these values:

| Allowed counted production surface | Gross raw-addition high |
| --- | ---: |
| `deploy/aws-feasibility/remote/completion_rootfs_builder.py` | 155 |
| `deploy/aws-feasibility/remote/completion_rootfs_build.py` | 15 |
| `scripts/run-stage2-phase-a-candidate.py` | 420 |
| `schemas/stage2-phase-a-candidate-v2.json` | 400 |
| **Total** | **990** |

The builder high is unchanged. The build-module high remains available only for ADR 0051's C3 trusted setup marker. No other counted production surface is authorized. Tests, the tracked native invoker, C4, documentation, and frozen reports remain excluded and create no cap credit. Deletions offset neither a surface nor the total, and unused allowance on one surface cannot authorize work on another.

The conservative hard-cap projection is:

`24,683 + 7,230 + 990 = 32,903 < 34,000`.

Stop and replan before further counted implementation if any per-surface high or the 990-line total high would be exceeded. ADR 0050's exact-head remeasurement, remaining-high calculation, and stop at or before the unchanged 34,000 hard cap remain binding.

## Candidate and retained stops

This decision adds no candidate. ADR 0050's one operationally selected non-authoritative candidate remains unconsumed. The `security` label must remain absent throughout implementation, ordinary CI, native qualification, formatting, remeasurement, and review. Nothing in this decision authorizes the label event or candidate freeze now.

Before ADR 0050's candidate may be frozen and selected, all C1–C3 and R1 findings must be closed, every retained portable, Docker-functional, native, schema, formatter, fault, ownership, recovery, and hostile-review gate must be green, and the exact head and run records must be reviewed. Docker remains functional-only. A passing native job qualifies only its exact reviewed run and revision and does not itself consume, replace, or authorize the candidate.

Except for the exact same-repository pull-request `quality`-job change above, every retained timeout, retry, rerun, duplicate-run, exact-SHA, Phase B, later-stage, workflow, candidate, campaign, production, issue-closure, cloud, AWS, and mandatory post-candidate stop remains unchanged. There is no fallback from an unavailable stage row, failed formatter gate, ambiguous native record, exceeded line high, or unresolved review finding.

This documentation-only proposal performs no code, workflow, dependency, lockfile, test, network, Docker, KVM, provider, cloud, AWS, candidate, campaign, or production action.

## Consequences

If accepted, the v2 contract can represent the runner's authentic cache-success/pre-phase-failure states without inventing a failed rootfs phase, while post-effect timing faults fail closed without falsifying completed work. Readable formatter-compliant causality receives sufficient bounded schema and runner margin.

Native C1 authority becomes an exact reviewed GitHub-job claim combined with bounded script observations rather than an impossible process-local proof of host init. The narrow same-repository pull-request route provides non-candidate C1 regression authority without changing `main`, invoking KVM or Phase A, adding privileges, consuming secrets, or producing C1 artifacts. The sole ADR 0050 candidate remains unavailable until all retained gates pass, and every candidate outcome still ends at the existing mandatory stop.
