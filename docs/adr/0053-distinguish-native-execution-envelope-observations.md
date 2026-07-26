# ADR 0053: Distinguish native execution-envelope observations

- Status: Proposed
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Acceptance authority: Nick Byrne, or the delegated project lead acting under Nick Byrne's standing bounded-local delegation.
- Amendment scope: This ADR amends only ADR 0052's requirement that the GitHub `github.sha` execution-envelope observation equal the event payload's `pull_request.merge_commit_sha`. Every other ADR 0050–0052 requirement remains binding.

## Context

The first reviewed same-repository pull-request exercise of ADR 0052's native C1 route was GitHub Actions [run 30192739504](https://github.com/nenb/cogs/actions/runs/30192739504), `run_attempt: 1`, for pull request #212 at exact source head `7c8780ffa8fcbc73df59abe4397ae34a474db8d4` (`7c8780f`). The bounded [`quality` job log](https://github.com/nenb/cogs/actions/runs/30192739504/job/89768797798) recorded this one envelope:

- repository `nenb/cogs`, workflow `.github/workflows/ci.yml`, job `quality`;
- event `pull_request`, action `synchronize`, pull request `212`, run `30192739504`, attempt `1`;
- `github.sha` `e977491c4b5731b55d60d4acf1f1c9be00d76008`;
- `github.workflow_sha` `e977491c4b5731b55d60d4acf1f1c9be00d76008`;
- event `pull_request.merge_commit_sha` `0d9fb80f329daa0df8a583cc816e6146a276f80f`;
- exact base `d76f8b7005efc78e165dc52b0d616e1ded91a481`; and
- exact pull-request head and checked-out SHA `7c8780ffa8fcbc73df59abe4397ae34a474db8d4`, with reviewed workflow-blob digest `b3c5be436a3f7a03bf95c6f29caa3f85ef983d3d9196e1512e034da2ac97a44a`.

All preceding `quality` steps, including exact-head checkout verification, ordinary formatting, tests, schemas, and repository checks, passed. The native step then failed before sudo or native C1 execution solely because the test-only invoker asserted that `github.sha` must equal the event merge SHA. The log proves that GitHub supplied different values for those two trusted synthetic execution-envelope observations in the same run attempt. It does not show a source mismatch: both values were distinct from the exact head and base, while the pull-request head and checkout remained equal.

This was ordinary label-absent pull-request CI, not ADR 0050's one authorized `security`-label candidate event. It consumed no candidate and issued no native C1 qualification.

## Decision

If accepted, remove only the cross-field equality requirement between `github.sha` and `pull_request.merge_commit_sha` from ADR 0052's native execution-envelope semantics.

The native C1 record must retain the two values as separate, named, trusted synthetic-envelope observations:

1. the exact `github.sha` value supplied by its matching trusted GitHub Actions context; and
2. the exact `pull_request.merge_commit_sha` value supplied by the trusted event payload.

Each must independently be canonical lowercase 40-hex and independently differ from both the exact pull-request head SHA and exact base SHA. Neither value is the tested source revision, and neither may be substituted for the other or for source. No equality between the two synthetic observations is required or inferred. Whether GitHub supplies equal or unequal values does not by itself establish or defeat authority; each field must still match its own trusted observation.

`github.workflow_sha` remains a separately named observation matched to its corresponding trusted GitHub Actions context. In run 30192739504 it was `e977491c4b5731b55d60d4acf1f1c9be00d76008`, equal to `github.sha`; that observed equality does not make either field source and creates no fallback or substitution rule.

Both synthetic observations must be bound through the same exact repository, workflow file and job, event and action, pull-request number, run ID, and run attempt. A value from another event, pull request, run, or attempt cannot be combined with this envelope. Missing or malformed values, a synthetic value equal to the exact head or base, mismatch against either field's own trusted context, cross-run assembly, field collapse, fallback, or local fabrication fails closed.

The source domain remains unchanged. One exact source revision must equal all of the same-repository pull-request head, explicit checkout, reviewed implementation head, workflow source revision, invoker source revision, native-test source revision, and native test's recorded source SHA. Reviewed code, test, and workflow blobs must remain the exact blobs bound to that head, and the workflow bytes must retain the exact reviewed workflow-blob digest. For run 30192739504 that exact source was `7c8780ffa8fcbc73df59abe4397ae34a474db8d4`; neither synthetic envelope SHA can replace it.

### Exact authorized correction

Authorize only the minimum assertion correction in the excluded test-only invoker `test/aws-stage2-completion-rootfs-builder-native.py`:

- remove its assertion that the `github.sha` and event merge observations are equal;
- independently require each observation to be canonical 40-hex and distinct from the exact head and base;
- retain both as separately named execution-envelope observations and compare each only with its matching trusted context; and
- update only that invoker's bounded portable assertions needed to prove the corrected accepted/rejected domain matrix.

All existing exact-source equality, exact-head checkout, head/base distinction, workflow-context matching, event readback, reviewed-blob, parent/child, sudo provenance, native observation, and fail-closed checks remain required. This is not authority to weaken another assertion, add a fallback, accept caller-supplied local authority, or fabricate a missing GitHub field.

No workflow edit, trigger, permission, runner, job-container, timeout, artifact, production code, counted code, schema, dependency, lockfile, candidate, or source-baseline change is authorized. The test-only invoker remains excluded under ADR 0052's unchanged counted-set rules and creates no line-cap credit.

## Candidate and retained stops

Run 30192739504 consumed no candidate. ADR 0050's sole operationally selected non-authoritative candidate remains unconsumed, and the `security` label must remain absent during this correction, ordinary CI, native qualification, remeasurement, and review. A corrected ordinary `quality` run is native C1 regression authority only for its own exact reviewed source and envelope; it is not KVM, Phase A, candidate creation or consumption, or later-stage authority.

Every retained C1–C3 and R1 gate, hostile review, exact-head review, counted high, candidate freeze and one-label-event rule, run-attempt rule, timeout, retry, rerun, duplicate-run, Phase B, later-stage, campaign, production, issue-closure, cloud, AWS, and mandatory-stop boundary remains unchanged. There is no fallback from this failed native observation and no authority to reuse it as a passing record.

This documentation-only proposal performs no code, workflow, test execution, dependency, lockfile, network, Docker, KVM, provider, cloud, AWS, candidate, campaign, or production action.

## Consequences

The native envelope can represent GitHub's actual distinct `github.sha` and event merge-SHA observations without falsely requiring them to be equal. Source identity remains stricter and unchanged: exact PR head, checkout, reviewed code/test/workflow sources, and their bound blobs still identify the one tested revision.

The correction is confined to the excluded test invoker. The observed run remains failed and non-qualifying, the sole candidate remains unconsumed, and every retained stop still applies.
