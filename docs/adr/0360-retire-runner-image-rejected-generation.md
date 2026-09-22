# ADR 0360: Retire runner-image-rejected generation

- Status: Accepted
- Date: 2026-09-22
- Decider: Nick Byrne
- Scope: terminal host-scoped H/G generation, authenticated hosted-runner image admission, and one fresh non-AWS H/G/Q chain

## Context

ADR 0358 froze host-scoped implementation H
`306727e28ed8b0257d84b7c6fdfd6ba1fde5a22c` and its sole producer
`35716917245`. Protected direct-child G
`21848f84f01d42f28ce2f6f2a177bfe62af8fc58` has H as its sole parent.
Its exact-main CI `35727728105` and Linux-foundations `35727728009` passed.
Publisher `35732877526`, attempt 1, then published artifact `10696531175`
with Actions archive digest
`sha256:5812ee3f4f0c5da208190d93a53db850d7fe2c7dae37796a43f93a3be06b3fb7`
and immutable OCI digest
`sha256:4d9144a61c509abab23462fd29fb59c4f110ac3d7e9105cfa0cd15d6376dab63`.
Independent readback accepted its exact descriptor, Cosign verification,
publication receipt, and cleanup.

The sole static-control run `35733919360`, attempt 1, failed at its first
admission step with `stage2.runner-image.rejected`. GitHub assigned
`ImageOS=ubuntu24` and `ImageVersion=20260920.314.1` while the protected
workflow required literal version `20260907.300.1`. All source checkout,
artifact acquisition, privileged preparation, KVM, publication, and upload
steps were skipped. The run published zero artifacts. Therefore there is no
static observation, Q, mixed preflight, formal qualification, planning, IAM
authority, approval, provider operation, or AWS effect for this generation.
Successful H, G, producer, and publisher evidence cannot be salvaged after the
terminal static gate.

`runs-on: ubuntu-24.04` is a floating hosted-runner label. GitHub can allocate
old and new weekly images concurrently during rollout, and `ImageVersion` is
not selectable. Replacing one literal with another would repeat the failure.
The assigned replacement is authenticated by the official
`actions/runner-images` release `ubuntu24/20260920.314`, release ID
`392922326`, and matching tag-ref commit
`e75633902841aa5479c759492b73409e6d317f12`.

## Decision

Retire H, G, producer `35716917245`, publisher `35732877526`, failed static
run `35733919360`, producer artifact `10690851656`, and publisher artifact
`10696531175` through additive closed retirement policy V5. Preserve V1
through V4 bytes exactly. V5 binds V4
`sha256:588468079ddcc6161a8cbc2bacc84d3cca2aac6e03a0325e2af72d846c9efa5d`
and has exact digest
`sha256:a2b2ca60e424d16a28f33d2d0a48b5f5b268fc26cedbe89d535d119af99033a7`.
All nineteen pre-effect selectors receive the same additional terminal
revision, run, and artifact identities. The failed static run has no artifact
to retire.

Replace exact-version admission with authentication of each assigned hosted
image before source effects:

1. Require fixed workflow label `ubuntu-24.04`, environment OS `ubuntu24`, and
   syntactically valid `ImageVersion`; derive tag
   `ubuntu24/<year-week.build>` from that assigned version.
2. Query both official `actions/runner-images` release-by-tag and tag-ref APIs
   using only `GITHUB_TOKEN`. Require the exact tag, release URL, positive
   safe-integer release ID, non-draft release, exact tag ref, and equal 40-hex
   release and ref commits. Active-rollout prereleases are admissible.
3. Fail closed on missing, malformed, draft, mismatched, or unofficial data.
   Every `test`, regex, API request, parser, and command substitution must
   propagate failure explicitly; Bash `set -e` inside a block tested by `||`
   is not an admission boundary.
4. Bind the authenticated identity as
   `cogs.github-hosted-runner-image/v1` with label, OS, assigned version,
   release tag, release ID, and release commit. Authenticate each host
   independently; mixed official versions across rollout are valid.

Carry the static host identity in additive local execution envelope V4 and
formal host identities in additive cycle-status V3. Preserve envelope V3 and
status V2 bytes as historical contracts. Aggregate only current prerequisite
package V6, recording the static identity and all seven independently
validated cycle identities; preserve package V5 for historical validation.
Current planning, approval, diagnostics, and production admission consume only
`pre-aws-package-v6.json`. The runner identity changes qualification evidence,
not production R's one-run/two-job architecture or AWS authority.

Establish a fresh implementation H only after complete tests, accounting,
independent review, protected PR checks, and fresh exact-main checks. Then run
exactly one audited producer; establish governance-only G as H's sole child;
run exactly one audited publisher and static observation; establish Q as G's
sole child; run one mixed H/G/Q preflight and one seven-host formal KVM
qualification. Any producer, publisher, static, preflight, or qualification
failure is terminal for that generation. No retired bytes or successful
subordinate evidence may be retried, stitched, resumed, or reinterpreted.

Reserve 1,793 lines of previously unallocated global headroom without raising
the 78,000-line global high: local-tofu-ssm rises from 6,207 to 6,300,
readiness-ci from 350 to 400, and final-HGQ from 2,150 to 3,800. The measured
five-task forecast rises from 40,157 to 41,950 lines; final-HGQ retains its
607-line pre-H cap and raises only its post-H line reserve from 1,500 to 3,150.
All task byte highs, the 35,000,000-byte global high, and source limits remain
unchanged. This is zero-sum against the existing global envelope. Retire the
ten superseded, non-authorizing `.pi/outcome-two/adr0093-review-*.md` shards
from the current source inventory; their complete bytes remain in Git and the
newer role-matched `adr0093b-review-*` set remains tracked. This creates source
capacity for this correction and its later G/Q decisions but earns no
retained-line or byte credit.

## Consequences

Planning, formal AWS roles, repository role variables, approval, production R,
and Issue 42 closure remain blocked until one wholly fresh protected H/G/Q
chain completes and its wholly fresh qualification
succeeds and passes independent audit. Q's seven GitHub-hosted KVM cycles remain
distinct from R's later seven sequential AWS create/measure/destroy cycles.
Stage 4 remains a separate non-authorizing consumer of accepted Stage 2
evidence.
