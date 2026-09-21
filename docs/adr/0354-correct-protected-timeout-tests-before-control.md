# ADR 0354: Correct protected timeout tests before control

- Status: Accepted
- Date: 2026-09-21
- Decider: Nick Byrne
- Scope: two test-only deadline corrections, replacement H and producer, then a separate G/Q chain; no AWS

## Context

ADR 0353 established workflow-corrected H
`6c200c6fcd87616244b38b6676d07c513aeb42fd`. Its protected pull-request
checks, exact-H protected-main checks, producer `35587992926`, artifact
`10634535621`, and independent producer audit passed. H's runtime, workflows,
Dockerfiles, and producer artifact have not demonstrated a defect.

The proposed governance-only child `6f57d37475178d2e3b014b5861e1a03bc64b57e6`
never became G. CI run `35593379965`, attempt 1, failed in image delivery and
one test. The image job received bytes inconsistent with the checksums in
Ubuntu's signed snapshot indexes and rejected them before creating an image.
Forty-eight subsequent IPv4/IPv6 cache-busting downloads matched the signed
hashes. The one explicitly documented unchanged-candidate revalidation,
attempt 2, passed the image job but failed two test-only fixtures. Linux
foundations `35593379911` passed completely. PR 568 was closed without merge.
No publisher, static observation, qualification, AWS credential, or provider
effect occurred.

Both test failures are causally reproducible as artificial deadline
sensitivity, not production failure. The helper fixture assigned every case a
30-millisecond deadline even though only its explicit `timeout` case needs the
short deadline. Under 32-way local contention the exact 30-millisecond fixture
failed 102 of 256 times, 100 milliseconds failed 16 of 256 times, and a
one-second non-timeout deadline failed 0 of 256 times. The failure retained
`helper-pending`, which is the production implementation's required
fail-closed result. The independent crash-cut fixture used 100 milliseconds;
under 16-way contention it failed 2 of 64 times, while one second failed 0 of
64 times.

Because G is restricted to governance and deterministic readiness evidence,
the test corrections cannot be added to G. A fresh protected implementation
identity is required even though executable product behavior is unchanged.

## Decision

Supersede H `6c200c6fcd87616244b38b6676d07c513aeb42fd`, producer
`35587992926`, and artifact `10634535621` for future-chain use. They remain
valid historical evidence but grant no publisher, static, qualification, or
AWS authority. The unmerged G candidate and both attempts of CI run
`35593379965` grant no authority and cannot be stitched into the replacement
chain.

Correct only these test deadlines:

- in `test/production-compose.test.ts`, retain 30 milliseconds for the explicit
  `timeout` case and use one second for every non-timeout case;
- in `test/ci-infrastructure-boundary.test.ts`, use one second instead of 100
  milliseconds for the portable crash-cut matrix.

Do not change `dev/product-test/host-custody.py`, any runtime, Dockerfile,
workflow, static boundary, retirement policy, qualification constant,
provider, campaign, or production behavior. Regenerate only deterministic,
non-authorizing Stage 4 readiness evidence required by the changed source.

Establish the protected squash result as replacement H only if every required
protected check passes, its reviewed tree is preserved, and exact-H
protected-main CI and Linux foundations pass. Then dispatch exactly one
first-created attempt-one producer for replacement H and independently audit
its complete artifact and readback. No prior producer or artifact may be
reused.

Only after that audit may a separately reviewed direct-child decision at
`docs/adr/0355-freeze-timeout-corrected-H-and-authorize-control.md` establish
G. G may authorize one publisher and, after independent publisher audit, one
static observation. A later Q decision may use only
`docs/adr/0356-establish-timeout-corrected-Q-and-authorize-qualification.md`.
Neither anticipated file exists in this H.

Retain ADR 0351's immutable 607-line / 1,700,000-byte pre-H cap, 900-line /
3,500,000-byte post-H reserve, combined 1,507-line / 5,200,000-byte final-HGQ
maximum, and the exact 22,157-line / 21,500,000-byte five-task tranche. Raise
only the tracked-file source limit from 1,561 to 1,562 for this ADR; aggregate
line and byte allocations remain unchanged.

## Consequences

The replacement costs another protected H and fresh producer but removes a
confirmed nondeterministic validation boundary without weakening fail-closed
runtime behavior. A failed required check stops this candidate. This decision
grants no publisher, static observation, mixed preflight, qualification, AWS
planning, approval, credentials, OpenTofu, SSM, deployment, campaign, or
production evidence authority.
