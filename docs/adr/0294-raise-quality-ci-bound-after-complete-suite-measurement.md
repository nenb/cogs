# ADR 0294: Raise the quality CI bound after complete-suite measurement

## Status

Accepted.

## Context

PR 505's quality job completed all 1,336 tests with zero failures, then reached the final audit checks. Two independent attempts were canceled by the job's 15-minute outer limit while `npm audit` was still running. The first attempt reached the audit at approximately 13 minutes 40 seconds; the second was also canceled at the same outer boundary. Security, image, root-tail, and all short Linux lifecycle checks passed. This is a measured outer-supervision shortage, not a test failure or permission request.

## Decision

Raise only the CI quality job outer bound from 15 to 25 minutes. Do not change any test, network, command, lifecycle, recovery, settlement, qualification, or production deadline. Preserve fail-closed cancellation and all existing steps.

## Consequences

The additional ten minutes permits the already completed suite and final registry audit to finish under observed hosted-runner variance. It grants no dispatch, credential, provider, publication, qualification, production, or AWS authority.
