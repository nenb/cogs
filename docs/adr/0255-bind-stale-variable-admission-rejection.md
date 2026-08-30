# ADR 0255: Bind the stale-variable admission rejection

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Qualification run `33321865244`, attempt 1, failed in the first admission step before any checkout, source, immutable preparation, KVM, or lifecycle effect. The dispatch and protected-main control head were exact, but repository variable `STAGE2_LOCAL_IMPLEMENTATION_HEAD` still held the preserved prior H and therefore correctly rejected final H `bf0479a012b39c074ecb623ea83e85b3dc3ebe36`. No local-Kata job ran, no report or artifact exists, and the run grants no claim.

Update that repository variable to the exact final H. Bind failed run `33321865244`, control head `dae1abcf40bd2ebbe9535d95732e5627e414c091`, exact title, attempt, repository, protected branch, and failed conclusion as the thirteenth non-authorizing predecessor. After this workflow correction merges, update the control variable to that protected-main merge and authorize exactly one attempt-1 replacement formal qualification.

Retain all lifecycle, evidence, timeout, cleanup, and line bounds. Raise only the complete tracked-source cardinality bound from 1,216 to exactly 1,217 files. This grants no AWS, provider, deployment, campaign, production, release, retry, or promotion operation.
