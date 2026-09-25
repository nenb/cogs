# ADR 0368: Correct post-qualification planning control

- Status: Accepted
- Date: 2026-09-24
- Decider: Nick Byrne
- Scope: accepted replacement qualification, bounded planning-control correction, protected R, and gated AWS continuation

## Context

Protected Q `2d4b61a63cdb08a92d5fbde9095532fad2383e90`, sole parent G `c37baf5c1fbb8f1e335945ad7ac93452d4537c9d`, has the exact reviewed tree `b25b3b162f2a38ca6f485896015fdc581c27618c`. Its fresh CI `36027639476`, Linux foundations `36027639213`, sole mixed preflight `36035076262`, and sole seven-runner qualification `36036544983` all passed on attempt one and were independently accepted.

Qualification artifact `10829051963` has archive digest `sha256:372c0a9ba454d1789eb2299495a58426190127548f4437c0be9f4746321a4fc2`. Its `pre-aws-package-v6.json` member has SHA-256 `44cbbb03b9b96bcd51cfd63c72f0de66845712826bd9ddf543f44353fc49e1d9`, its custody member has SHA-256 `aab70ff25a20fd52e90652cf5ab16d01b133680d60399e60e27fa60efd967af4`, and its batch commitment is `f18937b5b801ff5e13ceb69a8e56212f5c50ce6fbc58cdc4de160cdbb7d8ae0c`. The package states `aws_authorized=false`; qualification caused no AWS or provider effect.

The dormant planning workflow correctly selects package V6 but labels its artifact V5 and reads `stage2-local-execution-envelope-v3.json`. Accepted control V7 contains and authenticates only the additive V4 envelope. Dispatching the stale workflow would fail before credentials and waste a terminal planning generation.

The two functional filename corrections plus deterministic readiness regeneration consume all seven previously free gross lines, while literal task accounting exceeds `product` and `readiness-ci` by one line each. Encoding and testing the post-Q decision also requires governance lines. Deletion-blind accounting therefore cannot retain the old 24,782-line tranche.

## Decision

Correct only the planning workflow's two V5 labels to V6 and two envelope V3 paths to V4. Add a regression that requires V6/V4 and rejects the stale labels and path. Do not change the accepted thirteen control members or any H, G, Q, qualification, provider, approval, campaign, or Stage 4 executable semantics.

Reclassify `.github/workflows/stage2-production-plan.yml` from `final-HGQ` to `governance`. Raise `governance` from 8,550 to 8,680 lines, `product` from 5,056 to 5,058, and `readiness-ci` from 282 to 286. Keep `local-tofu-ssm` at 6,200, `final-HGQ` at 4,694, its pre-H cap at 604, and its post-H reserve at 4,090. Transfer 250,000 prospective bytes from unused `local-tofu-ssm` capacity to `readiness-ci`, making those byte highs 3,050,000 and 10,500,000. The remaining tranche becomes 24,918 lines and 21,500,000 bytes; the global forecast becomes 42,918 lines and 29,500,000 bytes. Every aggregate byte high, source/inventory limit, deletion-blind charge, and `PRODUCT_TEST_PENDING_READINESS_REGENERATIONS=0` remains unchanged.

Establish R only as a reviewed protected successor of Q whose tree equals the accepted candidate and whose protected checks pass. The source revision itself grants no credential or AWS effect. After independent R acceptance, the owner's explicit authorization permits bounded IAM/OIDC bootstrap, a zero-resource baseline, and exactly one first-created attempt-one read-only planning run bound to H, G, Q, qualification `36036544983`, artifact `10829051963`, and its archive digest.

Only independent acceptance of all seven plans may permit one plan-bound V6 approval. Only a valid unexpired approval with every pre-credential gate passing may permit exactly one two-job seven-cycle production run using `authorize-seven-stage2-production-cycles`. Any failure, retry, mismatch, uncertain cleanup, or nonzero unexpected inventory is terminal: stop, clean up only under proven ownership, and do not retry or reinterpret the generation.

## Consequences

The accepted Q and qualification remain immutable and non-AWS evidence. Planning is read-only and separately observed. Production, report publication, Issue 42 closure, and any temporary IAM cleanup remain conditional on all preceding gates; Stage 4 remains separate and non-authorized.
