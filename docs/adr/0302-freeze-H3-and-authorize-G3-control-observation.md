# ADR 0302: Freeze H3 and authorize G3 control observation

- Status: Accepted
- Date: 2026-09-05
- Accepted by: Nick Byrne through explicit standing authorization for all non-AWS prerequisite work

## Context

ADR 0301 corrected the inherited static-boundary hash before any H2 publisher or static observation. Protected-main H3 is `229ea62bce964086726181974a6fec1c6dfd1f86`, whose only parent is H2 `8e2af4398519ab8d64b7f9e7194f9c116c6f51d9`. H3 CI run `33977504256` and Linux/root run `33977504296` passed.

Replacement producer `33980034976`, attempt 1, is the sole producer at H3. Admission, two independent byte-identical builds, and exact readback passed. Artifact `9973726406` has archive SHA-256 `21d09f0f31dab34bf7fd01427cbdb02a42fab68f299fa168789f48aa80acbbbd`; source manifest `99f18cc63033dfbdc2686e021c0c46f0c41951f1833ed7f1cc1dd160af64ab28`; receipt `32b87fde2d66ca3f07c2ddfc04dc1857bbb8ea1b13c929c490c4f01cbed2d4ed`; package `30b56a38d98d705e467e9f4e7f36f0a808ee1a34b0671f146da7b87610da7eae`; provenance `d16191691a35186d0a2a31a4f2c7a930a7d865021f00c511b0c18ae535148db7`; and log SHA-256 `45fa85b8f4c638b2be75f9183693623b4567486042a5bb74d42640f1cc58496d`.

The canonical rootfs remains exactly 4,353 entries with ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`, manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`, metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`, and sentinel `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`. Two independent producer/whole-chain audits returned PASS.

## Decision

Freeze H3. Establish this commit's protected-main squash result as G3 only if its sole parent is H3 and protected checks pass. G3 binds H3 and its source manifest, clears all stale static authority, reserves additive package root `stage2-completion-local-control-v4`, and leaves mixed preflight and qualification fail-closed.

After G3 protected checks pass, authorize exactly one first-created attempt-one publisher for producer `33980034976`, artifact `9973726406`, and archive digest `sha256:21d09f0f31dab34bf7fd01427cbdb02a42fab68f299fa168789f48aa80acbbbd`. Only after successful publisher audit authorize one first-created attempt-one no-KVM static observation at exact G3. Independently audit both observations before committing exact read-back bytes as direct-child Q3.

## Consequences

The failed original tuple and retired H2 producer remain non-authorizing. G3 itself grants no preflight, KVM qualification, AWS, provider, OpenTofu, SSM, inventory, or production authority.
