# ADR 0295: Bind the final pre-H diagnostic producer

- Status: Accepted
- Date: 2026-09-04
- Accepted by: Nick Byrne through the standing instruction to complete every non-AWS prerequisite autonomously and stop at AWS

## Context

Protected-main revision `f93748b253c1429cce9149defde623f40c9cc0ab` passed CI after a transient npm-registry timeout and passed all 22 protected Linux/root lifecycle jobs. Reusable diagnostic run `33831411912`, attempt 1, then completed successfully on that exact protected-main revision. Its independent full and readiness jobs both passed authentic no-mint KVM execution, cleanup-only recovery, fixed-root settlement, independent process/mount/root/FD/network/cgroup zero-residue verification, hosted-scaffolding restoration, and final outcome enforcement. The aggregate job passed. The run produced no artifact.

Two fresh read-only audit processes independently inspected the captured run metadata, complete log, workflow, recovery entry, and settlement implementations. Both returned PASS with no evidentiary gap or hidden continue-on-error masking. The captured log has SHA-256 `cd01f8fc4228b63ae03e94b837847e7ac1122eac36fa7663d08de3ba312251c9`. This diagnostic remains non-authorizing.

Attempt-one diagnostic producer run `33837299968` then used exact revision `f93748b253c1429cce9149defde623f40c9cc0ab`. Its admission, independent dual-build, upload, and separate readback jobs passed. The seven-member artifact is `9924034454`, Actions digest `sha256:92f371b149762f1eca00d7f10fdcd6d19ef6798c2bcae07fea28b76c4a6d12ce`, and expires on 2026-09-11. Independent local readback confirmed exactly seven files and these commitments:

- producer receipt `5f7fa0bc3ef642892b5694d9f45ee9755638b3fabe4f510d43503db9ede937b6`;
- package manifest `1b0eed2e100b476c4d1903e031c97f9f142f826046cb07eb0a299288f0739cb6`;
- provenance `ebf9f23e4f75ca15d1b43a05de89785ecbac06734ef1d404f59fad544893e10d`;
- fixed source manifest `fcaff083d0ec5345d6f7efa0e884e484331de0f4b3d44da9295a0074830d81bc`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`, manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`, and metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`.

The producer receipt records exactly two independent equal builds, 4,353 entries, exact fixed pins, no KVM, no provider, no AWS, and no remote publication.

## Decision

This ADR merge must be the direct protected-main child of `f93748b253c1429cce9149defde623f40c9cc0ab`. It authorizes exactly one first-created attempt-one diagnostic publisher invocation bound to producer run `33837299968`, artifact `9924034454`, and archive digest `sha256:92f371b149762f1eca00d7f10fdcd6d19ef6798c2bcae07fea28b76c4a6d12ce`.

If publication, immutable digest resolution, keyless signature verification, exact readback, and retained custody all pass, that publication may feed exactly one first-created attempt-one no-mint full/readiness rehearsal on the same direct-child revision. No failed or retried run may be substituted.

## Consequences

This decision freezes neither final H nor final G and consumes no final producer/publisher authority. The publication and rehearsal remain diagnostic, cannot issue qualification evidence, and grant no provider, OpenTofu, SSM, inventory, credential, campaign, production, or AWS authority. Any failure, cancellation, retry, stale artifact, cleanup uncertainty, or residue retires this generation.
