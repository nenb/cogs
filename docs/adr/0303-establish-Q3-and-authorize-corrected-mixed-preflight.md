# ADR 0303: Establish Q3 and authorize the corrected mixed preflight

- Status: Accepted
- Date: 2026-09-05
- Accepted by: Nick Byrne through explicit standing authorization for all non-AWS prerequisite work

## Context

Protected-main G3 `821149ba4c3dbccef48694efcdb1eb29fa9fd2b9` has sole parent H3 `229ea62bce964086726181974a6fec1c6dfd1f86`. Its CI passed; the known unrelated network-runtime filesystem-generation flake failed once and passed on the failed-job rerun. No authority is taken from the failed attempt.

Final publisher `33987181596`, attempt 1, passed for H3 producer `33980034976`, artifact `9973726406`, and archive `sha256:21d09f0f31dab34bf7fd01427cbdb02a42fab68f299fa168789f48aa80acbbbd`. It published and read back immutable OCI subject `ghcr.io/nenb/cogs/stage2-rootfs@sha256:845807f1f280b80ec107738d97f3a4df4226ed22e5b35f31fe394c8831b2d3a3`. Publisher artifact `9975524471` has archive SHA-256 `821de38012e61a774d336cee6af284ee70062ba761c37d3cff4895cf44379684`; descriptor `b71c98f1721aca58328f92cdf61408038d3d10465361b84702c555b908ef5876`; publication receipt `3f9a1b8a5a9ef6d121edf3b31b79c01349dd3ae7b1f4c2c4b3cf7b8cae3eb730`; and log `e897812be95b22ad0f09c0f4b4d3246d0a96ae3e3e29d8da80d0730acc948e76`.

Final no-KVM static observation `33987659305`, attempt 1, passed at G3. Artifact `9975667979` has archive SHA-256 `94769e5b4dacfe280d059c453c4a1e722f5f0686509778d9c6f4b0fa00d44be0`; static control `80a962f87f35cf1653894168ebe32139d7d32bc0a21f89cf028ac02a67976fc8`; execution envelope `ae6da9cacd131c5796171801f4f8061607ffa230f4760bacf1f8781fad3bc6c7`; runtime manifest `83d26403a281dfa7c055c62daf8d939cfb81fc84e05f8e8229c79a4d6e712b6f`; and log `a41507fb9eddfa5636c929d18bb78c03631d820d0e95b77ff97a07c80252aab2`. Two independent publisher audits and two independent combined static/custody audits returned PASS.

## Decision

Commit the exact 13 independently read-back static members, without reserialization, under additive root `deploy/aws-feasibility/remote/stage2-completion-local-control-v4`; fill only the exact G3/static review constants; and require this commit's protected-main squash result Q3 to have sole parent G3.

After Q3 protected checks pass, configure the exact H3/G3/Q3 repository variables and authorize exactly one first-created attempt-one corrected no-KVM mixed preflight. It must authenticate exact H3/G3/Q3, normalize hosted `/opt`, complete immutable preparation and two settlement passes, restore hosted scaffolding only after exact absence, and succeed. Only that exact successful run may authorize one seven-runner formal qualification generation.

## Consequences

The original failed preflight, original H/G/Q tuple, and retired H2 producer remain non-authorizing. Any replacement preflight failure, retry, cancellation, malformed dispatch, cleanup uncertainty, or residue retires this generation. This decision grants no KVM qualification before preflight and no AWS, provider, OpenTofu, SSM, inventory, or production authority.
