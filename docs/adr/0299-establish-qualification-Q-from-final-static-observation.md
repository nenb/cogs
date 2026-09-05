# ADR 0299: Establish qualification Q from the final static observation

- Status: Accepted
- Date: 2026-09-04
- Accepted by: Nick Byrne through the standing instruction to complete every non-AWS prerequisite autonomously and stop at AWS

## Context

Final control revision G `a108f981dacad6978e2a37d16a143da5c3b51cf4` has exactly one parent, final implementation H `d2fe08553d25d73fa276794c96b0f311e5406186`. Its protected PR and main CI passed; the one unrelated native-package baseline flake on main passed on the failed-job rerun and granted no authority.

Final publisher `33931002300`, attempt 1, succeeded for final producer `33908498241` and artifact `9951239210`. It published, signed, independently verified, and byte-read immutable OCI subject `ghcr.io/nenb/cogs/stage2-rootfs@sha256:b6f3f9a4507e32e558a0fc495166d30ba0bcd22d1fb972d6b29434eaf1fb7788`; issued descriptor `da5e971e6ca56f001aa045d024d9ce164d3418955f75a8affa6f486ddbb8971d`; and uploaded custody artifact `9958532006` with archive digest `sha256:2756dab1c13bbe4dfd12b87ab1cbe82890becc5c9eff9af9528037b54490c70e`. The publisher log SHA-256 is `0530f34842397b74223998917293413ac537c336a6d41f76387dadb270fa21a0`; publication receipt SHA-256 is `49b42a6b1fa867bf1cd3376ada1a140bb49e9ffa680112ef4a75126f2e3053e8`.

Final no-KVM static observation `33931091412`, attempt 1, then succeeded at the same G. It authenticated the publisher, consumed only the immutable descriptor-selected rootfs, generated no runtime, performed exact-ID artifact readback, passed cleanup and process/FD/network boundaries, and produced exactly 13 canonical members. Artifact `9958574502` has archive digest `sha256:9a1f72632363ab9725ae79f7590af75723997e1b416cacb84ad10939bc65ee10`; static control SHA-256 is `753f1aa84d91c1a7a8447ef04403aef26a679230b3e0d1fb333c5cfbcb38b46a`; execution envelope SHA-256 is `59c8d28bca789709f9d30445677586696414170d998e60f76b2d9462e2bfb868`; runtime manifest SHA-256 is `8df27b0a7ac2159ea17f1ad69abb9971429cecef979ab4754688739c9e627471`; and log SHA-256 is `8ae7c6dd25920e1ef2dbb1f4d8abbe5ffb01f1c409a78bf79ed95a47a7d40b2a`. Two independent audits returned PASS.

## Decision

Commit the exact 13 independently read-back static members under `deploy/aws-feasibility/remote/stage2-completion-local-control-v3`, fill only the previously blocked immutable G/static review constants, and require this commit to have exactly one parent, G. Freeze its protected-main squash result as qualification revision Q.

After Q passes protected checks, authorize exactly one first-created attempt-one H/G/Q no-KVM mixed preflight. Only after that exact run succeeds may one first-created attempt-one seven-runner formal qualification be dispatched with H, G, Q, and the mixed-preflight run ID. Q is supplied by protected dispatch/configuration and current source identity rather than impossible self-reference. Every status, custody map, and aggregate package must preserve Q; runtime grants remain the frozen H contract and bind G plus the reviewed workflow digest.

## Consequences

Any preflight or qualification failure, cancellation, retry, malformed dispatch, missing artifact, cleanup uncertainty, or residue retires the generation. This decision grants no provider, OpenTofu, SSM, inventory, production campaign, or AWS authority.
