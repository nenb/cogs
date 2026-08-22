# ADR 0129: Replace the pre-KVM permission failure

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: One replacement generation for the Stage 2 local KVM workflow

## Context

Run `32584575939`, attempt 1, at control revision `a9e02f1269684db98a42bfdaed6e2f193ba1c631` passed the isolated authenticated admission and exact H/G acquisition, then failed before immutable preparation because the unprivileged shell attempted to hash the root-owned staged control. It never installed `/opt/kata`, opened `/dev/kvm` or QMP, launched containerd/Kata/task/network/SSH, or produced an artifact.

Cleanup-only recovery succeeded. Fixed-root cleanup and residue observation then failed because the settlement child saw its retained `timeout` parent command line, which contained the `cogs-stage2-local-*` staging values passed as arguments to `env`. The ephemeral runner was subsequently retired by GitHub, but repository evidence cannot claim certain cleanup. Private custody is `/Users/nenb/.pi/artifacts/cogs/issue42-local-kata-32584575939`; its custody-manifest SHA-256 is `386d1595c7f30ae8823b1e1bd3d06bda6d1d2cacebb227844b046ee696c98bf4`. The run grants no qualification, cleanup, artifact, promotion, AWS, or retry claim.

## Decision

Bind `32584575939` as the sole exact failed predecessor and authorize one earliest replacement generation under the standing instruction to complete all non-AWS prerequisites:

- require the predecessor's exact ID, attempt 1, completed/failure state, display title, and head SHA;
- require closed history containing only that predecessor and the current attempt-one generation;
- require two stable authenticated snapshots of complete row tuples;
- read the already validated root-owned staged control through `sudo -n sha256sum`;
- place `env -i` outside `timeout` for cleanup, residue, and final settlement, so the retained supervisor command line contains no owned resource marker while the child still receives only the fixed environment.

The replacement workflow SHA-256 is `d767a499f829b358f81b9ee06262d36149cf6dda4c56125309b3bbeea5085b49`. All earlier H, static-control bytes, first-job admission, unauthenticated source acquisition, evidence, and teardown semantics remain unchanged. The replacement still fails closed and cannot establish authority unless it completes the full report/receipt/readback/final-residue chain on attempt 1.

## Authority boundary

This authorizes only one distinct replacement generation because the predecessor provably stopped before KVM eligibility and produced no artifact, while cleanup remains uncertain. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, or release authority. No additional generation is implied by a future failure.
