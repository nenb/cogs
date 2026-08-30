# ADR 0248: Authorize a baseline-capture diagnostic

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Replacement qualification run `33299709836`, attempt 1, passed normalized static admission and progressed for 32 minutes before an internal-contract failure. Recovery reported `incomplete baseline capture is preserved`; fixed cleanup and residue consequently failed closed, no canonical report or artifact was produced, and hosted runner teardown removed the ephemeral machine. The run grants no qualification, retry, or promotion claim.

Repurpose the existing no-lifecycle diagnostic to execute only the fixed sequence through static custody, dual rootfs acquisition, operation opening, live custody, executable custody, input creation, and baseline capture. Stop before network creation, runtime staging, KVM/Kata launch, SSH, QMP, workload sampling, or evidence publication. Emit bounded stage and exception-chain diagnostics, attempt cleanup-only recovery, then remove the exact diagnostic roots and restore the hosted `/opt` mode. Establish absence of every removed root before effects.

This decision raises only the complete tracked-source cardinality bound from 1,209 to exactly 1,210 files. Retain the 1,460-line workflow correction high and all other bounds. Authorize one baseline diagnostic observation; it grants no AWS, provider, deployment, campaign, production, release, qualification, retry, or promotion operation.
