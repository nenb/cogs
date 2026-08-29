# ADR 0233: Preserve private strict-fresh environment failures

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-29

Three private strict-fresh observations grant no claim:

1. Direct immutable acquisition on Osito could not download the pinned 1.5 GB Kata archive within the fixed 1,770-second bound. No bound is raised from this single private-host transfer.
2. Strict fresh-rootfs run 103 completed workload execution but failed closed when host snap refresh replaced a squashfs mount between baseline and teardown. The exact mountinfo diff was retained; this was foreign host drift, not owned residue.
3. Strict fresh-rootfs run 104 reached `ROOTFS_RELEASE_READY` at the fixed outer lifecycle boundary and failed closed. It additionally exposed recovery-only policy and command-route defects described by ADR 0234. No performance bound is changed without repeatable qualifying measurements.

Every retained state was archived and manually removed only after exact private diagnosis; external physical residue then passed. These failed observations authorize neither retry claims nor promotion. The successful production-fsync retained-artifact rehearsal remains the private preflight; fresh acquisition/rootfs execution still requires the formal hosted qualification under unchanged bounds.

This grants no AWS, provider, deployment, campaign, production, release, qualification, or promotion authority.
