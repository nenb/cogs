# ADR 0250: Create and retire the hosted netns parent

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Corrected baseline diagnostic run `33303568218`, attempt 1, passed static custody, dual rootfs acquisition, operation opening, live custody, executable custody, and input creation. Baseline capture then failed exactly because fresh hosted runners lack `/run/netns`; support-directory creation could not create its children. The diagnostic attempted recovery and removed all exact ephemeral roots. No qualification claim exists.

For local qualification only, require `/run/netns` to be absent, create it root-owned mode 0755 before immutable preparation, and verify that exact identity before entry. Existing network ownership continues to own only its recorded children and private mount. After recovery, fixed cleanup, independent residue, publication/readback processing, and exact removal of every child/mount, require the parent to remain root-owned mode 0755, remove it with `rmdir`, prove absence, and only then complete hosted scaffolding restoration. Any nonempty, mounted, replaced, or differently owned parent fails closed.

Bind failed run `33299709836`, attempt 1, H `89243c8d9f7a946aefdaa4c445a5cfe1e0fe7e14`, G `9180ea85d42f3f3dc2703e1ba677c7dbdccfb104`, and failed conclusion as the eleventh predecessor. After review and a new protected-main G, authorize one replacement attempt-1 qualification observation.

This decision raises only the complete tracked-source cardinality bound from 1,211 to exactly 1,212 files and the measured workflow correction high from 1,460 to 1,490 gross lines. All other bounds remain unchanged. This grants no AWS, provider, deployment, campaign, production, or release operation.
