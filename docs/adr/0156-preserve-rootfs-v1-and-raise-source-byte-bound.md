# ADR 0156: Preserve rootfs V1 and raise the source byte bound

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

Final integration exposed two deterministic closure defects. First, the root-SSH correction replaced the bytes at the historical `stage2-completion-rootfs-v1.json` path, which broke the already-qualified package candidate's immutable V1 binding. Restore V1 exactly and publish the SSH-capable rootfs under additive V2 bytes. Rootfs construction/publication uses V2; historical package qualification continues validating exact V1. Completion static control independently binds V2, so no old bytes are reinterpreted.

Second, the complete tracked source inventory is 17,002,946 bytes after readable recovery, QMP, teardown, controller/evidence, and sealed cycle-owner code, exceeding ADR 0154's inherited 16 MiB aggregate while remaining below 18 MiB. Raise only that inventory aggregate to 18 MiB. Keep the 1,200-file and 4 MiB per-file bounds, complete Git inventory, canonical ordering, generated-evidence exclusions, and no-symlink/single-link policy unchanged.

These corrections preserve historical meanings and complete accounting. They grant no AWS, provider, inventory, deployment, campaign, promotion, production, or release authority.
