# ADR 0147: Refine build outcome and raise diagnostic bounds

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-23

Run `32635519776`, attempt 1, emitted `rootfs-build-first-internal`; recovery and all cleanup/residue checks passed, with no artifact. Private custody SHA-256 is `1ba7eb5d60b27e3ce0959af644e4b9b76b18957952b1cc430547bab0a25dd0c2`.

When no materializer substage exists, map the exact typed build outcome to fixed bounded tokens: setup, work, deadline, cancel, or post. Preserve any non-internal materializer substage. All complete diagnostics remain at most 64 bytes.

Repeated reviewed diagnostic history has legitimately consumed the prior correction slice. Raise only the workflow correction high from 1,250 to 1,320 and global correction high from 11,000 to 11,100. Keep deployment/retained highs, preferred 66,500, and hard 67,000 unchanged and independently enforced.

This H change requires fresh static control before one distinct local observation. No AWS/API/provider/deployment/promotion/release authority follows.
