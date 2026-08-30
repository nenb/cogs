# ADR 0171: Use fast private downstream diagnostics before one strict replay

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

Repeated strict private observations have now established deterministic rootfs, admission, executable custody, complete inputs, and baseline capture. A 4,500-second observation reached live namespace/veth/tc setup but exhausted its enclosing bound. Separate non-authoritative native fixtures then exercised the production network lifecycle, real Linux namespace/TAP/nft behavior, operation/runtime recovery matrix, and production SSH/input composition without repeating rootfs construction.

Use those private fixtures only for downstream defect discovery, then perform one fresh complete strict replay. The Linux fixture exposed that procfs renders still-named nsfs descriptors as `/run/netns/...`; census them only by exact expected device/inode. Synthetic memfds on this kernel report mount ID zero, so test journal fixtures normalize only their synthetic generation to the schema's positive mount identity; production retained host executables remain unchanged.

Raise the enclosing strict entry to 7,800 seconds and its workflow/job arithmetic. This covers measured pre-admission work plus the existing 5,430-second admitted lifecycle ceiling; no internal deadline changes. Fast fixtures grant no artifact, qualification, retry, AWS, provider, deployment, promotion, or release authority.
