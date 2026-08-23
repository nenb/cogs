# ADR 0144: Refine first rootfs build diagnostic

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-23

Run `32628930290`, attempt 1, emitted bounded stage `rootfs-build-first`; recovery and all residue/cleanup checks passed, with no artifact. Private custody SHA-256 is `2055e9f3ebf92593cfa2bd50244802224dc075b86195c84f7dd30dd5d285bd8f`.

Carry a fixed materialization substage through `MaterializerWorkError`, `BuildAttemptError`, `RootfsAcquireError`, and the lifecycle terminal. Allowed substages cover plan, directories, files, hardlinks, symlinks, directory metadata, root metadata, and postwalk; tokens are short enough that the complete diagnostic remains at most 64 ASCII bytes. Preserve cleanup causes privately and render no underlying data.

This H change requires a fresh static-control cycle before one distinct diagnostic observation. It grants no AWS/API/provider/deployment/promotion/release authority.
