# ADR 0104: Bound the native-package retained-build correction

- Status: Accepted under the owner's instruction to proceed at full speed with Docker and parallel hostile review
- Date: 2026-08-20
- Scope: PR 402 local implementation and non-AWS GitHub CI only

## Context

Exact-head workflow run `32393337510` failed closed after approximately 901 seconds. Its 3,000-second command guard did not fire. The timing is consistent with the shared 900-second retained-build/materializer boundary, or an immediate post-build invariant at that boundary. The run published no candidate or receipt, performed no KVM/AWS/provider action, and made no zero-residue claim.

The historical rootfs route is fixed by ADRs 0047 and 0048 at one shared 900-second per-build boundary. Raising its constants or adding a caller-selected timeout would change historical two-build and lease semantics. The authenticated native launcher was also omitted from the centralized retained-line inventory even though it owns production security effects.

## Decision

Keep historical `BUILD_SECONDS = 900`, `MATERIALIZE_SECONDS = 900`, and all historical qualification/lease callers unchanged. Add one fixed native-package retained-build profile with a single shared 1,200-second build/materializer boundary. It accepts no duration, environment, CLI, retry, fallback, second build, alternate writer, reduced durability, or weakened postwalk. The native launcher calls that profile exactly once.

Clamp rootfs bootstrap and retained-build effects to `lifecycle_deadline - 600 seconds` before either begins. Native inline cleanup is clamped to the earlier of a fresh 600 seconds and the original lifecycle deadline; the original lifecycle deadline remains the absolute cleanup ceiling. Existing child, reap, command, workflow, and publication bounds remain unchanged. A later failure remains terminal evidence, not a reason to tune or retry.

Retain `scripts/run-stage2-package-native-candidate.py` in the centralized no-deletion-credit inventory. Raise the measured preferred/hard caps to 52,000/53,000. With the launcher and this correction counted, the conservative measure is approximately 50,647 lines, below both limits. This accounting correction is not implementation scope.

The public diagnostic may remain categorical; exact-head tests must prove the fixed profile, shared rather than additive deadlines, unchanged historical controls, cleanup-reserve clamp, one build, no runtime constant mutation, and no retry.

## Authority boundary

This decision authorizes the local correction, Docker tests, hostile review, source/readiness regeneration, push, and ordinary non-AWS PR CI requested by the owner. It does **not** authorize rerunning failed run `32393337510`, dispatching a replacement package candidate after that failure, consuming the KVM attempt, changing a final pin, publishing a release, or performing any AWS/provider/controller/deployment action. A replacement dispatch requires a fresh explicit instruction after the corrected exact head and evidence are reported.
