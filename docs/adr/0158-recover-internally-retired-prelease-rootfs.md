# ADR 0158: Recover internally retired prelease rootfs

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

A private full-path attempt failed during first-build postvalidation. The rootfs builder correctly removed every candidate object and durably reached `retired` before any `leased` record or operation admission existed. Cross-owner recovery required exactly one lease, so it rejected this valid internally retired prelease state. Its aggregated fallback then removed independent immutable artifacts, making restart unable to reacquire static custody.

Permit the sealed unadmitted recovery route to consume only an exact journal-absent binding whose authenticated rootfs ledger has the same source approval, no lease or release authorization, no operation directory, exact fixed infrastructure names, and terminal `retired` tip. Close custody, invoke ordinary builder retired-ledger settlement, settle the prestage grant, and prove only fixed idle rootfs infrastructure remains. No rootfs bytes are deleted by this branch because the builder already proved them absent.

Immutable cleanup may proceed beside that independently authenticated fixed-idle rootfs state, while any active, uncertain, or malformed rootfs state remains a hard stop. The fixed-idle root is left for final fixed-root settlement. This grants no retry, evidence, AWS, provider, deployment, promotion, or release authority.
