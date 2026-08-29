# ADR 0227: Retire preverified consumed-source custody

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H70 reached final custody retirement but failed because ADRs 0225–0226 attempted to reopen the immutable prepared `kata-runtime-v1` source pathname. Forward staging had already recorded, independently reverified, consumed, and then exactly removed that prepared tree. Its original read-only descriptors remained held, but the pathname was intentionally absent.

Do not reinterpret expected absence as replacement or recreate a consumed pathname. At final retirement, require the sole prepared claim to have both `consumed` and `verified` state established before the staging cleanup effect. Then retire its tracked original read-only descriptors, the separately tracked complete-source-verification descriptors, and source anchor by exact membership and uniqueness. Their authenticated manifest/facts remain in sealed in-process custody for final evidence. Missing prior verification, unexpected live claim state, foreign descriptors, aliasing, or close failure remains fail-closed.

This supersedes only the final pathname-reopen requirement in ADRs 0225–0226; their exact descriptor ownership and closure requirements remain.

Focused admission, mutable-bridge, coordinator, TypeScript, formatting, and retained-line matrices pass. H70 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
