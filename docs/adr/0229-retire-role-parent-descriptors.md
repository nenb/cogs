# ADR 0229: Retire role-parent descriptors

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H72 passed the newly required direct prepared-custody verification and again reached independent residue with only the `runtime` descriptor marker. Complete descriptor accounting found that each executable-role claim retains both its regular-file descriptor and a trusted absolute parent descriptor. ADR 0222 retired only descriptors exposed through `RetainedObject`, which names the regular file; its separately held parent descriptors remained in static custody and still named `kata-runtime-v1`.

Record the complete descriptor tuple created by each role claim, including trusted parent and regular-file descriptors. At final retirement, require every descriptor from every consumed role claim to be unique and present in static custody, then retire that complete tuple. The retained objects remain the semantic executable descriptions, while descriptor ownership is no longer inferred from those descriptions. Missing, foreign, aliased, outstanding, or uncloseable parent custody fails closed; whole-custody abort cannot double-close retired descriptors.

Focused admission, runtime hostile, mutable-bridge, coordinator, TypeScript, formatting, and retained-line matrices pass. H72 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
