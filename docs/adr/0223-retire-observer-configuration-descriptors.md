# ADR 0223: Retire observer-configuration descriptors

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H67 still reported only runtime-marked descriptors after both duplicate and consumed role-object descriptors were retired. Static admission separately retained the active `kata-runtime-v1` observer configuration and its parent, plus the immutable base configuration and parent, so it could repeatedly revalidate configuration custody. Those descriptors are not executable-role objects and therefore were correctly untouched by ADR 0222.

At the same post-final-baseline boundary, perform one final derivation/hash verification of live observer configuration custody, require its four unique descriptors to belong to static custody, retire them together with consumed role descriptors, and replace the live configuration state with an internal exact retired proof containing the bound active digest. Final source/binding evidence may use that retired proof; no runtime or command use remains. Whole-custody abort cannot double-close the retired descriptors. Missing, changed, foreign, duplicate, or unverified configuration custody fails closed.

Focused admission, mutable-bridge, coordinator, TypeScript, formatting, and retained-line matrices pass. H67 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
