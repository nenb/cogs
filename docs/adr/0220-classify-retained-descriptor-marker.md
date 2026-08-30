# ADR 0220: Classify the retained descriptor marker

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H64 again completed every lifecycle and physical residue domain except `unexpected_descriptors` and `descriptor_baseline`. The independent observer proved the failure was in its own process, but the domain-only diagnostic did not distinguish input, runtime, alias, sandbox, named-netns, share, VM, or exact netns descriptor custody.

Keep the same target matching and exact success condition. On failure only, classify matching targets by fixed non-sensitive role names and append those roles to the error. Descriptor numbers and path contents are not emitted. This changes no descriptor census, identity comparison, domain verdict, or promotion semantics; it only identifies the retained owner for the next exact correction.

Focused coordinator, Docker final-integration, TypeScript, formatting, and retained-line checks pass. H64 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
