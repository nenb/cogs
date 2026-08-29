# ADR 0213: Use loaded production custody for input appends

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H57 demonstrated that ADR 0212 removed the inner duplicate reload, but the public production-capability wrapper still reclaimed and fully reloaded the operation before every input append. H57 nevertheless retired the complete input tree; the final `absent` record then failed because that wrapper tried to validate the already removed tree before the post-effect record could be appended.

For `INPUT_GRANT`, `INPUT_WA`, and `INPUT_STEP` appends under the original live production authority, validate the already loaded exact custody, the unique production admission and lifecycle deadline, and the still-live deadline without reclaiming it. Cleanup-capability and recovery callers retain their existing claim path. The downstream `write_validated` path remains unchanged: it validates semantics, held journal generation and offset before append, durable readback, and resulting filesystem layout. Thus intent appends still validate before effects and settled appends validate after effects; mutation or replacement remains fail-closed.

Focused operation, input, coordinator, TypeScript, formatting, and retained-line matrices pass. H57 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
