# ADR 0165: Accept zero OpenSSH none-cipher padding

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

After exact public-key derivation succeeded, native input validation rejected the pinned Ubuntu OpenSSH private key. Its unencrypted private block was already aligned to eight bytes and therefore contained zero padding bytes. The parser required one through eight even though every preceding private-key field, public half, role-specific fixed comment, and independently derived public line was exact.

Accept zero through eight padding bytes and retain the exact sequential `01 02 ...` check for every nonempty padding value. All cipher/KDF, key count, framing, check integers, type, private/public relation, comments, bounds, and independently derived public-key checks remain unchanged.

This is parser compatibility with the pinned native producer. It grants no alternate key, retry, caller input, AWS, provider, deployment, evidence, promotion, or release authority.
