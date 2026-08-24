# ADR 0167: Index input history validation

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

ADR 0166 advanced the same bounded observation from record 1,397 to record 2,087, but full legal-history validation still rescanned all prior input grants, write-ahead facts, and steps for every input record. Because complete legal validation runs before each append, those nested prefix scans preserved quadratic work inside an already linear prefix pass.

Within each complete `_legal` invocation, build ephemeral indexes while traversing records in order: grants by ID and settled path, write-ahead facts by action/path, and steps by path. Evaluate each existing uniqueness, pairing, generation, and ordering predicate against only the already traversed indexed prefix. Do not persist indexes across calls or trust them across process/recovery boundaries. Every append still validates the complete record sequence, every record body, and the same legal predicates before fsync.

This is an equivalent algorithmic implementation of existing validation. It grants no skipped record, batching, omitted fsync, retry, AWS, provider, deployment, evidence, promotion, or release authority.
