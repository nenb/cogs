# ADR 0252: Complete the terminal host-attestation binding

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

No-mint diagnostic run `33312269679`, attempt 1, completed the full real Kata/KVM owner path and exact cleanup, then reached terminal owner evidence. The diagnostic stopped before any receipt could be minted. Its bounded cause chain proved the sole terminal defect: `_BindingOwnerResult` lacked `host_attestation_sha256`. Exact recovery and diagnostic scaffolding cleanup passed. The run grants no qualification or promotion claim.

The reviewed static envelope intentionally contains a result-binding base without the runtime-derived fields. Complete that base inside static custody with the host attestation digest of the first five executable rows from the authenticated, descriptor-held runtime manifest, using the same canonical digest formula required by final envelope admission. Runtime attestation remains derived separately from the causal runtime proof. Reject any base with missing or extra keys and any malformed executable collection. No caller-supplied path, digest, or mutable result is admitted.

The earlier H `89243c8d9f7a946aefdaa4c445a5cfe1e0fe7e14` remains preserved history. This correction requires a newly reviewed merged implementation H, a later independently produced G describing that H, one new static observation, and then one replacement formal qualification. Retain every existing line, byte, timeout, cleanup, and evidence bound. Raise only the complete tracked-source cardinality bound from 1,213 to exactly 1,214 files.

This grants no AWS, provider, deployment, campaign, production, release, retry, or promotion operation.
