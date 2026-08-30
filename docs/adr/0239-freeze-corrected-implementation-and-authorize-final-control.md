# ADR 0239: Freeze the corrected implementation and authorize final control

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Freeze the corrected, reviewed implementation H as protected-main revision `89243c8d9f7a946aefdaa4c445a5cfe1e0fe7e14`. Its PR observation passed the complete quality, image/SBOM, secret, and Linux-foundation checks, including the 23-minute `network-runtime` shard. The matching private Osito diagnostic also passed with zero external residue but grants no qualification or promotion claim.

Produce the control generation after H. Guard v22 now accepts exactly H while preserving rejected wrong-ref run `33267664208` under its original title for earlier checkpoint `dfb28c2e8deb7fed90da095c41b4d556c737af97`; changing H must not rewrite that authenticated predecessor. Keep every other predecessor, protected-main requirement, one-attempt rule, earliest-current-run rule, immutable preparation boundary, static-only observation, exact artifact upload, and cleanup boundary unchanged. Refresh the normalized workflow digest only for those two reviewed control bindings.

After this independently reviewed control-only correction is merged to protected `main`, authorize exactly one no-KVM static-control observation G for H. Failure, cancellation, missing artifact, cleanup uncertainty, history drift, or any second current-generation run consumes the observation and grants no retry, qualification, or promotion claim. This authorization grants no AWS, provider, deployment, campaign, production, or release operation.
