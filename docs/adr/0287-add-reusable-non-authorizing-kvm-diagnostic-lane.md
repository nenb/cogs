# ADR 0287: Add a split-lineage current-source prebuilt KVM diagnostic lane

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the explicit request for the smallest secure reusable non-authorizing KVM integration diagnostic lane

## Context

The retired rehearsal generations repeatedly rebuilt and republished the same canonical rootfs before reaching downstream full-route defects. Successful diagnostic publisher run `33615572679` already authenticated and read back an immutable GHCR publication, but its small Actions custody artifact expires. Its publication is diagnostic and does not authorize qualification, production, or AWS effects. Failed rehearsal `33615698328` remains non-authorizing.

## Decision

Add one distinct protected-main manual workflow with no inputs and only `contents: read`. Attempt 1 is mandatory, reruns are rejected, and each dispatch is independent. Separate fresh jobs materialize exact `GITHUB_SHA` source and its complete manifest, then run that current implementation on exactly one sealed no-mint full or readiness route. The fixed prior publication supplies rootfs bytes and custody only; it never selects runtime source or grants evidence authority. Each job recovers, settles, and proves zero residue, while a third job aggregates only statuses.

Pin publication run `33615572679`, artifact `9840794063`, Actions archive digest `sha256:662bdd78f5b3088a37e226c54847cd19d3bb6ac044dc23f800046111d9983c45`, OCI manifest `sha256:f80a3eafb00a184fa0899014c91401d7d5f06d757b29f38562070d0b5dab2a67`, and canonical ustar `sha256:41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397` in one checked-in diagnostic-only lock. Retain its six small custody members byte-for-byte with exact sizes and SHA-256 digests so expiry cannot select a fallback artifact. The verifier accepts no caller coordinate or path.

Select only `cogs.stage2-current-source-prebuilt-diagnostic-control/v1`, with no fallback. This separate codec binds current revision, complete source-manifest digest, and selected security sources independently from prior producer H, source manifest, publication control G, descriptor, custody, OCI manifest, signature verification, and canonical ustar bytes. Diagnostic admission issues sealed custody only to dedicated coordinator full/readiness entries with `mint=False`. Formal control, grant, binding, evidence, and receipt codecs reject the profile; production routes and checks retain their prior behavior. The workflow has no OIDC, package write, artifact read, AWS/provider credential, evidence upload, publication, or promotion permission or step.

Raise only the tracked-source cardinality bound from 1,350 to 1,360 for this workflow, lock, verifier, custody directory, test, and decision. All retained line, workflow line, global line, preferred-total, and hard-stop limits remain unchanged and satisfied.

## Consequences

This lane diagnoses current protected-main corrections against only the exact lock-bound prior rootfs publication. Changing that publication requires a new reviewed lock; changing current source naturally creates a new exact diagnostic source lineage. A successful run is operational status only and cannot freeze H/G, satisfy qualification, authorize production, or supersede any failed rehearsal. No workflow is dispatched by this decision.
