# ADR 0287: Add a reusable non-authorizing prebuilt KVM diagnostic lane

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the explicit request for the smallest secure reusable non-authorizing KVM integration diagnostic lane

## Context

The retired rehearsal generations repeatedly rebuilt and republished the same canonical rootfs before reaching downstream full-route defects. Successful diagnostic publisher run `33615572679` already authenticated and read back an immutable GHCR publication, but its small Actions custody artifact expires. Its publication is diagnostic and does not authorize qualification, production, or AWS effects. Failed rehearsal `33615698328` remains non-authorizing.

## Decision

Add one distinct protected-main manual workflow with no inputs and only `contents: read`. Attempt 1 is mandatory, reruns are rejected, and each new dispatch is independent; no workflow-history uniqueness is consulted. Separate fresh jobs each acquire exact implementation `5bced6bdc54756761f28a393970301b9b24341cc`, materialize the fixed publication, perform immutable preparation, run exactly one actual no-mint full or readiness route, recover, settle, and prove zero residue. A third job aggregates only job statuses.

Pin publication run `33615572679`, artifact `9840794063`, Actions archive digest `sha256:662bdd78f5b3088a37e226c54847cd19d3bb6ac044dc23f800046111d9983c45`, OCI manifest `sha256:f80a3eafb00a184fa0899014c91401d7d5f06d757b29f38562070d0b5dab2a67`, and canonical ustar `sha256:41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397` in one checked-in diagnostic-only lock. Retain its six small custody members byte-for-byte with exact sizes and SHA-256 digests so expiry cannot select a fallback artifact. The verifier accepts no caller coordinate or path.

The diagnostic lock profile is never added to formal static control, production grant, campaign, or receipt codecs. Their exact-key and sealed-type checks reject it, and the diagnostic route remains on the existing explicit no-mint entry. No exception fallback is added. The workflow has no OIDC, package write, Actions artifact read, AWS/provider credential, evidence upload, publication, or promotion permission or step.

Raise only the tracked-source cardinality bound from 1,350 to 1,360 for this workflow, lock, verifier, custody directory, test, and decision. All retained line, workflow line, global line, preferred-total, and hard-stop limits remain unchanged and satisfied.

## Consequences

This lane repeatedly diagnoses only the exact lock-bound downstream integration generation; changing the rootfs publication or implementation requires a new reviewed lock. A successful run is operational diagnostic status only and cannot freeze H/G, satisfy formal qualification, authorize production, or supersede any failed rehearsal. No workflow is dispatched by this decision.
