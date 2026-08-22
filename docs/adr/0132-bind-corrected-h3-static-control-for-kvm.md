# ADR 0132: Bind corrected H3 static control for KVM

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Directional control revision after the sole corrected no-KVM observation

## Context

Protected `main` was fast-forwarded exactly to static binding `acb99d5d6ba4cbd94ad40c9bbe4520d2f8905368` after exact-head CI, Linux foundations, and two independent reviews. One attempt-one static workflow was then dispatched for self-consistent implementation H3 `33314a9999cbe1e0eb927ba4a1e6f1ee10fcd5df`.

Run `32590966571` completed successfully without KVM/runtime/network launch and published one artifact:

- artifact ID: `9480330947`
- artifact name: `non-authoritative-stage2-static-control-33314a9999cbe1e0eb927ba4a1e6f1ee10fcd5df-32590966571-1`
- ZIP SHA-256: `c20b3313d009261a01ec70ac52e5445cfadabccf27b6d0484189fcae543bc0d5`
- control SHA-256: `553813ce5ed576a015e5b089dbe4632a485c4abcb3ff0a3a89069025dc538531`
- envelope SHA-256: `70c26c49aa1801e31edd01cde8eee37f72a9577fd538e1a75a3de99b95e4a870`
- runtime-manifest SHA-256: `ca120ffffb8b76d37afedaa74688bab42e5fb2c20c1e1711e5a175c043ce6e02`
- source-manifest SHA-256: `237061a74a38ea9355fc25c5bebae91d683327d4d36db2acf33da13d7ba8c5fe`

Exact-ID readback was retained privately at `/Users/nenb/.pi/artifacts/cogs/issue42-static-control-32590966571`; canonical custody-manifest SHA-256 is `d3d844dc9cf5d71b171e5049399874ba19362590741e5854d0557129e5d4047e`. The archive had exactly thirteen unique regular members. Strict semantic loaders, all ten executable contracts, and the three Draft 2020-12 schemas accepted the exact bytes.

## Decision

Replace the prior committed static-control package with the thirteen exact members from artifact `9480330947`. Bind the local qualification guard to H3, source manifest `237061...c5fe`, control `553813...8531`, and unchanged reviewed workflow SHA-256 `108e0782daf7100d7fe7dd9354afa377f182cc2257e2927c142201b32c8834af`.

The later commit containing these bytes and guard is control revision G. H3 does not self-reference G. The two prior local qualification dispatches remain exact failed predecessors and grant no KVM, cleanup, or promotion claim.

## Authority boundary

This decision authorizes only the already-approved corrected local KVM/Kata qualification after exact G is reviewed, passes exact-head CI, reaches protected `main`, and repository variables are set exactly. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, or release authority.
