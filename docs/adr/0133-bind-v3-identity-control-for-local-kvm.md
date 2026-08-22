# ADR 0133: Bind V3 identity control for local KVM

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Directional G after corrected V3-identity static observation

## Context

After exact-head CI, Linux foundations, and two independent reviews, protected `main` was fast-forwarded to static-event binding `7759346c281b45a3d98476abdfaa820109601547`. Exactly one attempt-one no-KVM observation was dispatched for implementation H `a2c25f34c35d778965ab7b125fd3b8b4460b0617`.

Run `32594176203` completed successfully and published one artifact:

- artifact ID: `9481140232`
- artifact name: `non-authoritative-stage2-static-control-a2c25f34c35d778965ab7b125fd3b8b4460b0617-32594176203-1`
- ZIP SHA-256: `59ff3ad358d23c40d9494d3cf26d2c6f71c4afe6d46e761a13c1389b56f050e2`
- control SHA-256: `c20534f05f4bc1a4a31965ef5fc220bda20263024ad06b6f798f3f13bbfdbdf9`
- envelope SHA-256: `9bf0522ec0e6830757a168a51e0ee9b945f7a0c6cc27852525c16917a8b66d36`
- runtime-manifest SHA-256: `ca120ffffb8b76d37afedaa74688bab42e5fb2c20c1e1711e5a175c043ce6e02`
- source-manifest SHA-256: `0b2600579ff88d29f6670d75cd354ea8bfb03fed7697f19e7552bfc0083cc094`
- exact V3 guest stdin SHA-256: `990f3a2cb57121a4aab2fb79b347bc3904082572ef8177f3c2d79c28d96e3db1`

Exact-ID readback is privately retained at `/Users/nenb/.pi/artifacts/cogs/issue42-static-control-32594176203`; canonical custody-manifest SHA-256 is `e77ead79d511c91c160eaa7668056a965cf5d66f53d6f7ac34c8e40f76669ce3`. The ZIP contains exactly thirteen unique regular members. Strict semantic loaders, ten executable contracts, and all three Draft 2020-12 schemas accepted exact bytes. Producer, admission, SSH, and terminal evidence now bind the same exact V3 stdin digest.

## Decision

Commit the thirteen exact members from artifact `9481140232` as the local control package. Bind the qualification guard to H, source manifest `0b2600...c094`, control `c20534...bdf9`, unchanged workflow SHA-256 `108e0782daf7100d7fe7dd9354afa377f182cc2257e2927c142201b32c8834af`, and unchanged result-schema digest.

The later commit containing these bytes is directional control revision G. The two prior local qualification runs remain exact completed failures that did not reach the KVM entry and grant no cleanup or promotion claim.

## Authority boundary

After exact G review, exact-head CI/Linux foundations, protected-main fast-forward, exact repository-variable configuration, and unchanged two-run KVM history, this decision permits the one corrected local KVM/Kata dispatch covered by the standing non-AWS instruction. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign operation, deployment, production, promotion, or release authority.
