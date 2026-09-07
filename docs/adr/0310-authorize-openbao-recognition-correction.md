# ADR 0310: Authorize the bounded OpenBao recognition correction

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance approval to continue every required non-AWS correction until the authoritative-chain boundary
- Inputs: `/tmp/cogs42-posth-supply.md`, `/tmp/cogs42-openbao-path.md`, `/tmp/cogs42-obaobuild-impl.md`, and independent report `/tmp/cogs42-openbao-recognition.md`

## Context

ADR 0309 kept OpenBao 2.6.1 retired and authorized a time-boxed first-party local-functional derivative feasibility path. Upstream-signed 2.6.2 fixes the two original Go-standard-library findings but its exact images still fail fresh unsuppressed scans. Initial feasibility stopped because the binary's truthful Go main-module pseudo-version caused five already-fixed OpenBao advisories to compare below their v2 fix boundaries, while real dependency findings remained.

An independent high-thinking reviewer reproduced the recognition behavior against actual authenticated 2.6.2 source and found a narrow supported mechanism. Trivy 0.74.0 already prefers a used ELF link-time symbol ending in `.version` over a pseudo main-module version. Renaming OpenBao's private `fullVersion` variable to `version` and applying the matching `-X` value makes the same release value used by OpenBao's banner available to the scanner. The raw Go build information remains present. A genuine old 2.0.2 control still triggers the relevant advisories through independent supported inventory/scan paths.

The independent build also found that the initially proposed x/crypto 0.55.0 remains affected by `GO-2026-6354` and `GO-2026-6355`; the fixed boundary is 0.56.0. This is a new stop requiring an explicit decision rather than an automatic dependency update.

## Decision

Authorize continuation of the ADR 0309 first-party **local-functional-only** derivative feasibility with these exact corrections:

1. Add only the two-reference private version-symbol rename and matching deterministic linker flag. Preserve the truthful upstream source commit/tree, downstream patch identity, Go pseudo-version/VCS build information, unstripped symbol needed for recognition, and an honest derivative banner. No binary rewriting, fabricated module version, scanner fork, report editing, ignore, VEX, severity rewrite, or disabled analyzer is allowed.
2. Replace the proposed x/crypto 0.55.0 target with **0.56.0**. Freeze and review the complete resolver-selected module/go.sum/vendor delta, including newly observed x/mod and x/tools changes. Any additional HIGH/CRITICAL, unexpected application change, broad `/v2` migration, or unresolved source-local replacement coverage stops feasibility.
3. Require raw Trivy whole-image recognition of OS, compiler, all linked Go dependencies, and the actual OpenBao derivative release identity. Require zero HIGH/CRITICAL without suppression. Cross-check the unmodified Trivy-generated CycloneDX inventory with Grype and retain native Syft/Grype output, including its known pseudo-version limitation; a skipped or unrecognized application is not a pass.
4. Retain authenticated old-version and deliberately vulnerable dependency controls. Reconcile every linked dependency and four source-local replacements to authenticated source subtrees and advisory/fix evidence. Unknown identity or coverage is blocking.
5. Preserve ADR 0309's authenticated source, fixed builder/base/tool inputs, offline CGO-disabled no-UI compilation, two isolated reproducible builds per admitted platform, complete runtime-byte equality, SBOM/provenance, zero-finding scan, synthetic-secret functionality, cleanup, independent review, and local-only expiry requirements.
6. No release workflow is reserved or authorized now. A later publisher/signing decision requires a separate accepted record after successful feasibility. Remove that unused reservation and use its one new-file slot for this ADR. Future replacement-H freeze/control and Q/qualification decisions move to ADR 0311 and ADR 0312 respectively.

This decision does not activate upstream 2.6.2, admit a derivative, authorize signing/publication, permit production credentials, or waive ADR 0308's real-fixture gate. If feasibility remains blocked, a later explicit Stage2-only decision may separate the technically independent Stage2 execution graph while preserving OpenBao/Stage3/Stage4 and production-credential blockers; no such separation is made here.

## Validation and stop conditions

Before any local artifact can be considered for a later admission review:

- both actual builds and complete runtime manifests are byte-equal for every admitted platform;
- the actual binary reports the fixed compiler/dependencies and honest derivative identity;
- raw and cross-scanner reports retain all findings and meet the zero-HIGH/CRITICAL policy;
- old affected controls and vulnerable-module controls fail the gate;
- exact OpenBao ACL, KV-v2, PKI, root-retirement, storage and cleanup tests pass with synthetic values;
- no source, module, scanner, database, builder, base, platform or artifact identity is missing or inferred;
- all whole-file, line, byte, source-cardinality and workflow ceilings pass.

Any missing reviewer, stale/acquisition-failed scan, unsupported platform, nondeterministic build, scanner recognition failure, unresolved finding, cleanup uncertainty, or budget overrun preserves retirement and stops the path.

## Authority boundary

This ADR authorizes source/recipe/test implementation and local non-authorizing feasibility only. It grants no producer, publisher, preflight, qualification, image publication, release, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production effect, Stage 4 exit, or Issue #42 closure authority. Work still stops before the authoritative chain.
