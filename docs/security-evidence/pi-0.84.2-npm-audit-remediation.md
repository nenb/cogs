# Pi 0.84.2 npm-audit remediation

Status: reviewed source remediation replacing the temporary 2026-08-03 npm-audit disposition. This record establishes no runtime, image-publication, cloud, Stage 4 exit, production, or release authority.

## Exact change

Cogs upgrades these direct dependencies together from `0.80.6` to `0.84.2`:

- `@earendil-works/pi-agent-core`
- `@earendil-works/pi-ai`
- `@earendil-works/pi-coding-agent`

The authenticated Pi 0.84.2 shrinkwrap contains the fixed nested versions directly:

- `brace-expansion` `5.0.9`;
- `protobufjs` `7.6.5`; and
- `undici` `8.9.0`.

The root-only `brace-expansion` and `undici` dependencies and the production-worker copy-over workaround are removed. The worker build instead verifies all three Pi versions and the three exact nested fixed versions before copying runtime bytes.

The published Pi shrinkwrap omits SRI fields on six nested `@earendil-works` lock entries. Cogs restores those fields from the exact npm registry metadata for the same package name, version, and resolved tarball. `npm ci` preserves the normalized lock byte-for-byte, and `scripts/check-lock-integrity.ts` continues to reject every registry entry without SRI.

## Compatibility boundary

ADR 0098 replaces the initial ADR 0001 Pi pin and auth facade while preserving its security boundary. Cogs now supplies an in-memory `CredentialStore` to `ModelRuntime`, disables model-file and create-time network refresh, injects only one runtime API key, admits only the provisional Anthropic/OpenAI/OpenRouter API-key providers and requires exact stored-key auth with no provider-derived environment or synthesized auth headers, keeps the immutable closed `ResourceLoader`, exposes exactly `read`, `write`, `edit`, and `bash`, and removes the key through bounded sanitized cleanup. No ambient auth, model configuration, extension, package, prompt, theme, context, or skill discovery is enabled.

Export manifest v1alpha2 binds Pi `0.84.2`; historical v1alpha1 retains its Pi `0.80.6` meaning, and importing a differently versioned manifest continues to fail closed.

## Audit result

Before the organization-wide disposition below, `scripts/check-npm-audit.ts` required exit status zero, an empty finding object, and exact zero counts for INFO, LOW, MODERATE, HIGH, and CRITICAL. The former four-finding/nine-advisory exception and its expiry remain deleted rather than renewed. Canonical offline readiness continues to mark current registry audit as `not-run-not-claimed`; an invocation result is reported separately during change validation and is not promoted into that static evidence.

The existing reviewed worker digest was built from the earlier Pi source and is not promoted as evidence for this change. A later protected-main image publication and independent review are required before any new worker digest can enter release-image or runtime authority.

## Organization-wide GHSA-3wwx-pv8p-q78v accepted risk

Exact-head CI run `36495136155` first observed npm advisory source `1239932` against the immutable Pi 0.84.2 shrinkwrap's nested `undici` 8.9.0. The advisory is a moderate availability finding for an unhandled error while decompressing WebSocket `permessage-deflate` data. The package bytes are in the dependency tree, so this record does not dispute the registry's general technical finding.

Nick Byrne explicitly accepts this exact finding as an organization-wide production risk for every Cogs use of the pinned Pi 0.84.2 and its nested `undici` 8.9.0. The acceptance applies to Stage 2, Stage 4, release-image, promotion, and general production security gates, while leaving every independent gate and every other vulnerability finding unchanged. It remains in force only while those exact dependency versions and finding bytes remain current and must be removed when Pi is upgraded to a version carrying fixed `undici` bytes.

`scripts/check-npm-audit.ts` admits only the exact two-entry npm representation: the direct Pi meta-finding and the nested `undici` finding with advisory URL, source, severity, CWE, CVSS vector, vulnerable ranges, package paths, installed Pi/undici versions, direct lockfile dependency edges, fix representation, dependency counts, and zero findings at every other severity. A new key, advisory, affected path, version, severity, relationship, malformed result, high-severity status, accepted dependency-edge change, or package-count change fails closed. Removal or correction of the advisory also fails closed and requires removing this disposition rather than silently treating historical acceptance as a zero-finding result.

This changes no package, lock, Pi, worker image, H, G, Q, qualification, planner, campaign, provider, guest, schema, or production behavior byte. It permits one protected successor to restore exact-head audit admission and then use the already supplied planning and seven-cycle phrases. It does not independently waive any non-audit production or release control.

## Retirement after the Pi 0.86.0 upgrade

The upgrade from Pi 0.84.2 to Pi 0.86.0 replaces the affected nested `undici` 8.9.0 with fixed 8.10.2 and retires the executable GHSA-3wwx-pv8p-q78v disposition described above. The preceding text remains the historical record of why the temporary acceptance existed; it is no longer an active audit policy or acceptance for current dependency bytes.

`scripts/check-npm-audit.ts` once again requires a well-formed npm audit v2 report with an empty vulnerability object and zero INFO, LOW, MODERATE, HIGH, CRITICAL, and total findings. It invokes npm audit at the LOW threshold, rejects every advisory regardless of severity, and fails closed on invocation failure, malformed JSON, changed report structure, malformed counts, or nonzero findings. No advisory identity, package version, lock edge, dependency count, or historical risk acceptance can bypass that zero-tolerance rule.
