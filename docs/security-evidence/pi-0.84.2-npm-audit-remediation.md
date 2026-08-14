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

`scripts/check-npm-audit.ts` now requires exit status zero, an empty finding object, and exact zero counts for INFO, LOW, MODERATE, HIGH, and CRITICAL. The former four-finding/nine-advisory exception and its expiry are deleted rather than renewed. Canonical offline readiness continues to mark current registry audit as `not-run-not-claimed`; an invocation result is reported separately during change validation and is not promoted into that static evidence.

The existing reviewed worker digest was built from the earlier Pi source and is not promoted as evidence for this change. A later protected-main image publication and independent review are required before any new worker digest can enter release-image or runtime authority.
