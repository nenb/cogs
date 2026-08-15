# ADR 0098: Upgrade Pi and use the closed ModelRuntime API

- Status: Accepted by explicit owner instruction
- Date: 2026-08-14
- Supersedes: ADR 0001's exact Pi 0.80.6 pin and `AuthStorage`/`ModelRegistry.inMemory` construction, plus ADR 0014's `AuthStorage` mechanism, only

## Context

The Pi 0.80.6 development tree retained nine advisories across nested `brace-expansion`, `protobufjs`, and `undici`. A temporary exact disposition was due to expire on 2026-08-16 and required a separate compatibility, dependency-tree, image, and source-closure review before adopting the fixed Pi line. Pi 0.84.2 contains `brace-expansion` 5.0.9, `protobufjs` 7.6.5, and `undici` 8.9.0, but replaces the exported auth facade with `ModelRuntime` and adds resource-source methods to `ResourceLoader`.

## Decision

Pin `@earendil-works/pi-agent-core`, `@earendil-works/pi-ai`, and `@earendil-works/pi-coding-agent` to exactly 0.84.2.

Construct `ModelRuntime` with an application-owned in-memory credential store, `modelsPath: null`, `allowModelNetwork: false`, and `refreshOnCreate: false`. Add only the launch-authorized runtime API key, reject OAuth and provider auth that needs ambient environment or synthesized headers, pass that same runtime to `createAgentSession`, and remove the key through a bounded sanitized operation during normal, startup-failure, and fail-closed cleanup. Only the provisional `anthropic`, `openai`, and `openrouter` API-key providers are admitted; each auth result must be the exact stored key with no provider-derived environment or synthesized headers. Credential mutations and auth resolution receive bounded abort signals. Fake-model tests override only `Agent.streamFunction` behind that same check.

Keep the ADR 0001 containment boundary unchanged: one explicit model, one closed resource loader, no source paths for system-prompt additions, no ambient auth/model/settings/resource discovery, no built-in tools, and exactly four trusted custom tools named `read`, `write`, `edit`, and `bash`.

Require SRI for every registry lock entry. Where Pi's published shrinkwrap omits nested workspace-package SRI, bind the exact registry tarball through the registry SRI for the same package name, version, and resolved URL. Require `npm ci` to preserve that normalized lock.

Remove the temporary audit disposition and require a completely clean npm audit. Remove the worker's vulnerable-input replacement routine; verify the exact fixed Pi and nested package versions instead.

## Consequences

Exports now use manifest v1alpha2 bound to Pi 0.84.2 and reject manifests from other Pi versions; historical v1alpha1 retains its Pi 0.80.6 meaning. The dependency tree and production worker source change, so the previously reviewed worker image remains historical and cannot authorize the new source. Authenticated-runtime evidence v3 and readiness package/verdict v4 restore `RELEASE_IMAGE_SET_ABSENT` while preserving the older schemas. Runtime closure, campaign readiness, cloud truth, Stage 4 exit, production readiness, and release eligibility remain false.

This ADR grants no image publication, deployment, Kubernetes, provider, AWS, campaign, external-model, or release authority.
