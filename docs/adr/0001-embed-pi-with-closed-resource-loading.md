# ADR 0001: Embed Pi with closed resource loading

- Status: Accepted
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

Cogs must preserve Pi's agent/session behavior without allowing project or user package code to execute in the trusted worker. Pi's default loader discovers extensions, packages, settings, skills, prompts, themes, and context from global and project paths.

## Decision

Pin `@earendil-works/pi-coding-agent`, `pi-agent-core`, and `pi-ai` to `0.80.6`. Construct request-scoped/in-memory `AuthStorage`, `ModelRegistry`, `SessionManager`, settings, and a custom `ResourceLoader` explicitly; the worker must not read or write ambient home/project auth files. The loader returns no extensions, packages, prompts, themes, context, or ambient skills. Register exactly four SDK custom tools named `read`, `write`, `edit`, and `bash`; suppress built-ins. Stage 0 definitions are harmless no-I/O stubs. Production definitions must dispatch exclusively through the sandbox SSH/SFTP boundary and have no trusted-host fallback. Approved context and skills will later enter as bounded text/data through explicit trusted inputs.

Stage 0 relies on the documented SDK plus one public `Agent.streamFn` property to install a deterministic fake stream after session construction. Production model calls retain Pi's normal stream function.

## Consequences

- Default Pi resource discovery and project trust are not a Cogs security control and are never invoked.
- Any inability to retain the closed loader or custom-tool override on Pi upgrade blocks that upgrade.
- Hostile global/project extension and package canaries are permanent regression tests.
- Pi upgrades require JSONL, fake-model, tool-source, and discovery tests before merge.
