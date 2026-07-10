# ADR 0005: Preserve native Pi JSONL

- Status: Proposed
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

Prompt-to-commit synchronization and portable exports need durable session entries without creating a second transcript abstraction.

## Decision

Use Pi `SessionManager` and its append-only version 3 JSONL as authoritative active chat state. Preserve entry IDs, parent IDs, tree branches, compactions, and native messages. Store Cogs metadata in Pi custom entries only where compatible and in trusted sidecar manifests otherwise. Do not rewrite the authoritative transcript for export or future sanitization.

## Consequences

- The pinned Pi library/CLI must open every Cogs session fixture.
- Pi format migrations are accepted only after compatibility review and tests.
- Cogs-specific Git, skill, and export metadata must not make `session.jsonl` non-Pi-compatible.
- Sanitization, when implemented later, transforms a copied bundle and never mutates active JSONL.
