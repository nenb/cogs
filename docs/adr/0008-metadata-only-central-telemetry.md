# ADR 0008: Centralize operational metadata, not user content

- Status: Accepted
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

Users and administrators need token, resource, tool, and egress observability without creating a central copy of prompts, source, commands, paths, or tool output.

## Decision

Emit OpenTelemetry with opaque identifiers and operational metadata only. Exclude prompt/model text, source, complete commands, arbitrary paths, tool output, HTTP queries/bodies, credentials, and placeholders. Exact content remains in the user-owned Pi transcript. A separately protected enterprise command-audit sink is future, explicit, and disabled by default.

Credential-use audit authorization is fail-closed and separate from ordinary asynchronous OTLP delivery.

## Consequences

- OTLP outage does not stop ordinary work; an unavailable/unwritable credential-use audit path denies secret use.
- Telemetry privacy assertions are automated at the highest validated concurrency.
- Centralizing raw content crosses an ADR boundary and requires explicit review.
