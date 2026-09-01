# ADR 0274: Bind the Cosign-corrected diagnostic producer

- Status: Accepted
- Date: 2026-09-01
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

Diagnostic publisher `33512601698` failed before signing because the pinned nonroot Cosign container could not read ORAS's root-mounted registry configuration. PR #475 applied the already-qualified release-workflow custody pattern: runner UID/GID, private Cosign home, a mode-0600 registry configuration, and verified credential-directory removal. Its protected-main implementation revision is `c3190e246dc2aaaa005df1f167b77aa25df0e28b`.

Attempt-one diagnostic producer `33515553274` then completed two byte-identical builds and separate seven-member readback. Artifact `9804294193` has Actions digest `sha256:427a8aec627c145d7b31d59a6fc5a5d961e1f20a9686ec26e3363235e70297e6`.

## Decision

This ADR must be the direct protected-main child of `c3190e246dc2aaaa005df1f167b77aa25df0e28b`. It authorizes one first-created diagnostic publisher bound only to run `33515553274`, artifact `9804294193`, and the exact archive digest above.

This remains diagnostic authority solely for the one no-mint full/readiness rehearsal. It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All earlier diagnostic generations remain non-authorizing and cannot be retried or relabelled. Any further failure requires correction before another fresh generation.
