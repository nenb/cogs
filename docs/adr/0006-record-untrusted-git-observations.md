# ADR 0006: Record Git observations without claiming attestation

- Status: Accepted
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

Cogs must map commits and checkpoints to Pi entries, but Git commands and repository state are controlled by the untrusted guest.

## Decision

Cogs supplies the Pi entry ID, turn, and observation time authoritatively while recording the guest-reported repository and commit as explicitly untrusted observations. Store mappings in trusted session-side manifests and optionally write a non-secret Git note. Label exact boundary observations, inferred ancestors, and checkpoints distinctly. Never automatically push notes.

## Consequences

- An `exact` mapping means observed at an exact Pi boundary; it is not repository-integrity attestation.
- Brownfield and offline human commits are never fabricated as exact mappings.
- Hidden checkpoints must not modify `HEAD` or the user index and remain bounded/optional.
