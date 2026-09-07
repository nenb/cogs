# ADR 0318: Authorize S3 live-control response custody

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance non-AWS correction authority
- Input: `/tmp/cogs42-absolute-final-life.md` at `ad8ef903013215436d3ca257dafb25c69c5b3ff5`

## Context

The final lifecycle review confirmed all earlier response and transport ownership corrections and found one adjacent S3-09 live-control fetch that could reject on status without consuming or cancelling its acquired body. The same review also required sticky uncertainty when development OpenBao pre-reader cancellation rejects. Both are actual-work custody obligations already established by ADRs 0308 and 0316.

## Decision

Authorize a narrow permanent regression and correction in the existing trusted composition and development OpenBao files/tests:

1. capture the S3 live-control response body before status/header access;
2. consume through the existing bounded reader and initiate/join original-body cancellation on every exit;
3. keep the complete session operation in registered runtime cleanup so failure cannot precede body retirement;
4. retain development OpenBao request uncertainty when pre-reader cancellation rejects or throws;
5. preserve positive-only S3 semantics, no secret/body evidence, and ordinary failed-control classification.

Reallocate only owner ceilings: lifecycle 7,000 and integration 3,000. Keep global 18,500 and all other owner, Stage2, post-H reserve, source and v5 limits unchanged. Add one decision slot, bringing the exact new-file ceiling to thirty-eight. Future freeze/control and Q/qualification records become ADR 0319 and ADR 0320.

## Validation

Run held 503 and throwing-status live-control cases, body-read control, cancellation resolve/reject/throw fixture cases, all prior lifecycle reproducers, focused/full checks, deterministic evidence regeneration, accounting and exact final independent reviews.

## Authority boundary

This permits local correction, testing and ordinary protected CI only. It grants no producer, publisher, preflight, qualification, image publication, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production, release or Stage4 authority. Work stops before the authoritative chain.
