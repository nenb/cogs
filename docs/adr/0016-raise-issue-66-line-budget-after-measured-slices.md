# ADR 0016: Raise issue #66 line budget after measured secure-egress slices

- Status: Accepted
- Date: 2026-07-15
- Decision owner: Nick Byrne
- Accepted by: delegated project lead acting under Nick Byrne’s explicit delegation of project decisions in the 2026-07-15 conversation.

## Context

ADR 0015 accepted the Stage 3 issue #66 secure-egress integration scope and set a hard cap of 8,500 production TypeScript lines under `src/`, measured from the accepted baseline of 5,695 lines.

After the accepted descriptor, route-policy, WAL, loopback ext_authz server, and Envoy bootstrap renderer slices, the measured production count is 8,201 lines. The current implementation stayed within ADR 0015's architecture, dependency, proto, descriptor, static Envoy, fail-closed, and security constraints, but the renderer consumed more lines than the residual estimate because it replaced a coarse Stage 1 fixture estimate with full production fail-closed static topology validation and callback-scope credential containment.

The remaining issue #66 work still needs enough line budget for OpenBao credential/PKI access, trusted tmpfs/config writing, Envoy process management, completion/revocation/lifecycle wiring, and final hardening without unsafe compression.

## Decision

Replace ADR 0015's issue #66 aggregate cap of **8,500** production `src/**/*.ts` lines with a hard cap of **9,000** production `src/**/*.ts` lines.

This ADR changes only the line budget. ADR 0015 remains authoritative for every architecture, dependency, vendored proto closure, descriptor artifact, Envoy static-configuration, no-fallback, OpenBao, WAL, telemetry, security, and non-scope constraint.

No architecture, dependency, proto, protocol, release, AWS/EKS, OAuth, deployment, or production-readiness expansion follows from this amendment.

## Rationale

The measured slices show that the original 8,500 cap left too little safe room after implementing the production renderer with the required containment boundaries:

- accepted baseline: 5,695 production `src/**/*.ts` lines;
- current measured count after renderer slice: 8,201;
- remaining room under 8,500: 299 lines;
- conservative remaining implementation estimate: up to 650 lines;
- amended cap: 9,000 lines;
- remaining room under 9,000 at current count: 799 lines, leaving at least 149 lines of contingency after the conservative remaining estimate.

The increase is bounded and issue-specific. It preserves the original intent of ADR 0015: allow enough production code for fail-closed validation, redaction, cleanup, and evidence without encouraging compression of security-critical paths.

## Consequences

Issue #66 implementation may proceed up to 9,000 production `src/**/*.ts` lines, with every PR continuing to report the measured aggregate count.

The 9,000-line cap is hard. Breaching it, adding or changing production dependencies, changing the vendored proto source closure or descriptor artifact contract, changing the static Envoy architecture, or widening protocol/release/deployment scope still requires review and an accepted amendment or superseding ADR.

No release, AWS, EKS, production-readiness, or OAuth authorization follows from this ADR.
