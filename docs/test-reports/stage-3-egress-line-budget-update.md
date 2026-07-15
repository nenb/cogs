# Stage 3 secure egress line-budget update

Date: 2026-07-15
Issue: #66
Related ADRs: [ADR 0015](../adr/0015-stage-3-egress-integration-scope.md), [ADR 0016](../adr/0016-raise-issue-66-line-budget-after-measured-slices.md)

## Summary

ADR 0016 raises only the issue #66 production `src/**/*.ts` aggregate cap from 8,500 to 9,000 lines. It does not expand ADR 0015 architecture, dependency, proto, descriptor, security, deployment, release, AWS/EKS, or OAuth scope.

## Measurements

Accepted ADR 0015 baseline after PR #82:

```text
5,695 production src/**/*.ts lines
```

Current measured aggregate after the accepted descriptor, route-policy, WAL, loopback authz server, and Envoy runtime config renderer slices:

```text
8,201 production src/**/*.ts lines
```

Measured aggregate delta from baseline:

```text
8,201 - 5,695 = 2,506 lines
```

## Measured deltas by slice

| Slice | Measured aggregate after slice | Delta from prior checkpoint | Notes |
|---|---:|---:|---|
| ADR 0015 baseline | 5,695 | — | Accepted post-PR #82 baseline |
| Descriptor/ext_authz binding foundation | 6,134 | +439 | Pinned descriptor loader/adapter; vendored proto source is outside `src/` |
| Route-policy lowering | 6,668 | +534 | Secret-free preset/route lowering and revision helper |
| WAL durable intent audit | 7,063 | +395 | WAL-only Slice 3a |
| Loopback ext_authz server | 7,504 | +441 | Authenticated loopback gRPC server and verifier |
| Envoy runtime config renderer | 8,201 | +697 | Static topology renderer and callback-scoped credential containment |
| **Total delta** | **8,201** | **+2,506** | From 5,695 baseline |

## Why the renderer exceeded the residual estimate

The renderer grew because the production Slice 3c replaced the infeasible residual estimate with full fail-closed static topology and callback-containment behavior:

- sandbox-facing explicit proxy listener fixed to `0.0.0.0:<trusted port>`;
- authz target constrained to loopback with exact `initial_metadata`;
- fixed future-tmpfs certificate/key/config paths without accepting or returning PEM;
- explicit system CA filename and exact DNS SAN validation;
- deterministic CONNECT/internal-TLS topology with no direct, dynamic-forward, original-destination, or failure-mode fallback;
- route-plan revalidation/copying, unique route/integration IDs, and strict authority/path/method/header behavior;
- callback-scoped credential resolution once per credentialed integration;
- visible-ASCII credential and internal-token material, canonical Basic validation, and duplicate mutation avoidance;
- structural tests asserting topology and metadata-only access-log behavior.

Compressing these checks to fit the earlier residual would have made security-critical code harder to review and more fragile.

## Remaining production work estimate

Conservative estimate for remaining issue #66 implementation under ADR 0015 constraints:

| Remaining work | Conservative estimate |
|---|---:|
| OpenBao credential + PKI adapter | 220 |
| Trusted tmpfs/config writer + Envoy manager | 230 |
| Completion/revocation/lifecycle wiring | 200 |
| **Estimated remaining** | **650** |

Under the amended 9,000 cap:

```text
9,000 - 8,201 = 799 lines remaining
799 - 650 = 149 lines contingency
```

## Boundaries preserved

The 9,000-line cap is hard. Breach of the cap, new production dependencies, proto/descriptor contract changes, architecture changes, or protocol/deployment/release scope changes still require review and an accepted amendment or superseding ADR.

No release, AWS, EKS, production-readiness, OAuth, or broader issue authorization follows from the line-budget amendment.
