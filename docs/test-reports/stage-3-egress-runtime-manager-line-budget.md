# Stage 3 issue #66 runtime-manager line-budget update

Date: 2026-07-16

This report supports ADR 0017. It is docs-only and changes no production code.

## Current measured state

After the merged OpenBao PKI source slice, production TypeScript under `src/**/*.ts` measures:

- current aggregate: **8,758 / 9,000** under ADR 0016;
- remaining room under ADR 0016: **242** lines.

The remaining runtime-manager work cannot be implemented safely inside 242 lines.

## Remaining production estimate

Measured plan components:

| Component | Low | High |
|---|---:|---:|
| tmpfs material writer | 260 | 340 |
| Envoy process/readiness | 220 | 320 |
| runtime manager | 420 | 620 |
| completion queue | 160 | 240 |
| revocation watcher | 180 | 280 |
| lifecycle/config integration | 80 | 160 |
| shared small types/errors/helpers | 40 | 80 |
| **Total remaining** | **1,360** | **2,040** |

Planning estimate: **1,800** production lines.

15% contingency on 1,800 is **270** lines. The minimum cap for current measured code plus planning estimate plus 15% contingency is:

`8,758 + 1,800 + 270 = 10,828`.

ADR 0017 selects an **11,000** hard cap, leaving:

- current remaining room under 11,000: `11,000 - 8,758 = 2,242`;
- contingency over 1,800 planning estimate: `2,242 - 1,800 = 442`;
- contingency percentage: `442 / 1,800 = 24.6%`.

## Bounded PR sequence

The remaining issue #66 production work should proceed in bounded PRs:

1. trusted tmpfs material writer;
2. Envoy process/readiness ownership port;
3. completion queue;
4. revocation watcher;
5. runtime-manager composition;
6. lifecycle dependency wiring.

Each PR should continue reporting the production aggregate against the 11,000 hard cap.

## Deferred scope

The following remain out of scope for this line-budget amendment and should be deferred to later S3-08 launcher/tests or separate authorization:

- public launcher UX for enabling egress;
- broad S3-08 session launch tests;
- production OpenBao role bootstrap automation;
- AWS/EKS/Kubernetes manifests or release readiness;
- OAuth expansion;
- long-running soak/performance/operational dashboards;
- revocation webhooks/server-push revocation.

ADR 0015 remains authoritative for architecture, dependency, proto, descriptor, static Envoy, OpenBao, WAL, telemetry, fail-closed, and security constraints. ADR 0017 changes only the issue #66 line cap.
