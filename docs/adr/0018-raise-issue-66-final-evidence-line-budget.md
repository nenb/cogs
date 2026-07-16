# ADR 0018: Raise issue #66 final evidence line budget after measured OpenBao revocation attempt

- Status: Accepted
- Date: 2026-07-16
- Decision owner: Nick Byrne
- Accepted by: Nick Byrne on 2026-07-16 in conversation after explicit owner review of the proposed 11,650-line cap.

## Context

ADR 0015 accepted the issue #66 Stage 3 secure-egress architecture and scope. ADR 0017 superseded ADR 0016's numeric cap and set a hard cap of **11,000** production `src/**/*.ts` lines, without widening architecture, dependencies, protocol support, release claims, AWS/EKS scope, OAuth, or production-readiness claims.

After PR #100 was squash-merged, clean `main` measured:

```sh
find src -name '*.ts' -print0 | xargs -0 wc -l | tail -1
# 10730 total
```

At decision time, a local, uncommitted source-only implementation attempt for the next issue #66 slice added a strict OpenBao KV-v2 metadata revocation source and measured:

```sh
wc -l src/egress/openbao-revocation.ts
# 292 src/egress/openbao-revocation.ts
find src -name '*.ts' -print0 | xargs -0 wc -l | tail -1
# 11022 total
```

That exceeds ADR 0017 by **22** lines before the source-only adapter has passed focused tests, before any production composition wires it into runtime construction, and before the remaining issue #66 OTLP/default-deny evidence work. Compressing or deleting strict parsing, redaction, callback-scope, abort, timeout, content-type, size, no-redirect, handle, and metadata-shape checks would be contrary to ADR 0015's fail-closed requirements.

At decision time, that measured diff was intentionally preserved for review before any commit or push.

## Measured line breakdown

Production line count:

| State | Production `src/**/*.ts` lines | Delta vs PR #100 main | ADR 0017 headroom |
|---|---:|---:|---:|
| PR #100 merged main | 10,730 | 0 | 270 |
| Local OpenBao metadata revocation source attempt | 11,022 | +292 | -22 |

Decision-time source/test files:

| File | Lines | Counts toward production cap? | Notes |
|---|---:|---:|---|
| `src/egress/openbao-revocation.ts` | 292 | Yes | Source-only adapter implementing existing `CogsEgressRevocationSource`; strict KV-v2 metadata parser and generic errors. |
| `test/egress-openbao-revocation.test.ts` | 263 | No | Hostile parser/callback/watcher-interoperability tests; local and uncommitted at decision time. |

## Remaining issue #66 estimate

These estimates intentionally exclude formatting compression and assume strict fail-closed validation remains readable and reviewable.

| Remaining area | Estimated production lines | Evidence/test lines | Notes |
|---|---:|---:|---|
| Finish and harden OpenBao metadata revocation source | 292 measured | 260-340 | Already measured over cap by 22; focused tests still need fixes. |
| Source integration/composition | 80-140 | 80-160 | Wire source construction at the future trusted composition boundary with a consistently supplied baseline credential version; no lifecycle API widening. |
| Real-runtime harness revocation evidence | 0-30 | 180-320 | Convert revocation dependency from stable stub to real OpenBao metadata mutation in insecure-container evidence only; no release claim. Production lines should be zero unless a tiny exported helper is needed. |
| OTLP metadata-only buffering/export gap | 160-260 | 160-260 | ADR 0015 requires real Stage 3 telemetry rows; must preserve ADR 0008 forbidden-metadata constraints. |
| Guest reachability/default-deny/lifecycle evidence | 80-160 | 220-420 | Authoritative Linux/KVM evidence and any minimal lifecycle glue still pending; no Docker/AWS expansion follows from this ADR. |
| Final evidence/redaction/schema glue | 40-80 | 80-160 | Report/sidecar semantics and redaction assertions for final non-release/conditional-release evidence. |
| **Remaining planning estimate from PR #100 main** | **652-962** | **980-1,660** | Production estimate measured from `10,730` baseline. |

Planning estimate selected for cap sizing: **780** production lines from PR #100 main. A 15% contingency on 780 is **117** lines, requiring at least `10,730 + 780 + 117 = 11,627` production lines.

## Decision

Replace ADR 0017's issue #66 aggregate cap of **11,000** production `src/**/*.ts` lines with a hard cap of **11,650** production `src/**/*.ts` lines.

This is the smallest defensible rounded cap from the measured remaining-work plan:

- `11,650 - 10,730 = 920` total remaining allowance from PR #100 main;
- `920 - 780 = 140` contingency;
- `140 / 780 = 17.9%` contingency, satisfying the >=15% requirement;
- the measured source-only OpenBao revocation attempt at 292 lines would leave `11,650 - 11,022 = 628` lines for source integration, OTLP, and final lifecycle/evidence production glue.

## Non-expansion

This ADR changes only the issue #66 numeric production line cap. It does not approve:

- new production dependencies;
- Envoy version, descriptor, xDS/SDS, Lua, dynamic proxy, direct fallback, protocol, or credential architecture changes;
- AWS/EKS/deployment/release eligibility;
- OAuth refresh-token handling;
- Docker or AWS local validation requirements;
- closing issue #66 before final evidence review;
- weakening ADR 0008 metadata-only telemetry or ADR 0015 fail-closed constraints.

## Consequences

Implementation may continue without compressing security-critical OpenBao metadata parsing and revocation checks merely to fit the previous 270-line remainder. Every subsequent issue #66 PR must continue to report the measured production count and stop before exceeding 11,650 lines.
