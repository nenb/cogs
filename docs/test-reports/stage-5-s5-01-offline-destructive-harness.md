# Stage 5 S5-01 — offline destructive harness report

**Issue:** #364

**Scope:** local/static only

**Result:** bounded synthetic harness implemented; no runtime or release claim

## Implemented

- Added a canonical deterministic fixture suite for process, proxy, OpenBao, OTLP, WAL, disk, SSE, JSONL, Git, oversized skill, and hostile-output faults.
- Added paired `functional-insecure` and `authoritative-local-linux-kvm` applicability records without claiming either runtime was observed.
- Added a pure state machine that requires parent-only acquisition and exact reverse-order cleanup, reports unknown prompt outcomes, and rejects unknown prompt replay.
- Added a strict aggregation harness binding every case to an exact ordered governing-source set.
- Added metadata-only fixture/report schemas and a committed machine report.
- Added hostile getter, recursive Proxy, prototype, symbol, sparse array, cycle, depth, property, string, aggregate, oversize byte, source replay, sequence replay, duplicate case, profile substitution, and cleanup mutation coverage.
- Structurally fixed cloud, provider, cluster, deployment, external-model, scheduler, controller, and retry routes to false.

## Evidence location

- Fixture: `test/fixtures/stage5-destructive/suite-v1.canonical-json`
- Harness: `scripts/stage5-destructive-harness.ts`
- Tests: `test/stage5-destructive-harness.test.ts`
- Report: `docs/security-evidence/stage5-destructive-harness-report.canonical-json`
- Operating contract: `docs/operations/stage-5-offline-destructive-harness.md`

## Applicability

The insecure-container lane is functional-only. The Linux/KVM lane identifies the only permitted authoritative-local applicability class, but this static run observes no Linux/KVM environment and makes no authoritative claim. A future real Linux/KVM execution would require a separate executor and evidence authority; this issue intentionally adds neither.

## Non-claim

This result does not authorize a campaign, satisfy S4-11 or a Stage 5 criterion, validate a real dependency, establish release readiness, or permit a cloud/provider/model operation.
