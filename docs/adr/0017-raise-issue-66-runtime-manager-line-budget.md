# ADR 0017: Raise issue #66 runtime-manager line budget after measured remaining-work plan

- Status: Accepted
- Date: 2026-07-16
- Decision owner: Nick Byrne
- Accepted by: delegated project lead acting under Nick Byrne’s explicit delegation of project decisions in the 2026-07-16 conversation.

## Context

ADR 0015 accepted the Stage 3 issue #66 secure-egress integration architecture and constraints. ADR 0016 later amended only the issue #66 production `src/**/*.ts` line-budget cap from 8,500 to 9,000 after measured secure-egress slices.

After the merged model-backed credential adapter and OpenBao PKI source slices, the measured production count is **8,758 / 9,000**. The remaining 242 lines are not enough to safely implement the remaining issue #66 runtime integration: trusted tmpfs material writing, Envoy process/readiness ownership, runtime-manager composition, completion queueing, revocation/version polling, and lifecycle cleanup wiring.

A measured remaining-work plan estimates the remaining issue #66 production work at 1,360–2,040 lines, with a 1,800-line planning estimate. A revised hard cap must preserve at least 15% contingency over the planning estimate without compressing security-critical code.

## Decision

Replace ADR 0016's issue #66 aggregate cap of **9,000** production `src/**/*.ts` lines with a hard cap of **11,000** production `src/**/*.ts` lines.

This ADR changes only the issue #66 line budget. ADR 0015 remains authoritative for every architecture, dependency, vendored proto closure, descriptor artifact, Envoy static-configuration, no-fallback, OpenBao, WAL, telemetry, security, and non-scope constraint. ADR 0016 remains a historical measured line-budget amendment superseded only for the numeric cap.

No architecture, dependency, proto, protocol, release, AWS/EKS, OAuth, deployment, or production-readiness expansion follows from this amendment.

## Rationale

The current measured state is:

- current production `src/**/*.ts`: **8,758**;
- current ADR 0016 cap: **9,000**;
- current remaining room: **242** lines.

The measured remaining-work plan estimates:

- low remaining estimate: **1,360** lines;
- high remaining estimate: **2,040** lines;
- planning estimate: **1,800** lines;
- 15% contingency on 1,800: **270** lines;
- minimum cap for planning estimate plus 15% contingency: `8,758 + 1,800 + 270 = 10,828`.

A hard cap of **11,000** leaves `11,000 - 8,758 = 2,242` lines from the current measured baseline. That provides `2,242 - 1,800 = 442` lines of contingency, or **24.6%** over the planning estimate.

The additional budget is bounded and issue-specific. It is intended to preserve fail-closed validation, redaction, cleanup, process ownership, and evidence quality rather than encourage compression of security-critical paths.

## Consequences

Issue #66 implementation may proceed up to **11,000** production `src/**/*.ts` lines, with every PR continuing to report the measured aggregate count.

The 11,000-line cap is hard. Breaching it, adding or changing production dependencies, changing the vendored proto source closure or descriptor artifact contract, changing the static Envoy architecture, or widening protocol/release/deployment scope still requires review and an accepted amendment or superseding ADR.

No release, AWS, EKS, production-readiness, or OAuth authorization follows from this ADR.
