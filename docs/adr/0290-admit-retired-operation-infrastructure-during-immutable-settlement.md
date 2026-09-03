# ADR 0290: Admit retired operation infrastructure during immutable settlement

## Status

Accepted.

## Context

Protected-main reusable diagnostic run `33753005681`, attempt 1, executed both actual production-shaped routes without minting. The readiness route passed after 66 minutes and the full route passed after 106 minutes. Each route completed its lifecycle teardown and removed its retired journal. The subsequent cleanup-only entry correctly classified the operation as journal-absent, settled preproduction custody, closed static custody, and raised the dedicated `CoordinatorNoOperationPath` classification.

The immutable-preparation fallback then rejected the still-present `kata-operation-v1` infrastructure directory before rolling back authenticated runtime and rootfs preparation. Exact operation retirement intentionally removes the journal while retaining the fixed sentinel/lock infrastructure for the later fixed-root settlement step. Treating the directory pathname alone as active mutable state contradicts the operation owner's authenticated `infrastructure-absent`, `infrastructure-subset`, and `infrastructure-complete` classifications. Recovery, settlement, residue proof, and scaffolding restoration consequently did not complete. Run `33753005681` remains non-authorizing despite both route passes.

## Decision

Before immutable rollback, independently reopen the fixed operation recovery probe when `kata-operation-v1` exists. Permit immutable rollback only when that sealed owner classifies the state as one of the three journal-absent infrastructure shapes. An exact journal, malformed generation, changed infrastructure, symlink, foreign entry, or any active/uncertain classification remains a hard stop.

Continue to reject every other mutable path exactly as before. Do not delete operation infrastructure in the immutable fallback; the existing settlement step may remove fixed roots only after recovery success and its independent process/mount scan. Add focused tests proving authenticated idle operation infrastructure is admitted while an active classification preserves all immutable custody.

After exact-head review and protected CI, one new attempt-one reusable diagnostic may run. Producer, publisher, rehearsal, qualification, and AWS remain frozen until both routes, recovery, settlement, residue, and scaffolding restoration pass together.

## Consequences

The correction grants no work construction, retry, receipt, publication, qualification, production, or AWS authority. Runs `33705783258` and `33753005681` remain historical non-authorizing diagnostics. A successful future diagnostic must still receive independent audit before authoritative generation work resumes.
